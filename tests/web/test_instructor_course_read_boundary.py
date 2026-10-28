"""Product scope forwarding at the installed Learning read boundary."""

from uuid import uuid4

import pytest

from app.web import instructor


def test_assigned_courses_delegate_once_and_keep_mutable_product_set(monkeypatch):
    db = object()
    tenant_id, instructor_id, course_id = uuid4(), uuid4(), uuid4()
    owner_result = frozenset({course_id})
    calls = []

    def read(actual_db, **scope):
        calls.append((actual_db, scope))
        return owner_result

    monkeypatch.setattr(instructor, "instructor_assigned_course_ids", read)
    result = instructor._assigned_course_ids(db, tenant_id=tenant_id, instructor_id=instructor_id)

    assert calls == [(db, {"tenant_id": tenant_id, "instructor_id": instructor_id})]
    assert type(result) is set
    assert result == {course_id}
    result.clear()
    assert owner_result == frozenset({course_id})


def test_assigned_courses_propagate_owner_failure_without_local_query(monkeypatch):
    error = RuntimeError("owner read unavailable")

    def read(*args, **kwargs):
        raise error

    monkeypatch.setattr(instructor, "instructor_assigned_course_ids", read)
    with pytest.raises(RuntimeError) as observed:
        instructor._assigned_course_ids(object(), tenant_id=uuid4(), instructor_id=uuid4())
    assert observed.value is error

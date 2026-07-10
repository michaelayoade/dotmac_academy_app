"""Service-level tests for app/services/announcements.py."""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select, text

from app.models.cohort import Cohort, Enrollment
from app.models.notification import Notification
from app.models.person import Person
from app.models.rbac import AuditEvent
from app.services import announcements as ann_svc


def _set_tenant(db, tenant_id):
    db.execute(text("SELECT set_config('app.current_tenant', :t, true)"), {"t": str(tenant_id)})


def _make_person(db, tenant, suffix=""):
    pid = uuid4()
    p = Person(
        tenant_id=tenant.id,
        email=f"{pid}{suffix}@ann.test",
        first_name="Ann",
        last_name="Test",
    )
    p.id = pid
    db.add(p)
    db.flush()
    return p


def _make_cohort(db, tenant, name="Cohort"):
    c = Cohort(tenant_id=tenant.id, name=name, discipline="net", status="active")
    db.add(c)
    db.flush()
    return c


def _enroll(db, tenant, person, cohort, role="student", status="active"):
    e = Enrollment(
        tenant_id=tenant.id,
        cohort_id=cohort.id,
        person_id=person.id,
        role_in_cohort=role,
        status=status,
    )
    db.add(e)
    db.flush()
    return e


@pytest.fixture
def db_session(admin_session):
    return admin_session


def test_create_returns_announcement(db_session, tenant_a):
    _set_tenant(db_session, tenant_a.id)
    author = _make_person(db_session, tenant_a)

    ann = ann_svc.create(
        db_session,
        tenant_id=tenant_a.id,
        author_person_id=author.id,
        title="Hello World",
        body_md="**Bold** text",
    )
    db_session.flush()

    assert ann.id is not None
    assert ann.tenant_id == tenant_a.id
    assert ann.title == "Hello World"
    assert "<strong>Bold</strong>" in ann.body_html
    assert ann.cohort_id is None


def test_create_tenant_wide_emits_notifications_to_enrolled(db_session, tenant_a):
    """Tenant-wide announcement notifies all actively-enrolled persons."""
    _set_tenant(db_session, tenant_a.id)
    author = _make_person(db_session, tenant_a)
    cohort = _make_cohort(db_session, tenant_a)
    student1 = _make_person(db_session, tenant_a)
    student2 = _make_person(db_session, tenant_a)
    unenrolled = _make_person(db_session, tenant_a)

    _enroll(db_session, tenant_a, student1, cohort)
    _enroll(db_session, tenant_a, student2, cohort)
    # unenrolled gets no notification

    ann_svc.create(
        db_session,
        tenant_id=tenant_a.id,
        author_person_id=author.id,
        title="Tenant-wide notice",
        body_md="For everyone",
    )
    db_session.flush()

    notifs = db_session.scalars(
        select(Notification)
        .where(Notification.tenant_id == tenant_a.id)
        .where(Notification.kind == "announcement")
        .where(Notification.title == "Tenant-wide notice")
    ).all()
    notified_ids = {n.person_id for n in notifs}
    assert student1.id in notified_ids
    assert student2.id in notified_ids
    assert unenrolled.id not in notified_ids


def test_create_cohort_targeted_emits_notifications_only_to_that_cohort(db_session, tenant_a):
    """Cohort-targeted announcement notifies only that cohort's active students."""
    _set_tenant(db_session, tenant_a.id)
    author = _make_person(db_session, tenant_a)
    cohort_a = _make_cohort(db_session, tenant_a, "Alpha")
    cohort_b = _make_cohort(db_session, tenant_a, "Beta")
    student_a = _make_person(db_session, tenant_a)
    student_b = _make_person(db_session, tenant_a)

    _enroll(db_session, tenant_a, student_a, cohort_a)
    _enroll(db_session, tenant_a, student_b, cohort_b)

    ann_svc.create(
        db_session,
        tenant_id=tenant_a.id,
        author_person_id=author.id,
        title="Cohort A only",
        body_md="For cohort A",
        cohort_id=cohort_a.id,
    )
    db_session.flush()

    notifs = db_session.scalars(
        select(Notification)
        .where(Notification.tenant_id == tenant_a.id)
        .where(Notification.kind == "announcement")
        .where(Notification.title == "Cohort A only")
    ).all()
    notified_ids = {n.person_id for n in notifs}
    assert student_a.id in notified_ids
    assert student_b.id not in notified_ids


def test_create_writes_audit_event(db_session, tenant_a):
    _set_tenant(db_session, tenant_a.id)
    author = _make_person(db_session, tenant_a)

    ann = ann_svc.create(
        db_session,
        tenant_id=tenant_a.id,
        author_person_id=author.id,
        title="Audit check",
        body_md="body",
    )
    db_session.flush()

    events = db_session.scalars(
        select(AuditEvent)
        .where(AuditEvent.tenant_id == tenant_a.id)
        .where(AuditEvent.action == "announcement.created")
        .where(AuditEvent.entity_id == str(ann.id))
    ).all()
    assert len(events) == 1
    assert events[0].actor_person_id == author.id


def test_for_person_tenant_wide_visible_to_all_enrolled(db_session, tenant_a):
    """Tenant-wide announcement is returned for any enrolled person."""
    _set_tenant(db_session, tenant_a.id)
    author = _make_person(db_session, tenant_a)
    cohort = _make_cohort(db_session, tenant_a)
    student = _make_person(db_session, tenant_a)
    _enroll(db_session, tenant_a, student, cohort)

    ann = ann_svc.create(
        db_session,
        tenant_id=tenant_a.id,
        author_person_id=author.id,
        title="Global message",
        body_md="For all",
    )
    db_session.flush()

    items = ann_svc.for_person(db_session, tenant_id=tenant_a.id, person_id=student.id)
    assert any(a.id == ann.id for a in items)


def test_for_person_tenant_wide_visible_without_enrollment(db_session, tenant_a):
    """Tenant-wide announcement is returned even with no enrollments."""
    _set_tenant(db_session, tenant_a.id)
    author = _make_person(db_session, tenant_a)
    unenrolled = _make_person(db_session, tenant_a)

    ann = ann_svc.create(
        db_session,
        tenant_id=tenant_a.id,
        author_person_id=author.id,
        title="Open message",
        body_md="Anyone can see",
    )
    db_session.flush()

    items = ann_svc.for_person(db_session, tenant_id=tenant_a.id, person_id=unenrolled.id)
    assert any(a.id == ann.id for a in items)


def test_for_person_cohort_targeted_visible_only_to_that_cohort_member(db_session, tenant_a):
    """Cohort-targeted announcement is visible to enrolled member but NOT to other cohort member."""
    _set_tenant(db_session, tenant_a.id)
    author = _make_person(db_session, tenant_a)
    cohort_a = _make_cohort(db_session, tenant_a, "A")
    cohort_b = _make_cohort(db_session, tenant_a, "B")
    student_a = _make_person(db_session, tenant_a)
    student_b = _make_person(db_session, tenant_a)

    _enroll(db_session, tenant_a, student_a, cohort_a)
    _enroll(db_session, tenant_a, student_b, cohort_b)

    ann = ann_svc.create(
        db_session,
        tenant_id=tenant_a.id,
        author_person_id=author.id,
        title="Cohort A only",
        body_md="For A",
        cohort_id=cohort_a.id,
    )
    db_session.flush()

    # student_a (in cohort_a) should see it
    items_a = ann_svc.for_person(db_session, tenant_id=tenant_a.id, person_id=student_a.id)
    assert any(a.id == ann.id for a in items_a)

    # student_b (in cohort_b) should NOT see it
    items_b = ann_svc.for_person(db_session, tenant_id=tenant_a.id, person_id=student_b.id)
    assert not any(a.id == ann.id for a in items_b)


def test_for_person_newest_first(db_session, tenant_a):
    """for_person returns announcements newest first."""
    from datetime import UTC, datetime

    _set_tenant(db_session, tenant_a.id)
    author = _make_person(db_session, tenant_a)
    cohort = _make_cohort(db_session, tenant_a)
    student = _make_person(db_session, tenant_a)
    _enroll(db_session, tenant_a, student, cohort)

    ann1 = ann_svc.create(
        db_session, tenant_id=tenant_a.id, author_person_id=author.id, title="First", body_md=""
    )
    ann1.created_at = datetime(2024, 1, 1, tzinfo=UTC)
    ann2 = ann_svc.create(
        db_session, tenant_id=tenant_a.id, author_person_id=author.id, title="Second", body_md=""
    )
    ann2.created_at = datetime(2024, 1, 2, tzinfo=UTC)
    db_session.flush()

    items = ann_svc.for_person(db_session, tenant_id=tenant_a.id, person_id=student.id)
    titles = [a.title for a in items]
    assert titles.index("Second") < titles.index("First")


def test_list_for_tenant(db_session, tenant_a):
    _set_tenant(db_session, tenant_a.id)
    author = _make_person(db_session, tenant_a)

    ann_svc.create(
        db_session, tenant_id=tenant_a.id, author_person_id=author.id, title="T1", body_md=""
    )
    ann_svc.create(
        db_session, tenant_id=tenant_a.id, author_person_id=author.id, title="T2", body_md=""
    )
    db_session.flush()

    items = ann_svc.list_for_tenant(db_session, tenant_id=tenant_a.id)
    titles = [a.title for a in items]
    assert "T1" in titles
    assert "T2" in titles


def test_delete_removes_announcement(db_session, tenant_a):
    _set_tenant(db_session, tenant_a.id)
    author = _make_person(db_session, tenant_a)

    ann = ann_svc.create(
        db_session, tenant_id=tenant_a.id, author_person_id=author.id, title="To delete", body_md=""
    )
    db_session.flush()

    ann_svc.delete(db_session, tenant_id=tenant_a.id, announcement_id=ann.id)
    db_session.flush()

    items = ann_svc.list_for_tenant(db_session, tenant_id=tenant_a.id)
    assert not any(a.id == ann.id for a in items)


def test_delete_nonexistent_is_noop(db_session, tenant_a):
    """Deleting a nonexistent announcement does not raise."""
    _set_tenant(db_session, tenant_a.id)
    ann_svc.delete(db_session, tenant_id=tenant_a.id, announcement_id=uuid4())

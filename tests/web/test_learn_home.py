"""Tests for the student Learn Home (`GET /`) — Increment 3a Task 4."""

from __future__ import annotations

from app.models.assessment import Activity, Score, Submission
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.person import Person
from app.services.security import hash_password


def _login(app_client, admin_session, tenant, email="stu@a.edu"):
    p = Person(tenant_id=tenant.id, email=email, first_name="Stu", last_name="Dent")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant.id,
            person_id=p.id,
            email=email,
            password_hash=hash_password("password1"),
        )
    )
    admin_session.commit()
    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": email, "password": "password1"})
    return p, h


def test_learn_home_shows_course_completion_and_results(app_client, admin_session, tenant_a):
    p, h = _login(app_client, admin_session, tenant_a)
    tid = tenant_a.id

    course = Course(tenant_id=tid, slug="net", title="Networking 101",
                    discipline="networking", source_ref="x", version=1)
    admin_session.add(course)
    admin_session.flush()
    a1 = Activity(tenant_id=tid, course_id=course.id, chapter_number=1, type="mcq_test",
                  title="Ch1 Test", pass_threshold=0.6)
    a2 = Activity(tenant_id=tid, course_id=course.id, chapter_number=2, type="mcq_test",
                  title="Ch2 Test", pass_threshold=0.6)
    admin_session.add_all([a1, a2])
    admin_session.flush()

    coh = Cohort(tenant_id=tid, name="Abuja 2026", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.flush()
    admin_session.add(Enrollment(tenant_id=tid, cohort_id=coh.id, person_id=p.id,
                                 role_in_cohort="student", status="active"))
    admin_session.flush()

    # One passing score on a1 → 1 of 2 activities passed → 50% completion.
    sub = Submission(tenant_id=tid, activity_id=a1.id, person_id=p.id, answers={}, attempt_no=1)
    admin_session.add(sub)
    admin_session.flush()
    admin_session.add(Score(tenant_id=tid, submission_id=sub.id, score=10, max_score=10,
                            fraction=1.0, passed=True, per_item=[], source="auto"))
    admin_session.commit()

    r = app_client.get("/", headers=h)
    assert r.status_code == 200
    # My courses: title + completion percentage.
    assert "Networking 101" in r.text
    assert "50%" in r.text
    # Recent results: the passed activity shows up.
    assert "Ch1 Test" in r.text


def test_learn_home_empty_state_when_not_enrolled(app_client, admin_session, tenant_a):
    p, h = _login(app_client, admin_session, tenant_a, email="lonely@a.edu")
    # A course exists in the tenant, but the person is not enrolled in any cohort.
    course = Course(tenant_id=tenant_a.id, slug="net", title="Networking 101",
                    discipline="networking", source_ref="x", version=1)
    admin_session.add(course)
    admin_session.commit()

    r = app_client.get("/", headers=h)
    assert r.status_code == 200
    assert "not enrolled in a course yet" in r.text


def test_learn_home_separates_finished_courses(app_client, admin_session, tenant_a):
    p, h = _login(app_client, admin_session, tenant_a, email="finished@a.edu")
    active = Course(
        tenant_id=tenant_a.id,
        slug="active-net",
        title="Active Networking",
        discipline="networking",
        source_ref="x",
        version=1,
        status="active",
    )
    finished = Course(
        tenant_id=tenant_a.id,
        slug="finished-net",
        title="Finished Networking",
        discipline="networking",
        source_ref="x",
        version=1,
        status="finished",
    )
    hidden = Course(
        tenant_id=tenant_a.id,
        slug="draft-net",
        title="Draft Networking",
        discipline="networking",
        source_ref="x",
        version=1,
        status="draft",
    )
    cohort = Cohort(
        tenant_id=tenant_a.id,
        name="Networking",
        discipline="networking",
        status="active",
    )
    admin_session.add_all([active, finished, hidden, cohort])
    admin_session.flush()
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id,
            cohort_id=cohort.id,
            person_id=p.id,
            role_in_cohort="student",
            status="active",
        )
    )
    admin_session.commit()

    r = app_client.get("/", headers=h)

    assert r.status_code == 200
    assert "Active Networking" in r.text
    assert "Finished courses" in r.text
    assert "Finished Networking" in r.text
    assert "Draft Networking" not in r.text

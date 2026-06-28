"""Tests for the instructor portal — Task 12 (cohorts, enroll, results, override)."""

from __future__ import annotations

from app.models.auth import UserCredential
from app.models.cohort import Cohort
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password


def _login_instructor(app_client, admin_session, tenant):
    """Seed an instructor person, log in via TestClient, return Host header dict."""
    roles = ensure_roles(admin_session, tenant.id)
    p = Person(tenant_id=tenant.id, email="i@a.edu", first_name="In", last_name="Str")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant.id,
            person_id=p.id,
            email="i@a.edu",
            password_hash=hash_password("password1"),
        )
    )
    admin_session.add(
        PersonRole(tenant_id=tenant.id, person_id=p.id, role_id=roles["instructor"].id)
    )
    admin_session.commit()

    h = {"Host": "alpha.localhost"}
    # First POST to /login has an empty cookie jar → CSRF middleware skips check.
    # The 303 redirect to "/" is followed (default follow_redirects=True), which triggers
    # a GET "/" that makes the CSRF middleware set the csrf_token cookie in the jar.
    app_client.post("/login", headers=h, data={"email": "i@a.edu", "password": "password1"})
    return h


def test_instructor_can_create_cohort(app_client, admin_session, tenant_a):
    """An instructor can POST to create a cohort; the row lands in the DB."""
    h = _login_instructor(app_client, admin_session, tenant_a)

    # After login (with redirect to "/" followed), the TestClient jar has both
    # `session` and `csrf_token` cookies. Subsequent POSTs must include x-csrf-token.
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        "/instructor/cohorts",
        headers={**h, "x-csrf-token": csrf},
        data={"name": "Abuja 2026", "discipline": "networking"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    # admin_session bypasses RLS; the Cohort committed by get_db is visible here.
    assert (
        admin_session.query(Cohort).filter(Cohort.tenant_id == tenant_a.id).count() == 1
    )


def test_enroll_cross_tenant_404(app_client, admin_session, tenant_a, tenant_b):
    """POSTing to enroll with a cohort owned by a different tenant returns 404."""
    h = _login_instructor(app_client, admin_session, tenant_a)

    # Create a cohort under tenant_b directly (bypasses RLS via admin_session).
    cohort_b = Cohort(tenant_id=tenant_b.id, name="Beta Cohort", discipline="security", status="active")
    admin_session.add(cohort_b)
    admin_session.commit()
    admin_session.refresh(cohort_b)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{cohort_b.id}/enroll",
        headers={**h, "x-csrf-token": csrf},
        data={"email": "nobody@example.com"},
        follow_redirects=False,
    )
    assert r.status_code == 404


def test_bulk_enroll_surfaces_unknown_emails(app_client, admin_session, tenant_a):
    """Finding #6: enrolling reports unknown emails instead of silently no-oping."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    # A real student + a cohort.
    stu = Person(tenant_id=tenant_a.id, email="real@a.edu", first_name="Re", last_name="Al")
    admin_session.add(stu)
    coh = Cohort(tenant_id=tenant_a.id, name="Roster", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.commit()
    admin_session.refresh(coh)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/enroll",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={"emails": "real@a.edu, ghost@a.edu"},
    )
    assert r.status_code == 200
    assert "Enrolled 1" in r.text
    assert "ghost@a.edu" in r.text  # unknown email surfaced
    from app.models.cohort import Enrollment
    n = admin_session.query(Enrollment).filter(
        Enrollment.cohort_id == coh.id, Enrollment.status == "active").count()
    assert n == 1


def test_grading_queue_lists_pending(app_client, admin_session, tenant_a):
    """Finding #4: manual submissions awaiting a score appear in the queue."""
    from app.models.assessment import Activity, Submission
    from app.models.course import Course

    h = _login_instructor(app_client, admin_session, tenant_a)
    learner = Person(tenant_id=tenant_a.id, email="learner@a.edu", first_name="Le", last_name="Ar")
    course = Course(tenant_id=tenant_a.id, slug="mg", title="MG", discipline="networking",
                    source_ref="x", version=1)
    admin_session.add_all([learner, course])
    admin_session.flush()
    act = Activity(tenant_id=tenant_a.id, course_id=course.id, chapter_number=1, type="mcq_test",
                   title="Essay Q", pass_threshold=0.6, grading="manual")
    admin_session.add(act)
    admin_session.flush()
    admin_session.add(Submission(tenant_id=tenant_a.id, activity_id=act.id, person_id=learner.id,
                                 answers={}, attempt_no=1))  # no Score = pending
    admin_session.commit()

    r = app_client.get("/instructor/grading", headers=h)
    assert r.status_code == 200
    assert "Essay Q" in r.text
    assert "learner@a.edu" in r.text


def test_item_analytics_page(app_client, admin_session, tenant_a):
    """Finding #4/#9: per-question difficulty page renders p-values."""
    from app.models.assessment import Activity, Score, Submission
    from app.models.course import Course

    h = _login_instructor(app_client, admin_session, tenant_a)
    learner = Person(tenant_id=tenant_a.id, email="il@a.edu", first_name="Il", last_name="A")
    course = Course(tenant_id=tenant_a.id, slug="ia", title="IA", discipline="networking",
                    source_ref="x", version=1)
    admin_session.add_all([learner, course])
    admin_session.flush()
    act = Activity(tenant_id=tenant_a.id, course_id=course.id, chapter_number=1, type="mcq_test",
                   title="Analytics Quiz", pass_threshold=0.6)
    admin_session.add(act)
    admin_session.flush()
    sub = Submission(tenant_id=tenant_a.id, activity_id=act.id, person_id=learner.id,
                     answers={}, attempt_no=1)
    admin_session.add(sub)
    admin_session.flush()
    admin_session.add(Score(tenant_id=tenant_a.id, submission_id=sub.id, score=10, max_score=10,
                            fraction=1.0, passed=True, source="auto",
                            per_item=[{"id": "q1", "correct": True}]))
    admin_session.commit()

    r = app_client.get(f"/instructor/items/{act.id}", headers=h)
    assert r.status_code == 200
    assert "Analytics Quiz" in r.text
    assert "q1" in r.text


def test_student_forbidden(app_client, admin_session, tenant_a):
    """A user with only the student role gets 403 on any instructor-gated route."""
    roles = ensure_roles(admin_session, tenant_a.id)
    p = Person(tenant_id=tenant_a.id, email="s3@a.edu", first_name="S", last_name="T")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant_a.id,
            person_id=p.id,
            email="s3@a.edu",
            password_hash=hash_password("password1"),
        )
    )
    admin_session.add(
        PersonRole(tenant_id=tenant_a.id, person_id=p.id, role_id=roles["student"].id)
    )
    admin_session.commit()

    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": "s3@a.edu", "password": "password1"})
    assert app_client.get("/instructor/results", headers=h).status_code == 403

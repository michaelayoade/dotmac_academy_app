"""Tests for the instructor portal — Task 12 (cohorts, enroll, results, override)."""

from __future__ import annotations

from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password


def _login_user(app_client, admin_session, tenant, *, email, role_slug):
    """Seed a person, log in via TestClient, return Host header dict."""
    roles = ensure_roles(admin_session, tenant.id)
    p = Person(tenant_id=tenant.id, email=email, first_name="In", last_name="Str")
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
    admin_session.add(
        PersonRole(tenant_id=tenant.id, person_id=p.id, role_id=roles[role_slug].id)
    )
    admin_session.commit()

    h = {"Host": "alpha.localhost"}
    # First POST to /login has an empty cookie jar → CSRF middleware skips check.
    # The 303 redirect to "/" is followed (default follow_redirects=True), which triggers
    # a GET "/" that makes the CSRF middleware set the csrf_token cookie in the jar.
    app_client.post("/login", headers=h, data={"email": email, "password": "password1"})
    return h


def _login_instructor(app_client, admin_session, tenant):
    """Seed an instructor person, log in via TestClient, return Host header dict."""
    return _login_user(
        app_client,
        admin_session,
        tenant,
        email="i@a.edu",
        role_slug="instructor",
    )


def _login_admin(app_client, admin_session, tenant):
    """Seed an admin person, log in via TestClient, return Host header dict."""
    return _login_user(
        app_client,
        admin_session,
        tenant,
        email="admin@a.edu",
        role_slug="admin",
    )


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


def test_create_cohort_reuses_existing_name(app_client, admin_session, tenant_a):
    h = _login_instructor(app_client, admin_session, tenant_a)
    existing = Cohort(
        tenant_id=tenant_a.id,
        name="Lagos Fiber - Q3",
        discipline="Fiber",
        status="active",
    )
    admin_session.add(existing)
    admin_session.commit()

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        "/instructor/cohorts",
        headers={**h, "x-csrf-token": csrf},
        data={"name": " lagos fiber - q3 ", "discipline": "Fiber"},
        follow_redirects=False,
    )

    assert r.status_code == 303
    cohorts = (
        admin_session.query(Cohort)
        .filter(Cohort.tenant_id == tenant_a.id, Cohort.name == "Lagos Fiber - Q3")
        .all()
    )
    assert cohorts == [existing]


def test_instructor_can_create_edit_and_finish_course(app_client, admin_session, tenant_a):
    h = _login_instructor(app_client, admin_session, tenant_a)
    csrf = app_client.cookies.get("csrf_token", "")

    create = app_client.post(
        "/instructor/courses",
        headers={**h, "x-csrf-token": csrf},
        data={
            "title": "Fiber Foundations",
            "slug": "fiber-foundations",
            "discipline": "Fiber",
            "description": "Field-ready fiber basics.",
            "source_ref": "manual@1",
            "status": "active",
        },
        follow_redirects=False,
    )
    assert create.status_code == 303

    course = (
        admin_session.query(Course)
        .filter(Course.tenant_id == tenant_a.id, Course.slug == "fiber-foundations")
        .one()
    )
    assert course.status == "active"
    assert course.description == "Field-ready fiber basics."

    edit = app_client.post(
        f"/instructor/courses/{course.id}",
        headers={**h, "x-csrf-token": csrf},
        data={
            "title": "Fiber Operations",
            "slug": "fiber-operations",
            "discipline": "Fiber",
            "description": "Updated.",
            "source_ref": "manual@2",
            "status": "active",
        },
        follow_redirects=False,
    )
    assert edit.status_code == 303
    admin_session.refresh(course)
    assert course.title == "Fiber Operations"
    assert course.slug == "fiber-operations"
    assert course.description == "Updated."

    finish = app_client.post(
        f"/instructor/courses/{course.id}/finish",
        headers={**h, "x-csrf-token": csrf},
        follow_redirects=False,
    )
    assert finish.status_code == 303
    admin_session.refresh(course)
    assert course.status == "finished"
    assert course.finished_at is not None


def test_cohorts_page_lists_matching_courses_and_enrolled_students(
    app_client, admin_session, tenant_a
):
    h = _login_instructor(app_client, admin_session, tenant_a)
    cohort = Cohort(
        tenant_id=tenant_a.id,
        name="Lagos Fiber - Q3",
        discipline="Fiber",
        status="active",
    )
    course = Course(
        tenant_id=tenant_a.id,
        slug="fiber-foundations",
        title="Fiber Foundations",
        discipline="Fiber",
        source_ref="test",
    )
    second_course = Course(
        tenant_id=tenant_a.id,
        slug="fiber-ops",
        title="Fiber Operations",
        discipline="Fiber",
        source_ref="test",
    )
    student = Person(
        tenant_id=tenant_a.id,
        email="student@a.edu",
        first_name="Ada",
        last_name="Student",
    )
    admin_session.add_all([cohort, course, second_course, student])
    admin_session.flush()
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id,
            cohort_id=cohort.id,
            person_id=student.id,
            role_in_cohort="student",
            status="active",
        )
    )
    admin_session.commit()

    r = app_client.get("/instructor/cohorts", headers=h)

    assert r.status_code == 200
    assert "Courses and enrolled students" in r.text
    assert "Fiber Foundations" in r.text
    assert "Fiber Operations" in r.text
    assert "Ada Student" in r.text
    assert r.text.count("student@a.edu") == 2


def test_admin_can_view_cohorts_page_student_lists(app_client, admin_session, tenant_a):
    h = _login_admin(app_client, admin_session, tenant_a)
    cohort = Cohort(
        tenant_id=tenant_a.id,
        name="Admin Visible Fiber",
        discipline="Fiber",
        status="active",
    )
    course = Course(
        tenant_id=tenant_a.id,
        slug="admin-fiber",
        title="Admin Fiber",
        discipline="Fiber",
        source_ref="test",
    )
    student = Person(
        tenant_id=tenant_a.id,
        email="admin-visible-student@a.edu",
        first_name="Visible",
        last_name="Student",
    )
    admin_session.add_all([cohort, course, student])
    admin_session.flush()
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id,
            cohort_id=cohort.id,
            person_id=student.id,
            role_in_cohort="student",
            status="active",
        )
    )
    admin_session.commit()

    r = app_client.get("/instructor/cohorts", headers=h)

    assert r.status_code == 200
    assert "Admin Fiber" in r.text
    assert "Visible Student" in r.text
    assert "admin-visible-student@a.edu" in r.text


def test_create_cohort_auto_enrolls_existing_students_for_matching_course(
    app_client, admin_session, tenant_a
):
    h = _login_instructor(app_client, admin_session, tenant_a)
    source_cohort = Cohort(
        tenant_id=tenant_a.id,
        name="Existing Fiber",
        discipline="Fiber",
        status="active",
    )
    course = Course(
        tenant_id=tenant_a.id,
        slug="fiber-foundations",
        title="Fiber Foundations",
        discipline="Fiber",
        source_ref="test",
    )
    student = Person(
        tenant_id=tenant_a.id,
        email="existing-student@a.edu",
        first_name="Existing",
        last_name="Student",
    )
    admin_session.add_all([source_cohort, course, student])
    admin_session.flush()
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id,
            cohort_id=source_cohort.id,
            person_id=student.id,
            role_in_cohort="student",
            status="active",
        )
    )
    admin_session.commit()

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        "/instructor/cohorts",
        headers={**h, "x-csrf-token": csrf},
        data={"name": "Lagos Fiber - Q3", "discipline": "Fiber"},
        follow_redirects=False,
    )

    assert r.status_code == 303
    new_cohort = (
        admin_session.query(Cohort)
        .filter(
            Cohort.tenant_id == tenant_a.id,
            Cohort.name == "Lagos Fiber - Q3",
        )
        .one()
    )
    synced = (
        admin_session.query(Enrollment)
        .filter(
            Enrollment.tenant_id == tenant_a.id,
            Enrollment.cohort_id == new_cohort.id,
            Enrollment.person_id == student.id,
            Enrollment.role_in_cohort == "student",
            Enrollment.status == "active",
        )
        .one_or_none()
    )
    assert synced is not None


def test_enrolling_student_syncs_other_matching_course_cohorts(
    app_client, admin_session, tenant_a
):
    h = _login_instructor(app_client, admin_session, tenant_a)
    cohort_a = Cohort(
        tenant_id=tenant_a.id,
        name="Fiber A",
        discipline="Fiber",
        status="active",
    )
    cohort_b = Cohort(
        tenant_id=tenant_a.id,
        name="Fiber B",
        discipline="Fiber",
        status="active",
    )
    course = Course(
        tenant_id=tenant_a.id,
        slug="fiber-foundations",
        title="Fiber Foundations",
        discipline="Fiber",
        source_ref="test",
    )
    student = Person(
        tenant_id=tenant_a.id,
        email="sync-student@a.edu",
        first_name="Sync",
        last_name="Student",
    )
    admin_session.add_all([cohort_a, cohort_b, course, student])
    admin_session.commit()
    admin_session.refresh(cohort_a)
    admin_session.refresh(cohort_b)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{cohort_a.id}/enroll",
        headers={**h, "x-csrf-token": csrf},
        data={"email": "sync-student@a.edu"},
        follow_redirects=False,
    )

    assert r.status_code == 303
    synced_count = (
        admin_session.query(Enrollment)
        .filter(
            Enrollment.tenant_id == tenant_a.id,
            Enrollment.person_id == student.id,
            Enrollment.cohort_id.in_([cohort_a.id, cohort_b.id]),
            Enrollment.role_in_cohort == "student",
            Enrollment.status == "active",
        )
        .count()
    )
    assert synced_count == 2


def test_enroll_cross_tenant_404(app_client, admin_session, tenant_a, tenant_b):
    """POSTing to enroll with a cohort owned by a different tenant returns 404."""
    h = _login_instructor(app_client, admin_session, tenant_a)

    # Create a cohort under tenant_b directly (bypasses RLS via admin_session).
    cohort_b = Cohort(
        tenant_id=tenant_b.id,
        name="Beta Cohort",
        discipline="security",
        status="active",
    )
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

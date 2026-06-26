"""Tests for the instructor portal — Task 12 (cohorts, enroll, results, override)."""

from __future__ import annotations

from app.services.security import hash_password
from app.services.bootstrap import ensure_roles
from app.models.person import Person
from app.models.auth import UserCredential
from app.models.rbac import PersonRole
from app.models.cohort import Cohort


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

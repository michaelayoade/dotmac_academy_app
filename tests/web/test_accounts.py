"""Tests for the account-creation web flow (/instructor/users)."""

from __future__ import annotations

from app.models.auth import UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole, Role
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password


def _seed_user(admin_session, tenant, email, role_slug):
    """Seed a Person + credential (password 'password1') + the given role."""
    roles = ensure_roles(admin_session, tenant.id)
    p = Person(tenant_id=tenant.id, email=email, first_name="Seed", last_name="User")
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
    return p


def _login(app_client, email, password="password1"):
    """Log in and return (headers, csrf_token)."""
    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": email, "password": password})
    csrf = app_client.cookies.get("csrf_token", "")
    return h, csrf


def test_student_forbidden_on_users_page(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "stud@a.edu", "student")
    h, _ = _login(app_client, "stud@a.edu")
    assert app_client.get("/instructor/users", headers=h).status_code == 403


def test_instructor_can_list_users(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "inst@a.edu", "instructor")
    h, _ = _login(app_client, "inst@a.edu")
    r = app_client.get("/instructor/users", headers=h)
    assert r.status_code == 200
    assert "inst@a.edu" in r.text


def test_instructor_can_create_student(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "inst2@a.edu", "instructor")
    h, csrf = _login(app_client, "inst2@a.edu")

    r = app_client.post(
        "/instructor/users",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={
            "first_name": "New",
            "last_name": "Stud",
            "email": "created-stud@a.edu",
            "password": "password1",
            "role": "student",
        },
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert r.headers.get("HX-Redirect") == "/instructor/users"

    person = admin_session.query(Person).filter(
        Person.tenant_id == tenant_a.id, Person.email == "created-stud@a.edu"
    ).one()
    cred = admin_session.query(UserCredential).filter(
        UserCredential.tenant_id == tenant_a.id, UserCredential.person_id == person.id
    ).one()
    assert cred is not None
    student_role = admin_session.query(Role).filter(
        Role.tenant_id == tenant_a.id, Role.slug == "student"
    ).one()
    grant = admin_session.query(PersonRole).filter(
        PersonRole.tenant_id == tenant_a.id, PersonRole.person_id == person.id
    ).one()
    assert grant.role_id == student_role.id


def test_instructor_cannot_create_admin(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "inst3@a.edu", "instructor")
    h, csrf = _login(app_client, "inst3@a.edu")

    r = app_client.post(
        "/instructor/users",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={
            "first_name": "Bad",
            "last_name": "Admin",
            "email": "no-admin@a.edu",
            "password": "password1",
            "role": "admin",
        },
        follow_redirects=False,
    )
    assert r.status_code == 403
    assert admin_session.query(Person).filter(
        Person.tenant_id == tenant_a.id, Person.email == "no-admin@a.edu"
    ).count() == 0


def test_admin_can_create_admin(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "admin@a.edu", "admin")
    h, csrf = _login(app_client, "admin@a.edu")

    r = app_client.post(
        "/instructor/users",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={
            "first_name": "Extra",
            "last_name": "Admin",
            "email": "extra-admin@a.edu",
            "password": "password1",
            "role": "admin",
        },
        follow_redirects=False,
    )
    assert r.status_code == 200
    admin_role = admin_session.query(Role).filter(
        Role.tenant_id == tenant_a.id, Role.slug == "admin"
    ).one()
    person = admin_session.query(Person).filter(
        Person.tenant_id == tenant_a.id, Person.email == "extra-admin@a.edu"
    ).one()
    grant = admin_session.query(PersonRole).filter(
        PersonRole.tenant_id == tenant_a.id, PersonRole.person_id == person.id
    ).one()
    assert grant.role_id == admin_role.id


def test_created_student_can_login_and_reach_learner_page(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "inst4@a.edu", "instructor")
    h, csrf = _login(app_client, "inst4@a.edu")
    app_client.post(
        "/instructor/users",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={
            "first_name": "Login",
            "last_name": "Able",
            "email": "loginable@a.edu",
            "password": "s3cret-pass",
            "role": "student",
        },
        follow_redirects=False,
    )

    # Fresh client → the newly created student logs in and reaches the dashboard.
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as student_client:
        sh = {"Host": "alpha.localhost"}
        login = student_client.post(
            "/login",
            headers=sh,
            data={"email": "loginable@a.edu", "password": "s3cret-pass"},
            follow_redirects=False,
        )
        assert login.status_code == 303
        dash = student_client.get("/", headers=sh)
        assert dash.status_code == 200

"""Tests for GET /admin/audit — admin audit-log viewer."""

from __future__ import annotations

from app.models.auth import UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.audit import write_audit_event
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password


def _seed_login(admin_session, tenant, email, role_slug):
    roles = ensure_roles(admin_session, tenant.id)
    p = Person(tenant_id=tenant.id, email=email, first_name="Test", last_name="User")
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


def _login(app_client, email):
    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": email, "password": "password1"})
    return h


def test_admin_sees_audit_events(app_client, admin_session, tenant_a):
    admin = _seed_login(admin_session, tenant_a, "admin@a.edu", "admin")
    write_audit_event(
        admin_session,
        tenant_id=tenant_a.id,
        actor_person_id=admin.id,
        action="user.login",
        entity_type="person",
        entity_id=str(admin.id),
    )
    admin_session.commit()

    h = _login(app_client, "admin@a.edu")
    r = app_client.get("/admin/audit", headers=h)
    assert r.status_code == 200
    assert "user.login" in r.text
    assert "person" in r.text


def test_student_forbidden(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "stu@a.edu", "student")
    h = _login(app_client, "stu@a.edu")
    assert app_client.get("/admin/audit", headers=h).status_code == 403


def test_instructor_forbidden(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "inst@a.edu", "instructor")
    h = _login(app_client, "inst@a.edu")
    assert app_client.get("/admin/audit", headers=h).status_code == 403


def test_action_filter_narrows(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "admin@a.edu", "admin")
    write_audit_event(
        admin_session,
        tenant_id=tenant_a.id,
        actor_person_id=None,
        action="user.login",
        entity_type="person",
    )
    write_audit_event(
        admin_session,
        tenant_id=tenant_a.id,
        actor_person_id=None,
        action="course.viewed",
        entity_type="course",
    )
    admin_session.commit()

    h = _login(app_client, "admin@a.edu")
    r = app_client.get("/admin/audit?action=user.login", headers=h)
    assert r.status_code == 200
    assert "user.login" in r.text
    assert "course.viewed" not in r.text


def test_null_actor_shows_system(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "admin@a.edu", "admin")
    write_audit_event(
        admin_session,
        tenant_id=tenant_a.id,
        actor_person_id=None,
        action="system.sweep",
        entity_type="system",
    )
    admin_session.commit()

    h = _login(app_client, "admin@a.edu")
    r = app_client.get("/admin/audit?action=system.sweep", headers=h)
    assert r.status_code == 200
    assert "system" in r.text


def test_actor_email_resolved(app_client, admin_session, tenant_a):
    actor = _seed_login(admin_session, tenant_a, "admin@a.edu", "admin")
    write_audit_event(
        admin_session,
        tenant_id=tenant_a.id,
        actor_person_id=actor.id,
        action="user.created",
        entity_type="person",
    )
    admin_session.commit()

    h = _login(app_client, "admin@a.edu")
    r = app_client.get("/admin/audit?action=user.created", headers=h)
    assert r.status_code == 200
    assert "admin@a.edu" in r.text


def test_tenant_isolation(app_client, admin_session, tenant_a, tenant_b):
    """Events seeded for tenant_b must not appear in tenant_a's audit log (RLS)."""
    _seed_login(admin_session, tenant_a, "admin@a.edu", "admin")
    write_audit_event(
        admin_session,
        tenant_id=tenant_b.id,
        actor_person_id=None,
        action="secret.event",
        entity_type="system",
    )
    admin_session.commit()

    h = _login(app_client, "admin@a.edu")
    r = app_client.get("/admin/audit", headers=h)
    assert r.status_code == 200
    assert "secret.event" not in r.text

"""Instructor timetable UI: view, create, cancel sessions + set delivery mode."""

from __future__ import annotations

from sqlalchemy import select

from app.models.auth import UserCredential
from app.models.class_session import ClassSession
from app.models.cohort import Cohort
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password

H = {"Host": "alpha.localhost"}


def _login_instructor(app_client, admin_session, tenant):
    roles = ensure_roles(admin_session, tenant.id)
    p = Person(tenant_id=tenant.id, email="tt@a.edu", first_name="Ti", last_name="Me")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(tenant_id=tenant.id, person_id=p.id, email="tt@a.edu",
                       password_hash=hash_password("password1"))
    )
    admin_session.add(PersonRole(tenant_id=tenant.id, person_id=p.id, role_id=roles["instructor"].id))
    admin_session.commit()
    app_client.post("/login", headers=H, data={"email": "tt@a.edu", "password": "password1"})
    return H


def _cohort(admin_session, tenant):
    c = Cohort(tenant_id=tenant.id, name="TT Cohort", discipline="fiber",
               status="active", delivery_mode="self_paced")
    admin_session.add(c)
    admin_session.commit()
    admin_session.refresh(c)
    return c


def test_timetable_page_renders(app_client, admin_session, tenant_a):
    _login_instructor(app_client, admin_session, tenant_a)
    c = _cohort(admin_session, tenant_a)
    r = app_client.get(f"/instructor/cohorts/{c.id}/timetable", headers=H)
    assert r.status_code == 200
    assert "Timetable" in r.text and "Add a session" in r.text


def test_create_session_and_autopromote_delivery_mode(app_client, admin_session, tenant_a):
    h = _login_instructor(app_client, admin_session, tenant_a)
    c = _cohort(admin_session, tenant_a)
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{c.id}/sessions",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={"title": "Live Q&A", "session_type": "live_class",
              "starts_at": "2026-08-01T10:00", "ends_at": "2026-08-01T11:00",
              "location": "Lagos lab", "join_url": "https://meet.example/x"},
    )
    assert r.status_code == 200
    session = admin_session.scalars(
        select(ClassSession).where(ClassSession.cohort_id == c.id)
    ).first()
    assert session is not None and session.title == "Live Q&A"
    # Scheduling on a self-paced cohort promotes it to blended.
    admin_session.expire(c)
    assert admin_session.get(Cohort, c.id).delivery_mode == "blended"


def test_cancel_session(app_client, admin_session, tenant_a):
    h = _login_instructor(app_client, admin_session, tenant_a)
    c = _cohort(admin_session, tenant_a)
    csrf = app_client.cookies.get("csrf_token", "")
    app_client.post(
        f"/instructor/cohorts/{c.id}/sessions",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={"title": "Doomed", "starts_at": "2026-08-02T09:00"},
    )
    session = admin_session.scalars(select(ClassSession).where(ClassSession.cohort_id == c.id)).first()
    r = app_client.post(
        f"/instructor/sessions/{session.id}/cancel",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
    )
    assert r.status_code == 200
    admin_session.expire(session)
    assert admin_session.get(ClassSession, session.id).status == "cancelled"


def test_set_delivery_mode(app_client, admin_session, tenant_a):
    h = _login_instructor(app_client, admin_session, tenant_a)
    c = _cohort(admin_session, tenant_a)
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{c.id}/delivery-mode",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={"mode": "live"},
    )
    assert r.status_code == 200
    admin_session.expire(c)
    assert admin_session.get(Cohort, c.id).delivery_mode == "live"

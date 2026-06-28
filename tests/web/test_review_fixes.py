"""Web regression test for the review fix: announcement create validates cohort_id
(400 instead of 500 on a non-UUID or cross-tenant cohort)."""

from __future__ import annotations

from app.models.auth import UserCredential
from app.models.cohort import Cohort
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password


def _admin_login(app_client, db, tenant, email="adm@a.edu"):
    roles = ensure_roles(db, tenant.id)
    p = Person(tenant_id=tenant.id, email=email, first_name="Ad", last_name="Min")
    db.add(p)
    db.flush()
    db.add(UserCredential(tenant_id=tenant.id, person_id=p.id, email=email,
                          password_hash=hash_password("password1")))
    db.add(PersonRole(tenant_id=tenant.id, person_id=p.id, role_id=roles["admin"].id))
    db.commit()
    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": email, "password": "password1"})
    return h, app_client.cookies.get("csrf_token", "")


def test_announcement_bad_cohort_id_returns_400(app_client, admin_session, tenant_a):
    h, csrf = _admin_login(app_client, admin_session, tenant_a)
    r = app_client.post(
        "/instructor/announcements",
        headers={**h, "x-csrf-token": csrf},
        data={"title": "T", "body_md": "b", "cohort_id": "not-a-uuid"},
    )
    assert r.status_code == 400


def test_announcement_cross_tenant_cohort_returns_400(app_client, admin_session, tenant_a, tenant_b):
    h, csrf = _admin_login(app_client, admin_session, tenant_a)
    other = Cohort(tenant_id=tenant_b.id, name="B", discipline="networking", status="active")
    admin_session.add(other)
    admin_session.commit()
    r = app_client.post(
        "/instructor/announcements",
        headers={**h, "x-csrf-token": csrf},
        data={"title": "T", "body_md": "b", "cohort_id": str(other.id)},
    )
    assert r.status_code == 400

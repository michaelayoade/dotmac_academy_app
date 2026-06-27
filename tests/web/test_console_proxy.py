"""Task 8 — auth-gated lab console proxy.

The security-critical behaviour is the gate: only the owning, authenticated
person of a tenant-scoped LabInstance may reach a console. The upstream proxy
call is stubbed so no real network is required — we assert the gate let the
request through (non-403/404), not that bytes were shuttled.
"""

from __future__ import annotations

import pytest
from fastapi import Response

from app.models.auth import UserCredential
from app.models.lab import LabInstance
from app.models.person import Person
from app.services.security import hash_password


def _make_person(admin_session, tenant, email: str) -> Person:
    p = Person(tenant_id=tenant.id, email=email, first_name="S", last_name="L")
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
    return p


def _login(app_client, email: str) -> dict[str, str]:
    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": email, "password": "password1"})
    return h


def _seed_instance(admin_session, tenant, person_id) -> LabInstance:
    li = LabInstance(
        tenant_id=tenant.id,
        activity_id=person_id,  # any UUID; not FK-constrained
        person_id=person_id,
        instance_name="dal-x",
        seed={"o": 5},
        status="active",
        consoles={"r1": {"kind": "linux", "port": 9001}},
    )
    admin_session.add(li)
    admin_session.commit()
    admin_session.refresh(li)
    return li


def test_owner_passes_gate(app_client, admin_session, tenant_a, monkeypatch):
    """Owner reaching their own console → gate passes (stubbed upstream → 200)."""
    p = _make_person(admin_session, tenant_a, "owner@a.edu")
    li = _seed_instance(admin_session, tenant_a, p.id)
    h = _login(app_client, "owner@a.edu")

    async def _fake_proxy(request, target):
        assert target == "http://127.0.0.1:9001/"
        return Response(content=b"console", status_code=200)

    monkeypatch.setattr("app.web.labs._proxy_http", _fake_proxy)

    r = app_client.get(f"/labs/instances/{li.id}/console/r1", headers=h)
    assert r.status_code == 200
    assert r.status_code not in (403, 404)


def test_other_person_same_tenant_forbidden(app_client, admin_session, tenant_a):
    """A different logged-in person in the same tenant → 403."""
    owner = _make_person(admin_session, tenant_a, "owner2@a.edu")
    _make_person(admin_session, tenant_a, "intruder@a.edu")
    li = _seed_instance(admin_session, tenant_a, owner.id)
    h = _login(app_client, "intruder@a.edu")

    r = app_client.get(f"/labs/instances/{li.id}/console/r1", headers=h)
    assert r.status_code == 403


def test_cross_tenant_not_found(app_client, admin_session, tenant_a, tenant_b):
    """Instance belongs to tenant B; requester authenticated in tenant A → 404."""
    _make_person(admin_session, tenant_a, "owner3@a.edu")
    # Owner person + instance live entirely in tenant_b.
    p_b = Person(tenant_id=tenant_b.id, email="owner@b.edu", first_name="B", last_name="B")
    admin_session.add(p_b)
    admin_session.flush()
    li = _seed_instance(admin_session, tenant_b, p_b.id)
    h = _login(app_client, "owner3@a.edu")

    r = app_client.get(f"/labs/instances/{li.id}/console/r1", headers=h)
    assert r.status_code == 404


def test_unknown_node_not_found(app_client, admin_session, tenant_a):
    """Owner but node/target missing → 404."""
    p = _make_person(admin_session, tenant_a, "owner4@a.edu")
    li = _seed_instance(admin_session, tenant_a, p.id)
    h = _login(app_client, "owner4@a.edu")

    r = app_client.get(f"/labs/instances/{li.id}/console/nope", headers=h)
    assert r.status_code == 404


@pytest.mark.anyio
def test_unauthenticated_redirects(app_client, admin_session, tenant_a):
    """No session → require_web_user redirects to /login (never reaches proxy)."""
    p = _make_person(admin_session, tenant_a, "owner5@a.edu")
    li = _seed_instance(admin_session, tenant_a, p.id)
    h = {"Host": "alpha.localhost"}

    r = app_client.get(
        f"/labs/instances/{li.id}/console/r1", headers=h, follow_redirects=False
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/login"

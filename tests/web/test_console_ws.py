"""Task 12 — auth-gated ttyd console WebSocket.

The security-critical behaviour mirrors the HTTP console proxy: only the
authenticated **owner** of a **tenant-scoped** LabInstance may reach a node's
ttyd terminal. The gate (`_authorize_console`) runs BEFORE the socket is
accepted; an unauthorized peer is closed with policy code 1008 and never pumped.

The upstream ttyd pump is monkeypatched on the owner path so no real ttyd is
needed — we assert the gate let the connection through to the correct upstream
URL, not that bytes were shuttled to a live terminal.
"""

from __future__ import annotations

import pytest
from starlette.websockets import WebSocketDisconnect

from app.models.auth import UserCredential
from app.models.lab import LabInstance
from app.models.person import Person
from app.services.security import hash_password

H = {"Host": "alpha.localhost"}


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


def _login(app_client, email: str) -> None:
    app_client.post("/login", headers=H, data={"email": email, "password": "password1"})


def _seed_instance(admin_session, tenant, person_id) -> LabInstance:
    li = LabInstance(
        tenant_id=tenant.id,
        activity_id=person_id,  # any UUID; not FK-constrained here
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


def _ws_url(li, node="r1") -> str:
    return f"/labs/instances/{li.id}/console/{node}/ws"


def test_non_owner_ws_rejected(app_client, admin_session, tenant_a):
    """A different logged-in person in the same tenant → closed 1008, not pumped."""
    owner = _make_person(admin_session, tenant_a, "owner@a.edu")
    _make_person(admin_session, tenant_a, "intruder@a.edu")
    li = _seed_instance(admin_session, tenant_a, owner.id)
    _login(app_client, "intruder@a.edu")

    with pytest.raises(WebSocketDisconnect) as ei:
        with app_client.websocket_connect(_ws_url(li), headers=H) as ws:
            ws.receive_text()
    assert ei.value.code == 1008


def test_cross_tenant_ws_rejected(app_client, admin_session, tenant_a, tenant_b):
    """Instance belongs to tenant B; requester authed in tenant A → closed 1008."""
    _make_person(admin_session, tenant_a, "owner3@a.edu")
    p_b = Person(tenant_id=tenant_b.id, email="owner@b.edu", first_name="B", last_name="B")
    admin_session.add(p_b)
    admin_session.flush()
    li = _seed_instance(admin_session, tenant_b, p_b.id)
    _login(app_client, "owner3@a.edu")

    with pytest.raises(WebSocketDisconnect) as ei:
        with app_client.websocket_connect(_ws_url(li), headers=H) as ws:
            ws.receive_text()
    assert ei.value.code == 1008


def test_unauthenticated_ws_rejected(app_client, admin_session, tenant_a):
    """No session cookie → closed 1008 before any pump."""
    p = _make_person(admin_session, tenant_a, "owner5@a.edu")
    li = _seed_instance(admin_session, tenant_a, p.id)

    with pytest.raises(WebSocketDisconnect) as ei:
        with app_client.websocket_connect(_ws_url(li), headers=H) as ws:
            ws.receive_text()
    assert ei.value.code == 1008


def test_unknown_node_ws_rejected(app_client, admin_session, tenant_a):
    """Owner but node/target missing → closed 1008."""
    p = _make_person(admin_session, tenant_a, "owner6@a.edu")
    li = _seed_instance(admin_session, tenant_a, p.id)
    _login(app_client, "owner6@a.edu")

    with pytest.raises(WebSocketDisconnect) as ei:
        with app_client.websocket_connect(_ws_url(li, node="nope"), headers=H) as ws:
            ws.receive_text()
    assert ei.value.code == 1008


def test_owner_ws_passes_gate(app_client, admin_session, tenant_a, monkeypatch):
    """Owner reaching their own console → gate passes, pump invoked w/ ttyd URL."""
    p = _make_person(admin_session, tenant_a, "owner7@a.edu")
    li = _seed_instance(admin_session, tenant_a, p.id)
    _login(app_client, "owner7@a.edu")

    captured: dict[str, str] = {}

    async def _fake_proxy(websocket, upstream_url):
        captured["url"] = upstream_url
        await websocket.accept()
        await websocket.send_text("ok")
        await websocket.close()

    monkeypatch.setattr("app.web.labs._proxy_ws", _fake_proxy)

    with app_client.websocket_connect(_ws_url(li), headers=H) as ws:
        assert ws.receive_text() == "ok"

    assert captured["url"] == f"ws://127.0.0.1:9001/labs/instances/{li.id}/console/r1/ws"

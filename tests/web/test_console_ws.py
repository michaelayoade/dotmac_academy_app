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

from urllib.parse import urlsplit

import pytest
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app.models.assessment import Activity
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.lab import LabInstance
from app.models.offering import CourseOffering
from app.models.person import Person
from app.services.security import hash_password
from app.web.labs import _console_target


def _entitled_activity(admin_session, tenant, person_id):
    """Create a lab activity the person is entitled to (course+cohort+offering)."""
    c = Course(tenant_id=tenant.id, slug="lab-course", title="Lab", discipline="networking",
               source_ref="x", version=1)
    admin_session.add(c)
    admin_session.flush()
    act = Activity(tenant_id=tenant.id, course_id=c.id, chapter_number=1, type="lab",
                   title="Lab", pass_threshold=0.5)
    coh = Cohort(tenant_id=tenant.id, name="C", discipline="networking", status="active")
    admin_session.add_all([act, coh])
    admin_session.flush()
    admin_session.add(Enrollment(tenant_id=tenant.id, cohort_id=coh.id, person_id=person_id,
                                 role_in_cohort="student", status="active"))
    admin_session.add(CourseOffering(tenant_id=tenant.id, cohort_id=coh.id, course_id=c.id,
                                     status="active"))
    admin_session.flush()
    return act.id

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


def _seed_instance(
    admin_session, tenant, person_id, *, status="active", runtime_presence="present",
    error=None, name="dal-x", consoles=None, activity_id=None,
) -> LabInstance:
    li = LabInstance(
        tenant_id=tenant.id,
        activity_id=activity_id or _entitled_activity(admin_session, tenant, person_id),
        person_id=person_id,
        instance_name=name,
        seed={"o": 5},
        status=status,
        runtime_presence=runtime_presence,
        error=error,
        consoles={"r1": {"kind": "linux", "port": 9001}} if consoles is None else consoles,
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


# --- non-live instances must never reach a console (security hotfix) --------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": "reaped", "runtime_presence": "absent"},
        {"status": "reaped"},
        {"status": "error", "error": "boom"},
        {"status": "active", "error": "boom"},
        {"status": "active", "runtime_presence": "absent"},
        {"status": "active", "runtime_presence": "unknown"},
        {"status": "active", "runtime_presence": "present", "error": "uncertain runtime"},
        {"status": "resetting"},
    ],
)
def test_non_live_instance_ws_rejected(app_client, admin_session, tenant_a, monkeypatch, kwargs):
    p = _make_person(admin_session, tenant_a, "nl@a.edu")
    li = _seed_instance(admin_session, tenant_a, p.id, **kwargs)
    _login(app_client, "nl@a.edu")

    async def _must_not_pump(websocket, upstream_url):  # pragma: no cover - failure path
        raise AssertionError(f"pumped a non-live instance to {upstream_url}")

    monkeypatch.setattr("app.web.labs._proxy_ws", _must_not_pump)

    with pytest.raises(WebSocketDisconnect) as ei:
        with app_client.websocket_connect(_ws_url(li), headers=H) as ws:
            ws.receive_text()
    assert ei.value.code == 1008


def test_reaped_instance_ws_cannot_reach_port_now_owned_by_another_instance(
    app_client, admin_session, tenant_a, monkeypatch
):
    attacker = _make_person(admin_session, tenant_a, "attacker@a.edu")
    victim = _make_person(admin_session, tenant_a, "victim@a.edu")
    old = _seed_instance(
        admin_session, tenant_a, attacker.id, status="reaped", runtime_presence="absent",
        name="dal-old",
    )
    coh = admin_session.scalars(select(Cohort).where(Cohort.tenant_id == tenant_a.id)).first()
    admin_session.add(Enrollment(tenant_id=tenant_a.id, cohort_id=coh.id, person_id=victim.id,
                                 role_in_cohort="student", status="active"))
    admin_session.commit()
    live = _seed_instance(
        admin_session, tenant_a, victim.id, name="dal-live", activity_id=old.activity_id
    )
    assert urlsplit(_console_target(old, "r1")).netloc == urlsplit(_console_target(live, "r1")).netloc

    captured: list[str] = []

    async def _record(websocket, upstream_url):
        captured.append(upstream_url)
        await websocket.accept()
        await websocket.send_text("ok")
        await websocket.close()

    monkeypatch.setattr("app.web.labs._proxy_ws", _record)

    # Positive control: the victim's owner reaches the live socket.
    _login(app_client, "victim@a.edu")
    with app_client.websocket_connect(_ws_url(live), headers=H) as ws:
        assert ws.receive_text() == "ok"
    assert len(captured) == 1
    assert urlsplit(captured[0]).netloc == "127.0.0.1:9001"

    # The reaped owner is closed 1008 and nothing is pumped.
    _login(app_client, "attacker@a.edu")
    with pytest.raises(WebSocketDisconnect) as ei:
        with app_client.websocket_connect(_ws_url(old), headers=H) as ws:
            ws.receive_text()
    assert ei.value.code == 1008
    assert len(captured) == 1

    # The denial is the liveness gate: the same row, made live, is pumped.
    old.status, old.runtime_presence = "active", "present"
    admin_session.commit()
    with app_client.websocket_connect(_ws_url(old), headers=H) as ws:
        assert ws.receive_text() == "ok"
    assert urlsplit(captured[-1]).netloc == "127.0.0.1:9001"

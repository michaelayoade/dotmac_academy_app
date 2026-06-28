# app/web/labs.py
"""Student lab routes.

This module currently hosts only the auth-gated console proxy (Task 8). The
student-facing lab pages (launch / status / check) land in Task 9 in this same
file.

Security model: a console may only be reached by the authenticated **owner** of
a **tenant-scoped** LabInstance. The gate (`_authorize_console`) is enforced
*before* any byte is proxied. It is factored out so the WebSocket (ttyd) path
can reuse it verbatim when ttyd ports are wired on the `.42` VM (Task 12).
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import websockets
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session
from starlette.websockets import WebSocketDisconnect

from app.api.deps import get_db, require_tenant
from app.config import settings
from app.db import SessionLocal
from app.middleware.tenant import TenantResolverMiddleware
from app.models.assessment import Activity
from app.models.lab import LabInstance, LabTemplate
from app.models.person import Person
from app.models.tenant import Tenant
from app.services import lab_lifecycle, web_auth
from app.services.entitlements import require_course_open
from app.services.labengine.containerlab import ContainerlabEngine
from app.services.web_auth import require_web_user
from app.web.templating import templates

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_tenant)])

# WebSocket routes cannot carry the HTTP-only `require_tenant` dependency
# (BaseHTTPMiddleware does not run for the websocket scope, and FastAPI does not
# inject a `Request` into ws dependencies), so the ttyd console socket lives on a
# dependency-free router and resolves tenant/person inline — see `console_ws`.
ws_router = APIRouter()

# Reuse the app's own Host→Tenant resolver verbatim for the websocket scope.
_tenant_resolver = TenantResolverMiddleware(app=None)  # type: ignore[arg-type]

# Hop-by-hop headers must not be forwarded across a proxy (RFC 7230 §6.1).
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)


def _console_target(instance: LabInstance, node: str) -> str | None:
    """Resolve the upstream console URL for `node`, or None if unavailable.

    - RouterOS (kind == "vr-ros" or starting with "vr-") → webfig at the node's
      mgmt address: ``http://{mgmt}/``.
    - Linux → ttyd, exposed locally on the lab host: ``http://127.0.0.1:{port}/``.
    """
    spec = (instance.consoles or {}).get(node)
    if not spec:
        return None
    kind = str(spec.get("kind", ""))
    if kind == "vr-ros" or kind.startswith("vr-"):
        mgmt = spec.get("mgmt")
        return f"http://{mgmt}/" if mgmt else None
    port = spec.get("port")
    return f"http://127.0.0.1:{port}/" if port else None


def _authorize_console(
    db: Session,
    tenant: Tenant,
    person: Person,
    instance_id: UUID,
    node: str,
) -> str:
    """Security gate shared by the HTTP (and future WebSocket) console paths.

    Returns the upstream target URL, or raises:
      404 — instance not found in this tenant, or node/target missing.
      403 — instance exists in-tenant but is owned by another person.

    Loads via a tenant-filtered select (never ``db.get(PK)``) so a cross-tenant
    id can never be resolved.
    """
    instance = db.scalars(
        select(LabInstance)
        .where(LabInstance.id == instance_id)
        .where(LabInstance.tenant_id == tenant.id)
    ).first()
    if instance is None:
        raise HTTPException(status_code=404)
    if instance.person_id != person.id:
        raise HTTPException(status_code=403)
    target = _console_target(instance, node)
    if target is None:
        raise HTTPException(status_code=404)
    return target


async def _proxy_http(request: Request, target: str) -> Response:
    """Reverse-proxy an HTTP request to `target`, streaming the response back."""
    fwd_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP
    }
    body = await request.body()
    client = httpx.AsyncClient(timeout=30.0)
    upstream_req = client.build_request(
        request.method,
        target,
        headers=fwd_headers,
        content=body,
        params=request.query_params,
    )
    upstream = await client.send(upstream_req, stream=True)
    resp_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in _HOP_BY_HOP
    }

    async def _body_iter():
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    return StreamingResponse(
        _body_iter(),
        status_code=upstream.status_code,
        headers=resp_headers,
        media_type=upstream.headers.get("content-type"),
    )


# ---------------------------------------------------------------------------
# Student lab portal (Task 9): launch / status / check / reset.
# All routes are tenant-filtered + ownership-checked; mutations are htmx forms
# that rely on the global CSRF injector. NO mid-handler commit (get_db owns it).
# ---------------------------------------------------------------------------


def _lab_activity(db: Session, tenant: Tenant, activity_id: UUID) -> Activity:
    """Load a tenant-scoped lab Activity or 404."""
    act = db.scalars(
        select(Activity)
        .where(Activity.id == activity_id)
        .where(Activity.tenant_id == tenant.id)
        .where(Activity.type == "lab")
    ).first()
    if act is None:
        raise HTTPException(status_code=404)
    return act


def _lab_template(db: Session, tenant: Tenant, activity_id: UUID) -> LabTemplate:
    """Load the LabTemplate for a tenant-scoped activity or 404."""
    tpl = db.scalars(
        select(LabTemplate)
        .where(LabTemplate.activity_id == activity_id)
        .where(LabTemplate.tenant_id == tenant.id)
    ).first()
    if tpl is None:
        raise HTTPException(status_code=404)
    return tpl


def _current_instance(
    db: Session, tenant: Tenant, person: Person, activity_id: UUID
) -> LabInstance | None:
    """Latest non-reaped instance for this person+activity, if any."""
    return db.scalars(
        select(LabInstance)
        .where(LabInstance.tenant_id == tenant.id)
        .where(LabInstance.activity_id == activity_id)
        .where(LabInstance.person_id == person.id)
        .where(LabInstance.status != "reaped")
        .order_by(desc(LabInstance.created_at))
    ).first()


def _owned_instance(
    db: Session, tenant: Tenant, person: Person, instance_id: UUID
) -> LabInstance:
    """Load a tenant-scoped instance and assert ownership (404/403)."""
    inst = db.scalars(
        select(LabInstance)
        .where(LabInstance.id == instance_id)
        .where(LabInstance.tenant_id == tenant.id)
    ).first()
    if inst is None:
        raise HTTPException(status_code=404)
    if inst.person_id != person.id:
        raise HTTPException(status_code=403)
    return inst


def _engine() -> ContainerlabEngine:
    return ContainerlabEngine(settings.lab_workdir)


@router.get("/labs/{activity_id}", response_class=HTMLResponse)
def lab_detail(
    activity_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Lab page: instructions + Launch (if none/reaped) or status/console/Check."""
    tenant = require_tenant(request)
    act = _lab_activity(db, tenant, activity_id)
    require_course_open(db, tenant_id=tenant.id, person_id=person.id, course_id=act.course_id)
    tpl = _lab_template(db, tenant, activity_id)
    instance = _current_instance(db, tenant, person, activity_id)
    return templates.TemplateResponse(
        "labs/detail.html",
        {"request": request, "activity": act, "template": tpl, "instance": instance},
    )


@router.post("/labs/{activity_id}/launch", response_class=HTMLResponse)
def lab_launch(
    activity_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Request a new lab instance (queued/provisioning) → status partial."""
    tenant = require_tenant(request)
    act = _lab_activity(db, tenant, activity_id)
    require_course_open(db, tenant_id=tenant.id, person_id=person.id, course_id=act.course_id)
    tpl = _lab_template(db, tenant, activity_id)
    instance = lab_lifecycle.request_lab(
        db, tenant_id=tenant.id, person_id=person.id, activity=act, template=tpl
    )
    return templates.TemplateResponse(
        "labs/_status.html", {"request": request, "instance": instance}
    )


@router.get("/labs/instances/{instance_id}/status", response_class=HTMLResponse)
def lab_status(
    instance_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """htmx polling target — current instance status + console links when active."""
    tenant = require_tenant(request)
    instance = _owned_instance(db, tenant, person, instance_id)
    return templates.TemplateResponse(
        "labs/_status.html", {"request": request, "instance": instance}
    )


@router.post("/labs/instances/{instance_id}/check", response_class=HTMLResponse)
def lab_check(
    instance_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Grade the live instance against the template checks → results partial."""
    tenant = require_tenant(request)
    instance = _owned_instance(db, tenant, person, instance_id)
    tpl = _lab_template(db, tenant, instance.activity_id)
    handle = lab_lifecycle.handle_for(instance)
    score = lab_lifecycle.grade(db, instance, _engine(), tpl, handle)
    return templates.TemplateResponse(
        "labs/_checks.html", {"request": request, "score": score}
    )


@router.post("/labs/instances/{instance_id}/reset", response_class=HTMLResponse)
def lab_reset(
    instance_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Tear down + redeploy the instance topology → status partial."""
    tenant = require_tenant(request)
    instance = _owned_instance(db, tenant, person, instance_id)
    tpl = _lab_template(db, tenant, instance.activity_id)
    lab_lifecycle.reset(db, instance, _engine(), tpl)
    return templates.TemplateResponse(
        "labs/_status.html", {"request": request, "instance": instance}
    )


@router.get("/labs/instances/{instance_id}/console/{node}")
async def console(
    instance_id: UUID,
    node: str,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
) -> Response:
    """Auth-gated reverse proxy to a lab node's web console (webfig/ttyd)."""
    tenant = require_tenant(request)
    target = _authorize_console(db, tenant, person, instance_id, node)
    # ttyd is launched with `-b <base>` so it serves its index UNDER the base path
    # (root 404s); webfig serves at the mgmt root. Reuse _subpath_target("") to
    # land on the correct index for each.
    return await _proxy_http(request, _subpath_target(target, instance_id, node, ""))


def _subpath_target(target: str, instance_id: UUID, node: str, subpath: str) -> str:
    """Build the upstream URL for a console sub-resource.

    ttyd is launched with ``-b /labs/instances/{id}/console/{node}`` so its own
    assets/token/ws live under that base prefix — sub-requests must keep it.
    RouterOS webfig is served at the mgmt root, so its sub-resources hang off ``/``.
    """
    base = target.rstrip("/")
    if target.startswith("http://127.0.0.1:"):
        return f"{base}/labs/instances/{instance_id}/console/{node}/{subpath}"
    return f"{base}/{subpath}"


@router.get("/labs/instances/{instance_id}/console/{node}/{subpath:path}")
async def console_subpath(
    instance_id: UUID,
    node: str,
    subpath: str,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
) -> Response:
    """Auth-gated proxy for console sub-resources (ttyd assets/token, webfig)."""
    tenant = require_tenant(request)
    target = _authorize_console(db, tenant, person, instance_id, node)
    return await _proxy_http(request, _subpath_target(target, instance_id, node, subpath))


async def _proxy_ws(websocket: WebSocket, upstream_url: str) -> None:
    """Accept the client WS and bidirectionally pump it to the upstream ttyd WS.

    Negotiates the ``tty`` subprotocol ttyd requires when the browser offered it,
    and tears both legs down when either side closes.
    """
    offered = websocket.scope.get("subprotocols") or []
    subprotocol = "tty" if "tty" in offered else None
    await websocket.accept(subprotocol=subprotocol)
    try:
        upstream = await websockets.connect(upstream_url, subprotocols=["tty"])  # type: ignore[list-item]
    except Exception as exc:  # upstream ttyd unreachable
        logger.warning("ttyd upstream connect failed (%s): %s", upstream_url, exc)
        await websocket.close(code=1011)
        return

    async def client_to_upstream() -> None:
        try:
            while True:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                if msg.get("text") is not None:
                    await upstream.send(msg["text"])
                elif msg.get("bytes") is not None:
                    await upstream.send(msg["bytes"])
        except (WebSocketDisconnect, websockets.ConnectionClosed):
            pass
        finally:
            await upstream.close()

    async def upstream_to_client() -> None:
        try:
            async for data in upstream:
                if isinstance(data, bytes):
                    await websocket.send_bytes(data)
                else:
                    await websocket.send_text(data)
        except websockets.ConnectionClosed:
            pass
        finally:
            try:
                await websocket.close()
            except Exception as exc:  # client already gone — nothing to close
                logger.debug("client ws close failed: %s", exc)

    await asyncio.gather(client_to_upstream(), upstream_to_client())


@ws_router.websocket("/labs/instances/{instance_id}/console/{node}/ws")
async def console_ws(websocket: WebSocket, instance_id: UUID, node: str) -> None:
    """Auth-gated WebSocket proxy to a Linux node's ttyd terminal.

    The HTTP-only tenant middleware does not run for the ws scope, so we resolve
    the tenant from the Host header (same resolver the app uses), the person from
    the session cookie (same logic as `require_web_user`), and run the shared
    `_authorize_console` gate BEFORE accepting. Any auth failure closes 1008.
    """
    host = (websocket.headers.get("host") or "").split(":")[0].lower()
    tenant = _tenant_resolver._resolve(host)
    if tenant is None:
        await websocket.close(code=1008)
        return

    db = SessionLocal()
    try:
        db.execute(
            text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
            {"tenant_id": str(tenant.id)},
        )
        person = web_auth._current_person(
            db, tenant.id, websocket.cookies.get(web_auth.COOKIE)
        )
        if person is None:
            await websocket.close(code=1008)
            return
        try:
            target = _authorize_console(db, tenant, person, instance_id, node)
        except HTTPException:
            await websocket.close(code=1008)
            return
        port = urlsplit(target).port
    finally:
        db.close()

    upstream_url = (
        f"ws://127.0.0.1:{port}/labs/instances/{instance_id}/console/{node}/ws"
    )
    await _proxy_ws(websocket, upstream_url)

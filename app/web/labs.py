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
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import websockets
from dotmac_kernel.db import SessionLocal
from dotmac_kernel.middleware.tenant import TenantResolverMiddleware
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session
from starlette.websockets import WebSocketDisconnect

from app.api.deps import get_db, require_tenant
from app.config import settings
from app.models.assessment import Activity, Score, Submission
from app.models.lab import LabInstance, LabOperation, LabTemplate
from app.models.person import Person
from app.models.tenant import Tenant
from app.services import lab_console_activity, lab_lifecycle, web_auth
from app.services.entitlements import require_course_open
from app.services.lab_content import render_instance_instructions
from app.services.lab_operations import OPEN_STATES, enqueue
from app.services.web_auth import require_web_user
from app.web.templating import templates

logger = logging.getLogger(__name__)

#: Shown in place of instructions before a learner has an instance (queued,
#: provisioning, active, or error — any non-reaped LabInstance) to render
#: against: there is no seed yet, so there is nothing to interpolate.
_NO_INSTANCE_INSTRUCTIONS = (
    "<p>Launch the lab to view your instance-specific instructions.</p>"
)


#: Instance states in which the learner has (or is getting) a lab, so the
#: device logins are useful. ``error`` and ``reaped`` show none.
_ACCESS_VISIBLE_STATUSES = frozenset({"queued", "provisioning", "resetting", "active"})


class _TenantContext(Protocol):
    """The common request-tenant shape shared by Academy and kernel models."""

    id: UUID


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
    - Linux → ttyd on the LAB host: ``http://{LAB_CONSOLE_HOST}:{port}/``
      (loopback when the worker is co-located; the lab host's tunnel address
      when it runs on a separate KVM host).
    """
    spec = (instance.consoles or {}).get(node)
    if not spec:
        return None
    kind = str(spec.get("kind", ""))
    if kind == "vr-ros" or kind.startswith("vr-"):
        mgmt = spec.get("mgmt")
        return f"http://{mgmt}/" if mgmt else None
    port = spec.get("port")
    return f"http://{settings.lab_console_host}:{port}/" if port else None


def _require_instance_entitlement(
    db: Session,
    tenant: _TenantContext,
    person: Person,
    instance: LabInstance,
) -> None:
    """Re-check the owner is STILL entitled to the lab's course.

    Ownership alone is not enough: a learner who launched a lab while entitled may
    since have been dropped/suspended, had the offering window close, or the course
    unpublished. Without this, a now-non-entitled owner could keep grading/resetting
    the lab and holding a live console until the instance is reaped.
    """
    act = db.scalars(
        select(Activity).where(Activity.id == instance.activity_id).where(Activity.tenant_id == tenant.id)
    ).first()
    if act is None:
        raise HTTPException(status_code=404)
    require_course_open(db, tenant_id=tenant.id, person_id=person.id, course_id=act.course_id)


def _console_live(instance: LabInstance) -> bool:
    """The one definition of "this instance's consoles are reachable".

    Stored mgmt IPs / ttyd ports are only meaningful while the instance's own
    runtime is live; after reap/error/reset they may belong to another learner.
    Shared by the console gate and the status template so a link is shown only
    when following it can succeed.
    """
    return (
        instance.status == "active"
        and instance.error is None
        and instance.runtime_presence == "present"
    )


templates.env.globals["lab_console_live"] = _console_live


def _authorize_console(
    db: Session,
    tenant: _TenantContext,
    person: Person,
    instance_id: UUID,
    node: str,
) -> str:
    """Security gate shared by the HTTP (and future WebSocket) console paths.

    Returns the upstream target URL, or raises:
      404 — instance not found in this tenant, not live, or node/target missing.
      403 — instance exists in-tenant but is owned by another person.

    Loads via a tenant-filtered select (never ``db.get(PK)``) so a cross-tenant
    id can never be resolved.
    """
    instance = db.scalars(
        select(LabInstance).where(LabInstance.id == instance_id).where(LabInstance.tenant_id == tenant.id)
    ).first()
    if instance is None:
        raise HTTPException(status_code=404)
    if instance.person_id != person.id:
        raise HTTPException(status_code=403)
    _require_instance_entitlement(db, tenant, person, instance)
    if not _console_live(instance):
        raise HTTPException(status_code=404)
    target = _console_target(instance, node)
    if target is None:
        raise HTTPException(status_code=404)
    return target


def _note_console_use(db: Session, tenant: _TenantContext, instance_id: UUID) -> None:
    """Record console use for the idle reaper; never lets a failure reach the proxy.

    Call only AFTER ``_authorize_console`` succeeded. A savepoint keeps a failed
    write from poisoning the request's session.
    """
    try:
        with db.begin_nested():
            lab_console_activity.record(db, tenant_id=tenant.id, instance_id=instance_id)
    except Exception as exc:
        lab_console_activity.warn_failure(instance_id, exc)


async def _proxy_http(request: Request, target: str) -> Response:
    """Reverse-proxy an HTTP request to `target`, streaming the response back."""
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
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
    resp_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in _HOP_BY_HOP}

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
        select(LabTemplate).where(LabTemplate.activity_id == activity_id).where(LabTemplate.tenant_id == tenant.id)
    ).first()
    if tpl is None:
        raise HTTPException(status_code=404)
    return tpl


def _current_instance(db: Session, tenant: Tenant, person: Person, activity_id: UUID) -> LabInstance | None:
    """Latest non-reaped instance for this person+activity, if any."""
    return db.scalars(
        select(LabInstance)
        .where(LabInstance.tenant_id == tenant.id)
        .where(LabInstance.activity_id == activity_id)
        .where(LabInstance.person_id == person.id)
        .where(LabInstance.status != "reaped")
        .order_by(desc(LabInstance.created_at))
    ).first()


def _owned_instance(db: Session, tenant: Tenant, person: Person, instance_id: UUID) -> LabInstance:
    """Load a tenant-scoped instance, assert ownership (404/403) AND current
    entitlement to the lab's course (so revocation propagates to live instances)."""
    inst = db.scalars(
        select(LabInstance).where(LabInstance.id == instance_id).where(LabInstance.tenant_id == tenant.id)
    ).first()
    if inst is None:
        raise HTTPException(status_code=404)
    if inst.person_id != person.id:
        raise HTTPException(status_code=403)
    _require_instance_entitlement(db, tenant, person, inst)
    return inst


def _operation_score(
    db: Session, tenant: Tenant, person: Person, instance: LabInstance, operation: LabOperation
) -> Score | None:
    """Read only the durable result inside this worker operation's window."""
    if (
        operation.tenant_id != tenant.id or operation.instance_id != instance.id
        or instance.tenant_id != tenant.id or instance.person_id != person.id
        or operation.kind != "check" or operation.state != "succeeded"
        or operation.claimed_at is None or operation.finished_at is None
        or operation.finished_at < operation.claimed_at
    ):
        return None
    return db.scalars(
        select(Score)
        .join(Submission, Score.submission_id == Submission.id)
        .where(Score.tenant_id == tenant.id)
        .where(Score.tenant_id == Submission.tenant_id)
        .where(Submission.tenant_id == tenant.id)
        .where(Submission.person_id == person.id)
        .where(Submission.activity_id == instance.activity_id)
        .where(Submission.answers["instance"].astext == str(instance.id))
        .where(Submission.created_at >= operation.claimed_at)
        .where(Submission.created_at <= operation.finished_at)
        .order_by(Score.created_at.desc(), Score.id.desc())
    ).first()


def _result_context(db: Session, tenant: Tenant, person: Person, instance: LabInstance) -> dict:
    """Recover current work and the last saved check for this runtime journey.

    A deploy request (including a reset that subsequently fails) invalidates the
    old live-configuration display. Academic submissions remain untouched.
    """
    operations = (
        select(LabOperation)
        .where(LabOperation.tenant_id == tenant.id)
        .where(LabOperation.instance_id == instance.id)
    )
    # Open work is authoritative even if terminal requests share a timestamp.
    latest = db.scalars(operations.where(LabOperation.state.in_(OPEN_STATES))).first()
    if latest is None:
        recent = list(db.scalars(operations.order_by(LabOperation.requested_at.desc()).limit(2)))
        latest = recent[0] if recent else None
        if len(recent) == 2 and recent[0].requested_at == recent[1].requested_at:
            latest = None  # UUID order cannot establish which action happened last.
    deploy = db.scalars(
        operations.where(LabOperation.kind == "deploy")
        .order_by(LabOperation.requested_at.desc(), LabOperation.id.desc())
    ).first()
    saved_query = operations.where(LabOperation.kind == "check").where(LabOperation.state == "succeeded")
    if deploy is not None:
        saved_query = saved_query.where(LabOperation.requested_at > deploy.requested_at)
    saved_checks = list(db.scalars(saved_query.order_by(LabOperation.requested_at.desc()).limit(2)))
    saved = saved_checks[0] if saved_checks else None
    if len(saved_checks) == 2 and saved_checks[0].requested_at == saved_checks[1].requested_at:
        saved = None  # Never choose a result using random UUID order.
    score = _operation_score(db, tenant, person, instance, saved) if saved else None
    return {
        "recovered_operation": latest if latest is not None and (
            latest.state in OPEN_STATES or latest.state in ("failed", "cancelled")
            or (saved is not None and latest.id == saved.id and score is None)
        ) else None,
        "saved_score": score,
    }


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
    instructions_html = (
        render_instance_instructions(tpl, instance) if instance is not None else _NO_INSTANCE_INSTRUCTIONS
    )
    return templates.TemplateResponse(
        request,
        "labs/detail.html",
        {
            "request": request,
            "activity": act,
            "template": tpl,
            "instance": instance,
            "instructions_html": instructions_html,
            # Device login info is released only alongside the caller's OWN live
            # instance (``_current_instance`` is scoped to this person and
            # tenant), and only the sanitised list the loader validated.
            "device_access": (
                (tpl.access or [])
                if instance is not None and instance.status in _ACCESS_VISIBLE_STATUSES
                else []
            ),
            **(_result_context(db, tenant, person, instance) if instance else {}),
        },
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
    instance = lab_lifecycle.request_lab(db, tenant_id=tenant.id, person_id=person.id, activity=act, template=tpl)
    resp = templates.TemplateResponse(request, "labs/_status.html", {"request": request, "instance": instance})
    # The instance's seed now exists but the instructions column (rendered
    # server-side into the surrounding page, not this swapped fragment) has
    # not been refreshed — force a full-page reload so the follow-up GET
    # renders instructions interpolated with the real seed instead of the
    # pre-launch placeholder.
    resp.headers["HX-Refresh"] = "true"
    return resp


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
        request, "labs/_status.html",
        {"request": request, "instance": instance, **_result_context(db, tenant, person, instance)},
    )


@router.post("/labs/instances/{instance_id}/check", response_class=HTMLResponse)
def lab_check(
    instance_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Enqueue worker-owned grading and return a polling partial."""
    tenant = require_tenant(request)
    instance = _owned_instance(db, tenant, person, instance_id)
    if instance.status != "active" or instance.error is not None:
        detail = (
            f"status {instance.status!r}"
            if instance.status != "active"
            else "an unresolved infrastructure error"
        )
        raise HTTPException(status_code=409, detail=f"cannot check a lab with {detail}")
    operation = enqueue(db, instance=instance, kind="check", requested_by=person.id)
    if operation.kind != "check":
        raise HTTPException(
            status_code=409,
            detail=f"lab operation {operation.kind!r} is already in progress",
        )
    return templates.TemplateResponse(
        request,
        "labs/_operation.html",
        {"request": request, "operation": operation, "instance": instance, "score": None},
    )


@router.post("/labs/instances/{instance_id}/reset", response_class=HTMLResponse)
def lab_reset(
    instance_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Enqueue a worker-owned destroy-then-deploy reset/retry."""
    tenant = require_tenant(request)
    instance = _owned_instance(db, tenant, person, instance_id)
    retry_in_progress = instance.status == "resetting" or (
        instance.status in ("queued", "provisioning") and instance.error is not None
    )
    if retry_in_progress:
        # Preserve idempotency after the worker commits its reservation. Active
        # resets become ``resetting``; error retries retain their prior error
        # while ``queued`` for capacity or ``provisioning`` after admission.
        # Initial launch/provisioning has no prior error and remains ineligible.
        operation = db.scalars(
            select(LabOperation)
            .where(LabOperation.tenant_id == tenant.id)
            .where(LabOperation.instance_id == instance.id)
            .where(LabOperation.state.in_(OPEN_STATES))
        ).first()
        if operation is not None and operation.kind == "deploy":
            return templates.TemplateResponse(
                request,
                "labs/_operation.html",
                {
                    "request": request,
                    "operation": operation,
                    "instance": instance,
                    "score": None,
                },
            )
    if instance.status not in ("active", "error"):
        raise HTTPException(status_code=409, detail=f"cannot reset a lab with status {instance.status!r}")
    operation = enqueue(db, instance=instance, kind="deploy", requested_by=person.id)
    if operation.kind != "deploy":
        raise HTTPException(
            status_code=409,
            detail=f"lab operation {operation.kind!r} is already in progress",
        )
    return templates.TemplateResponse(
        request,
        "labs/_operation.html",
        {"request": request, "operation": operation, "instance": instance, "score": None},
    )


@router.get("/labs/operations/{operation_id}", response_class=HTMLResponse)
def lab_operation_status(
    operation_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Poll an owned operation; expose a completed check's durable score."""
    tenant = require_tenant(request)
    operation = db.scalars(
        select(LabOperation)
        .where(LabOperation.id == operation_id)
        .where(LabOperation.tenant_id == tenant.id)
    ).first()
    if operation is None:
        raise HTTPException(status_code=404)
    instance = _owned_instance(db, tenant, person, operation.instance_id)
    score = _operation_score(db, tenant, person, instance, operation)
    # Lifecycle polling owns all of #lab-state. On settlement return the whole
    # status fragment (including retry controls), never nest it in a poll card.
    template = (
        "labs/_status.html"
        if operation.kind != "check" and operation.state not in OPEN_STATES
        else "labs/_operation.html"
    )
    return templates.TemplateResponse(
        request,
        template,
        {
            "request": request, "operation": operation, "instance": instance, "score": score,
            **_result_context(db, tenant, person, instance),
        },
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
    _note_console_use(db, tenant, instance_id)  # opening a console is use
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
    if target.startswith(f"http://{settings.lab_console_host}:"):
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
    # Deliberately no heartbeat here: sub-resources are assets, tokens and
    # WebFig polling, not user action, so an idle open page must not keep a lab
    # alive. Typing is counted on the ttyd websocket; opening a console above.
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

    # ttyd command byte "0" is INPUT (keystrokes/paste); resize, pause and
    # keepalive frames are not user activity, so an idle open tab does not
    # keep a lab alive.
    beat = getattr(websocket.state, "console_heartbeat", None)

    async def client_to_upstream() -> None:
        try:
            while True:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                if msg.get("text") is not None:
                    if beat is not None and msg["text"][:1] == "0":
                        await beat()
                    await upstream.send(msg["text"])
                elif msg.get("bytes") is not None:
                    if beat is not None and msg["bytes"][:1] == b"0":
                        await beat()
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


_heartbeat_tasks: set[asyncio.Task] = set()


def _write_console_heartbeat(tenant_id: UUID, instance_id: UUID) -> None:
    """Short-lived session for one heartbeat write; failures are swallowed."""
    db = SessionLocal()
    try:
        db.execute(
            text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        lab_console_activity.record(db, tenant_id=tenant_id, instance_id=instance_id, throttled=False)
        db.commit()
    except Exception as exc:
        lab_console_activity.warn_failure(instance_id, exc)
    finally:
        db.close()


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
        person = web_auth._current_person(db, tenant.id, websocket.cookies.get(web_auth.COOKIE))
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

    tenant_id = tenant.id

    async def _heartbeat() -> None:
        # In-process gate first: keystrokes cost a dict lookup, not a thread.
        if not lab_console_activity.try_acquire(instance_id):
            return
        # Background task: input forwarding must never wait on the database
        # (a saturated pool would otherwise stall keystrokes for the pool
        # timeout). The set keeps a reference so the task is not collected.
        task = asyncio.create_task(asyncio.to_thread(_write_console_heartbeat, tenant_id, instance_id))
        _heartbeat_tasks.add(task)
        task.add_done_callback(_heartbeat_tasks.discard)

    websocket.state.console_heartbeat = _heartbeat

    upstream_url = f"ws://{settings.lab_console_host}:{port}" f"/labs/instances/{instance_id}/console/{node}/ws"
    await _proxy_ws(websocket, upstream_url)

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

from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.lab import LabInstance
from app.models.person import Person
from app.models.tenant import Tenant
from app.services.web_auth import require_web_user

router = APIRouter(dependencies=[Depends(require_tenant)])

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
    return await _proxy_http(request, target)

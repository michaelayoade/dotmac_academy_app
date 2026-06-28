"""Admin audit-log viewer — GET /admin/audit.

Admin-only (require_web_role("admin") role gate only). No platform-admin token required —
that is distinct from /admin/settings which also has a token gate.

IMPORTANT: no db.commit() inside the handler — get_db owns the transaction and
commits after the response (a mid-handler commit clears the RLS tenant GUC).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.person import Person
from app.services.audit import list_events
from app.services.web_auth import require_web_role
from app.web.templating import templates

router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(require_tenant), Depends(require_web_role("admin"))],
)


@router.get("/audit", response_class=HTMLResponse)
def audit_log(
    request: Request,
    db: Session = Depends(get_db),
    action: str | None = Query(None),
    actor_email: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> HTMLResponse:
    """Render the admin audit-log viewer with optional action/actor filters."""
    tenant = require_tenant(request)

    # Resolve actor email → person_id for filtering (user-friendly filter).
    filter_actor_id: UUID | None = None
    actor_not_found = False
    if actor_email:
        person = db.scalars(
            select(Person).where(
                Person.tenant_id == tenant.id,
                Person.email == actor_email,
            )
        ).first()
        if person is not None:
            filter_actor_id = person.id
        else:
            actor_not_found = True

    events = (
        []
        if actor_not_found
        else list_events(
            db,
            tenant_id=tenant.id,
            limit=limit,
            offset=offset,
            action=action or None,
            actor_person_id=filter_actor_id,
        )
    )

    # Resolve actor emails for display in the table.
    person_ids = {e.actor_person_id for e in events if e.actor_person_id is not None}
    actor_map: dict[UUID, str] = {}
    if person_ids:
        people = db.scalars(
            select(Person).where(
                Person.tenant_id == tenant.id,
                Person.id.in_(person_ids),
            )
        ).all()
        actor_map = {p.id: p.email for p in people}

    return templates.TemplateResponse(
        "admin/audit.html",
        {
            "request": request,
            "events": events,
            "actor_map": actor_map,
            "action_filter": action or "",
            "actor_email_filter": actor_email or "",
            "limit": limit,
            "offset": offset,
            "has_prev": offset > 0,
            "has_next": len(events) == limit,
        },
    )

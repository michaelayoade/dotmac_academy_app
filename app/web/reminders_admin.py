"""Admin reminder history + authorized resend — GET/POST /admin/reminders.

Thin adapter over the reminder policy service: the page projects the
ReminderLog ledger joined with outbox delivery state; resend is an audited
service action. No decisions live here.

IMPORTANT: no db.commit() inside handlers — get_db owns the transaction
(a mid-handler commit clears the RLS tenant GUC).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.email_outbox import EmailOutbox
from app.models.person import Person
from app.services import reminders as reminders_service
from app.services.web_auth import require_web_role, require_web_user
from app.web.templating import templates

router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(require_tenant), Depends(require_web_role("admin"))],
)


@router.get("/reminders", response_class=HTMLResponse)
def reminders_history(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> HTMLResponse:
    tenant = require_tenant(request)
    rows = reminders_service.recent_log(db, tenant_id=tenant.id, limit=limit, offset=offset)
    outbox_keys = [log.outbox_key for log, _p in rows if log.outbox_key]
    delivery: dict[str, EmailOutbox] = {}
    if outbox_keys:
        for ob in db.scalars(
            select(EmailOutbox)
            .where(EmailOutbox.tenant_id == tenant.id)
            .where(EmailOutbox.idempotency_key.in_(outbox_keys))
        ).all():
            delivery[ob.idempotency_key] = ob
    return templates.TemplateResponse(
        request,
        "admin/reminders.html",
        {"rows": rows, "delivery": delivery, "limit": limit, "offset": offset},
    )


@router.post("/reminders/{log_id}/resend", response_class=HTMLResponse)
def reminders_resend(
    log_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    person: Person = Depends(require_web_user),
) -> HTMLResponse:
    tenant = require_tenant(request)
    try:
        log = reminders_service.resend(
            db, tenant_id=tenant.id, log_id=log_id, actor_person_id=person.id
        )
    except ValueError as exc:
        return HTMLResponse(f'<span class="text-sm font-semibold text-red-700">{exc}</span>')
    return HTMLResponse(
        f'<span class="text-sm font-semibold text-brand-700">Requeued ({log.outbox_key})</span>'
    )

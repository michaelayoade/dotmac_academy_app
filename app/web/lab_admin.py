"""Instructor lab admin routes — monitor active lab instances + override lab scores.

All routes are gated by require_web_role("instructor") (admins inherit the role).
Students and unauthenticated users receive 403 / a redirect to /login.

IMPORTANT: no db.commit() inside any handler. The get_db dependency owns the
transaction (SET LOCAL app.current_tenant, then commit after the response). A
mid-handler commit would clear that GUC and break RLS.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.lab import LabInstance
from app.models.person import Person
from app.services.assessment import override_score
from app.services.web_auth import require_web_role
from app.web.templating import templates

router = APIRouter(
    prefix="/instructor/labs",
    dependencies=[Depends(require_tenant), Depends(require_web_role("instructor"))],
)

# Statuses considered "live" for the monitor view.
_ACTIVE_STATUSES = ("active", "provisioning", "queued")


@router.get("", response_class=HTMLResponse)
def monitor(request: Request, db: Session = Depends(get_db)):
    """Cross-person monitor of live lab instances for the current tenant."""
    tenant = require_tenant(request)
    rows = db.execute(
        select(
            LabInstance.id,
            LabInstance.status,
            LabInstance.instance_name,
            LabInstance.activity_id,
            LabInstance.last_active_at,
            Person.email,
        )
        .join(
            Person,
            (Person.id == LabInstance.person_id)
            & (Person.tenant_id == LabInstance.tenant_id),
        )
        .where(LabInstance.tenant_id == tenant.id)
        .where(LabInstance.status.in_(_ACTIVE_STATUSES))
        .order_by(LabInstance.last_active_at.desc().nullslast())
    ).all()
    return templates.TemplateResponse(
        "labs/admin_monitor.html", {"request": request, "rows": rows}
    )


@router.post("/scores/{submission_id}/override")
def override(
    submission_id: UUID,
    request: Request,
    score_value: float = Form(...),
    max_score: float = Form(...),
    reason: str = Form(...),
    db: Session = Depends(get_db),
):
    """Manually override the score for a lab submission (tenant-scoped)."""
    tenant = require_tenant(request)
    override_score(
        db,
        tenant_id=tenant.id,
        submission_id=submission_id,
        score_value=score_value,
        max_score=max_score,
        reason=reason,
    )
    # No db.commit() here — get_db commits after the response is returned.
    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/labs"
        return resp
    return RedirectResponse("/instructor/labs", status_code=status.HTTP_303_SEE_OTHER)

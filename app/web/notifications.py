# app/web/notifications.py
"""Notifications center — /notifications."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.person import Person
from app.services import notifications as notif_svc
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])


@router.get("/notifications", response_class=HTMLResponse)
def notifications_list(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    tenant = require_tenant(request)
    items = notif_svc.recent(db, tenant_id=tenant.id, person_id=person.id)
    return templates.TemplateResponse(
        "notifications.html",
        {
            "request": request,
            "person": person,
            "notifications": items,
        },
    )


@router.post("/notifications/read-all")
def read_all(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    tenant = require_tenant(request)
    notif_svc.mark_all_read(db, tenant_id=tenant.id, person_id=person.id)
    # HX-Redirect for htmx callers; plain redirect otherwise.
    redirect = RedirectResponse(url="/notifications", status_code=303)
    redirect.headers["HX-Redirect"] = "/notifications"
    return redirect

"""Public application page — the fiber-academy website intake.

``GET /apply`` renders the form; ``POST /apply`` records the application via the
admissions service. Public (no login): the tenant is resolved from the host and
primed for RLS by ``get_db``. The form uses htmx with the same CSRF cookie→header
shim as the login page.
"""

from __future__ import annotations

import html

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.services import admissions as admissions_service
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])

_THANKS = (
    '<div id="apply-result" class="mt-8 rounded-lg border border-brand-200 '
    'bg-brand-50 p-6">'
    '<h2 class="font-display text-xl font-[560] text-ink">Application received</h2>'
    '<p class="mt-2 text-sm text-ink-soft">Thanks, {name} — we\'ve got your '
    "application for the Fiber Academy and will reach out by email.</p></div>"
)


@router.get("/apply")
def apply_form(request: Request):
    return templates.TemplateResponse("apply.html", {"request": request})


@router.post("/apply")
def submit_apply(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(default=""),
    program: str = Form(default="Fiber Academy"),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    tenant = require_tenant(request)
    admissions_service.submit_application(
        db,
        tenant_id=tenant.id,
        email=email,
        first_name=first_name,
        last_name=last_name,
        phone=phone or None,
        program=program or None,
        source="website",
    )
    # htmx swaps this into #apply-result (outerHTML).
    safe_name = html.escape((first_name or "").strip()[:80]) or "there"
    return HTMLResponse(_THANKS.format(name=safe_name))

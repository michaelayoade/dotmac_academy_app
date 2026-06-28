"""Platform admin Settings portal — configure SMTP / email toggles / branding /
lab limits in the browser (DB-stored, overriding env defaults).

ADMIN ONLY: every route is gated by ``require_web_role("admin")`` — instructors
and students get 403.

Settings are PLATFORM-wide, not per-tenant, and live in the ``platform_settings``
table which only ``platform_api`` may write. Reads use the tenant-scoped
``get_db`` session (``app_user`` may SELECT platform tables); WRITES use a
separate ``get_platform_db`` session (``platform_api``) — the app_user role
cannot write platform tables.

The stored SMTP password is NEVER echoed back to the form; a blank password field
on POST means "keep the existing value".
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_platform_db, require_tenant
from app.models.person import Person
from app.services.email import send_email
from app.services.settings_store import effective, set_many
from app.services.web_auth import require_web_role
from app.web.templating import templates

router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(require_tenant), Depends(require_web_role("admin"))],
)

_BOOL_FIELDS = ("smtp_starttls", "email_auto_on_pass", "email_digest_enabled")


def _context(request: Request, db: Session) -> dict:
    cfg = effective(db)
    return {
        "request": request,
        "branding_name": cfg.branding_name,
        "cfg": cfg,
    }


@router.get("/settings", response_class=HTMLResponse)
def settings_form(request: Request, db: Session = Depends(get_db)):
    """Render the settings form pre-filled with current effective values.

    The SMTP password is intentionally rendered BLANK (never echoed).
    """
    return templates.TemplateResponse("admin/settings.html", _context(request, db))


@router.post("/settings")
def settings_save(
    request: Request,
    smtp_host: str = Form(""),
    smtp_port: str = Form(""),
    smtp_user: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
    branding_name: str = Form(""),
    max_concurrent_labs: str = Form(""),
    lab_idle_minutes: str = Form(""),
    smtp_starttls: str | None = Form(None),
    email_auto_on_pass: str | None = Form(None),
    email_digest_enabled: str | None = Form(None),
    platform_db: Session = Depends(get_platform_db),
):
    """Upsert settings via a platform_api session. Blank password keeps existing."""
    values: dict[str, str | None] = {
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_from": smtp_from,
        "branding_name": branding_name,
        "max_concurrent_labs": max_concurrent_labs,
        "lab_idle_minutes": lab_idle_minutes,
        # Checkboxes: present => "true", absent => "false".
        "smtp_starttls": "true" if smtp_starttls is not None else "false",
        "email_auto_on_pass": "true" if email_auto_on_pass is not None else "false",
        "email_digest_enabled": "true" if email_digest_enabled is not None else "false",
    }
    # Blank password => keep the existing stored value (never wipe on blank).
    if smtp_password:
        values["smtp_password"] = smtp_password

    set_many(platform_db, values)
    # get_platform_db commits after the response is returned.

    if request.headers.get("HX-Request"):
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/admin/settings"
        return resp
    return RedirectResponse("/admin/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/settings/test-email", response_class=HTMLResponse)
def settings_test_email(
    request: Request,
    person: Person = Depends(require_web_role("admin")),
    db: Session = Depends(get_db),
):
    """Send a test email to the current admin's own address; render a flash."""
    to = person.email
    cfg = effective(db)
    if not cfg.smtp_host:
        return templates.TemplateResponse(
            "admin/_test_email_result.html",
            {"request": request, "sent": False, "to": to, "unconfigured": True},
        )
    sent = send_email(
        to,
        "Dotmac Academy — test email",
        "<p>This is a test email from your Dotmac Academy settings page.</p>",
        text_body="This is a test email from your Dotmac Academy settings page.",
        db=db,
    )
    return templates.TemplateResponse(
        "admin/_test_email_result.html",
        {"request": request, "sent": sent, "to": to, "unconfigured": False},
    )

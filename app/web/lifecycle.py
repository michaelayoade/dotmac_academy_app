# app/web/lifecycle.py
"""Public account-lifecycle pages: forgot/reset password and accept invite.

Self-contained minimal pages (pre-login, no nav chrome) that reuse the same
htmx + CSRF-cookie pattern as the login form. The service layer
(app.services.lifecycle) holds all the security logic.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.services import lifecycle
from app.services.exceptions import BadRequestError, ConflictError

router = APIRouter(dependencies=[Depends(require_tenant)])

# Shared CSRF snippet so htmx form POSTs carry the double-submit token.
_CSRF_JS = (
    "<script>document.body.addEventListener('htmx:configRequest',function(e){"
    "var m=document.cookie.match(/(?:^|;\\s*)csrf_token=([^;]+)/);"
    "if(m){e.detail.headers['x-csrf-token']=m[1];}});</script>"
)


def _page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html lang=en><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width, initial-scale=1'>"
        f"<title>{title}</title><link rel=stylesheet href='/static/app.css?v=2'>"
        f"<script src='/static/htmx.min.js' defer></script></head>"
        f"<body class='min-h-screen bg-sand-100 text-ink'>"
        f"<main class='mx-auto max-w-sm px-6 py-16'><h1 class='font-display text-2xl mb-4'>{title}</h1>"
        f"{body}</main>{_CSRF_JS}</body></html>"
    )


# ── Forgot / reset password ───────────────────────────────────────────────────

@router.get("/forgot")
def forgot_form(request: Request):
    return _page("Reset your password",
        "<form hx-post='/forgot' hx-target='#msg' hx-swap='innerHTML' class='space-y-4'>"
        "<input name='email' type='email' required placeholder='you@example.com' "
        "class='w-full px-3 py-2'>"
        "<button class='btn-primary w-full py-2'>Send reset link</button></form>"
        "<div id='msg' class='mt-4 text-sm' role='status'></div>")


@router.post("/forgot")
def forgot_submit(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    raw = lifecycle.request_password_reset(db, tenant_id=tenant.id, email=email)
    if raw is not None:
        # Best-effort email; never block on delivery and never reveal existence.
        try:
            from app.services.email import send_email
            link = f"/reset?token={raw}"
            send_email(to=email.strip().lower(), subject="Reset your password",
                       html=f"<p>Reset your password: <a href='{link}'>{link}</a></p>")
        except Exception:  # noqa: BLE001 - delivery failures must stay silent here
            pass
    # Identical response whether or not the email exists (anti-enumeration).
    return HTMLResponse("If that email has an account, a reset link is on its way.")


@router.get("/reset")
def reset_form(request: Request, token: str = ""):
    return _page("Choose a new password",
        f"<form hx-post='/reset' hx-target='#msg' hx-swap='innerHTML' class='space-y-4'>"
        f"<input type='hidden' name='token' value='{token}'>"
        f"<input name='password' type='password' required minlength='8' "
        f"placeholder='New password (min 8 chars)' class='w-full px-3 py-2'>"
        f"<button class='btn-primary w-full py-2'>Set password</button></form>"
        f"<div id='msg' class='mt-4 text-sm' role='status'></div>")


@router.post("/reset")
def reset_submit(request: Request, token: str = Form(...), password: str = Form(...),
                 db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    try:
        lifecycle.reset_password(db, tenant_id=tenant.id, raw=token, new_password=password)
    except BadRequestError as exc:
        return HTMLResponse(f"<span class='text-clay-600'>{exc}</span>", status_code=400)
    return HTMLResponse("Password updated. <a href='/login'>Sign in</a>.")


# ── Accept invitation ─────────────────────────────────────────────────────────

@router.get("/accept-invite")
def accept_form(request: Request, token: str = ""):
    return _page("Set up your account",
        f"<form hx-post='/accept-invite' hx-target='#msg' hx-swap='innerHTML' class='space-y-4'>"
        f"<input type='hidden' name='token' value='{token}'>"
        f"<input name='password' type='password' required minlength='8' "
        f"placeholder='Choose a password (min 8 chars)' class='w-full px-3 py-2'>"
        f"<button class='btn-primary w-full py-2'>Activate account</button></form>"
        f"<div id='msg' class='mt-4 text-sm' role='status'></div>")


@router.post("/accept-invite")
def accept_submit(request: Request, token: str = Form(...), password: str = Form(...),
                  db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    try:
        lifecycle.accept_invite(db, tenant_id=tenant.id, raw=token, password=password)
    except (BadRequestError, ConflictError) as exc:
        return HTMLResponse(f"<span class='text-clay-600'>{exc}</span>", status_code=400)
    return HTMLResponse("Account activated. <a href='/login'>Sign in</a>.")

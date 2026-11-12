# Ported at new-composition genesis (web layer wave).
# app/web/lifecycle.py
"""Public account-lifecycle pages: forgot/reset password and accept invite.

Kernel forms rendered through the product shell use native and HTMX CSRF
transports. The service layer
(canonical_lifecycle and invitation_claim) holds all the security logic.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from html import escape

from dotmac_kernel.branding import get_brand
from dotmac_kernel.credential_lifecycle import CredentialLifecycleError
from dotmac_kernel.transactions import conflict_savepoint, conflict_savepoint_requires_rollback
from dotmac_kernel.web_surfaces import SurfaceContext
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.services import canonical_lifecycle as lifecycle
from app.services import invitation_claim
from app.services.credential_policy import password_reset_policy
from app.services.email_outbox import enqueue_email
from app.services.exceptions import BadRequestError, ConflictError
from app.services.invitation_policy import invitation_acceptance_policy
from app.services.security import hash_token
from app.web.email_links import absolute_surface_link
from app.web.templating import templates

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_tenant)])


def _render(request: Request, name: str, context: dict) -> HTMLResponse:
    """Bind shared forms to Academy's branding, shell and public login route."""
    brand = dict(getattr(request.state, "branding", None) or get_brand())
    surface = getattr(request.state, "surface_context", SurfaceContext.empty())
    return templates.TemplateResponse(
        request,
        name,
        {
            "brand": brand,
            "surface": replace(surface, login_path="/login"),
            "csrf_token": getattr(request.state, "csrf_token", ""),
            "lifecycle_page": True,
            **context,
        },
    )


def _result(request: Request, card: str, title: str, message: str, *, ok: bool = True, redirect: bool = False):
    # A handled validation failure is a successful HTML exchange (200), so
    # default HTMX swaps it. Security failures still use Kernel's error path.
    response = _render(
        request,
        "lifecycle/result.html",
        {"card": card, "title": title, "message": message, "ok": ok, "redirect": redirect},
    )
    if request.headers.get("HX-Request"):
        response.headers.update({"HX-Retarget": f"#{card}", "HX-Reselect": f"#{card}", "HX-Reswap": "outerHTML"})
    return response


# ── Forgot / reset password ───────────────────────────────────────────────────


@router.get("/forgot")
def forgot_form(request: Request):
    return _render(request, "auth/forgot.html", {"form_action": "/forgot"})


@router.post("/forgot")
def forgot_submit(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    raw = lifecycle.request_password_reset(db, tenant_id=tenant.id, email=email)
    if raw is not None:
        root = db.get_transaction()
        # Best-effort enqueue; a failed row must not poison the caller root.
        # Actual provider delivery remains outside this request transaction.
        try:
            link = absolute_surface_link(request, "reset_form", token=raw)
            escaped_link = escape(link, quote=True)
            with conflict_savepoint(db):
                enqueue_email(
                    db,
                    tenant_id=tenant.id,
                    idempotency_key=f"password-reset:{hash_token(raw)}",
                    kind="password_reset",
                    recipient=email.strip().lower(),
                    subject="Reset your password",
                    html_body=(f"<p>Reset your password: <a href='{escaped_link}'>{escaped_link}</a></p>"),
                    text_body=f"Reset your password: {link}\n",
                )
        except Exception as exc:
            if (
                root is None
                or not db.is_active
                or db.get_transaction() is not root
                or conflict_savepoint_requires_rollback(db, expected_root=root)
            ):
                raise CredentialLifecycleError("password reset delivery requires caller transaction rollback") from None
            logger.warning(
                "password-reset outbox enqueue failed for tenant %s (%s)",
                tenant.id,
                type(exc).__name__,
            )
    # Identical response whether or not the email exists (anti-enumeration).
    return _result(
        request,
        "forgot-card",
        "Reset link requested",
        "If that email has an account, a reset link is on its way.",
        redirect=True,
    )


@router.get("/reset")
def reset_form(request: Request, token: str = "", db: Session = Depends(get_db)):
    minimum = password_reset_policy(db).minimum_length
    return _render(
        request, "auth/reset.html", {"form_action": "/reset", "token": token, "min_password_length": minimum}
    )


@router.post("/reset")
def reset_submit(request: Request, token: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    try:
        lifecycle.reset_password(db, tenant_id=tenant.id, raw=token, new_password=password)
    except BadRequestError as exc:
        return _result(request, "reset-card", "Password was not changed", str(exc), ok=False)
    return _result(request, "reset-card", "Password updated", "You can now sign in with your new password.")


# ── Accept invitation ─────────────────────────────────────────────────────────


@router.get("/accept-invite")
def accept_form(request: Request, token: str = "", db: Session = Depends(get_db)):
    minimum = invitation_acceptance_policy(db).minimum_length
    return _render(
        request,
        "auth/accept.html",
        {"form_action": "/accept-invite", "token": token, "min_password_length": minimum},
    )


@router.post("/accept-invite")
def accept_submit(request: Request, token: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    try:
        invitation_claim.accept_invite(
            db,
            tenant_id=tenant.id,
            raw=token,
            password=password,
            password_policy=invitation_acceptance_policy(db),
        )
    except (BadRequestError, ConflictError) as exc:
        return _result(request, "accept-card", "Account was not activated", str(exc), ok=False)
    return _result(request, "accept-card", "Account activated", "Your password has been saved. You can now sign in.")

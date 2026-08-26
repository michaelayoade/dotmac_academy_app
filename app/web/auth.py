"""Web auth routes: login form, login POST, logout, and account probe.

Routes
------
GET  /login   — render login form
POST /login   — validate credentials, set HttpOnly session cookie, 303 → /
POST /logout  — revoke session, clear cookie, 303 → /login

(The real /account page lives in app/web/account.py — Task 7.)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.config import settings
from app.services import oidc_login, web_auth
from app.services.roles import role_slugs
from app.web.responses import hx_redirect
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])
OIDC_STATE_COOKIE = "academy_oidc_state"


@router.get("/login")
def login_form(request: Request):
    return templates.TemplateResponse(
        request,
        "login.html",
        {"request": request, "error": None, "oidc_enabled": bool(settings.oidc_issuer)},
    )


@router.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    person = web_auth.authenticate(db, tenant.id, email, password)
    hx = request.headers.get("HX-Request")
    if person is None:
        if hx:
            return PlainTextResponse("Invalid credentials", status_code=200)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "error": "Invalid credentials",
                "oidc_enabled": bool(settings.oidc_issuer),
            },
            status_code=401,
        )
    token = web_auth.start_session(db, tenant.id, person.id)
    slugs = role_slugs(db, tenant.id, person.id)
    redirect_to = "/instructor" if "instructor" in slugs and "admin" not in slugs else "/"
    # No db.commit() here — get_db commits at request end (and a mid-route commit
    # would clear the transaction-scoped app.current_tenant GUC).
    resp = hx_redirect(request, redirect_to, hx_status=204)
    resp.set_cookie(
        web_auth.COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return resp


@router.post("/login/oidc")
def oidc_start(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    try:
        started = oidc_login.begin_login(db, tenant_id=tenant.id)
    except oidc_login.LoginRefused:
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "error": "External sign-in is unavailable.",
                "oidc_enabled": bool(settings.oidc_issuer),
            },
            status_code=503,
        )
    response = hx_redirect(request, started.url)
    response.set_cookie(
        OIDC_STATE_COOKIE,
        started.state,
        max_age=settings.oidc_ceremony_ttl_seconds,
        path="/login/callback",
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response


@router.get("/login/callback")
def oidc_callback(
    request: Request,
    code: str = "",
    state: str = "",
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    try:
        completed = oidc_login.complete_login(
            db,
            tenant_id=tenant.id,
            code=code,
            state=state,
            stored_state=request.cookies.get(OIDC_STATE_COOKIE),
        )
    except oidc_login.LoginRefused:
        failed_response = templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "error": "External sign-in could not be completed.",
                "oidc_enabled": bool(settings.oidc_issuer),
            },
            status_code=401,
        )
        failed_response.delete_cookie(OIDC_STATE_COOKIE, path="/login/callback")
        return failed_response

    success_response = RedirectResponse("/", status_code=303)
    success_response.set_cookie(
        web_auth.COOKIE,
        completed.token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    success_response.delete_cookie(OIDC_STATE_COOKIE, path="/login/callback")
    return success_response


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    web_auth.revoke_session(db, tenant.id, request.cookies.get(web_auth.COOKIE))
    # No db.commit() here — get_db commits at request end.
    resp = hx_redirect(request, "/login", hx_status=204)
    resp.delete_cookie(web_auth.COOKIE)
    return resp

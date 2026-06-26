"""Web auth routes: login form, login POST, logout, and account probe.

Routes
------
GET  /login   — render login form
POST /login   — validate credentials, set HttpOnly session cookie, 303 → /
POST /logout  — revoke session, clear cookie, 303 → /login
GET  /account — tiny probe route that requires a valid session; returns person
                email as plain text. Added in Task 3 so tests can exercise the
                unauthenticated-redirect without waiting for /progress (Task N).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.services import web_auth
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])


@router.get("/login")
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


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
            "login.html",
            {"request": request, "error": "Invalid credentials"},
            status_code=401,
        )
    token = web_auth.start_session(db, tenant.id, person.id)
    db.commit()
    if hx:
        resp: Response = Response(status_code=204)
        resp.headers["HX-Redirect"] = "/"
    else:
        resp = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(web_auth.COOKIE, token, httponly=True, samesite="lax")
    return resp


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    web_auth.revoke_session(db, tenant.id, request.cookies.get(web_auth.COOKIE))
    db.commit()
    resp = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(web_auth.COOKIE)
    return resp


@router.get("/account")
def account(person=Depends(web_auth.require_web_user)):
    """Minimal probe route — returns the current person's email.

    Added in Task 3 as an always-protected endpoint so the web-auth test can
    verify the unauthenticated-redirect without depending on /progress (Task N).
    Later tasks may replace or extend this with a real account page.
    """
    return PlainTextResponse(person.email)

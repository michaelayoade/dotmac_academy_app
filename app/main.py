"""FastAPI app entrypoint.

Middleware order (outermost → innermost):
1. ObservabilityMiddleware — request id + structured request logs
2. TrustedHostMiddleware — drops requests to unknown hosts (prod)
3. TenantResolverMiddleware — sets request.state.tenant
4. RateLimitMiddleware — tenant/ip/path keyed budget
5. CSRFMiddleware — double-submit guard for browser-cookie flows
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.auth import router as auth_router
from app.api.admissions import router as admissions_router
from app.api.persons import router as persons_router
from app.api.rbac import router as rbac_router
from app.api.tenants import router as tenants_router
from app.config import settings, validate_settings
from app.middleware.csrf import CSRFMiddleware
from app.middleware.observability import ObservabilityMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.tenant import TenantResolverMiddleware
from app.services.exceptions import (
    BadRequestError,
    ConflictError,
    DomainError,
    NotFoundError,
)
from app.web.account import router as web_account_router
from app.web.accounts import router as web_accounts_router
from app.web.admin_home import router as web_admin_router
from app.web.auth import router as web_auth_router
from app.web.instructor import router as web_instructor_router
from app.web.lab_admin import router as web_lab_admin_router
from app.web.labs import router as web_labs_router
from app.web.labs import ws_router as web_labs_ws_router
from app.web.learn import router as web_learn_router
from app.web.reports import router as web_reports_router
from app.web.settings import router as web_settings_router
from app.web.teaching import router as web_teaching_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    errors = validate_settings(settings)
    for err in errors:
        if settings.is_production:
            raise RuntimeError(f"Configuration error: {err}")
        logger.warning("Config: %s", err)
    yield


app = FastAPI(title="dotmac_academy_app", lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")


# FastAPI/Starlette runs the last added middleware first.
app.add_middleware(CSRFMiddleware, enabled=settings.csrf_enabled)
app.add_middleware(
    RateLimitMiddleware,
    enabled=settings.rate_limit_enabled,
    requests=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds,
)

app.add_middleware(TenantResolverMiddleware)

# Trusted hosts — only enable in prod with explicit list.
if settings.trusted_hosts:
    hosts = [h.strip() for h in settings.trusted_hosts.split(",") if h.strip()]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

app.add_middleware(
    ObservabilityMiddleware,
    trust_inbound_request_id=settings.trust_inbound_request_id,
)


# --- Error responses: branded HTML for browsers, JSON for API clients --------
# Self-contained markup (no Jinja context processors) so an error page can never
# itself fail. Title/message come ONLY from the static maps below — exc.detail is
# never interpolated into HTML, so user input can't be reflected (no XSS).
_ERROR_PAGE = (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1">'
    "<title>{code} — Dotmac Academy</title>"
    '<link rel="stylesheet" href="/static/app.css?v=3"></head>'
    '<body class="min-h-screen bg-sand-100 text-ink antialiased">'
    '<main class="mx-auto flex min-h-screen max-w-xl flex-col items-center justify-center px-6 text-center">'
    '<p class="font-mono text-7xl font-bold tracking-tight text-brand-600">{code}</p>'
    '<h1 class="mt-4 font-display text-2xl tracking-tight">{title}</h1>'
    '<p class="mt-3 text-ink-soft">{message}</p>'
    '<a class="btn-primary mt-8" href="/">Back to safety</a>'
    "</main></body></html>"
)
_ERROR_TITLES = {
    400: "Bad request", 401: "Sign in required", 403: "Not allowed",
    404: "Page not found", 405: "Not allowed", 409: "That didn't work",
    500: "Something went wrong",
}
_ERROR_MESSAGES = {
    400: "That request didn't look right. Check the details and try again.",
    401: "Please sign in to continue.",
    403: "You don't have access to this page.",
    404: "We couldn't find that page. It may have moved, or never existed.",
    405: "That action isn't allowed here.",
    409: "That conflicts with something that already exists.",
    500: "An unexpected error occurred. Please try again in a moment.",
}


def _wants_html(request: Request) -> bool:
    """True for browser navigations (Accept: text/html), False for API clients."""
    return "text/html" in request.headers.get("accept", "")


def _error_response(request: Request, *, status_code: int, detail: str):
    if _wants_html(request):
        body = _ERROR_PAGE.format(
            code=status_code,
            title=_ERROR_TITLES.get(status_code, "Error"),
            message=_ERROR_MESSAGES.get(status_code, "Something went wrong."),
        )
        return HTMLResponse(body, status_code=status_code)
    return JSONResponse(status_code=status_code, content={"detail": detail})


@app.exception_handler(StarletteHTTPException)
async def _http_exc(request: Request, exc: StarletteHTTPException):
    return _error_response(request, status_code=exc.status_code, detail=str(exc.detail))


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return _error_response(request, status_code=500, detail="Internal error")


# Domain exception handlers — branded HTML for browsers, JSON envelope for API.
@app.exception_handler(NotFoundError)
async def _not_found(request: Request, exc: NotFoundError):
    return _error_response(request, status_code=404, detail=str(exc))


@app.exception_handler(BadRequestError)
async def _bad_request(request: Request, exc: BadRequestError):
    return _error_response(request, status_code=400, detail=str(exc))


@app.exception_handler(ConflictError)
async def _conflict(request: Request, exc: ConflictError):
    return _error_response(request, status_code=409, detail=str(exc))


@app.exception_handler(DomainError)
async def _domain_fallback(request: Request, exc: DomainError):
    logger.exception("Unhandled DomainError")
    return _error_response(request, status_code=500, detail="Internal error")


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness — does not touch DB."""
    return {"status": "ok"}


app.include_router(tenants_router)
app.include_router(auth_router)
app.include_router(persons_router)
app.include_router(admissions_router)
app.include_router(rbac_router)
app.include_router(web_auth_router)
app.include_router(web_instructor_router)
app.include_router(web_accounts_router)
app.include_router(web_lab_admin_router)
app.include_router(web_labs_router)
app.include_router(web_labs_ws_router)
app.include_router(web_learn_router)
app.include_router(web_reports_router)
app.include_router(web_settings_router)
app.include_router(web_teaching_router)
app.include_router(web_admin_router)
app.include_router(web_account_router)

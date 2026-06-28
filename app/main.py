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
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.auth import router as auth_router
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
from app.web.audit import router as web_audit_router
from app.web.auth import router as web_auth_router
from app.web.catalog import router as web_catalog_router
from app.web.instructor import router as web_instructor_router
from app.web.lab_admin import router as web_lab_admin_router
from app.web.labs import router as web_labs_router
from app.web.labs import ws_router as web_labs_ws_router
from app.web.learn import router as web_learn_router
from app.web.lifecycle import router as web_lifecycle_router
from app.web.reports import router as web_reports_router
from app.web.search import router as web_search_router
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


# Domain exception handlers — same envelope shape as dotmac_starter.
@app.exception_handler(NotFoundError)
async def _not_found(_: Request, exc: NotFoundError) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(BadRequestError)
async def _bad_request(_: Request, exc: BadRequestError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(ConflictError)
async def _conflict(_: Request, exc: ConflictError) -> JSONResponse:
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(DomainError)
async def _domain_fallback(_: Request, exc: DomainError) -> JSONResponse:
    logger.exception("Unhandled DomainError")
    return JSONResponse(status_code=500, content={"detail": "Internal error"})


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness — does not touch DB."""
    return {"status": "ok"}


app.include_router(tenants_router)
app.include_router(auth_router)
app.include_router(persons_router)
app.include_router(rbac_router)
app.include_router(web_auth_router)
app.include_router(web_lifecycle_router)
app.include_router(web_instructor_router)
app.include_router(web_accounts_router)
app.include_router(web_lab_admin_router)
app.include_router(web_labs_router)
app.include_router(web_labs_ws_router)
app.include_router(web_catalog_router)
app.include_router(web_search_router)
app.include_router(web_learn_router)
app.include_router(web_reports_router)
app.include_router(web_settings_router)
app.include_router(web_teaching_router)
app.include_router(web_audit_router)
app.include_router(web_admin_router)
app.include_router(web_account_router)

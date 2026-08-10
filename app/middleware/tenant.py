"""Tenant resolver middleware.

Resolves a Tenant from the incoming Host header and attaches it to `request.state.tenant`.
Routes that require a tenant use `Depends(require_tenant)`.

Resolution order:
1. Custom domain match in `tenant_domains.verified_at IS NOT NULL`
2. Subdomain extraction against PLATFORM_ROOT_DOMAIN
3. Host == PLATFORM_ROOT_DOMAIN → no tenant (health checks only)
4. Otherwise: 404
"""

from __future__ import annotations

import logging

from dotmac_kernel.db import resolver_session
from dotmac_kernel.tenancy import single_tenant_binding
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

from app.config import settings
from app.models.tenant import Tenant, TenantDomain

logger = logging.getLogger(__name__)


class TenantResolverMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._root = settings.platform_root_domain.lower().lstrip(".")
        # The lockdown is the kernel's now: TENANCY=single makes it assert at
        # startup that exactly one tenant exists and bind to it. This reads that
        # binding rather than a slug of our own, so the identity comes from the
        # database instead of from configuration that could drift from it.

    async def dispatch(self, request: Request, call_next):
        host = (request.headers.get("host") or "").split(":")[0].lower()
        request.state.tenant = self._resolve(host)

        if request.state.tenant is None and request.url.path not in {"/health", "/health/ready"}:
            return JSONResponse(
                status_code=404,
                content={"detail": "Tenant not found"},
            )
        return await call_next(request)

    def _resolve(self, host: str) -> Tenant | None:
        if not host:
            return None
        # `resolver_session` is the kernel's boundary for exactly this: an
        # unscoped session on the main engine, for deciding which tenant to
        # scope to. Before kernel 0.1.0a32 there was no such name and this
        # reached for the private `SessionLocal`.
        with resolver_session() as db:
            # 1. Custom domain
            tenant = db.scalars(
                select(Tenant)
                .join(TenantDomain, TenantDomain.tenant_id == Tenant.id)
                .where(TenantDomain.domain == host)
                .where(TenantDomain.verified_at.is_not(None))
                .where(Tenant.is_active.is_(True))
                .where(Tenant.deleted_at.is_(None))
                .limit(1)
            ).first()
            if tenant is not None:
                return self._allow_single_tenant(tenant)

            # 2. Subdomain on platform_root_domain
            suffix = "." + self._root
            if host.endswith(suffix):
                slug = host[: -len(suffix)]
                if slug and "." not in slug:  # reject nested subdomains
                    tenant = db.scalars(
                        select(Tenant)
                        .where(Tenant.slug == slug)
                        .where(Tenant.is_active.is_(True))
                        .where(Tenant.deleted_at.is_(None))
                        .limit(1)
                    ).first()
                    return self._allow_single_tenant(tenant)

            # 3. Host == root domain → platform context
            if host == self._root:
                return None

            # 4. Unknown host → caller decides (will 404)
            return None

    def _allow_single_tenant(self, tenant: Tenant | None) -> Tenant | None:
        """Refuse a tenant this deployment is not bound to.

        The binding is produced by the kernel's startup assertion under
        `TENANCY=single`; this covers the remaining window, a tenant created
        after startup that no assertion would see until the next restart.
        """
        bound = single_tenant_binding()
        if tenant is None or bound is None:
            return tenant
        if tenant.slug.lower() != bound:
            logger.warning("rejected non-Academy tenant host for slug=%s", tenant.slug)
            return None
        return tenant

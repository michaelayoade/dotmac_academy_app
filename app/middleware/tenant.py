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

from dotmac_kernel.db import SessionLocal
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
        self._single_tenant_slug = settings.academy_tenant_slug.strip().lower()

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
        # The one place this repo still imports the kernel's private
        # `SessionLocal`, and the reason is structural: resolving a tenant from
        # the Host header is what DECIDES the scope, so there is nothing to scope
        # to yet. `tenant_session_by_slug` cannot help — we have a host, not a
        # slug — and `platform_session` is the wrong tool despite fitting
        # semantically: its engine is pool_size=2/max_overflow=2, and this runs on
        # every request.
        #
        # The kernel's own `TenantResolverMiddleware` does exactly this with the
        # same private import, so the primitive it needs — an unscoped session on
        # the main engine, for resolving which tenant to scope to — is simply
        # missing from the public surface. Raised upstream; adopting the kernel's
        # middleware wholesale is NOT the answer here, because it has no
        # equivalent of `_allow_single_tenant` and would silently drop this
        # deployment's single-tenant lockdown.
        with SessionLocal() as db:
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
        if tenant is None:
            return None
        if self._single_tenant_slug and tenant.slug != self._single_tenant_slug:
            logger.warning("rejected non-Academy tenant host for slug=%s", tenant.slug)
            return None
        return tenant

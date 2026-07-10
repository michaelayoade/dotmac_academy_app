"""Tenant resolver middleware.

Resolves a Tenant from the incoming Host header and attaches it to `request.state.tenant`.
Routes that require a tenant use `Depends(require_tenant)`; platform routes assert
`request.state.tenant is None`.

Resolution order:
1. Custom domain match in `tenant_domains.verified_at IS NOT NULL`
2. Subdomain extraction against PLATFORM_ROOT_DOMAIN
3. Host == PLATFORM_ROOT_DOMAIN → no tenant (platform routes only)
4. Otherwise: 404
"""

from __future__ import annotations

import logging

from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

from app.config import settings
from app.db import SessionLocal
from app.models.tenant import Tenant, TenantDomain

logger = logging.getLogger(__name__)


class TenantResolverMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._root = settings.platform_root_domain.lower().lstrip(".")

    async def dispatch(self, request: Request, call_next):
        host = (request.headers.get("host") or "").split(":")[0].lower()
        request.state.tenant = self._resolve(host)

        # Platform paths are allowed without a tenant.
        if request.state.tenant is None and not _is_platform_path(
            request.url.path,
            host,
            self._root,
        ):
            return JSONResponse(
                status_code=404,
                content={"detail": "Tenant not found"},
            )
        return await call_next(request)

    def _resolve(self, host: str) -> Tenant | None:
        if not host:
            return None
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
                return tenant

            # 2. Subdomain on platform_root_domain
            suffix = "." + self._root
            if host.endswith(suffix):
                slug = host[: -len(suffix)]
                if slug and "." not in slug:  # reject nested subdomains
                    return db.scalars(
                        select(Tenant)
                        .where(Tenant.slug == slug)
                        .where(Tenant.is_active.is_(True))
                        .where(Tenant.deleted_at.is_(None))
                        .limit(1)
                    ).first()

            # 3. Host == root domain → platform context
            if host == self._root:
                return None

            # 4. Unknown host → caller decides (will 404)
            return None


def _is_platform_path(path: str, host: str, root: str) -> bool:
    """Routes that are valid without a resolved tenant."""
    if host == root:
        return True
    return path.startswith("/platform/") or path in {"/health", "/health/ready", "/"}

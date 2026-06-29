"""Platform-admin shared-secret dependency."""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from app.config import settings


def require_platform_admin_token(
    authorization: str | None = Header(default=None),
    x_platform_admin_token: str | None = Header(
        default=None, alias="X-Platform-Admin-Token"
    ),
) -> None:
    """Require the configured platform-admin shared secret.

    This is deliberately separate from tenant RBAC: platform tables and tenant
    provisioning are global, so a tenant-local admin role is insufficient.
    """
    configured = settings.platform_admin_token
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform admin auth is not configured",
        )
    supplied = x_platform_admin_token or _bearer_token(authorization)
    if supplied is None or not hmac.compare_digest(supplied, configured):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token

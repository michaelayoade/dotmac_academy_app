"""Shared route dependencies."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db, get_platform_db
from app.models.auth import AuthSession
from app.models.person import Person
from app.models.rbac import PersonRole, Role
from app.models.tenant import Tenant
from app.services.platform_auth import require_platform_admin_token
from app.services.security import decode_access_token, hash_token


def require_tenant(request: Request) -> Tenant:
    """For routes that operate on a tenant-scoped resource."""
    tenant = getattr(request.state, "tenant", None)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def require_platform(request: Request) -> None:
    """For routes that operate platform-wide (no tenant context).

    Platform routes are only valid on PLATFORM_ROOT_DOMAIN. Authentication is
    layered separately by require_platform_admin().
    """
    host = (request.headers.get("host") or "").split(":")[0].lower()
    root = settings.platform_root_domain.lower().lstrip(".")
    if host != root:
        raise HTTPException(status_code=404, detail="Platform route not found")
    if getattr(request.state, "tenant", None) is not None:
        raise HTTPException(
            status_code=404,
            detail="Platform routes are not available on tenant subdomains",
        )


def require_platform_admin(
    request: Request,
    authorization: str | None = Header(default=None),
    x_platform_admin_token: str | None = Header(
        default=None, alias="X-Platform-Admin-Token"
    ),
) -> None:
    """Require platform host plus the configured platform-admin shared secret."""
    require_platform(request)
    require_platform_admin_token(authorization, x_platform_admin_token)


def require_user_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Person:
    """Validate JWT/session and return the tenant-local person."""
    tenant = require_tenant(request)
    token = _bearer_token(authorization)
    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    payload = decode_access_token(token)
    if payload is None or payload.get("tenant_id") != str(tenant.id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    try:
        person_id = UUID(str(payload["sub"]))
    except (KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        ) from None

    session = db.scalars(
        select(AuthSession)
        .where(AuthSession.tenant_id == tenant.id)
        .where(AuthSession.token_hash == hash_token(token))
        .where(AuthSession.revoked_at.is_(None))
        .where(AuthSession.expires_at > datetime.now(UTC))
    ).first()
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    if session.person_id != person_id or session.tenant_id != tenant.id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    person = db.get(Person, person_id)
    if person is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    return person


def require_role(role_slug: str):
    """Return a dependency that requires the current person to hold `role_slug`."""

    def _dependency(
        request: Request,
        person: Person = Depends(require_user_auth),
        db: Session = Depends(get_db),
    ) -> Person:
        tenant = require_tenant(request)
        has_role = db.scalars(
            select(PersonRole)
            .join(
                Role,
                (Role.id == PersonRole.role_id)
                & (Role.tenant_id == PersonRole.tenant_id),
            )
            .where(PersonRole.tenant_id == tenant.id)
            .where(PersonRole.person_id == person.id)
            .where(Role.tenant_id == tenant.id)
            .where(Role.slug == role_slug)
        ).first()
        if has_role is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return person

    return _dependency


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


__all__ = [
    "Depends",
    "get_db",
    "get_platform_db",
    "require_platform",
    "require_platform_admin",
    "require_platform_admin_token",
    "require_role",
    "require_tenant",
    "require_user_auth",
]

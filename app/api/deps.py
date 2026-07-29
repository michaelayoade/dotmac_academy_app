"""Shared route dependencies."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db, get_platform_db
from app.models.auth import AuthSession
from app.models.person import Person
from app.models.rbac import PersonRole, Role
from app.models.tenant import Tenant
from app.services.security import decode_access_token, hash_token


def require_tenant(request: Request) -> Tenant:
    """For routes that operate on a tenant-scoped resource."""
    tenant = getattr(request.state, "tenant", None)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


_bearer = HTTPBearer(auto_error=False)


def require_user_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    db: Session = Depends(get_db),
) -> Person:
    """Validate JWT/session and return the tenant-local person."""
    tenant = require_tenant(request)
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    token = credentials.credentials

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

__all__ = [
    "Depends",
    "get_db",
    "get_platform_db",
    "require_role",
    "require_tenant",
    "require_user_auth",
]

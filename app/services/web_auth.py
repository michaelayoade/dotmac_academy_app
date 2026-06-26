"""Cookie-based web auth service.

Provides authenticate(), start_session(), require_web_user(), and
require_web_role() for server-rendered (Jinja2) routes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.auth import AuthSession, UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole, Role
from app.services.security import hash_token, issue_access_token, verify_password

COOKIE = "session"


def authenticate(db: Session, tenant_id: UUID, email: str, password: str) -> Person | None:
    """Return the Person if email+password match for the tenant, else None."""
    cred = db.scalars(
        select(UserCredential)
        .where(UserCredential.tenant_id == tenant_id)
        .where(UserCredential.email == email)
    ).first()
    if cred is None or not verify_password(password, cred.password_hash):
        return None
    return db.get(Person, cred.person_id)


def start_session(db: Session, tenant_id: UUID, person_id: UUID) -> str:
    """Create an AuthSession and return the raw token to set as the cookie value."""
    token, expires_at = issue_access_token(person_id, tenant_id)
    db.add(
        AuthSession(
            tenant_id=tenant_id,
            person_id=person_id,
            token_hash=hash_token(token),
            expires_at=expires_at,
        )
    )
    db.flush()
    return token


def _current_person(db: Session, tenant_id: UUID, token: str | None) -> Person | None:
    """Resolve the session cookie to a Person, or None if missing/invalid/expired."""
    if not token:
        return None
    session = db.scalars(
        select(AuthSession)
        .where(AuthSession.tenant_id == tenant_id)
        .where(AuthSession.token_hash == hash_token(token))
        .where(AuthSession.revoked_at.is_(None))
        .where(AuthSession.expires_at > datetime.now(UTC))
    ).first()
    return db.get(Person, session.person_id) if session else None


def require_web_user(
    request: Request,
    db: Session = Depends(get_db),
) -> Person:
    """Dependency: read the session cookie and return the Person.

    Raises HTTPException(303) → /login when missing or invalid.
    FastAPI/Starlette's default HTTPException handler preserves the Location
    header and returns a real 303 response, so TestClient(follow_redirects=False)
    sees the redirect directly.
    """
    tenant = require_tenant(request)
    person = _current_person(db, tenant.id, request.cookies.get(COOKIE))
    if person is None:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    return person


def require_web_role(role_slug: str):
    """Return a dependency that ensures the current person holds role_slug."""

    def _dep(
        request: Request,
        person: Person = Depends(require_web_user),
        db: Session = Depends(get_db),
    ) -> Person:
        tenant = require_tenant(request)
        has = db.scalars(
            select(PersonRole)
            .join(
                Role,
                (Role.id == PersonRole.role_id) & (Role.tenant_id == PersonRole.tenant_id),
            )
            .where(PersonRole.tenant_id == tenant.id)
            .where(PersonRole.person_id == person.id)
            .where(Role.slug == role_slug)
        ).first()
        if has is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return person

    return _dep

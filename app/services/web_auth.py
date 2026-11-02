"""Cookie-based web auth service.

Provides authenticate(), start_session(), require_web_user(), and
require_web_role() for server-rendered (Jinja2) routes.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlencode, urlsplit, urlunsplit
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.auth import AuthSession, UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole, Role
from app.services.identity import normalize_email, sync_credential_emails
from app.services.security import hash_token, issue_access_token, verify_password

COOKIE = "session"
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
MAX_RETURN_TARGET_LENGTH = 2048

logger = logging.getLogger(__name__)

SessionRejectionReason = Literal[
    "missing_cookie",
    "session_not_found",
    "revoked",
    "expired",
    "person_not_found",
    "inactive_person",
]


def authenticate(db: Session, tenant_id: UUID, email: str, password: str) -> Person | None:
    """Authenticate and own the durable account lockout policy.

    The credential row is locked so concurrent failures cannot race below the
    threshold. Callers must return an error response rather than raise after a
    failed attempt, allowing the request transaction to commit the counter.
    """
    now = datetime.now(UTC)
    row = db.execute(
        select(UserCredential, Person)
        .join(
            Person,
            (Person.tenant_id == UserCredential.tenant_id) & (Person.id == UserCredential.person_id),
        )
        .where(UserCredential.tenant_id == tenant_id)
        .where(func.lower(func.btrim(Person.email)) == normalize_email(email))
        .with_for_update(of=UserCredential)
    ).first()
    if row is None:
        return None
    cred, person = row
    if cred.locked_until is not None and cred.locked_until > now:
        return None
    if not verify_password(password, cred.password_hash):
        cred.failed_login_attempts += 1
        if cred.failed_login_attempts >= MAX_FAILED_LOGINS:
            cred.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
        db.flush()
        return None
    cred.failed_login_attempts = 0
    cred.locked_until = None
    sync_credential_emails(db, person=person)
    db.flush()
    if person.status != "active":
        return None  # suspended accounts cannot authenticate
    return person


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


def revoke_session(db: Session, tenant_id: UUID, token: str | None) -> None:
    """Mark the AuthSession identified by token as revoked (logout)."""
    if not token:
        return
    s = db.scalars(
        select(AuthSession)
        .where(AuthSession.tenant_id == tenant_id)
        .where(AuthSession.token_hash == hash_token(token))
        .where(AuthSession.revoked_at.is_(None))
    ).first()
    if s is not None:
        s.revoked_at = datetime.now(UTC)
        db.flush()


def safe_return_target(value: str | None) -> str | None:
    """Return a same-site relative navigation target, or ``None``.

    The login flow must never become an open redirect.  Only an absolute-path
    reference is accepted; origins, scheme-relative paths, backslashes,
    fragments, control characters and the authentication endpoints themselves
    are rejected.
    """
    if value is None:
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > MAX_RETURN_TARGET_LENGTH:
        return None
    if "\\" in candidate or any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        return None
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return None
    if not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return None
    if parsed.path in {"/login", "/logout"}:
        return None
    return urlunsplit(("", "", parsed.path, parsed.query, ""))


def return_target_for_request(request: Request) -> str | None:
    """Choose the safe GET destination to resume after authentication.

    Safe requests resume themselves.  Mutating requests are never replayed;
    they resume the same-origin page from which the form was submitted.
    """
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"
        return safe_return_target(target)

    referer = request.headers.get("referer")
    if not referer:
        return None
    parsed = urlsplit(referer)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != request.url.scheme or parsed.netloc != request.url.netloc:
            return None
    return safe_return_target(urlunsplit(("", "", parsed.path, parsed.query, "")))


def login_url_for_request(request: Request) -> str:
    """Build the login URL while preserving one validated return target."""
    target = return_target_for_request(request)
    if target is None:
        return "/login"
    return f"/login?{urlencode({'next': target})}"


def _current_person(
    db: Session,
    tenant_id: UUID,
    token: str | None,
) -> tuple[Person | None, SessionRejectionReason | None]:
    """Resolve a session cookie and retain a non-sensitive rejection reason."""
    if not token:
        return None, "missing_cookie"
    session = db.scalars(
        select(AuthSession)
        .where(AuthSession.tenant_id == tenant_id)
        .where(AuthSession.token_hash == hash_token(token))
    ).first()
    if session is None:
        return None, "session_not_found"
    if session.revoked_at is not None:
        return None, "revoked"
    if session.expires_at <= datetime.now(UTC):
        return None, "expired"
    person = db.scalars(
        select(Person).where(Person.id == session.person_id).where(Person.tenant_id == tenant_id)
    ).first()
    if person is None:
        return None, "person_not_found"
    if person.status != "active":
        return None, "inactive_person"  # suspended mid-session → treated as logged out
    return person, None


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
    person, rejection_reason = _current_person(db, tenant.id, request.cookies.get(COOKIE))
    if person is None:
        logger.info("web session rejected reason=%s", rejection_reason)
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": login_url_for_request(request)},
        )
    return person


def optional_web_user(
    request: Request,
    db: Session = Depends(get_db),
) -> Person | None:
    """Dependency: the session's Person, or None when anonymous.

    For routes that render differently for visitors and signed-in users
    (e.g. the public landing at ``/``) instead of redirecting to /login.
    """
    tenant = require_tenant(request)
    person, _ = _current_person(db, tenant.id, request.cookies.get(COOKIE))
    return person


def require_web_role(role_slug: str):
    """Return a dependency that ensures the current person holds role_slug.

    ``admin`` is a superset role: a person holding ``admin`` satisfies ANY role
    requirement (so an admin can reach instructor-gated areas like Cohorts and
    the Lab monitor without also holding the instructor role). This matches the
    Teaching area being shown to admins by the nav (``areas_for_roles``).
    """
    accepted = {role_slug, "admin"}

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
            .where(Role.slug.in_(accepted))
        ).first()
        if has is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return person

    return _dep

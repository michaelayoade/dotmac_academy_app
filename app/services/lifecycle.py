# app/services/lifecycle.py
"""Account lifecycle: invitations and password reset (Slice 3b).

Tokens are single-use and stored hashed (HMAC via ``security.hash_token``). The
raw token is returned to the caller exactly once for delivery (email link).
Flows never reveal whether an email exists (anti-enumeration) — request helpers
return the raw token or ``None`` and the route responds identically either way.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.account_token import AccountToken
from app.models.auth import UserCredential
from app.models.person import Person
from app.services.bootstrap import ensure_roles
from app.services.exceptions import BadRequestError, ConflictError
from app.services.security import hash_password, hash_token

KINDS = frozenset({"password_reset", "invite", "email_verify"})
DEFAULT_TTL_HOURS = {"password_reset": 2, "invite": 168, "email_verify": 72}


def _issue_token(db: Session, *, tenant_id: UUID, person_id: UUID, kind: str,
                 now: datetime, ttl_hours: int | None = None) -> str:
    if kind not in KINDS:
        raise BadRequestError(f"invalid token kind: {kind}")
    raw = uuid4().hex + uuid4().hex  # 64 hex chars of entropy
    ttl = ttl_hours if ttl_hours is not None else DEFAULT_TTL_HOURS[kind]
    db.add(AccountToken(
        tenant_id=tenant_id, person_id=person_id, kind=kind,
        token_hash=hash_token(raw), expires_at=now + timedelta(hours=ttl),
    ))
    db.flush()
    return raw


def _consume_token(db: Session, *, tenant_id: UUID, kind: str, raw: str,
                   now: datetime) -> AccountToken:
    tok = db.scalars(
        select(AccountToken)
        .where(AccountToken.tenant_id == tenant_id)
        .where(AccountToken.kind == kind)
        .where(AccountToken.token_hash == hash_token(raw))
    ).first()
    if tok is None or tok.used_at is not None or tok.expires_at < now:
        raise BadRequestError("invalid or expired token")
    tok.used_at = now
    db.flush()
    return tok


# ── Password reset ────────────────────────────────────────────────────────────

def request_password_reset(db: Session, *, tenant_id: UUID, email: str,
                           now: datetime | None = None) -> str | None:
    """Return a reset token for the email's account, or None if unknown.

    Callers MUST respond identically whether or not None is returned.
    """
    now = now or datetime.now(UTC)
    person = db.scalars(
        select(Person).where(Person.tenant_id == tenant_id)
        .where(Person.email == (email or "").strip().lower())
    ).first()
    if person is None:
        return None
    return _issue_token(db, tenant_id=tenant_id, person_id=person.id,
                        kind="password_reset", now=now)


def reset_password(db: Session, *, tenant_id: UUID, raw: str, new_password: str,
                   now: datetime | None = None) -> Person:
    """Consume a reset token and set the account's password."""
    now = now or datetime.now(UTC)
    if not new_password or len(new_password) < 8:
        raise BadRequestError("password must be at least 8 characters")
    tok = _consume_token(db, tenant_id=tenant_id, kind="password_reset", raw=raw, now=now)
    cred = db.scalars(
        select(UserCredential).where(UserCredential.tenant_id == tenant_id)
        .where(UserCredential.person_id == tok.person_id)
    ).first()
    if cred is None:
        raise BadRequestError("no credential for this account")
    cred.password_hash = hash_password(new_password)
    db.flush()
    return db.get(Person, tok.person_id)


# ── Invitations ───────────────────────────────────────────────────────────────

def invite_user(db: Session, *, tenant_id: UUID, email: str, first_name: str,
                last_name: str, role: str, now: datetime | None = None) -> tuple[Person, str]:
    """Create a credential-less Person with a role and return (person, invite_token).

    The invitee sets their password via :func:`accept_invite`. Raises ConflictError
    if a person with the email already exists.
    """
    now = now or datetime.now(UTC)
    email = (email or "").strip().lower()
    existing = db.scalars(
        select(Person).where(Person.tenant_id == tenant_id).where(Person.email == email)
    ).first()
    if existing is not None:
        raise ConflictError(f"a person with email {email!r} already exists")
    roles = ensure_roles(db, tenant_id)
    if role not in roles:
        raise BadRequestError(f"invalid role: {role}")
    person = Person(tenant_id=tenant_id, email=email, first_name=first_name, last_name=last_name)
    db.add(person)
    db.flush()
    from app.models.rbac import PersonRole
    db.add(PersonRole(tenant_id=tenant_id, person_id=person.id, role_id=roles[role].id))
    db.flush()
    token = _issue_token(db, tenant_id=tenant_id, person_id=person.id, kind="invite", now=now)
    return person, token


def set_account_status(db: Session, *, tenant_id: UUID, person_id: UUID,
                       status: str) -> Person:
    """Suspend or reactivate an account (status in {active, suspended})."""
    if status not in {"active", "suspended"}:
        raise BadRequestError(f"invalid account status: {status}")
    person = db.scalars(
        select(Person).where(Person.tenant_id == tenant_id).where(Person.id == person_id)
    ).first()
    if person is None:
        raise BadRequestError("person not found")
    person.status = status
    if status == "suspended":
        # Revoke all live sessions so the suspension takes effect immediately.
        from app.models.auth import AuthSession
        for s in db.scalars(
            select(AuthSession).where(AuthSession.tenant_id == tenant_id)
            .where(AuthSession.person_id == person_id)
            .where(AuthSession.revoked_at.is_(None))
        ).all():
            s.revoked_at = now_utc()
    db.flush()
    return person


def now_utc() -> datetime:
    return datetime.now(UTC)


def accept_invite(db: Session, *, tenant_id: UUID, raw: str, password: str,
                  now: datetime | None = None) -> Person:
    """Consume an invite token and create the account's first credential."""
    now = now or datetime.now(UTC)
    if not password or len(password) < 8:
        raise BadRequestError("password must be at least 8 characters")
    tok = _consume_token(db, tenant_id=tenant_id, kind="invite", raw=raw, now=now)
    person = db.get(Person, tok.person_id)
    existing = db.scalars(
        select(UserCredential).where(UserCredential.tenant_id == tenant_id)
        .where(UserCredential.person_id == tok.person_id)
    ).first()
    if existing is not None:
        raise ConflictError("account already has a credential")
    db.add(UserCredential(tenant_id=tenant_id, person_id=person.id, email=person.email,
                          password_hash=hash_password(password)))
    db.flush()
    return person

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
from app.models.auth import AuthSession, UserCredential
from app.models.person import Person
from app.services.exceptions import BadRequestError, ConflictError
from app.services.identity import normalize_email, person_for_email, sync_credential_emails
from app.services.security import hash_password, hash_token

KINDS = frozenset({"password_reset", "invite", "email_verify"})
DEFAULT_TTL_HOURS = {"password_reset": 2, "invite": 168, "email_verify": 72}


def _issue_token(
    db: Session, *, tenant_id: UUID, person_id: UUID, kind: str, now: datetime, ttl_hours: int | None = None
) -> str:
    if kind not in KINDS:
        raise BadRequestError(f"invalid token kind: {kind}")
    raw = uuid4().hex + uuid4().hex  # 64 hex chars of entropy
    ttl = ttl_hours if ttl_hours is not None else DEFAULT_TTL_HOURS[kind]
    db.add(
        AccountToken(
            tenant_id=tenant_id,
            person_id=person_id,
            kind=kind,
            token_hash=hash_token(raw),
            expires_at=now + timedelta(hours=ttl),
        )
    )
    db.flush()
    return raw


def _consume_token(db: Session, *, tenant_id: UUID, kind: str, raw: str, now: datetime) -> AccountToken:
    tok = db.scalars(
        select(AccountToken)
        .where(AccountToken.tenant_id == tenant_id)
        .where(AccountToken.kind == kind)
        .where(AccountToken.token_hash == hash_token(raw))
        .with_for_update()
    ).first()
    if tok is None or tok.used_at is not None or tok.expires_at < now:
        raise BadRequestError("invalid or expired token")
    tok.used_at = now
    db.flush()
    return tok


# ── Password reset ────────────────────────────────────────────────────────────


def _invalidate_outstanding_tokens(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    kind: str,
    now: datetime,
) -> None:
    tokens = db.scalars(
        select(AccountToken)
        .where(AccountToken.tenant_id == tenant_id)
        .where(AccountToken.person_id == person_id)
        .where(AccountToken.kind == kind)
        .where(AccountToken.used_at.is_(None))
        .with_for_update()
    ).all()
    for token in tokens:
        token.used_at = now


def _revoke_active_sessions(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    now: datetime,
) -> None:
    sessions = db.scalars(
        select(AuthSession)
        .where(AuthSession.tenant_id == tenant_id)
        .where(AuthSession.person_id == person_id)
        .where(AuthSession.revoked_at.is_(None))
        .with_for_update()
    ).all()
    for session in sessions:
        session.revoked_at = now


def set_account_password(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    new_password: str,
    now: datetime | None = None,
) -> Person:
    """Apply the complete password-change security transition."""
    now = now or datetime.now(UTC)
    if not new_password or len(new_password) < 8:
        raise BadRequestError("password must be at least 8 characters")
    person = db.scalars(
        select(Person).where(Person.tenant_id == tenant_id).where(Person.id == person_id).with_for_update()
    ).first()
    if person is None:
        raise BadRequestError("account no longer exists")
    credentials = sync_credential_emails(db, person=person)
    if not credentials:
        raise BadRequestError("no credential for this account")

    password_hash = hash_password(new_password)
    for credential in credentials:
        credential.password_hash = password_hash
        credential.failed_login_attempts = 0
        credential.locked_until = None
    _revoke_active_sessions(db, tenant_id=tenant_id, person_id=person_id, now=now)
    _invalidate_outstanding_tokens(
        db,
        tenant_id=tenant_id,
        person_id=person_id,
        kind="password_reset",
        now=now,
    )
    db.flush()
    return person


def request_password_reset(db: Session, *, tenant_id: UUID, email: str, now: datetime | None = None) -> str | None:
    """Return a reset token for the email's account, or None if unknown.

    Callers MUST respond identically whether or not None is returned.
    """
    now = now or datetime.now(UTC)
    person = person_for_email(db, tenant_id=tenant_id, email=email)
    if person is None:
        return None
    credential = db.scalars(
        select(UserCredential).where(UserCredential.tenant_id == tenant_id).where(UserCredential.person_id == person.id)
    ).first()
    if credential is None:
        return None
    return _issue_token(db, tenant_id=tenant_id, person_id=person.id, kind="password_reset", now=now)


def reset_password(db: Session, *, tenant_id: UUID, raw: str, new_password: str, now: datetime | None = None) -> Person:
    """Consume a reset token and set the account's password."""
    now = now or datetime.now(UTC)
    if not new_password or len(new_password) < 8:
        raise BadRequestError("password must be at least 8 characters")
    tok = _consume_token(db, tenant_id=tenant_id, kind="password_reset", raw=raw, now=now)
    return set_account_password(
        db,
        tenant_id=tenant_id,
        person_id=tok.person_id,
        new_password=new_password,
        now=now,
    )


# ── Invitations ───────────────────────────────────────────────────────────────


def issue_invite_for_person(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None) -> str:
    """Issue an invite token for an EXISTING Person (e.g. one created by
    enrolment) so they can set their first password via :func:`accept_invite`.

    Returns the raw token — deliver once (email link) and never store it.
    """
    now = now or datetime.now(UTC)
    _invalidate_outstanding_tokens(
        db,
        tenant_id=tenant_id,
        person_id=person_id,
        kind="invite",
        now=now,
    )
    return _issue_token(db, tenant_id=tenant_id, person_id=person_id, kind="invite", now=now)


def invite_user(
    db: Session, *, tenant_id: UUID, email: str, first_name: str, last_name: str, role: str, now: datetime | None = None
) -> tuple[Person, str]:
    """Create or reinvite a credential-less person and return its invite token.

    Login-capable existing accounts still conflict because they do not need an
    activation flow.
    """
    from app.services.account_invitations import invite_and_enroll

    result = invite_and_enroll(
        db,
        tenant_id=tenant_id,
        email=email,
        first_name=first_name,
        last_name=last_name,
        role=role,
        now=now,
    )
    if result.token is None:
        raise ConflictError("account already has a credential")
    return result.person, result.token


def set_account_status(db: Session, *, tenant_id: UUID, person_id: UUID, status: str) -> Person:
    """Suspend or reactivate an account (status in {active, suspended})."""
    if status not in {"active", "suspended"}:
        raise BadRequestError(f"invalid account status: {status}")
    person = db.scalars(select(Person).where(Person.tenant_id == tenant_id).where(Person.id == person_id)).first()
    if person is None:
        raise BadRequestError("person not found")
    person.status = status
    if status == "suspended":
        # Revoke all live sessions so the suspension takes effect immediately.
        _revoke_active_sessions(
            db,
            tenant_id=tenant_id,
            person_id=person_id,
            now=now_utc(),
        )
    db.flush()
    return person


def now_utc() -> datetime:
    return datetime.now(UTC)


def accept_invite(db: Session, *, tenant_id: UUID, raw: str, password: str, now: datetime | None = None) -> Person:
    """Consume an invite token and create the account's first credential."""
    now = now or datetime.now(UTC)
    if not password or len(password) < 8:
        raise BadRequestError("password must be at least 8 characters")
    tok = _consume_token(db, tenant_id=tenant_id, kind="invite", raw=raw, now=now)
    person = db.get(Person, tok.person_id)
    if person is None:
        raise BadRequestError("account no longer exists")
    existing = db.scalars(
        select(UserCredential)
        .where(UserCredential.tenant_id == tenant_id)
        .where(UserCredential.person_id == tok.person_id)
    ).first()
    if existing is not None:
        raise ConflictError("account already has a credential")
    canonical = normalize_email(person.email)
    person.email = canonical
    db.add(
        UserCredential(tenant_id=tenant_id, person_id=person.id, email=canonical, password_hash=hash_password(password))
    )
    _invalidate_outstanding_tokens(
        db,
        tenant_id=tenant_id,
        person_id=person.id,
        kind="invite",
        now=now,
    )
    db.flush()
    return person

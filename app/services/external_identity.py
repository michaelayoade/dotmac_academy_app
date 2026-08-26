"""Academy's single local external-identity and revocation owner.

Protocol verification happens before this module is called.  This service does
not know OIDC, perform I/O, read claims, provision people, or decide roles.  It
only binds an exact verified subject to an existing Academy ``Person`` and
serializes session issuance against disablement in Academy's own transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.auth import AuthSession
from app.models.external_identity import ExternalIdentityBinding
from app.models.person import Person
from app.services.exceptions import ConflictError, NotFoundError
from app.services.security import hash_token


@dataclass(frozen=True, slots=True)
class FinalizedExternalLogin:
    """The Academy person and provenance-stamped session created together."""

    person: Person
    binding_id: UUID
    token: str
    token_hash: str
    expires_at: datetime


def _exact_text(value: str, *, field: str, limit: int) -> str:
    exact = value.strip()
    if not exact:
        raise ValueError(f"external identity {field} must not be blank")
    if len(exact) > limit:
        raise ValueError(f"external identity {field} exceeds {limit} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in exact):
        raise ValueError(f"external identity {field} contains control characters")
    return exact


def bind_external_identity(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    provider_binding: str,
    issuer: str,
    subject: str,
    bound_by: str,
    reason: str,
) -> ExternalIdentityBinding:
    """Bind or re-enable one exact subject for the same existing person.

    A disabled row retains both evidence and its unique tuple. It can be
    re-enabled for the same person, never reassigned as a side effect of a new
    approved command.
    """

    provider_binding = _exact_text(provider_binding, field="provider_binding", limit=80)
    issuer = _exact_text(issuer, field="issuer", limit=512)
    subject = _exact_text(subject, field="subject", limit=255)
    bound_by = _exact_text(bound_by, field="bound_by", limit=120)
    reason = _exact_text(reason, field="bind_reason", limit=500)

    # Lock order is binding -> person whenever the binding exists. The login
    # finalizer takes the same order, while an account-only suspension locks
    # just the person and can finish without waiting back on the binding.
    existing = db.scalars(
        select(ExternalIdentityBinding)
        .where(ExternalIdentityBinding.tenant_id == tenant_id)
        .where(ExternalIdentityBinding.provider_binding == provider_binding)
        .where(ExternalIdentityBinding.issuer == issuer)
        .where(ExternalIdentityBinding.subject == subject)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()
    if existing is not None:
        person = db.scalars(
            select(Person)
            .where(Person.tenant_id == tenant_id)
            .where(Person.id == person_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        if person is None:
            raise NotFoundError("Academy person not found")
        if existing.person_id != person_id:
            raise ConflictError(
                "this external subject is already bound to a different Academy person; "
                "disabling a binding does not release its tuple"
            )
        existing.is_active = True
        existing.bound_at = datetime.now(UTC)
        existing.bound_by = bound_by
        existing.bind_reason = reason
        db.flush()
        return existing

    person = db.scalars(
        select(Person)
        .where(Person.tenant_id == tenant_id)
        .where(Person.id == person_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()
    if person is None:
        raise NotFoundError("Academy person not found")

    held = db.scalars(
        select(ExternalIdentityBinding)
        .where(ExternalIdentityBinding.tenant_id == tenant_id)
        .where(ExternalIdentityBinding.provider_binding == provider_binding)
        .where(ExternalIdentityBinding.person_id == person_id)
    ).first()
    if held is not None:
        raise ConflictError("this Academy person already holds an external identity at this provider registration")

    try:
        # The database constraints arbitrate concurrent binders. A SAVEPOINT
        # keeps their expected conflict from aborting the request transaction
        # and losing its transaction-local tenant context.
        with db.begin_nested():
            binding = ExternalIdentityBinding(
                tenant_id=tenant_id,
                person_id=person_id,
                provider_binding=provider_binding,
                issuer=issuer,
                subject=subject,
                is_active=True,
                bound_at=datetime.now(UTC),
                bound_by=bound_by,
                bind_reason=reason,
            )
            db.add(binding)
            db.flush()
    except IntegrityError as exc:
        raise ConflictError(
            "this external identity was bound concurrently; re-read the current Academy binding"
        ) from exc
    return binding


def _revoke_sessions_for_binding(
    db: Session,
    *,
    tenant_id: UUID,
    binding_id: UUID,
    now: datetime,
) -> int:
    sessions = db.scalars(
        select(AuthSession)
        .where(AuthSession.tenant_id == tenant_id)
        .where(AuthSession.external_identity_binding_id == binding_id)
        .where(AuthSession.revoked_at.is_(None))
        .with_for_update()
    ).all()
    for session in sessions:
        session.revoked_at = now
    return len(sessions)


def disable_external_identity_binding(
    db: Session,
    *,
    tenant_id: UUID,
    binding_id: UUID,
    now: datetime | None = None,
) -> ExternalIdentityBinding:
    """Disable the binding and selectively revoke its sessions atomically."""

    binding = db.scalars(
        select(ExternalIdentityBinding)
        .where(ExternalIdentityBinding.tenant_id == tenant_id)
        .where(ExternalIdentityBinding.id == binding_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()
    if binding is None:
        raise NotFoundError("external identity binding not found")
    binding.is_active = False
    _revoke_sessions_for_binding(
        db,
        tenant_id=tenant_id,
        binding_id=binding.id,
        now=now or datetime.now(UTC),
    )
    db.flush()
    return binding


def finalize_external_login(
    db: Session,
    *,
    tenant_id: UUID,
    provider_binding: str,
    issuer: str,
    subject: str,
) -> FinalizedExternalLogin | None:
    """Lock the binding, validate local state, and issue one Academy session.

    Session creation is inside this function and the caller's current
    transaction. The binding lock is therefore still held when the session is
    flushed; disablement cannot land in a resolve-then-issue window.
    """

    provider_binding = _exact_text(provider_binding, field="provider_binding", limit=80)
    issuer = _exact_text(issuer, field="issuer", limit=512)
    subject = _exact_text(subject, field="subject", limit=255)
    binding = db.scalars(
        select(ExternalIdentityBinding)
        .where(ExternalIdentityBinding.tenant_id == tenant_id)
        .where(ExternalIdentityBinding.provider_binding == provider_binding)
        .where(ExternalIdentityBinding.issuer == issuer)
        .where(ExternalIdentityBinding.subject == subject)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()
    if binding is None or not binding.is_active:
        return None

    person = db.scalars(
        select(Person)
        .where(Person.tenant_id == tenant_id)
        .where(Person.id == binding.person_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()
    if person is None or person.status != "active":
        return None

    # Local import avoids a module cycle: web_auth validates binding
    # provenance on refresh, while this owner deliberately reuses its single
    # session issuance primitive rather than becoming a second session writer.
    from app.services.web_auth import start_session

    token = start_session(
        db,
        tenant_id,
        person.id,
        external_identity_binding_id=binding.id,
    )
    session = db.scalars(
        select(AuthSession).where(AuthSession.tenant_id == tenant_id).where(AuthSession.token_hash == hash_token(token))
    ).one()
    binding.last_authenticated_at = datetime.now(UTC)
    db.flush()
    return FinalizedExternalLogin(
        person=person,
        binding_id=binding.id,
        token=token,
        token_hash=session.token_hash,
        expires_at=session.expires_at,
    )


def session_provenance_is_active(db: Session, session: AuthSession) -> bool:
    """Validate a federated session's binding on every refresh.

    Password sessions carry NULL and are valid on provenance terms. Account,
    expiry, and revocation checks remain the caller's responsibility.
    """

    if session.external_identity_binding_id is None:
        return True
    binding = db.scalars(
        select(ExternalIdentityBinding)
        .where(ExternalIdentityBinding.tenant_id == session.tenant_id)
        .where(ExternalIdentityBinding.person_id == session.person_id)
        .where(ExternalIdentityBinding.id == session.external_identity_binding_id)
    ).first()
    return binding is not None and binding.is_active


def binding_state_for_subject(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    provider_binding: str,
    issuer: str,
    subject: str,
) -> str:
    """Return ``active``, ``disabled``, ``different_person`` or ``missing``.

    This is an observation for the managed lifecycle result. Login never calls
    it; the locked finalizer remains the only session-producing decision.
    """

    binding = db.scalars(
        select(ExternalIdentityBinding)
        .where(ExternalIdentityBinding.tenant_id == tenant_id)
        .where(
            ExternalIdentityBinding.provider_binding
            == _exact_text(provider_binding, field="provider_binding", limit=80)
        )
        .where(ExternalIdentityBinding.issuer == _exact_text(issuer, field="issuer", limit=512))
        .where(ExternalIdentityBinding.subject == _exact_text(subject, field="subject", limit=255))
    ).first()
    if binding is None:
        return "missing"
    if binding.person_id != person_id:
        return "different_person"
    return "active" if binding.is_active else "disabled"


__all__ = [
    "FinalizedExternalLogin",
    "binding_state_for_subject",
    "bind_external_identity",
    "disable_external_identity_binding",
    "finalize_external_login",
    "session_provenance_is_active",
]

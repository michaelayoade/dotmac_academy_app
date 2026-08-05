"""Canonical account identity helpers.

``Person.email`` is the account's source of truth.  ``UserCredential.email`` is
kept in sync for compatibility with the existing schema, but authentication and
account recovery resolve identity through ``Person``.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.auth import UserCredential
from app.models.person import Person


def normalize_email(email: str) -> str:
    """Return the canonical representation used for account identity."""
    return (email or "").strip().lower()


def person_for_email(db: Session, *, tenant_id: UUID, email: str) -> Person | None:
    """Resolve a person using a trimmed, case-insensitive tenant lookup."""
    canonical = normalize_email(email)
    if not canonical:
        return None
    return db.scalars(
        select(Person).where(Person.tenant_id == tenant_id).where(func.lower(func.btrim(Person.email)) == canonical)
    ).first()


def sync_credential_emails(db: Session, *, person: Person) -> list[UserCredential]:
    """Make Person authoritative while preserving legacy credential rows.

    Older databases can contain more than one credential for a person, while
    the credential table also requires email uniqueness.  Only one compatible
    row can therefore carry the canonical email; every row still participates
    in password and lockout transitions by ``person_id``.
    """
    canonical = normalize_email(person.email)
    person.email = canonical
    credentials = list(
        db.scalars(
            select(UserCredential)
            .where(UserCredential.tenant_id == person.tenant_id)
            .where(UserCredential.person_id == person.id)
            .with_for_update()
        ).all()
    )
    if credentials:
        canonical_credential = next(
            (credential for credential in credentials if normalize_email(credential.email) == canonical),
            credentials[0],
        )
        canonical_credential.email = canonical
    return credentials

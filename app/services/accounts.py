"""Account-creation service.

Creates a login-capable account (Person + UserCredential + role grant) for an
existing tenant. This is the application-level counterpart to
``bootstrap.bootstrap_tenant`` (which creates the tenant itself and its first
admin). Reuses ``bootstrap.ensure_roles`` so the three standard roles are
guaranteed to exist for the tenant.

Like the rest of the service layer, this ``flush``es but never ``commit``s — the
caller (request handler via ``get_db``, or a CLI/test) owns the transaction.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.auth import UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ROLE_SLUGS, ensure_roles
from app.services.security import hash_password

VALID_ROLES = frozenset(ROLE_SLUGS)  # {"student", "instructor", "admin"}


def create_user(
    db: Session,
    *,
    tenant_id: UUID,
    email: str,
    first_name: str,
    last_name: str,
    password: str,
    role: str,
) -> Person:
    """Create a login-capable account within ``tenant_id`` and return the Person.

    Creates a tenant-scoped :class:`Person`, a :class:`UserCredential` with the
    hashed password, ensures the named role exists for the tenant, and grants it
    to the new person.

    Args:
        db: SQLAlchemy session (transaction owned by the caller — no commit here).
        tenant_id: Tenant the account belongs to.
        email: Login email; must be unique within the tenant.
        first_name / last_name: Person name fields.
        password: Plaintext password — hashed before storage.
        role: One of ``"student"``, ``"instructor"``, ``"admin"``.

    Returns:
        The newly created :class:`Person` (flushed, not committed).

    Raises:
        ValueError: If ``role`` is not a valid role, or a Person with ``email``
            already exists in the tenant.
    """
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role {role!r}; expected one of {sorted(VALID_ROLES)}")

    existing = db.scalars(
        select(Person)
        .where(Person.tenant_id == tenant_id)
        .where(Person.email == email)
    ).first()
    if existing is not None:
        raise ValueError(f"A person with email {email!r} already exists in this tenant")

    roles = ensure_roles(db, tenant_id)

    person = Person(
        tenant_id=tenant_id,
        email=email,
        first_name=first_name,
        last_name=last_name,
    )
    db.add(person)
    db.flush()

    db.add(
        UserCredential(
            tenant_id=tenant_id,
            person_id=person.id,
            email=email,
            password_hash=hash_password(password),
        )
    )
    db.add(
        PersonRole(
            tenant_id=tenant_id,
            person_id=person.id,
            role_id=roles[role].id,
        )
    )
    db.flush()
    return person

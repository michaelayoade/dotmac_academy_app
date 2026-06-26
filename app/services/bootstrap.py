"""Tenant bootstrap service.

Creates a new tenant with the three standard roles (student, instructor, admin),
an initial admin Person + UserCredential, and grants that person the admin role.
This is a platform-level operation — the caller must pass a session connected as a
role with INSERT privileges on the ``tenants`` table (e.g. the migration/superuser
role). The application ``app_user`` role is RLS-restricted and cannot create tenants.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from app.models.auth import UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole, Role
from app.models.tenant import Tenant
from app.services.security import hash_password

ROLE_SLUGS: dict[str, str] = {
    "student": "Student",
    "instructor": "Instructor",
    "admin": "Administrator",
}


def ensure_roles(db: Session, tenant_id: UUID) -> dict[str, Role]:
    """Idempotent: return slug→Role for the three standard roles, creating any that are missing."""
    existing = {r.slug: r for r in db.query(Role).filter(Role.tenant_id == tenant_id)}
    for slug, name in ROLE_SLUGS.items():
        if slug not in existing:
            role = Role(tenant_id=tenant_id, slug=slug, name=name)
            db.add(role)
            db.flush()
            existing[slug] = role
    return existing


def bootstrap_tenant(
    db: Session,
    *,
    slug: str,
    name: str,
    admin_email: str,
    admin_password: str,
) -> Tenant:
    """Create a tenant, its three standard roles, and an initial admin user.

    Args:
        db: A SQLAlchemy session connected as a role that can INSERT into ``tenants``
            (superuser or migration role). ``app_user`` will not work under RLS.
        slug: URL-safe identifier for the tenant.
        name: Human-readable tenant name.
        admin_email: Email address for the initial admin user.
        admin_password: Plaintext password — hashed before storage.

    Returns:
        The newly created :class:`Tenant` instance (flushed but not committed).
    """
    tenant = Tenant(slug=slug, name=name)
    db.add(tenant)
    db.flush()

    roles = ensure_roles(db, tenant.id)

    person = Person(
        tenant_id=tenant.id,
        email=admin_email,
        first_name="Admin",
        last_name=name,
    )
    db.add(person)
    db.flush()

    db.add(
        UserCredential(
            tenant_id=tenant.id,
            person_id=person.id,
            email=admin_email,
            password_hash=hash_password(admin_password),
        )
    )
    db.add(
        PersonRole(
            tenant_id=tenant.id,
            person_id=person.id,
            role_id=roles["admin"].id,
        )
    )
    db.flush()
    return tenant

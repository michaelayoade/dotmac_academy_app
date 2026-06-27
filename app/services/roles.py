"""Shared role lookup.

`role_slugs` returns the set of role slugs a person holds within a tenant. It is
the single source of truth for role membership used by the web auth gates, the
account routes, and the nav context processor.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.rbac import PersonRole, Role


def role_slugs(db: Session, tenant_id: UUID, person_id: UUID) -> set[str]:
    """Return the set of role slugs held by the person within the tenant."""
    rows = db.scalars(
        select(Role.slug)
        .join(
            PersonRole,
            (PersonRole.role_id == Role.id) & (PersonRole.tenant_id == Role.tenant_id),
        )
        .where(Role.tenant_id == tenant_id)
        .where(PersonRole.tenant_id == tenant_id)
        .where(PersonRole.person_id == person_id)
    ).all()
    return set(rows)

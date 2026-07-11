"""Shared tenant-scoped entity lookups.

One place for the "fetch by (tenant, id) or 404" pattern that several services
and routes had each copied. Raises the domain ``NotFoundError`` (mapped to HTTP
404 by the app's exception handler), so web and service callers share it.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cohort import Cohort
from app.services.exceptions import NotFoundError


def cohort_or_404(db: Session, *, tenant_id: UUID, cohort_id: UUID) -> Cohort:
    """Return the tenant's cohort or raise ``NotFoundError`` (missing or RLS-hidden)."""
    cohort = db.scalars(
        select(Cohort).where(Cohort.tenant_id == tenant_id).where(Cohort.id == cohort_id)
    ).first()
    if cohort is None:
        raise NotFoundError("cohort not found for tenant")
    return cohort

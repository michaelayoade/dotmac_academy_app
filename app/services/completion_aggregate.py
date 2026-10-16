"""Serialize completion and certificate writers on their learning aggregate.

The unique (tenant, person, course) row is the lock anchor, including its first
creation. These helpers only flush/lock; the caller owns the transaction.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import Select, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.completion import CourseCompletion


def _locked_query(*, tenant_id: UUID, person_id: UUID, course_id: UUID) -> Select[tuple[CourseCompletion]]:
    return (
        select(CourseCompletion)
        .where(CourseCompletion.tenant_id == tenant_id)
        .where(CourseCompletion.person_id == person_id)
        .where(CourseCompletion.course_id == course_id)
        .with_for_update()
        # A lock acquired after waiting must refresh any earlier ORM snapshot.
        .execution_options(populate_existing=True)
    )


def lock_existing_completion(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID
) -> CourseCompletion | None:
    """Lock an existing aggregate without creating a record on refusal."""
    return db.scalars(_locked_query(tenant_id=tenant_id, person_id=person_id, course_id=course_id)).first()


def ensure_locked_completion(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID
) -> CourseCompletion:
    """Create the lock anchor if absent, then refresh it under a row lock.

    ON CONFLICT serializes competing first writers before either reads scores;
    existing rows retain their completion timestamp and integration state.
    """
    db.execute(
        insert(CourseCompletion)
        .values(
            id=uuid4(), tenant_id=tenant_id, person_id=person_id, course_id=course_id,
            pct=0.0, status="in_progress",
        )
        .on_conflict_do_nothing(
            index_elements=[CourseCompletion.tenant_id, CourseCompletion.person_id, CourseCompletion.course_id]
        )
    )
    return db.scalars(_locked_query(tenant_id=tenant_id, person_id=person_id, course_id=course_id)).one()

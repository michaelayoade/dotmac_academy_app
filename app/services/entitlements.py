# app/services/entitlements.py
"""Course entitlement checks.

Single source of truth for "may this person study this course?". Access requires
an active Enrollment tying the person to a Cohort that has an active
CourseOffering for the course. Discipline strings do not grant access.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.cohort import Enrollment
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.prerequisite import CoursePrerequisite


def accessible_course_ids(db: Session, *, tenant_id: UUID, person_id: UUID) -> set[UUID]:
    """Course ids the person may access via active enrollment -> active offering."""
    rows = db.scalars(
        select(CourseOffering.course_id)
        .join(
            Enrollment,
            (Enrollment.cohort_id == CourseOffering.cohort_id)
            & (Enrollment.tenant_id == CourseOffering.tenant_id),
        )
        .join(
            Course,
            (Course.id == CourseOffering.course_id)
            & (Course.tenant_id == CourseOffering.tenant_id),
        )
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.status == "active")
        .where(Course.status == "published")
        .where(Enrollment.person_id == person_id)
        .where(Enrollment.status == "active")
    ).all()
    return set(rows)


def person_can_access_course(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID
) -> bool:
    return course_id in accessible_course_ids(db, tenant_id=tenant_id, person_id=person_id)


def require_course_access(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID
) -> None:
    """Raise 403 if the person is not entitled to the course."""
    if not person_can_access_course(
        db, tenant_id=tenant_id, person_id=person_id, course_id=course_id
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


def open_course_ids(
    db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None
) -> set[UUID]:
    """Entitled course ids whose offering window is currently open.

    A null window edge is open-ended; a fully null window is always open.
    """
    now = now or datetime.now(UTC)
    rows = db.scalars(
        select(CourseOffering.course_id)
        .join(
            Enrollment,
            (Enrollment.cohort_id == CourseOffering.cohort_id)
            & (Enrollment.tenant_id == CourseOffering.tenant_id),
        )
        .join(
            Course,
            (Course.id == CourseOffering.course_id)
            & (Course.tenant_id == CourseOffering.tenant_id),
        )
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.status == "active")
        .where(Course.status == "published")
        .where(Enrollment.person_id == person_id)
        .where(Enrollment.status == "active")
        .where(or_(CourseOffering.starts_at.is_(None), CourseOffering.starts_at <= now))
        .where(or_(CourseOffering.ends_at.is_(None), CourseOffering.ends_at >= now))
    ).all()
    return set(rows)


def unmet_prerequisites(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID
) -> list[UUID]:
    """Prerequisite course ids the person has not yet completed."""
    required = db.scalars(
        select(CoursePrerequisite.requires_course_id)
        .where(CoursePrerequisite.tenant_id == tenant_id)
        .where(CoursePrerequisite.course_id == course_id)
    ).all()
    if not required:
        return []
    completed = set(db.scalars(
        select(CourseCompletion.course_id)
        .where(CourseCompletion.tenant_id == tenant_id)
        .where(CourseCompletion.person_id == person_id)
        .where(CourseCompletion.status == "completed")
        .where(CourseCompletion.course_id.in_(set(required)))
    ).all())
    return [cid for cid in required if cid not in completed]


def require_course_open(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID,
    now: datetime | None = None,
) -> None:
    """Raise 403 if not entitled, the offering window isn't open, or a
    prerequisite course is not yet completed."""
    if course_id not in open_course_ids(
        db, tenant_id=tenant_id, person_id=person_id, now=now
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    if unmet_prerequisites(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Prerequisite course not completed")

# app/services/pacing.py
"""Per-activity release/due enforcement within a learner's offering.

An activity may have a per-offering pacing override (OfferingActivity). With no
override it follows the offering window (already enforced by require_course_open).
A future release_at blocks read+submit; a past due_at blocks submit only.

A learner may belong to more than one offering of a course; the most permissive
applicable override wins (released and not past-due preferred).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cohort import Enrollment
from app.models.offering import CourseOffering
from app.models.pacing import OfferingActivity


def _applicable_overrides(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID, activity_id: UUID
) -> list[OfferingActivity]:
    """OfferingActivity rows for this activity across the person's active offerings."""
    return list(
        db.scalars(
            select(OfferingActivity)
            .join(
                CourseOffering,
                (CourseOffering.id == OfferingActivity.offering_id)
                & (CourseOffering.tenant_id == OfferingActivity.tenant_id),
            )
            .join(
                Enrollment,
                (Enrollment.cohort_id == CourseOffering.cohort_id)
                & (Enrollment.tenant_id == CourseOffering.tenant_id),
            )
            .where(OfferingActivity.tenant_id == tenant_id)
            .where(OfferingActivity.activity_id == activity_id)
            .where(CourseOffering.course_id == course_id)
            .where(CourseOffering.status == "active")
            .where(Enrollment.person_id == person_id)
            .where(Enrollment.status == "active")
        ).all()
    )


def activity_pacing(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID, activity_id: UUID,
    now: datetime | None = None,
) -> dict:
    """Return {"readable", "submittable", "has_override"} for the activity.

    No override ⇒ readable and submittable (offering window governs elsewhere).
    """
    now = now or datetime.now(UTC)
    overrides = _applicable_overrides(
        db, tenant_id=tenant_id, person_id=person_id, course_id=course_id, activity_id=activity_id
    )
    if not overrides:
        return {"readable": True, "submittable": True, "has_override": False}

    readable = False
    submittable = False
    for ov in overrides:
        released = ov.release_at is None or ov.release_at <= now
        not_past_due = ov.due_at is None or ov.due_at >= now
        readable = readable or released
        submittable = submittable or (released and not_past_due)
    return {"readable": readable, "submittable": submittable, "has_override": True}


def require_activity_readable(db: Session, *, tenant_id, person_id, course_id, activity_id,
                              now: datetime | None = None) -> None:
    p = activity_pacing(db, tenant_id=tenant_id, person_id=person_id,
                        course_id=course_id, activity_id=activity_id, now=now)
    if not p["readable"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Activity not yet released")


def require_activity_submittable(db: Session, *, tenant_id, person_id, course_id, activity_id,
                                 now: datetime | None = None) -> None:
    p = activity_pacing(db, tenant_id=tenant_id, person_id=person_id,
                        course_id=course_id, activity_id=activity_id, now=now)
    if not p["submittable"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Activity is not open for submission (not released or past due)")

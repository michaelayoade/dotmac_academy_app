# app/services/completion.py
"""Course completion recomputation.

Completion = fraction of a course's activities with a passing best score. The
single per-(person, course) ``CourseCompletion`` record is upserted on every
score write; ``completed_at`` is stamped once, the first time pct reaches 1.0.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.assessment import Activity
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.services.assessment import best_scores_for

logger = logging.getLogger(__name__)


def recompute_completion(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID,
    now: datetime | None = None,
) -> CourseCompletion:
    """Upsert the person's completion record for the course and return it."""
    total = db.scalar(
        select(func.count()).select_from(Activity)
        .where(Activity.tenant_id == tenant_id)
        .where(Activity.course_id == course_id)
    ) or 0
    best = best_scores_for(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
    passed = sum(1 for s in best.values() if s.passed)
    pct = (passed / total) if total else 0.0
    is_complete = total > 0 and passed == total

    rec = db.scalars(
        select(CourseCompletion)
        .where(CourseCompletion.tenant_id == tenant_id)
        .where(CourseCompletion.person_id == person_id)
        .where(CourseCompletion.course_id == course_id)
    ).first()
    if rec is None:
        rec = CourseCompletion(tenant_id=tenant_id, person_id=person_id, course_id=course_id)
        db.add(rec)

    first_completion = is_complete and rec.completed_at is None
    rec.pct = pct
    if is_complete:
        rec.status = "completed"
        if rec.completed_at is None:  # stamp once
            rec.completed_at = now or datetime.now(UTC)
    else:
        rec.status = "in_progress"
        rec.completed_at = None
    db.flush()
    if first_completion:
        try:
            from app.services.notifications import notify

            course = db.scalars(
                select(Course).where(Course.tenant_id == tenant_id).where(Course.id == course_id)
            ).first()
            course_title = course.title if course is not None else "the course"
            notify(
                db,
                tenant_id=tenant_id,
                person_id=person_id,
                kind="course_completed",
                title="Well done, course completed",
                body=f"Congratulations on completing {course_title}.",
                link=f"/certificates/{course_id}",
            )
        except Exception as exc:
            logger.warning("course completion notification failed: %s", exc)
    return rec

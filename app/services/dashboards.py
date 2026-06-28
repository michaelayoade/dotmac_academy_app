# app/services/dashboards.py
"""Instructor dashboards (Slice 5 / finding #9).

Cohort overview combines roster, completion records (Slice 2c) and last activity
into an at-risk view: learners falling behind on completion AND inactive.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.assessment import Score, Submission
from app.models.cohort import Cohort, Enrollment
from app.models.completion import CourseCompletion
from app.models.offering import CourseOffering
from app.models.person import Person
from app.services.exceptions import NotFoundError


def cohort_overview(
    db: Session, *, tenant_id: UUID, cohort_id: UUID, now: datetime | None = None,
    at_risk_pct: float = 0.5, stale_days: int = 14,
) -> dict:
    """Per-learner completion %, last activity, and an at-risk flag.

    completion_pct = mean of the learner's CourseCompletion.pct across the
    cohort's offered courses (missing course ⇒ 0). at_risk = below at_risk_pct
    AND no activity within stale_days (or never active).
    """
    now = now or datetime.now(UTC)
    cohort = db.scalars(
        select(Cohort).where(Cohort.tenant_id == tenant_id).where(Cohort.id == cohort_id)
    ).first()
    if cohort is None:
        raise NotFoundError("cohort not found for tenant")

    course_ids = list(db.scalars(
        select(CourseOffering.course_id)
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.cohort_id == cohort_id)
        .where(CourseOffering.status == "active")
    ).all())

    students = db.scalars(
        select(Person)
        .join(Enrollment, (Enrollment.person_id == Person.id)
              & (Enrollment.tenant_id == Person.tenant_id))
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.cohort_id == cohort_id)
        .where(Enrollment.role_in_cohort == "student")
        .where(Enrollment.status == "active")
        .order_by(Person.last_name, Person.first_name, Person.email)
    ).all()

    stale_before = now - timedelta(days=stale_days)
    rows = []
    for p in students:
        if course_ids:
            pcts: dict[UUID, float] = {
                cid: pct for cid, pct in db.execute(
                    select(CourseCompletion.course_id, CourseCompletion.pct)
                    .where(CourseCompletion.tenant_id == tenant_id)
                    .where(CourseCompletion.person_id == p.id)
                    .where(CourseCompletion.course_id.in_(course_ids))
                ).all()
            }
            completion_pct = sum(pcts.get(cid, 0.0) for cid in course_ids) / len(course_ids)
        else:
            completion_pct = 0.0

        last_activity_at = db.scalar(
            select(func.max(Score.created_at))
            .join(Submission, (Submission.id == Score.submission_id)
                  & (Submission.tenant_id == Score.tenant_id))
            .where(Score.tenant_id == tenant_id)
            .where(Submission.person_id == p.id)
        )
        inactive = last_activity_at is None or last_activity_at < stale_before
        at_risk = completion_pct < at_risk_pct and inactive
        rows.append({
            "person_id": p.id,
            "name": f"{p.first_name} {p.last_name}".strip(),
            "email": p.email,
            "completion_pct": completion_pct,
            "last_activity_at": last_activity_at,
            "at_risk": at_risk,
        })

    return {"cohort": cohort, "rows": rows}

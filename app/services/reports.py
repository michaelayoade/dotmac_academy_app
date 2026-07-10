# app/services/reports.py
"""Read-only reporting over the assessment ledger.

Builds the cohort progress matrix and per-student transcript from existing data
(Cohorts/Enrollments + Courses/Activities + the best Score per activity). No
writes, no new tables.

A cohort has no direct course FK; it is linked to course(s) by matching
`discipline`. The matrix columns are every Activity across the courses that
share the cohort's discipline, ordered by chapter_number then type.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Activity, Score, Submission
from app.models.cohort import Cohort, Enrollment
from app.models.offering import CourseOffering
from app.models.person import Person
from app.services.assessment import best_scores_for
from app.services.exceptions import NotFoundError


def _cohort_or_404(db: Session, tenant_id: UUID, cohort_id: UUID) -> Cohort:
    cohort = db.scalars(
        select(Cohort).where(Cohort.tenant_id == tenant_id).where(Cohort.id == cohort_id)
    ).first()
    if cohort is None:
        raise NotFoundError("cohort not found for tenant")
    return cohort


def _cohort_activities(db: Session, tenant_id: UUID, cohort_id: UUID) -> tuple[list[Activity], list[UUID]]:
    """Activities across the cohort's offered courses, ordered chapter then type.

    Scoped to courses explicitly linked via CourseOffering (active) — not by
    shared discipline string.
    """
    course_ids = db.scalars(
        select(CourseOffering.course_id)
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.cohort_id == cohort_id)
        .where(CourseOffering.status == "active")
    ).all()
    if not course_ids:
        return [], []
    activities = db.scalars(
        select(Activity)
        .where(Activity.tenant_id == tenant_id)
        .where(Activity.course_id.in_(course_ids))
        .order_by(Activity.chapter_number, Activity.type)
    ).all()
    return list(activities), list(course_ids)


def _best_for_person(db: Session, tenant_id: UUID, person_id: UUID, course_ids: list[UUID]) -> dict[UUID, Score]:
    """Merge best_scores_for across every course in the discipline."""
    best: dict[UUID, Score] = {}
    for cid in course_ids:
        best.update(best_scores_for(db, tenant_id=tenant_id, person_id=person_id, course_id=cid))
    return best


def cohort_matrix(db: Session, *, tenant_id: UUID, cohort_id: UUID) -> dict:
    """Progress matrix for one cohort.

    Returns {"cohort", "activities", "rows"} where each row is
    {"person_id", "name", "email", "cells": {activity_id: Score|None}, "completion": float}.
    completion = (# activities with a passing best score) / (# activities).
    """
    cohort = _cohort_or_404(db, tenant_id, cohort_id)
    activities, course_ids = _cohort_activities(db, tenant_id, cohort_id)
    total = len(activities)

    students = db.scalars(
        select(Person)
        .join(
            Enrollment,
            (Enrollment.person_id == Person.id) & (Enrollment.tenant_id == Person.tenant_id),
        )
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.cohort_id == cohort_id)
        .where(Enrollment.role_in_cohort == "student")
        .where(Enrollment.status == "active")
        .order_by(Person.last_name, Person.first_name, Person.email)
    ).all()

    rows = []
    for p in students:
        best = _best_for_person(db, tenant_id, p.id, course_ids)
        cells = {a.id: best.get(a.id) for a in activities}
        passing = sum(1 for a in activities if best.get(a.id) is not None and best[a.id].passed)
        completion = (passing / total) if total else 0.0
        rows.append({
            "person_id": p.id,
            "name": f"{p.first_name} {p.last_name}".strip(),
            "email": p.email,
            "cells": cells,
            "completion": completion,
        })

    return {"cohort": cohort, "activities": activities, "rows": rows}


def student_transcript(db: Session, *, tenant_id: UUID, person_id: UUID) -> dict:
    """Per-student transcript: every Activity the student has a best score for.

    Returns {"person", "rows"} where each row is
    {"activity", "score", "fraction", "passed", "graded_at", "source"}.
    """
    person = db.scalars(
        select(Person).where(Person.tenant_id == tenant_id).where(Person.id == person_id)
    ).first()
    if person is None:
        raise NotFoundError("person not found for tenant")

    pairs = db.execute(
        select(Activity, Score)
        .join(Submission, (Submission.activity_id == Activity.id) & (Submission.tenant_id == Activity.tenant_id))
        .join(Score, (Score.submission_id == Submission.id) & (Score.tenant_id == Submission.tenant_id))
        .where(Activity.tenant_id == tenant_id)
        .where(Submission.person_id == person_id)
        .order_by(Activity.chapter_number, Activity.type)
    ).all()

    best: dict[UUID, tuple[Activity, Score]] = {}
    for activity, score in pairs:
        cur = best.get(activity.id)
        if cur is None or score.fraction > cur[1].fraction:
            best[activity.id] = (activity, score)

    rows = []
    for activity, score in sorted(
        best.values(),
        key=lambda t: (t[0].chapter_number if t[0].chapter_number is not None else 0, t[0].type),
    ):
        rows.append({
            "activity": activity,
            "score": score,
            "fraction": score.fraction,
            "passed": score.passed,
            "graded_at": score.created_at,
            "source": score.source,
        })

    return {"person": person, "rows": rows}

# app/services/gradebook.py
"""Weighted gradebook service.

course_grade  — weighted fraction for one student across one course.
cohort_gradebook — full student x activity grid for a cohort.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Activity
from app.models.cohort import Enrollment
from app.models.person import Person
from app.services.assessment import best_scores_for
from app.services.reports import _best_for_person, _cohort_activities, _cohort_or_404


def course_grade(db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID) -> dict:
    """Weighted grade for one student across one course.

    Returns {"pct": int 0-100, "per_activity": [{activity, fraction, weight}...]}.
    Missing submission → fraction 0 but weight still in denominator.
    """
    activities = list(
        db.scalars(
            select(Activity)
            .where(Activity.tenant_id == tenant_id)
            .where(Activity.course_id == course_id)
            .order_by(Activity.chapter_number, Activity.type)
        ).all()
    )
    if not activities:
        return {"pct": 0, "per_activity": []}

    best = best_scores_for(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
    per_activity = [
        {
            "activity": a,
            "fraction": best[a.id].fraction if a.id in best else 0.0,
            "weight": a.weight,
        }
        for a in activities
    ]
    total_weight = sum(a.weight for a in activities)
    if total_weight == 0:
        return {"pct": 0, "per_activity": per_activity}

    weighted_sum = sum(
        (best[a.id].fraction if a.id in best else 0.0) * a.weight
        for a in activities
    )
    pct = int(round(weighted_sum / total_weight * 100))
    return {"pct": pct, "per_activity": per_activity}


def cohort_gradebook(db: Session, *, tenant_id: UUID, cohort_id: UUID) -> dict:
    """Student x activity weighted gradebook for a cohort.

    Returns {cohort, activities, rows:[{person, email, cells:[{activity_id, pct}], final_pct}]}.
    """
    cohort = _cohort_or_404(db, tenant_id, cohort_id)
    activities, course_ids = _cohort_activities(db, tenant_id, cohort_id)
    total_weight = sum(a.weight for a in activities)

    students = list(
        db.scalars(
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
    )

    rows = []
    for p in students:
        best = _best_for_person(db, tenant_id, p.id, course_ids)
        cells = [
            {
                "activity_id": a.id,
                "pct": int(round((best[a.id].fraction if a.id in best else 0.0) * 100)),
            }
            for a in activities
        ]
        if total_weight > 0:
            weighted_sum = sum(
                (best[a.id].fraction if a.id in best else 0.0) * a.weight
                for a in activities
            )
            final_pct = int(round(weighted_sum / total_weight * 100))
        else:
            final_pct = 0
        rows.append({"person": p, "email": p.email, "cells": cells, "final_pct": final_pct})

    return {"cohort": cohort, "activities": activities, "rows": rows}

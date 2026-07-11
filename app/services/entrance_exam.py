"""Entrance assessment — grade an applicant's exam into a competency profile.

Applicants aren't Persons, so we grade with the pure grader (``grade_submission``)
rather than ``submit_activity``, and store the result — overall score, level
band, and a per-category profile — directly on the Applicant. That profile is
the reusable candidate-level signal admissions, placement, and talent selection
all run on.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.admissions import Applicant
from app.models.assessment import Question
from app.models.cohort import Cohort
from app.services.exceptions import BadRequestError, NotFoundError
from app.services.grading import grade_submission

# Overall-fraction → level band. Ordered low→high; tune the floors as needed.
LEVELS: tuple[tuple[str, float], ...] = (("beginner", 0.0), ("intermediate", 0.4), ("advanced", 0.7))


def level_for(fraction: float) -> str:
    """Map an overall fraction (0..1) to a level band."""
    band = LEVELS[0][0]
    for name, floor in LEVELS:
        if fraction >= floor:
            band = name
    return band


def resolve_bank_id(db: Session, *, applicant: Applicant) -> UUID:
    """The entrance bank configured for the applicant's cohort."""
    if applicant.cohort_id is None:
        raise BadRequestError("Applicant is not linked to a cohort.")
    cohort = db.get(Cohort, applicant.cohort_id)
    if cohort is None or cohort.entrance_bank_id is None:
        raise BadRequestError("This cohort has no entrance assessment configured.")
    return cohort.entrance_bank_id


def grade_and_record(
    db: Session,
    *,
    tenant_id: UUID,
    applicant: Applicant,
    answers: dict,
    bank_id: UUID | None = None,
    now: datetime | None = None,
) -> dict:
    """Grade ``answers`` into a competency profile and store it on the applicant.

    One sitting only — raises if the applicant has already taken it. Returns
    {score, level, profile}.
    """
    if applicant.assessment_taken_at is not None:
        raise BadRequestError("Entrance assessment already completed.")
    bank_id = bank_id or resolve_bank_id(db, applicant=applicant)

    questions = list(
        db.scalars(
            select(Question).where(Question.tenant_id == tenant_id).where(Question.bank_id == bank_id)
        ).all()
    )
    if not questions:
        raise NotFoundError("Entrance assessment has no questions.")

    q_dicts = [
        {"ext_id": q.ext_id, "type": q.type, "correct": q.correct, "weight": q.weight, "options": q.options}
        for q in questions
    ]
    result = grade_submission(answers, q_dicts, 0.0)

    cat_of = {q.ext_id: (q.category or "general") for q in questions}
    weight_of = {q.ext_id: float(q.weight) for q in questions}
    agg: dict[str, list[float]] = {}  # category -> [correct_weight, total_weight]
    for item in result.per_item:
        cat = cat_of.get(item["id"], "general")
        w = weight_of.get(item["id"], 1.0)
        bucket = agg.setdefault(cat, [0.0, 0.0])
        bucket[1] += w
        if item["correct"]:
            bucket[0] += w
    profile = {cat: (round(correct / total, 4) if total else 0.0) for cat, (correct, total) in agg.items()}

    overall = round(result.fraction, 4)
    level = level_for(overall)
    applicant.assessment_score = overall
    applicant.assessment_level = level
    applicant.assessment_profile = profile
    applicant.assessment_taken_at = now or datetime.now(UTC)
    db.flush()
    return {"score": overall, "level": level, "profile": profile}

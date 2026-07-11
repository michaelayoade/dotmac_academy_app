"""Entrance assessment — grade an applicant's exam into a competency profile.

Applicants aren't Persons, so we grade with the pure grader (``grade_submission``)
rather than ``submit_activity``, and store the result — overall score, level
band, and a per-category profile — directly on the Applicant. That profile is
the reusable candidate-level signal admissions, placement, and talent selection
all run on.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.admissions import Applicant
from app.models.assessment import Question
from app.models.cohort import Cohort
from app.services.exceptions import BadRequestError, NotFoundError
from app.services.grading import grade_submission
from app.services.security import hash_token

# Overall-fraction → level band. Ordered low→high; tune the floors as needed.
LEVELS: tuple[tuple[str, float], ...] = (("beginner", 0.0), ("intermediate", 0.4), ("advanced", 0.7))


def level_for(fraction: float) -> str:
    """Map an overall fraction (0..1) to a level band."""
    band = LEVELS[0][0]
    for name, floor in LEVELS:
        if fraction >= floor:
            band = name
    return band


def issue_token(db: Session, *, applicant: Applicant) -> str:
    """Mint a self-serve access token for the applicant's entrance exam.

    Returns the raw token (deliver once, e.g. by email); only its hash is stored.
    """
    raw = secrets.token_urlsafe(32)
    applicant.assessment_token_hash = hash_token(raw)
    db.flush()
    return raw


def applicant_for_token(db: Session, *, tenant_id: UUID, raw: str) -> Applicant | None:
    """Resolve the applicant holding this access token (tenant-scoped by RLS)."""
    if not raw:
        return None
    return db.scalars(
        select(Applicant)
        .where(Applicant.tenant_id == tenant_id)
        .where(Applicant.assessment_token_hash == hash_token(raw))
    ).first()


def resolve_bank_id(db: Session, *, applicant: Applicant) -> UUID:
    """The entrance bank configured for the applicant's cohort."""
    if applicant.cohort_id is None:
        raise BadRequestError("Applicant is not linked to a cohort.")
    cohort = db.get(Cohort, applicant.cohort_id)
    if cohort is None or cohort.entrance_bank_id is None:
        raise BadRequestError("This cohort has no entrance assessment configured.")
    return cohort.entrance_bank_id


# A submit within this many seconds past the limit still counts as on-time
# (network / auto-submit latency).
GRACE_SECONDS = 15


def time_limit_minutes(db: Session, *, applicant: Applicant) -> int | None:
    """The cohort's per-sitting entrance limit in minutes (None = untimed)."""
    if applicant.cohort_id is None:
        return None
    cohort = db.get(Cohort, applicant.cohort_id)
    return cohort.entrance_time_limit_minutes if cohort is not None else None


def start_exam(db: Session, *, applicant: Applicant, now: datetime | None = None) -> dict:
    """Stamp the sitting start on first open (idempotent). Returns timing info.

    ``remaining_seconds`` counts down from the first open, so re-opening the page
    doesn't reset the clock; ``expired`` is true once it hits zero.
    """
    now = now or datetime.now(UTC)
    if applicant.assessment_started_at is None:
        applicant.assessment_started_at = now
        db.flush()
    limit = time_limit_minutes(db, applicant=applicant)
    remaining: int | None = None
    if limit is not None:
        elapsed = (now - applicant.assessment_started_at).total_seconds()
        remaining = max(0, int(limit * 60 - elapsed))
    return {
        "limit_minutes": limit,
        "remaining_seconds": remaining,
        "expired": (remaining == 0) if limit is not None else False,
    }


def _time_exceeded(db: Session, applicant: Applicant, now: datetime) -> bool:
    limit = time_limit_minutes(db, applicant=applicant)
    if limit is None or applicant.assessment_started_at is None:
        return False
    elapsed = (now - applicant.assessment_started_at).total_seconds()
    return elapsed > limit * 60 + GRACE_SECONDS


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
    now = now or datetime.now(UTC)
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
    applicant.assessment_time_exceeded = _time_exceeded(db, applicant, now)
    applicant.assessment_taken_at = now
    db.flush()
    return {"score": overall, "level": level, "profile": profile}

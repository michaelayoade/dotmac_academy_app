"""Entrance assessment — grade an applicant's exam into a competency profile.

Applicants aren't Persons, so we grade with the pure grader (``grade_submission``)
rather than ``submit_activity``, and store the result — overall score, level
band, and a per-category profile — directly on the Applicant. That profile is
the reusable candidate-level signal admissions, placement, and talent selection
all run on.
"""

from __future__ import annotations

import hashlib
import random
import secrets
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.admissions import Applicant
from app.models.assessment import Question
from app.models.cohort import Cohort
from app.models.tenant import Tenant
from app.services.exceptions import BadRequestError, NotFoundError
from app.services.grading import grade_submission
from app.services.security import hash_token

# Overall-fraction → level band. Ordered low→high.
#
# These floors are PROVISIONAL. They are a prediction of item difficulty, not a
# measurement of it. Once a cohort has sat the exam, re-derive them from the real
# distribution with `recompute-entrance-levels` (percentile banding), which is
# immune to a mis-rated item.
LEVELS: tuple[tuple[str, float], ...] = (("beginner", 0.0), ("intermediate", 0.4), ("advanced", 0.7))


def level_for(fraction: float, levels: tuple[tuple[str, float], ...] = LEVELS) -> str:
    """Map an overall fraction (0..1) to a level band."""
    band = levels[0][0]
    for name, floor in levels:
        if fraction >= floor:
            band = name
    return band


# --- validity gate ---------------------------------------------------------
#
# A sitting that fails these is NOT a weak candidate — it is an ABSENCE OF DATA.
# Scoring it as a genuine low result pollutes the admissions ranking and, worse,
# the talent pool, which is only worth querying later if the rows in it are real.
#
# With 4 options the guessing baseline is 25%; a score at or below a third is
# indistinguishable from clicking at random. And nobody engages with a 30-question
# assessment in under six minutes.
MIN_VALID_FRACTION = 1.0 / 3.0  # <= this is at/near chance
MIN_DURATION_SECONDS = 6 * 60  # faster than this = did not engage

INVALID_NEAR_CHANCE = "near_chance"
INVALID_TOO_FAST = "too_fast"


def check_validity(fraction: float, duration_seconds: float | None) -> tuple[bool, str | None]:
    """Is this sitting real signal? Returns (valid, reason_if_not)."""
    if fraction <= MIN_VALID_FRACTION + 1e-9:
        return False, INVALID_NEAR_CHANCE
    if duration_seconds is not None and duration_seconds < MIN_DURATION_SECONDS:
        return False, INVALID_TOO_FAST
    return True, None


def options_for(applicant: Applicant, question) -> list[str]:
    """Question options in a per-applicant order.

    A fixed bank sat by every applicant on a rolling basis leaks — candidates talk,
    and "the answer is C" spreads. Shuffling per applicant breaks that.

    The order is DETERMINISTIC in (applicant, question), so it is stable across a
    page reload or a resumed sitting — otherwise autosaved answers would appear
    against the wrong options. Safe because answers are posted by option TEXT, not
    by index, so grading is order-independent.
    """
    opts = list(question.options or [])
    seed = f"{applicant.id}:{question.ext_id}"
    rng = random.Random(hashlib.sha256(seed.encode()).hexdigest())
    rng.shuffle(opts)
    return opts


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
    """The entrance bank for this applicant: the cohort's override, else the
    academy-wide default (so every applicant sits an entrance exam)."""
    if applicant.cohort_id is not None:
        cohort = db.get(Cohort, applicant.cohort_id)
        if cohort is not None and cohort.entrance_bank_id is not None:
            return cohort.entrance_bank_id
    tenant = db.get(Tenant, applicant.tenant_id)
    if tenant is not None and tenant.default_entrance_bank_id is not None:
        return tenant.default_entrance_bank_id
    raise BadRequestError("No entrance assessment is configured for this cohort or academy.")


def has_entrance_exam(db: Session, *, applicant: Applicant) -> bool:
    """Whether an entrance exam applies to this applicant (cohort or academy default)."""
    try:
        resolve_bank_id(db, applicant=applicant)
        return True
    except BadRequestError:
        return False


# A submit within this many seconds past the limit still counts as on-time
# (network / auto-submit latency).
GRACE_SECONDS = 15


def time_limit_minutes(db: Session, *, applicant: Applicant) -> int | None:
    """Per-sitting entrance limit in minutes: cohort override, else the
    academy-wide default (None = untimed)."""
    if applicant.cohort_id is not None:
        cohort = db.get(Cohort, applicant.cohort_id)
        if cohort is not None and cohort.entrance_time_limit_minutes is not None:
            return cohort.entrance_time_limit_minutes
    tenant = db.get(Tenant, applicant.tenant_id)
    return tenant.default_entrance_time_limit_minutes if tenant is not None else None


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


def save_answers(db: Session, *, applicant: Applicant, answers: dict) -> None:
    """Autosave in-progress answers so an interrupted sitting can resume.

    Called as the candidate answers, not just on submit. Without this, a dropped
    connection loses every answer while the clock keeps running — the applicant
    returns to "Time is up" with no score and (before ``reset_exam``) no way back.
    Ignored once the sitting is graded.
    """
    if applicant.assessment_taken_at is not None:
        return
    applicant.assessment_answers = {k: v for k, v in (answers or {}).items() if v}
    db.flush()


def reset_exam(db: Session, *, applicant: Applicant) -> str:
    """Give an applicant a fresh sitting, and return a new access token.

    The recovery path when a sitting is lost to a dropped connection, a device
    failure, or an expired clock the candidate never actually got to use. Clears
    the timer, the autosaved answers and any recorded result, and audits the reset.
    """
    applicant.assessment_started_at = None
    applicant.assessment_taken_at = None
    applicant.assessment_answers = None
    applicant.assessment_score = None
    applicant.assessment_level = None
    applicant.assessment_profile = None
    applicant.assessment_valid = None
    applicant.assessment_invalid_reason = None
    applicant.assessment_time_exceeded = False
    applicant.assessment_reset_count = (applicant.assessment_reset_count or 0) + 1
    return issue_token(db, applicant=applicant)


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
        db.scalars(select(Question).where(Question.tenant_id == tenant_id).where(Question.bank_id == bank_id)).all()
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

    # Validity gate: is this a real measurement, or an absence of data?
    duration: float | None = None
    if applicant.assessment_started_at is not None:
        duration = (now - applicant.assessment_started_at).total_seconds()
    valid, reason = check_validity(overall, duration)

    applicant.assessment_score = overall
    applicant.assessment_level = level
    applicant.assessment_profile = profile
    applicant.assessment_valid = valid
    applicant.assessment_invalid_reason = reason
    applicant.assessment_time_exceeded = _time_exceeded(db, applicant, now)
    applicant.assessment_taken_at = now
    applicant.assessment_answers = None  # graded; drop the autosave scratchpad
    db.flush()
    return {
        "score": overall,
        "level": level,
        "profile": profile,
        "valid": valid,
        "invalid_reason": reason,
    }

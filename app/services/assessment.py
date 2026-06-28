# app/services/assessment.py
from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.assessment import Activity, Question, Score, Submission
from app.models.person import Person
from app.services.grading import grade_submission

logger = logging.getLogger(__name__)


def _questions_for(db: Session, tenant_id, bank_id, only_ext_ids=None) -> list[dict]:
    rows = db.scalars(select(Question).where(Question.tenant_id == tenant_id)
                      .where(Question.bank_id == bank_id)).all()
    if only_ext_ids is not None:
        keep = set(only_ext_ids)
        rows = [q for q in rows if q.ext_id in keep]
    return [{"ext_id": q.ext_id, "type": q.type, "correct": q.correct, "weight": q.weight,
             "explanation": q.explanation, "options": q.options} for q in rows]


def submit_activity(db: Session, *, tenant_id, person_id, activity: Activity, answers: dict,
                    only_ext_ids: list | None = None) -> Score | None:
    """Record a submission. Auto-grades and returns the Score, or returns None for
    manual-grading activities (the submission then waits in the grading queue).

    ``only_ext_ids`` (a randomized attempt's question subset) restricts grading to
    exactly those questions; None grades the whole bank.
    """
    qs = _questions_for(db, tenant_id, activity.bank_id, only_ext_ids) if activity.bank_id else []
    prev = db.scalar(select(func.coalesce(func.max(Submission.attempt_no), 0))
                     .where(Submission.tenant_id == tenant_id)
                     .where(Submission.activity_id == activity.id)
                     .where(Submission.person_id == person_id))
    sub = Submission(tenant_id=tenant_id, activity_id=activity.id, person_id=person_id,
                     answers=answers, attempt_no=int(prev or 0) + 1)
    db.add(sub); db.flush()
    if activity.grading == "manual":
        return None  # awaits instructor grading (no auto Score)
    r = grade_submission(answers, qs, activity.pass_threshold)
    score = Score(tenant_id=tenant_id, submission_id=sub.id, score=r.score, max_score=r.max_score,
                  fraction=r.fraction, passed=r.passed, per_item=r.per_item, source="auto")
    db.add(score); db.flush()
    _recompute_completion(db, tenant_id, person_id, activity.course_id)
    # Auto-on-pass notification — best effort, must never break grading.
    try:
        from app.services.email import notify_score_if_first_pass
        person = db.get(Person, person_id)
        notify_score_if_first_pass(db, score=score, activity=activity, person=person)
    except Exception as exc:
        logger.warning("auto-on-pass notification failed: %s", exc)
    return score


def _recompute_completion(db: Session, tenant_id, person_id, course_id) -> None:
    """Update the learner's course completion after a score write (best effort)."""
    try:
        from app.services.completion import recompute_completion
        recompute_completion(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
    except Exception as exc:
        logger.warning("completion recompute failed: %s", exc)


def pending_grading(db: Session, *, tenant_id) -> list[tuple[Submission, Activity, str]]:
    """Submissions with no Score yet — the manual grading queue.

    Returns (submission, activity, person_email) ordered oldest-first.
    """
    rows = db.execute(
        select(Submission, Activity, Person.email)
        .join(Activity, (Activity.id == Submission.activity_id)
              & (Activity.tenant_id == Submission.tenant_id))
        .join(Person, (Person.id == Submission.person_id)
              & (Person.tenant_id == Submission.tenant_id))
        .outerjoin(Score, (Score.submission_id == Submission.id)
                   & (Score.tenant_id == Submission.tenant_id))
        .where(Submission.tenant_id == tenant_id)
        .where(Score.id.is_(None))
        .order_by(Submission.created_at)
    ).all()
    return [(s, a, email) for s, a, email in rows]


def attempts_used(db: Session, *, tenant_id, person_id, activity_id) -> int:
    """Number of submissions this person has made for the activity."""
    return int(db.scalar(
        select(func.count()).select_from(Submission)
        .where(Submission.tenant_id == tenant_id)
        .where(Submission.activity_id == activity_id)
        .where(Submission.person_id == person_id)
    ) or 0)


def best_scores_for(db: Session, *, tenant_id, person_id, course_id) -> dict[UUID, Score]:
    rows = db.execute(
        select(Activity.id, Score)
        .join(Submission, (Submission.activity_id == Activity.id) & (Submission.tenant_id == Activity.tenant_id))
        .join(Score, (Score.submission_id == Submission.id) & (Score.tenant_id == Submission.tenant_id))
        .where(Activity.tenant_id == tenant_id)
        .where(Activity.course_id == course_id)
        .where(Submission.person_id == person_id)
    ).all()
    best: dict = {}
    for activity_id, score in rows:
        cur = best.get(activity_id)
        if cur is None or score.fraction > cur.fraction:
            best[activity_id] = score
    return best


def override_score(db: Session, *, tenant_id, submission_id, score_value, max_score, reason) -> Score:
    sub = db.get(Submission, submission_id)
    if sub is None or sub.tenant_id != tenant_id:
        raise ValueError("submission not found for tenant")
    activity = db.scalars(
        select(Activity).where(Activity.tenant_id == tenant_id).where(Activity.id == sub.activity_id)
    ).first()
    threshold = activity.pass_threshold if activity is not None else 0.0
    frac = (score_value / max_score) if max_score else 0.0
    score = Score(
        tenant_id=tenant_id, submission_id=submission_id, score=score_value, max_score=max_score,
        fraction=frac, passed=(max_score > 0 and frac >= threshold),
        per_item=[], source="override", override_reason=reason,
    )
    db.add(score); db.flush()
    if activity is not None:
        _recompute_completion(db, tenant_id, sub.person_id, activity.course_id)
    return score

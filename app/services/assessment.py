# app/services/assessment.py
from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.assessment import Activity, Question, Score, Submission
from app.models.person import Person
from app.services import learning_events
from app.services.exceptions import ConflictError
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
    """Grade a submission. Every auto-graded attempt is scored (best-of policy).

    Each attempt is a Submission; for auto-graded activities each attempt also
    gets its own Score, and the *score of record* is the best attempt (see
    ``best_scores_for``). A weak first attempt therefore no longer locks a
    learner out — retakes can improve the recorded score, bounded by
    ``activity.max_attempts`` (enforced by this canonical writer). Manual-graded
    activities record the Submission and await instructor grading (no auto Score).

    only_ext_ids (a randomized attempt's question subset) restricts grading to
    exactly those questions; None grades the whole bank.
    """
    person = db.scalars(
        select(Person)
        .where(Person.tenant_id == tenant_id)
        .where(Person.id == person_id)
        .with_for_update()
    ).first()
    if person is None:
        raise ConflictError("Learner account no longer exists.")
    used = attempts_used(db, tenant_id=tenant_id, person_id=person_id, activity_id=activity.id)
    if activity.max_attempts is not None and used >= activity.max_attempts:
        raise ConflictError("No attempts remaining.")
    qs = _questions_for(db, tenant_id, activity.bank_id, only_ext_ids) if activity.bank_id else []
    prev = db.scalar(select(func.coalesce(func.max(Submission.attempt_no), 0))
                     .where(Submission.tenant_id == tenant_id)
                     .where(Submission.activity_id == activity.id)
                     .where(Submission.person_id == person_id))
    sub = Submission(tenant_id=tenant_id, activity_id=activity.id, person_id=person_id,
                     answers=answers, attempt_no=int(prev or 0) + 1)
    db.add(sub); db.flush()
    learning_events.emit(
        db, tenant_id=tenant_id, person_id=person_id, kind="submission_made",
        course_id=activity.course_id, subject_id=sub.id,
        detail={"activity_id": str(activity.id), "attempt_no": sub.attempt_no},
    )
    if activity.grading == "manual":
        return None  # awaits instructor grading (no auto Score)
    r = grade_submission(answers, qs, activity.pass_threshold)
    score = Score(tenant_id=tenant_id, submission_id=sub.id, score=r.score, max_score=r.max_score,
                  fraction=r.fraction, passed=r.passed, per_item=r.per_item, source="auto")
    db.add(score); db.flush()
    learning_events.emit(
        db, tenant_id=tenant_id, person_id=person_id, kind="work_graded",
        course_id=activity.course_id, subject_id=sub.id,
        detail={"activity_id": str(activity.id), "passed": r.passed,
                "fraction": float(r.fraction)},
    )
    _recompute_completion(db, tenant_id, person_id, activity.course_id)
    # Auto-on-pass notification: best effort, must never break grading.
    try:
        from app.services.email import notify_score_if_first_pass
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


def reveal_feedback(activity: Activity, *, passed: bool, attempts_used: int) -> bool:
    """Whether to show per-question feedback (correct/incorrect, explanations,
    expected answers) for this activity, given the learner's current state.

    - practice: always (formative — learning first)
    - graded:   once the learner passes or has used all their attempts
    - exam:     never (score + pass/fail only)

    Withholding the answer key on graded/exam assessments stops a learner from
    failing once, reading the key, and acing the retake.
    """
    mode = activity.assessment_mode
    if mode == "practice":
        return True
    if mode == "exam":
        return False
    # graded
    exhausted = activity.max_attempts is not None and attempts_used >= activity.max_attempts
    return passed or exhausted


def best_scores_for(db: Session, *, tenant_id, person_id, course_id) -> dict[UUID, Score]:
    """The score of record per activity: the best attempt (highest fraction).

    Ties prefer a passing score, then a manual override, then the most recent —
    so passing is sticky (a later failing retake can't un-pass you) and an
    instructor override wins over an auto score of equal fraction.
    """
    rows = db.execute(
        select(Activity.id, Score)
        .join(Submission, (Submission.activity_id == Activity.id) & (Submission.tenant_id == Activity.tenant_id))
        .join(Score, (Score.submission_id == Submission.id) & (Score.tenant_id == Submission.tenant_id))
        .where(Activity.tenant_id == tenant_id)
        .where(Activity.course_id == course_id)
        .where(Submission.person_id == person_id)
        .order_by(Activity.id, Submission.attempt_no, Score.created_at)
    ).all()

    def _rank(score: Score) -> tuple:
        # Higher is better: fraction, then passed, then override, then recency.
        return (score.fraction, score.passed, score.source == "override", score.created_at)

    best: dict[UUID, Score] = {}
    for activity_id, score in rows:
        current = best.get(activity_id)
        if current is None or _rank(score) > _rank(current):
            best[activity_id] = score
    return best


def _best_rank(score: Score) -> tuple:
    """Shared ranking for best-of selection (see :func:`best_scores_for`)."""
    return (score.fraction, score.passed, score.source == "override", score.created_at)


def best_scores_for_person(
    db: Session, *, tenant_id, person_id, course_ids=None
) -> dict[UUID, Score]:
    """Best score per activity across many courses in ONE query.

    Same best-of semantics as :func:`best_scores_for` (activity ids are unique
    across courses, so a flat activity_id->Score map is unambiguous). Pass
    ``course_ids`` to restrict; ``None`` covers every course. Returns ``{}`` for
    an empty ``course_ids`` list without touching the database.
    """
    if course_ids is not None and not course_ids:
        return {}
    q = (
        select(Activity.id, Score)
        .join(Submission, (Submission.activity_id == Activity.id) & (Submission.tenant_id == Activity.tenant_id))
        .join(Score, (Score.submission_id == Submission.id) & (Score.tenant_id == Submission.tenant_id))
        .where(Activity.tenant_id == tenant_id)
        .where(Submission.person_id == person_id)
        .order_by(Activity.id, Submission.attempt_no, Score.created_at)
    )
    if course_ids is not None:
        q = q.where(Activity.course_id.in_(course_ids))
    best: dict[UUID, Score] = {}
    for activity_id, score in db.execute(q).all():
        current = best.get(activity_id)
        if current is None or _best_rank(score) > _best_rank(current):
            best[activity_id] = score
    return best


def best_scores_by_course_for_person(
    db: Session, *, tenant_id, person_id, course_ids=None
) -> dict[UUID, dict[UUID, Score]]:
    """Best score per activity, grouped by course, in ONE query."""
    if course_ids is not None and not course_ids:
        return {}
    q = (
        select(Activity.course_id, Activity.id, Score)
        .join(Submission, (Submission.activity_id == Activity.id) & (Submission.tenant_id == Activity.tenant_id))
        .join(Score, (Score.submission_id == Submission.id) & (Score.tenant_id == Submission.tenant_id))
        .where(Activity.tenant_id == tenant_id)
        .where(Submission.person_id == person_id)
        .order_by(Activity.id, Submission.attempt_no, Score.created_at)
    )
    if course_ids is not None:
        q = q.where(Activity.course_id.in_(course_ids))
    out: dict[UUID, dict[UUID, Score]] = {}
    for course_id, activity_id, score in db.execute(q).all():
        per_course = out.setdefault(course_id, {})
        current = per_course.get(activity_id)
        if current is None or _best_rank(score) > _best_rank(current):
            per_course[activity_id] = score
    return out


def attempts_used_by_person(db: Session, *, tenant_id, person_id) -> dict[UUID, int]:
    """Submission count per activity for the person, in ONE grouped query."""
    rows = db.execute(
        select(Submission.activity_id, func.count())
        .where(Submission.tenant_id == tenant_id)
        .where(Submission.person_id == person_id)
        .group_by(Submission.activity_id)
    ).all()
    return {activity_id: int(n) for activity_id, n in rows}


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

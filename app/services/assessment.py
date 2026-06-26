# app/services/assessment.py
from __future__ import annotations
from uuid import UUID
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.models.assessment import Activity, Question, Submission, Score
from app.services.grading import grade_submission


def _questions_for(db: Session, tenant_id, bank_id) -> list[dict]:
    rows = db.scalars(select(Question).where(Question.tenant_id == tenant_id)
                      .where(Question.bank_id == bank_id)).all()
    return [{"ext_id": q.ext_id, "type": q.type, "correct": q.correct, "weight": q.weight,
             "explanation": q.explanation} for q in rows]


def submit_activity(db: Session, *, tenant_id, person_id, activity: Activity, answers: dict) -> Score:
    qs = _questions_for(db, tenant_id, activity.bank_id) if activity.bank_id else []
    prev = db.scalar(select(func.coalesce(func.max(Submission.attempt_no), 0))
                     .where(Submission.tenant_id == tenant_id)
                     .where(Submission.activity_id == activity.id)
                     .where(Submission.person_id == person_id))
    sub = Submission(tenant_id=tenant_id, activity_id=activity.id, person_id=person_id,
                     answers=answers, attempt_no=int(prev) + 1)
    db.add(sub); db.flush()
    r = grade_submission(answers, qs, activity.pass_threshold)
    score = Score(tenant_id=tenant_id, submission_id=sub.id, score=r.score, max_score=r.max_score,
                  fraction=r.fraction, passed=r.passed, per_item=r.per_item, source="auto")
    db.add(score); db.flush()
    return score


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
    frac = (score_value / max_score) if max_score else 0.0
    score = Score(tenant_id=tenant_id, submission_id=submission_id, score=score_value,
                  max_score=max_score, fraction=frac, passed=frac >= 0.0, per_item=[],
                  source="override", override_reason=reason)
    db.add(score); db.flush()
    return score

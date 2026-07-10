# app/services/analytics.py
"""Read-only assessment analytics (Slice 4c, finding #4).

Item analysis derives per-question difficulty from the ``per_item`` payload each
auto-graded Score already stores. Uses each learner's best Score for the activity
so multiple attempts don't skew the statistics.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Score, Submission


def _best_scores_for_activity(db: Session, *, tenant_id: UUID, activity_id: UUID) -> list[Score]:
    rows = db.execute(
        select(Submission.person_id, Score)
        .join(Score, (Score.submission_id == Submission.id)
              & (Score.tenant_id == Submission.tenant_id))
        .where(Submission.tenant_id == tenant_id)
        .where(Submission.activity_id == activity_id)
    ).all()
    best: dict[UUID, Score] = {}
    for person_id, score in rows:
        cur = best.get(person_id)
        if cur is None or score.fraction > cur.fraction:
            best[person_id] = score
    return list(best.values())


def item_analysis(db: Session, *, tenant_id: UUID, activity_id: UUID) -> list[dict]:
    """Per-question stats: responses, correct, and p-value (difficulty).

    p-value is the fraction answering correctly — high = easy, low = hard.
    Questions are returned in first-seen order.
    """
    tally: dict[str, list[int]] = {}  # id -> [responses, correct]
    order: list[str] = []
    for score in _best_scores_for_activity(db, tenant_id=tenant_id, activity_id=activity_id):
        for item in (score.per_item or []):
            qid = item.get("id")
            if qid is None:
                continue
            if qid not in tally:
                tally[qid] = [0, 0]
                order.append(qid)
            tally[qid][0] += 1
            if item.get("correct"):
                tally[qid][1] += 1
    return [
        {
            "id": qid,
            "responses": tally[qid][0],
            "correct": tally[qid][1],
            "p_value": (tally[qid][1] / tally[qid][0]) if tally[qid][0] else 0.0,
        }
        for qid in order
    ]

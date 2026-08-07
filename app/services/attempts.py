# app/services/attempts.py
"""Question pools for course activities, fixed per attempt.

When an activity has a pool (``Activity.question_count`` set), opening it fixes
a subset and order of question ext_ids in an ``ActivityAttempt``, so the submit
grades exactly what was shown. Submitting closes the attempt; the next open
draws a fresh one.

Selection itself belongs to ``exam_engine`` — this module owns only *when* a
draw happens and that it is written down. The draw is **persisted rather than
derived** deliberately: banks are re-loaded in place (``load-banks`` replaces a
bank's questions), so a draw recomputed at grading time could differ from the
one the learner actually sat if the bank changed mid-attempt. The stored list
is the record of what was in front of them.

See ``docs/adr/0005-assessment-engine-owns-exam-logic.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.attempt import ActivityAttempt
from app.models.person import Person
from app.services import exam_engine


@dataclass(frozen=True)
class _Sitter:
    """Adapts a person id to what the engine needs: an identity, nothing more."""

    id: UUID


@dataclass(frozen=True)
class _ExtIdOnly:
    """A question the engine can rank when the caller only has ext_ids."""

    ext_id: str
    category: str | None = None
    options: list | None = None


def _lock_learner(db: Session, *, tenant_id: UUID, person_id: UUID) -> None:
    db.execute(
        select(Person.id)
        .where(Person.tenant_id == tenant_id)
        .where(Person.id == person_id)
        .with_for_update()
    )


def _open_attempt(db: Session, *, tenant_id: UUID, person_id: UUID, activity_id: UUID):
    return db.scalars(
        select(ActivityAttempt)
        .where(ActivityAttempt.tenant_id == tenant_id)
        .where(ActivityAttempt.activity_id == activity_id)
        .where(ActivityAttempt.person_id == person_id)
        .where(ActivityAttempt.submitted_at.is_(None))
        .order_by(ActivityAttempt.started_at.desc())
    ).first()


def _prior_attempts(db: Session, *, tenant_id: UUID, person_id: UUID, activity_id: UUID) -> int:
    """How many attempts this learner has already opened on this activity."""
    return int(
        db.scalar(
            select(func.count())
            .select_from(ActivityAttempt)
            .where(ActivityAttempt.tenant_id == tenant_id)
            .where(ActivityAttempt.activity_id == activity_id)
            .where(ActivityAttempt.person_id == person_id)
        )
        or 0
    )


def open_or_create_attempt(
    db: Session, *, tenant_id: UUID, person_id: UUID, activity_id: UUID,
    all_ext_ids: list[str], count: int, now: datetime | None = None,
    questions: list | None = None,
) -> ActivityAttempt:
    """Return the learner's open attempt, drawing a fresh subset if there is none.

    ``questions`` are the bank's question rows; when given, the draw goes
    through the engine and can stratify by competency. Falls back to ext_ids
    alone for callers that have not been migrated.
    """
    _lock_learner(db, tenant_id=tenant_id, person_id=person_id)
    existing = _open_attempt(db, tenant_id=tenant_id, person_id=person_id, activity_id=activity_id)
    if existing is not None:
        return existing
    k = min(count, len(all_ext_ids))
    if k <= 0:
        chosen: list[str] = []
    else:
        # The attempt number varies the draw, so a retake is not the same paper.
        variant = f"attempt{_prior_attempts(db, tenant_id=tenant_id, person_id=person_id, activity_id=activity_id)}:"
        sitter = _Sitter(person_id)
        if questions is not None:
            drawn = exam_engine.select(
                sitter, list(questions), exam_engine.SelectionPolicy(total=k), variant=variant
            )
            chosen = [q.ext_id for q in drawn]
        else:
            shims = [_ExtIdOnly(e) for e in all_ext_ids]
            drawn = exam_engine.select(
                sitter, shims, exam_engine.SelectionPolicy(total=k), variant=variant
            )
            chosen = [q.ext_id for q in drawn]
    attempt = ActivityAttempt(
        tenant_id=tenant_id, activity_id=activity_id, person_id=person_id,
        question_ext_ids=chosen, started_at=now or datetime.now(UTC),
    )
    db.add(attempt)
    db.flush()
    from app.services import learning_events

    learning_events.emit(
        db, tenant_id=tenant_id, person_id=person_id,
        kind="activity_started", subject_id=activity_id,
        detail={"attempt": len(chosen)},
    )
    return attempt


def close_open_attempt(
    db: Session, *, tenant_id: UUID, person_id: UUID, activity_id: UUID,
    now: datetime | None = None,
) -> ActivityAttempt | None:
    """Mark the learner's open attempt submitted and return it (or None if none)."""
    _lock_learner(db, tenant_id=tenant_id, person_id=person_id)
    attempt = _open_attempt(db, tenant_id=tenant_id, person_id=person_id, activity_id=activity_id)
    if attempt is None:
        return None
    attempt.submitted_at = now or datetime.now(UTC)
    db.flush()
    return attempt

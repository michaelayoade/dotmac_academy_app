# app/services/attempts.py
"""Randomized question pools via a persisted attempt (Slice 4e, finding #4).

When an activity has a question pool (``Activity.question_count`` set), opening it
fixes a random subset (and order) of question ext_ids in an ``ActivityAttempt``,
so the submit grades exactly what was shown. Submitting closes the attempt; the
next open draws a fresh one.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.attempt import ActivityAttempt


def _open_attempt(db: Session, *, tenant_id: UUID, person_id: UUID, activity_id: UUID):
    return db.scalars(
        select(ActivityAttempt)
        .where(ActivityAttempt.tenant_id == tenant_id)
        .where(ActivityAttempt.activity_id == activity_id)
        .where(ActivityAttempt.person_id == person_id)
        .where(ActivityAttempt.submitted_at.is_(None))
        .order_by(ActivityAttempt.started_at.desc())
    ).first()


def open_or_create_attempt(
    db: Session, *, tenant_id: UUID, person_id: UUID, activity_id: UUID,
    all_ext_ids: list[str], count: int, now: datetime | None = None,
) -> ActivityAttempt:
    """Return the learner's open attempt, creating one with a random subset if none."""
    existing = _open_attempt(db, tenant_id=tenant_id, person_id=person_id, activity_id=activity_id)
    if existing is not None:
        return existing
    k = min(count, len(all_ext_ids))
    chosen = random.sample(all_ext_ids, k) if k > 0 else []  # random subset + order
    attempt = ActivityAttempt(
        tenant_id=tenant_id, activity_id=activity_id, person_id=person_id,
        question_ext_ids=chosen, started_at=now or datetime.now(UTC),
    )
    db.add(attempt)
    db.flush()
    return attempt


def close_open_attempt(
    db: Session, *, tenant_id: UUID, person_id: UUID, activity_id: UUID,
    now: datetime | None = None,
) -> ActivityAttempt | None:
    """Mark the learner's open attempt submitted and return it (or None if none)."""
    attempt = _open_attempt(db, tenant_id=tenant_id, person_id=person_id, activity_id=activity_id)
    if attempt is None:
        return None
    attempt.submitted_at = now or datetime.now(UTC)
    db.flush()
    return attempt

"""Learning-event ledger — sole writer and primitive readers (roadmap P3a).

``record`` is the only code path that inserts :class:`LearningEvent` rows
(append-only; the migration grants no UPDATE/DELETE). ``emit`` is the wiring
wrapper used at the owning services' commit points: it runs ``record`` inside
a savepoint and swallows every failure, so a ledger problem can never break
grading, reading, labs, or certificates. Analytics projections live in
``app.services.analytics`` and only read this table.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, time, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.learning_event import (
    EVENT_KINDS,
    KIND_CERTIFICATE_EARNED,
    KIND_CHAPTER_COMPLETED,
    KIND_CHAPTER_VIEWED,
    KIND_COURSE_VIEWED,
    LearningEvent,
)
from app.services.localtime import academy_zone

logger = logging.getLogger(__name__)

# Kinds that must exist at most once per (person, kind, subject).
_ONCE_PER_SUBJECT = {KIND_CHAPTER_COMPLETED, KIND_CERTIFICATE_EARNED}
# Kinds throttled to one row per (person, kind, subject) per academy-local day.
_ONCE_PER_LOCAL_DAY = {KIND_COURSE_VIEWED, KIND_CHAPTER_VIEWED}


def _local_day_start_utc(now: datetime) -> datetime:
    local = now.astimezone(academy_zone())
    day_start = datetime.combine(local.date(), time.min, tzinfo=academy_zone())
    return day_start.astimezone(UTC)


def record(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    kind: str,
    course_id: UUID | None = None,
    subject_id: UUID | None = None,
    detail: dict | None = None,
    occurred_at: datetime | None = None,
) -> LearningEvent | None:
    """Append one event; returns None when a dedupe rule suppressed it."""
    if kind not in EVENT_KINDS:
        raise ValueError(f"unknown learning-event kind {kind!r}")
    now = occurred_at or datetime.now(UTC)

    if kind in _ONCE_PER_LOCAL_DAY:
        # Day-throttled: no static unique index fits a per-local-day bucket, so
        # the SELECT pre-check stands. A concurrent race costs at most one extra
        # view row per day — harmless to analytics.
        dupe = (
            select(LearningEvent.id)
            .where(LearningEvent.tenant_id == tenant_id)
            .where(LearningEvent.person_id == person_id)
            .where(LearningEvent.kind == kind)
            .where(LearningEvent.subject_id == subject_id)
            .where(LearningEvent.occurred_at >= _local_day_start_utc(now))
        )
        if db.scalars(dupe.limit(1)).first() is not None:
            return None

    values = {
        "tenant_id": tenant_id,
        "person_id": person_id,
        "kind": kind,
        "course_id": course_id,
        "subject_id": subject_id,
        "detail": detail or {},
        "occurred_at": now,
    }

    if kind in _ONCE_PER_SUBJECT:
        # The partial unique index (migration 0047) is the real guard; ON
        # CONFLICT DO NOTHING makes once-per-subject hold under concurrency.
        stmt = (
            pg_insert(LearningEvent)
            .values(**values)
            .on_conflict_do_nothing(
                index_elements=["tenant_id", "person_id", "kind", "subject_id"],
                index_where=LearningEvent.kind.in_(tuple(_ONCE_PER_SUBJECT)),
            )
            .returning(LearningEvent.id)
        )
        inserted_id = db.execute(stmt).scalar()
        if inserted_id is None:
            return None
        db.flush()
        return db.get(LearningEvent, inserted_id)

    event = LearningEvent(**values)
    db.add(event)
    db.flush()
    return event


def emit(db: Session, **kwargs) -> None:
    """Best-effort ``record`` for wiring points: never raises, never breaks
    the host transaction (savepoint-isolated)."""
    try:
        with db.begin_nested():
            record(db, **kwargs)
    except Exception as exc:
        logger.warning("learning-event emission failed (%s): %s", kwargs.get("kind"), exc)


# --------------------------------------------------------------------------
# Primitive readers (analytics and future consumers build on these).
# --------------------------------------------------------------------------


def last_activity_at(db: Session, *, tenant_id: UUID, person_id: UUID) -> datetime | None:
    return db.scalar(
        select(func.max(LearningEvent.occurred_at))
        .where(LearningEvent.tenant_id == tenant_id)
        .where(LearningEvent.person_id == person_id)
    )


def weekly_buckets(
    db: Session, *, tenant_id: UUID, person_id: UUID, weeks: int = 8,
    kinds: tuple[str, ...] | None = None, now: datetime | None = None,
) -> list[dict]:
    """Per-ISO-week event counts for the trailing ``weeks`` weeks (oldest first)."""
    now = now or datetime.now(UTC)
    start = now - timedelta(weeks=weeks)
    q = (
        select(LearningEvent.occurred_at)
        .where(LearningEvent.tenant_id == tenant_id)
        .where(LearningEvent.person_id == person_id)
        .where(LearningEvent.occurred_at >= start)
    )
    if kinds:
        q = q.where(LearningEvent.kind.in_(kinds))
    stamps = list(db.scalars(q).all())

    buckets: list[dict] = []
    for i in range(weeks):
        w_start = (now - timedelta(weeks=weeks - i)).date()
        w_end = (now - timedelta(weeks=weeks - i - 1)).date()
        count = sum(1 for s in stamps if w_start <= s.date() < w_end)
        buckets.append({"week_start": w_start, "count": count})
    return buckets


def active_person_ids(
    db: Session, *, tenant_id: UUID, person_ids: list[UUID], since: datetime,
) -> set[UUID]:
    """Subset of ``person_ids`` with at least one ledger event since ``since``."""
    if not person_ids:
        return set()
    rows = db.scalars(
        select(LearningEvent.person_id)
        .where(LearningEvent.tenant_id == tenant_id)
        .where(LearningEvent.person_id.in_(person_ids))
        .where(LearningEvent.occurred_at >= since)
        .distinct()
    ).all()
    return set(rows)


def kind_counts(
    db: Session, *, tenant_id: UUID, kinds: tuple[str, ...],
    course_ids: list[UUID] | None = None, person_ids: list[UUID] | None = None,
    since: datetime | None = None,
) -> dict[UUID | None, dict[str, int]]:
    """Counts per (course_id, kind) — the instructor-analytics primitive.

    Pass ``person_ids`` to scope to a cohort roster; without it the counts span
    every learner in the tenant for the given courses.
    """
    q = (
        select(LearningEvent.course_id, LearningEvent.kind, func.count())
        .where(LearningEvent.tenant_id == tenant_id)
        .where(LearningEvent.kind.in_(kinds))
        .group_by(LearningEvent.course_id, LearningEvent.kind)
    )
    if course_ids:
        q = q.where(LearningEvent.course_id.in_(course_ids))
    if person_ids is not None:
        q = q.where(LearningEvent.person_id.in_(person_ids))
    if since is not None:
        q = q.where(LearningEvent.occurred_at >= since)
    out: dict[UUID | None, dict[str, int]] = {}
    for course_id, kind, count in db.execute(q).all():
        out.setdefault(course_id, {})[kind] = int(count)
    return out

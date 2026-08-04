"""Subtopic reading progress — the single writer for ``subtopic_reads``.

Owns one question: which subtopics of a chapter has this learner finished?
That answer gates the chapter's activity links, so it has to survive a change
of device. It previously lived in ``window.localStorage``, which meant a
learner who moved from phone to laptop, or cleared site data, found the tests
re-locked with nothing on the server to show they had done the work.

Completion is append-only and idempotent: marking the same subtopic twice is a
no-op, and there is no un-complete path (the migration grants no DELETE).
Routes stay thin — entitlement checks belong to the caller.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.reading import SubtopicRead


def completed_slugs(db: Session, *, tenant_id: UUID, person_id: UUID, chapter_id: UUID) -> set[str]:
    """Subtopic slugs this learner has completed in this chapter."""
    return set(
        db.scalars(
            select(SubtopicRead.subtopic_slug)
            .where(SubtopicRead.tenant_id == tenant_id)
            .where(SubtopicRead.person_id == person_id)
            .where(SubtopicRead.chapter_id == chapter_id)
        ).all()
    )


def completed_slugs_by_chapter(
    db: Session, *, tenant_id: UUID, person_id: UUID, chapter_ids: list[UUID]
) -> dict[UUID, set[str]]:
    """The same, for many chapters in one query — the sidebar renders them all."""
    if not chapter_ids:
        return {}
    out: dict[UUID, set[str]] = {}
    for chapter_id, slug in db.execute(
        select(SubtopicRead.chapter_id, SubtopicRead.subtopic_slug)
        .where(SubtopicRead.tenant_id == tenant_id)
        .where(SubtopicRead.person_id == person_id)
        .where(SubtopicRead.chapter_id.in_(chapter_ids))
    ).all():
        out.setdefault(chapter_id, set()).add(slug)
    return out


def mark_complete(
    db: Session, *, tenant_id: UUID, person_id: UUID, chapter_id: UUID, subtopic_slug: str
) -> bool:
    """Record a completed subtopic. Returns True when this call created the row.

    Idempotent by the unique constraint rather than a read-then-write, so two
    concurrent requests from the same learner cannot race into a duplicate.
    """
    slug = (subtopic_slug or "").strip()[:64]
    if not slug:
        return False
    inserted = db.execute(
        insert(SubtopicRead)
        .values(tenant_id=tenant_id, person_id=person_id, chapter_id=chapter_id, subtopic_slug=slug)
        .on_conflict_do_nothing(constraint="uq_subtopic_reads_person_subtopic")
        .returning(SubtopicRead.id)
    ).first()
    db.flush()
    return inserted is not None

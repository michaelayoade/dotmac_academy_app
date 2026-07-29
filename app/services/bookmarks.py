"""Bookmarks & personal notes service — the single writer for both tables.

Routes stay thin: they resolve course/chapter and delegate here. Entitlement
checks belong to the caller (the web layer uses ``require_course_access`` for
chapter-scoped actions and ``visible_course_ids`` for listings).
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.bookmark import ChapterBookmark, ChapterNote
from app.models.course import Chapter, Course
from app.services.entitlements import visible_course_ids


def get_state(db: Session, *, tenant_id: UUID, person_id: UUID, chapter_id: UUID) -> dict:
    """The learner's bookmark/note state for one chapter."""
    bookmark = db.scalars(
        select(ChapterBookmark)
        .where(ChapterBookmark.tenant_id == tenant_id)
        .where(ChapterBookmark.person_id == person_id)
        .where(ChapterBookmark.chapter_id == chapter_id)
    ).first()
    note = db.scalars(
        select(ChapterNote)
        .where(ChapterNote.tenant_id == tenant_id)
        .where(ChapterNote.person_id == person_id)
        .where(ChapterNote.chapter_id == chapter_id)
    ).first()
    return {"bookmarked": bookmark is not None, "note": note}


def toggle_bookmark(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID, chapter_id: UUID
) -> bool:
    """Flip the bookmark; returns the new state (True = bookmarked)."""
    existing = db.scalars(
        select(ChapterBookmark)
        .where(ChapterBookmark.tenant_id == tenant_id)
        .where(ChapterBookmark.person_id == person_id)
        .where(ChapterBookmark.chapter_id == chapter_id)
    ).first()
    if existing is not None:
        db.delete(existing)
        db.flush()
        return False
    db.add(
        ChapterBookmark(
            tenant_id=tenant_id, person_id=person_id,
            course_id=course_id, chapter_id=chapter_id,
        )
    )
    db.flush()
    return True


def save_note(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID,
    chapter_id: UUID, body: str,
) -> ChapterNote | None:
    """Create/update the learner's note; an emptied body deletes it."""
    body = (body or "").strip()
    note = db.scalars(
        select(ChapterNote)
        .where(ChapterNote.tenant_id == tenant_id)
        .where(ChapterNote.person_id == person_id)
        .where(ChapterNote.chapter_id == chapter_id)
    ).first()
    if not body:
        if note is not None:
            db.delete(note)
            db.flush()
        return None
    if note is None:
        note = ChapterNote(
            tenant_id=tenant_id, person_id=person_id,
            course_id=course_id, chapter_id=chapter_id, body=body,
        )
        db.add(note)
    else:
        note.body = body
    db.flush()
    return note


def list_for_person(db: Session, *, tenant_id: UUID, person_id: UUID) -> list[dict]:
    """Bookmarked chapters and notes grouped by course, entitled courses only."""
    course_ids = visible_course_ids(db, tenant_id=tenant_id, person_id=person_id)
    if not course_ids:
        return []

    bookmarks = db.execute(
        select(ChapterBookmark, Chapter)
        .join(Chapter, (Chapter.id == ChapterBookmark.chapter_id)
              & (Chapter.tenant_id == ChapterBookmark.tenant_id))
        .where(ChapterBookmark.tenant_id == tenant_id)
        .where(ChapterBookmark.person_id == person_id)
        .where(ChapterBookmark.course_id.in_(course_ids))
    ).all()
    notes = db.execute(
        select(ChapterNote, Chapter)
        .join(Chapter, (Chapter.id == ChapterNote.chapter_id)
              & (Chapter.tenant_id == ChapterNote.tenant_id))
        .where(ChapterNote.tenant_id == tenant_id)
        .where(ChapterNote.person_id == person_id)
        .where(ChapterNote.course_id.in_(course_ids))
    ).all()

    by_course: dict[UUID, dict] = {}
    for bm, chapter in bookmarks:
        entry = by_course.setdefault(bm.course_id, {})
        ch = entry.setdefault(chapter.number, {"chapter": chapter, "bookmarked": False, "note": None})
        ch["bookmarked"] = True
    for note, chapter in notes:
        entry = by_course.setdefault(note.course_id, {})
        ch = entry.setdefault(chapter.number, {"chapter": chapter, "bookmarked": False, "note": None})
        ch["note"] = note

    if not by_course:
        return []
    courses = {
        c.id: c
        for c in db.scalars(
            select(Course).where(Course.tenant_id == tenant_id)
            .where(Course.id.in_(by_course.keys()))
        ).all()
    }
    groups: list[dict] = []
    for course in sorted(courses.values(), key=lambda c: c.title):
        chapters = by_course.get(course.id)
        if not chapters:
            continue
        groups.append({
            "course": course,
            "chapters": [chapters[n] for n in sorted(chapters)],
        })
    return groups

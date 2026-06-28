"""Content search service — scoped to accessible courses or all tenant courses for staff."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.course import Chapter, Course
from app.services.entitlements import accessible_course_ids

_CAP = 20


def search(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    q: str,
    is_staff: bool,
) -> dict:
    if not q or not q.strip():
        return {"courses": [], "chapters": []}

    pattern = f"%{q.strip()}%"

    if is_staff:
        allowed_ids: set[UUID] | None = None
    else:
        allowed_ids = accessible_course_ids(db, tenant_id=tenant_id, person_id=person_id)
        if not allowed_ids:
            return {"courses": [], "chapters": []}

    course_q = (
        select(Course)
        .where(Course.tenant_id == tenant_id)
        .where(Course.title.ilike(pattern))
    )
    if allowed_ids is not None:
        course_q = course_q.where(Course.id.in_(allowed_ids))
    course_rows = db.scalars(course_q.limit(_CAP)).all()
    courses = [{"slug": c.slug, "title": c.title} for c in course_rows]

    chapter_q = (
        select(Chapter, Course.slug)
        .join(Course, (Course.id == Chapter.course_id) & (Course.tenant_id == Chapter.tenant_id))
        .where(Chapter.tenant_id == tenant_id)
        .where(or_(Chapter.title.ilike(pattern), Chapter.body_html.ilike(pattern)))
    )
    if allowed_ids is not None:
        chapter_q = chapter_q.where(Chapter.course_id.in_(allowed_ids))
    chapter_rows = db.execute(chapter_q.limit(_CAP)).all()

    chapters = []
    for chap, course_slug in chapter_rows:
        snippet = _extract_snippet(chap.body_html, q.strip())
        chapters.append({
            "title": chap.title,
            "course_slug": course_slug,
            "chapter_number": chap.number,
            "snippet": snippet,
        })

    return {"courses": courses, "chapters": chapters}


def _extract_snippet(html: str, term: str, radius: int = 100) -> str:
    """Return a short plain-text snippet around the first occurrence of term."""
    import re
    plain = re.sub(r"<[^>]+>", " ", html)
    plain = re.sub(r"\s+", " ", plain).strip()
    lower = plain.lower()
    idx = lower.find(term.lower())
    if idx == -1:
        return plain[:radius * 2]
    start = max(0, idx - radius)
    end = min(len(plain), idx + len(term) + radius)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(plain) else ""
    return prefix + plain[start:end] + suffix

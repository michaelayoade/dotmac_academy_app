# app/services/authoring.py
"""In-app course authoring (Slice 5c, finding #8).

Lets instructors create draft courses and author chapters in markdown without a
filesystem import. Markdown is rendered to HTML on save (the same renderer the
import pipeline uses); the markdown source is retained in ``Chapter.body_md`` so
it stays editable. Each chapter save bumps ``Course.version``.
"""

from __future__ import annotations

from uuid import UUID

import markdown as md
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.course import Chapter, Course
from app.services.exceptions import ConflictError, NotFoundError

_MD_EXTENSIONS = ["tables", "fenced_code"]


def render_markdown(body_md: str) -> str:
    return md.markdown(body_md or "", extensions=_MD_EXTENSIONS)


def create_course(db: Session, *, tenant_id: UUID, slug: str, title: str,
                  discipline: str) -> Course:
    """Create a new draft course. Raises ConflictError if the slug is taken."""
    slug = (slug or "").strip().lower()
    existing = db.scalars(
        select(Course).where(Course.tenant_id == tenant_id).where(Course.slug == slug)
    ).first()
    if existing is not None:
        raise ConflictError(f"a course with slug {slug!r} already exists")
    course = Course(tenant_id=tenant_id, slug=slug, title=title, discipline=discipline,
                    source_ref="in-app", version=1, status="draft")
    db.add(course)
    db.flush()
    return course


def upsert_chapter(db: Session, *, tenant_id: UUID, course_id: UUID, number: int,
                   title: str, body_md: str, part: str = "") -> Chapter:
    """Create or update a chapter from markdown, rendering HTML and bumping the
    course content version."""
    course = db.scalars(
        select(Course).where(Course.tenant_id == tenant_id).where(Course.id == course_id)
    ).first()
    if course is None:
        raise NotFoundError("course not found for tenant")

    body_html = render_markdown(body_md)
    chapter = db.scalars(
        select(Chapter)
        .where(Chapter.tenant_id == tenant_id)
        .where(Chapter.course_id == course_id)
        .where(Chapter.number == number)
    ).first()
    if chapter is None:
        chapter = Chapter(tenant_id=tenant_id, course_id=course_id, number=number,
                          title=title, part=part, body_md=body_md, body_html=body_html,
                          order_index=number)
        db.add(chapter)
    else:
        chapter.title = title
        chapter.part = part
        chapter.body_md = body_md
        chapter.body_html = body_html
    course.version += 1
    db.flush()
    return chapter

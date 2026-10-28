"""Reading-completion tracking: a learner marking a chapter, or one of its
subtopics, as read.

Subtopic progress was previously held in ``window.localStorage``, which made it
per-browser: switching device or clearing site data silently discarded it and
re-locked the chapter's activities, with no server-side record that the learner
had done the work. It is durable, per-person state and belongs here.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class ChapterRead(Base, TimestampMixin):
    __tablename__ = "chapter_reads"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "person_id", "chapter_id",
            name="uq_chapter_reads_person_chapter",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    chapter_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("chapters.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )


class SubtopicRead(Base, TimestampMixin):
    """One completed subtopic within a chapter, for one learner.

    ``subtopic_slug`` is the slug ``learn._chapter_subtopics`` derives from the
    chapter's headings. It is content-derived rather than a foreign key, so an
    edited heading orphans its row instead of breaking: the learner sees that
    subtopic as incomplete again, which is the honest outcome when the material
    has changed under them.
    """

    __tablename__ = "subtopic_reads"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "person_id", "chapter_id", "subtopic_slug",
            name="uq_subtopic_reads_person_subtopic",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    chapter_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("chapters.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Matches the 64-char cap in ``learn._slugify_heading``.
    subtopic_slug: Mapped[str] = mapped_column(String(64), nullable=False)

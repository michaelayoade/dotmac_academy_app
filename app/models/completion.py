from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, ForeignKeyConstraint, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class CourseCompletion(Base, TimestampMixin):
    """A learner's completion state for a course.

    ``pct`` is the fraction of the course's activities with a passing best score.
    ``status`` flips to ``completed`` (and stamps ``completed_at`` once) when pct
    reaches 1.0. Recomputed whenever a score is written for the person/course.
    """

    __tablename__ = "course_completions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_course_completions_tenant_id_id"),
        UniqueConstraint("tenant_id", "person_id", "course_id",
                         name="uq_course_completions_person_course"),
        # course_id is FK-constrained (referential integrity + cascade on course
        # delete). person_id is intentionally FK-less, matching the existing
        # submissions/scores ledger convention.
        ForeignKeyConstraint(["tenant_id", "course_id"], ["courses.tenant_id", "courses.id"],
                             ondelete="CASCADE", name="fk_course_completions_tenant_course"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="in_progress")
    pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

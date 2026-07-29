"""Canonical learning-event ledger (roadmap P3, item 18).

``LearningEvent`` records meaningful learning observations, append-only:
``app.services.learning_events.record`` is the SOLE writer, there are no
update or delete paths, and the migration grants only SELECT + INSERT so the
append-only rule holds at the database as well as the code layer. Analytics
(learner and instructor) are read-only projections of this table;
consequences (reminders, the future Success Queue) stay with their owning
services and only ever *read* the ledger.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, ForeignKeyConstraint, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk

# The complete, closed set of event kinds. ``session_attended`` is defined now
# but dormant until roadmap P4 (attendance) introduces its emitter.
KIND_COURSE_VIEWED = "course_viewed"
KIND_CHAPTER_VIEWED = "chapter_viewed"
KIND_CHAPTER_COMPLETED = "chapter_completed"
KIND_ACTIVITY_STARTED = "activity_started"
KIND_SUBMISSION_MADE = "submission_made"
KIND_WORK_GRADED = "work_graded"
KIND_LAB_LAUNCHED = "lab_launched"
KIND_LAB_CHECK_PASSED = "lab_check_passed"
KIND_LAB_CHECK_FAILED = "lab_check_failed"
KIND_SESSION_ATTENDED = "session_attended"
KIND_CERTIFICATE_EARNED = "certificate_earned"

EVENT_KINDS: tuple[str, ...] = (
    KIND_COURSE_VIEWED,
    KIND_CHAPTER_VIEWED,
    KIND_CHAPTER_COMPLETED,
    KIND_ACTIVITY_STARTED,
    KIND_SUBMISSION_MADE,
    KIND_WORK_GRADED,
    KIND_LAB_LAUNCHED,
    KIND_LAB_CHECK_PASSED,
    KIND_LAB_CHECK_FAILED,
    KIND_SESSION_ATTENDED,
    KIND_CERTIFICATE_EARNED,
)


class LearningEvent(Base, TimestampMixin):
    __tablename__ = "learning_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_learning_events_tenant_person",
        ),
        Index("ix_learning_events_person_time", "tenant_id", "person_id", "occurred_at"),
        Index("ix_learning_events_course_kind", "tenant_id", "course_id", "kind"),
        Index("ix_learning_events_kind_time", "tenant_id", "kind", "occurred_at"),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    course_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    # The event's primary subject (chapter, activity, submission, session or
    # course id depending on kind); extra facts go in ``detail``.
    subject_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

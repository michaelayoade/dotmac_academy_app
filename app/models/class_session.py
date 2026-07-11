"""Scheduled class sessions — the timetable for live/blended cohorts.

A ``ClassSession`` is a point in a cohort's timetable: a live class, a scheduled
lab session, or a lecture, with a start/end time and (optionally) an instructor,
a room, and a join URL. Self-paced cohorts simply have none.

Sessions feed the shared agenda (``app/services/agenda.py``), so the existing
email digest + in-app notifications remind both students and the assigned
instructor of what's coming up — no separate reminder channel needed.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk

# live_class | lab | lecture | other
SESSION_TYPES = ("live_class", "lab", "lecture", "other")
# scheduled | cancelled | completed
SESSION_STATUSES = ("scheduled", "cancelled", "completed")


class ClassSession(Base, TimestampMixin):
    __tablename__ = "class_sessions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_class_sessions_tenant_id_id"),
        # tenant-consistent composite FK to the owning cohort
        ForeignKeyConstraint(
            ["tenant_id", "cohort_id"],
            ["cohorts.tenant_id", "cohorts.id"],
            ondelete="CASCADE",
            name="fk_class_sessions_tenant_cohort",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cohort_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    # Optional link to a specific course run; NULL = a cohort-wide session
    # (orientation, review) not tied to one course.
    offering_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

    session_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="live_class")
    title: Mapped[str] = mapped_column(String(200), nullable=False)

    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # The person teaching/running it (a role_in_cohort='instructor' enrollment).
    instructor_person_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    location: Mapped[str | None] = mapped_column(String(160), nullable=True)  # room / venue
    join_url: Mapped[str | None] = mapped_column(String(500), nullable=True)  # virtual link
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="scheduled")

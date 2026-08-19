"""Learner-initiated access exceptions for locked course enrollment.

A learner can open a request for admin review when a course is locked due to:
- missing prerequisite completion
- track sequence order

If an admin approves the request, this creates a deterministic entitlement
override used by learner access checks.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, ForeignKeyConstraint, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


REQUEST_STATUS_PENDING = "pending"
REQUEST_STATUS_APPROVED = "approved"
REQUEST_STATUS_DENIED = "denied"
REQUEST_STATUS_CANCELLED = "cancelled"

REQUEST_STATUSES = (
    REQUEST_STATUS_PENDING,
    REQUEST_STATUS_APPROVED,
    REQUEST_STATUS_DENIED,
    REQUEST_STATUS_CANCELLED,
)


class CourseAccessRequest(Base, TimestampMixin):
    """Request by a learner for admin approval to remove one lock for a course."""

    __tablename__ = "course_access_requests"
    __table_args__ = (
        UniqueConstraint("tenant_id", "person_id", "course_id", name="uq_course_access_requests_tenant_person_course"),
        ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_course_access_requests_tenant_person",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "course_id"],
            ["courses.tenant_id", "courses.id"],
            ondelete="CASCADE",
            name="fk_course_access_requests_tenant_course",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "reviewed_by_person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="SET NULL",
            name="fk_course_access_requests_tenant_reviewer",
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
    course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=REQUEST_STATUS_PENDING)
    requested_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_by_person_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, ForeignKeyConstraint, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class CourseOffering(Base, TimestampMixin):
    """Explicit link: a Cohort studies a Course.

    Replaces discipline-string matching as the entitlement source. A person can
    access a course iff an active Enrollment ties them to a Cohort that has an
    active CourseOffering for that course. Slice 2 adds scheduling columns here.
    """

    __tablename__ = "course_offerings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_course_offerings_tenant_id_id"),
        UniqueConstraint("tenant_id", "cohort_id", "course_id",
                         name="uq_course_offerings_cohort_course"),
        ForeignKeyConstraint(["tenant_id", "cohort_id"], ["cohorts.tenant_id", "cohorts.id"],
                             ondelete="CASCADE", name="fk_course_offerings_tenant_cohort"),
        ForeignKeyConstraint(["tenant_id", "course_id"], ["courses.tenant_id", "courses.id"],
                             ondelete="CASCADE", name="fk_course_offerings_tenant_course"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    cohort_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")

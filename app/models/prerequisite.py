from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, ForeignKeyConstraint, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class CoursePrerequisite(Base, TimestampMixin):
    """``course_id`` requires ``requires_course_id`` to be completed first."""

    __tablename__ = "course_prerequisites"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_course_prerequisites_tenant_id_id"),
        UniqueConstraint("tenant_id", "course_id", "requires_course_id",
                         name="uq_course_prerequisites_pair"),
        ForeignKeyConstraint(["tenant_id", "course_id"], ["courses.tenant_id", "courses.id"],
                             ondelete="CASCADE", name="fk_course_prerequisites_tenant_course"),
        ForeignKeyConstraint(["tenant_id", "requires_course_id"],
                             ["courses.tenant_id", "courses.id"],
                             ondelete="CASCADE", name="fk_course_prerequisites_tenant_requires"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    requires_course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)

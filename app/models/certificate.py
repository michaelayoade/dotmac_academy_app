from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, ForeignKeyConstraint, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class Certificate(Base, TimestampMixin):
    """A credential issued when a learner completes a course.

    One per (person, course). ``serial`` is a tenant-unique, human-readable code
    printed on the PDF for verification.
    """

    __tablename__ = "certificates"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_certificates_tenant_id_id"),
        UniqueConstraint("tenant_id", "person_id", "course_id",
                         name="uq_certificates_person_course"),
        UniqueConstraint("tenant_id", "serial", name="uq_certificates_tenant_serial"),
        # course_id FK-constrained; person_id FK-less (matches submissions/scores).
        ForeignKeyConstraint(["tenant_id", "course_id"], ["courses.tenant_id", "courses.id"],
                             ondelete="CASCADE", name="fk_certificates_tenant_course"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    serial: Mapped[str] = mapped_column(String(32), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

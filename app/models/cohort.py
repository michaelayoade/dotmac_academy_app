from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, ForeignKeyConstraint, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class Cohort(Base, TimestampMixin):
    __tablename__ = "cohorts"
    __table_args__ = (UniqueConstraint("tenant_id", "id", name="uq_cohorts_tenant_id_id"),)
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    discipline: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")


class Enrollment(Base, TimestampMixin):
    __tablename__ = "enrollments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "cohort_id", "person_id", name="uq_enrollments_member"),
        ForeignKeyConstraint(["tenant_id", "cohort_id"], ["cohorts.tenant_id", "cohorts.id"],
                             ondelete="CASCADE", name="fk_enrollments_tenant_cohort"),
        ForeignKeyConstraint(["tenant_id", "person_id"], ["people.tenant_id", "people.id"],
                             ondelete="CASCADE", name="fk_enrollments_tenant_person"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    cohort_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    role_in_cohort: Mapped[str] = mapped_column(String(20), nullable=False, default="student")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")

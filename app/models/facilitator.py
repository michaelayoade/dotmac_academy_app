"""Durable facilitator nominations and their completion requirements."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class FacilitatorNomination(Base, TimestampMixin):
    """One course- or cohort-scoped nomination and assignment lifecycle."""

    __tablename__ = "facilitator_nominations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_facilitator_nominations_tenant_id_id"),
        ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_facilitator_nominations_person",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "nominated_by_person_id"],
            ["people.tenant_id", "people.id"],
            name="fk_facilitator_nominations_nominator",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "cohort_id"],
            ["cohorts.tenant_id", "cohorts.id"],
            ondelete="CASCADE",
            name="fk_facilitator_nominations_cohort",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "offering_id"],
            ["course_offerings.tenant_id", "course_offerings.id"],
            ondelete="CASCADE",
            name="fk_facilitator_nominations_offering",
        ),
        CheckConstraint("scope_type IN ('course', 'cohort')", name="ck_facilitator_nominations_scope"),
        CheckConstraint("status IN ('pending', 'active', 'revoked')", name="ck_facilitator_nominations_status"),
        CheckConstraint(
            "(scope_type = 'cohort' AND cohort_id IS NOT NULL AND offering_id IS NULL) OR "
            "(scope_type = 'course' AND cohort_id IS NULL AND offering_id IS NOT NULL)",
            name="ck_facilitator_nominations_target",
        ),
        Index(
            "uq_facilitator_nominations_cohort_scope",
            "tenant_id",
            "person_id",
            "cohort_id",
            unique=True,
            postgresql_where=text("scope_type = 'cohort'"),
        ),
        Index(
            "uq_facilitator_nominations_course_scope",
            "tenant_id",
            "person_id",
            "offering_id",
            unique=True,
            postgresql_where=text("scope_type = 'course'"),
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    nominated_by_person_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)
    cohort_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True, index=True)
    offering_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activation_reason: Mapped[str | None] = mapped_column(String(40), nullable=True)


class FacilitatorRequirement(Base, TimestampMixin):
    """A course completion snapshotted when a nomination is created."""

    __tablename__ = "facilitator_requirements"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_facilitator_requirements_tenant_id_id"),
        UniqueConstraint(
            "tenant_id", "nomination_id", "course_id", name="uq_facilitator_requirements_nomination_course"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "nomination_id"],
            ["facilitator_nominations.tenant_id", "facilitator_nominations.id"],
            ondelete="CASCADE",
            name="fk_facilitator_requirements_nomination",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "course_id"],
            ["courses.tenant_id", "courses.id"],
            name="fk_facilitator_requirements_course",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    nomination_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)

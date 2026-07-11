"""Admissions — prospective students applying to the academy.

An ``Applicant`` moves through a status pipeline before becoming an enrolled
learner (``Person`` + ``Enrollment``). It is the student equivalent of the ERP
ATS: applications previously landed in the ERP job-applicant table (the
"Fiber Academy" opening); this module lets them land in the academy directly.

Tenant-scoped and RLS-isolated like every other table.
"""

from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk

# Pipeline: applied -> screened -> accepted -> onboarding -> enrolled,
# with rejected / waitlisted as off-ramps. Allowed transitions are enforced
# in app/services/admissions.py (no Postgres enum — repo convention is a
# String column validated in the service layer).
APPLICANT_STATUSES = (
    "applied",
    "screened",
    "accepted",
    "onboarding",
    "enrolled",
    "rejected",
    "waitlisted",
)


class Applicant(Base, TimestampMixin):
    __tablename__ = "applicants"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_applicants_tenant_email"),
        # Parallels the other tables' (tenant_id, id) unique so future children
        # can reference an applicant via a tenant-consistent composite FK.
        UniqueConstraint("tenant_id", "id", name="uq_applicants_tenant_id_id"),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(String(254), nullable=False)
    first_name: Mapped[str] = mapped_column(String(80), nullable=False)
    last_name: Mapped[str] = mapped_column(String(80), nullable=False)
    phone: Mapped[str | None] = mapped_column(String(40), nullable=True)

    # What they applied for (e.g. "Fiber Academy"); free text for now.
    program: Mapped[str | None] = mapped_column(String(120), nullable=True)

    # applied|screened|accepted|onboarding|enrolled|rejected|waitlisted
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="applied")
    # website|erp_backfill — provenance of the application.
    source: Mapped[str] = mapped_column(String(30), nullable=False, server_default="website")
    # ERP JobApplicant id when imported by the backfill (idempotency/provenance).
    external_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Free-text screening / classification notes.
    notes: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    # The date the application was made (may predate row creation on backfill).
    applied_on: Mapped[date] = mapped_column(
        Date, nullable=False, server_default=func.current_date()
    )

    # Set when the applicant is converted to an enrolled learner (P2).
    person_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

    # Which cohort/intake they applied to (FK-less, matching the person_id convention).
    cohort_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

    # Entrance-assessment result — a competency profile, stored once taken:
    #   assessment_score   overall fraction 0..1
    #   assessment_level   band (see entrance_exam.LEVELS)
    #   assessment_profile per-category fractions, e.g. {"numeracy": 0.8, "safety": 0.9}
    assessment_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    assessment_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    assessment_profile: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    assessment_taken_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # HMAC of the self-serve entrance-exam access token (the raw is emailed once).
    assessment_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Timed sitting: stamped when the exam is first opened; flagged if a submit
    # arrives past the cohort's time limit (+grace).
    assessment_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assessment_time_exceeded: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, ForeignKeyConstraint, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk

# Reason kinds — deterministic rules owned by services.success_queue.
REASON_INACTIVITY = "inactivity"
REASON_OVERDUE_WORK = "overdue_work"
REASON_BELOW_PASSING = "below_passing"
REASON_FAILED_FINAL = "failed_final"
REASON_CERTIFICATE_BLOCKED = "certificate_blocked"
REASON_KINDS = (
    REASON_INACTIVITY,
    REASON_OVERDUE_WORK,
    REASON_BELOW_PASSING,
    REASON_FAILED_FINAL,
    REASON_CERTIFICATE_BLOCKED,
)

STATUS_OPEN = "open"
STATUS_ACKNOWLEDGED = "acknowledged"
STATUS_RESOLVED = "resolved"


class SuccessQueueEntry(Base, TimestampMixin):
    """One explainable intervention item (roadmap P3b, item 21).

    Replaces the boolean at-risk flag: every entry names its rule
    (``reason_kind``), carries the exact numbers that fired it
    (``supporting_facts``), and moves through open → acknowledged → resolved
    under instructor control. The detection sweep never duplicates an open
    entry — it refreshes facts and ``detected_at`` in place.
    """

    __tablename__ = "success_queue_entries"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_success_queue_tenant_id_id"),
        ForeignKeyConstraint(["tenant_id", "person_id"], ["people.tenant_id", "people.id"],
                             ondelete="CASCADE", name="fk_success_queue_tenant_person"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    cohort_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True, index=True)
    reason_kind: Mapped[str] = mapped_column(String(30), nullable=False)
    supporting_facts: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    # Freshness weight for ordering; refreshed by every sweep that re-confirms the rule.
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assigned_to: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(15), nullable=False, default=STATUS_OPEN, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    # Kept for ordering heuristics; not a decision input.
    score_hint: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

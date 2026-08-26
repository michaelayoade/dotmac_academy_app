"""Durable Academy-side execution evidence for managed account lifecycle.

Integrator owns cross-system commands and receipts.  This row is narrower: it
is the Academy owner's immutable PLAN plus the local APPLY result that makes a
retry safe and lets OBSERVE/CANCEL identify the exact product operation without
accepting a caller-supplied target again.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, ForeignKeyConstraint, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class ManagedApplicationLifecycleOperation(Base, TimestampMixin):
    __tablename__ = "managed_application_lifecycle_operations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_managed_application_lifecycle_tenant_idempotency",
        ),
        UniqueConstraint(
            "tenant_id",
            "id",
            name="uq_managed_application_lifecycle_tenant_id",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="RESTRICT",
            name="fk_managed_application_lifecycle_tenant_person",
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
    idempotency_key: Mapped[str] = mapped_column(String(120), nullable=False)
    target: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    target_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    expected_state: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    expected_state_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    desired_state: Mapped[str] = mapped_column(String(20), nullable=False)
    operation_state: Mapped[str] = mapped_column(String(20), nullable=False, default="planned")
    result_state: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    result_state_digest: Mapped[str | None] = mapped_column(String(71), nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


__all__ = ["ManagedApplicationLifecycleOperation"]

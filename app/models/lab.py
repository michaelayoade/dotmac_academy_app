from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


def _tenant_fk():
    return mapped_column(PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"),
                         nullable=False, index=True)


class LabTemplate(Base, TimestampMixin):
    __tablename__ = "lab_templates"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_lab_templates_tenant_id_id"),
        UniqueConstraint("activity_id", name="uq_lab_templates_activity_id"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = _tenant_fk()
    course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    chapter_number: Mapped[int | None] = mapped_column(Integer)
    activity_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(63), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    topology: Mapped[str] = mapped_column(Text, nullable=False, default="")
    instructions_html: Mapped[str] = mapped_column(Text, nullable=False, default="")
    instructions_md: Mapped[str | None] = mapped_column(Text)
    checks: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    seed_spec: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    limits: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    engine: Mapped[str] = mapped_column(String(20), nullable=False, default="containerlab")
    source_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class LabInstance(Base, TimestampMixin):
    __tablename__ = "lab_instances"
    __table_args__ = (UniqueConstraint("tenant_id", "id", name="uq_lab_instances_tenant_id_id"),)
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = _tenant_fk()
    activity_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    instance_name: Mapped[str] = mapped_column(String(120), nullable=False)
    seed: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    consoles: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_active_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LabOperation(Base, TimestampMixin):
    """One requested deploy/destroy/check for a `LabInstance` — a work queue
    row, not a decision record.

    Phase 1 (schema only): nothing reads or writes this table yet. `kind` and
    `state` deliberately carry no DB CHECK constraint and `requested_by` is
    deliberately not a declared FK — both enums/ownership are still settling
    ahead of the worker that will actually consume this queue.

    The load-bearing boundary is in the migration's grants, not here: the web
    tier may INSERT (request) and SELECT (observe), but only `app_admin` may
    UPDATE a row to claim, heartbeat, or finish it — the web tier can never
    settle its own request. `uq_lab_operations_open_per_instance` backs the
    other half of the guarantee: at most one queued-or-claimed operation may
    exist per instance at a time.
    """

    __tablename__ = "lab_operations"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "instance_id"],
                             ["lab_instances.tenant_id", "lab_instances.id"],
                             ondelete="CASCADE", name="fk_lab_operations_tenant_instance"),
        Index(
            "uq_lab_operations_open_per_instance",
            "instance_id",
            unique=True,
            postgresql_where=text("state IN ('queued', 'claimed')"),
        ),
        Index("ix_lab_operations_claim", "state", "not_before", "requested_at"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = _tenant_fk()
    instance_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    requested_by: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                    server_default=func.now())
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                  server_default=func.now())
    claimed_by: Mapped[str | None] = mapped_column(String(200))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

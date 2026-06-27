from __future__ import annotations
from datetime import datetime
from uuid import UUID
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
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

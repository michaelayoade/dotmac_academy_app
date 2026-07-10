from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, ForeignKeyConstraint, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class Announcement(Base, TimestampMixin):
    __tablename__ = "announcements"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_announcements_tenant_id_id"),
        ForeignKeyConstraint(
            ["tenant_id", "cohort_id"],
            ["cohorts.tenant_id", "cohorts.id"],
            ondelete="CASCADE",
            name="fk_announcements_tenant_cohort",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "author_person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_announcements_tenant_author",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cohort_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True, index=True)
    author_person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False)
    body_html: Mapped[str] = mapped_column(Text, nullable=False)

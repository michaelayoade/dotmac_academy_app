from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, ForeignKeyConstraint, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class OfferingActivity(Base, TimestampMixin):
    """Per-offering pacing override for one activity.

    Optional. With no row, an activity follows the offering's own window. A future
    ``release_at`` hides/blocks the activity; a past ``due_at`` blocks *submission*
    (reading is still allowed). Enables "week 3 opens Monday / quiz due Friday".
    """

    __tablename__ = "offering_activities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_offering_activities_tenant_id_id"),
        UniqueConstraint("tenant_id", "offering_id", "activity_id",
                         name="uq_offering_activities_offering_activity"),
        ForeignKeyConstraint(["tenant_id", "offering_id"],
                             ["course_offerings.tenant_id", "course_offerings.id"],
                             ondelete="CASCADE", name="fk_offering_activities_tenant_offering"),
        ForeignKeyConstraint(["tenant_id", "activity_id"],
                             ["activities.tenant_id", "activities.id"],
                             ondelete="CASCADE", name="fk_offering_activities_tenant_activity"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    offering_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    activity_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    release_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

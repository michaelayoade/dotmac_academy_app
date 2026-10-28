"""NEW Academy ERP acknowledgement storage; not a historical a5 mapping.

A later genuine assembly migration must copy every legacy completion key and
raw erp_synced_at, including NULL, before committing. No writer is activated here.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from dotmac_kernel.models import Tenant
from dotmac_learning.models import CourseCompletion
from sqlalchemy import DateTime, ForeignKey, ForeignKeyConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ERPCompletionCheckpoint(Base):
    __tablename__ = "academy_erp_completion_checkpoints"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "completion_id"],
            [CourseCompletion.__table__.c.tenant_id, CourseCompletion.__table__.c.id],
            ondelete="CASCADE",
            name="fk_erp_checkpoint_tenant_completion",
        ),
    )
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(Tenant.__table__.c.id, ondelete="CASCADE"),
        primary_key=True,
    )
    completion_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    erp_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

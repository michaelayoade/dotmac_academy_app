"""Person — example tenant-scoped model.

Every tenant-scoped model follows this template:
- `tenant_id UUID NOT NULL REFERENCES tenants(id)`
- Composite uniqueness on `(tenant_id, X)` for any X that's "globally unique" per tenant
- RLS enabled in the migration that creates the table
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class Person(Base, TimestampMixin):
    __tablename__ = "people"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_people_tenant_email"),
        UniqueConstraint("tenant_id", "id", name="uq_people_tenant_id_id"),
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
    # Account lifecycle state: active | suspended (Slice 3c). Suspended accounts
    # cannot log in and existing sessions are rejected.
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default=text("'active'")
    )
    avatar_path: Mapped[str | None] = mapped_column(String(255))
    prefs: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

"""Tenant + tenant_domains models.

`Tenant` is the platform-level table — NO `tenant_id` column on it (it IS the tenant).
RLS is NOT applied to `tenants` or `tenant_domains` — those are read by the resolver
middleware before tenant context is established.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, uuid_pk


class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"

    id: Mapped[UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(63), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    domains: Mapped[list["TenantDomain"]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
    )


class TenantDomain(Base, TimestampMixin):
    """Custom-domain mapping. Subdomain on platform_root_domain works without a row here."""

    __tablename__ = "tenant_domains"
    __table_args__ = (UniqueConstraint("domain", name="uq_tenant_domains_domain"),)

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    tenant: Mapped[Tenant] = relationship(back_populates="domains")

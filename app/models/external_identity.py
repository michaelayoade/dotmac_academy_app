"""Academy-owned external login bindings.

The protocol adapter proves an issuer/subject pair.  This row is Academy's one
answer to the local question: which existing ``Person`` may that exact subject
authenticate as in this tenant?  It deliberately contains no provider claims,
roles, groups, email, entitlement, or JIT-provisioning state.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, ForeignKeyConstraint, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class ExternalIdentityBinding(Base, TimestampMixin):
    __tablename__ = "external_identity_bindings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "provider_binding",
            "issuer",
            "subject",
            name="uq_academy_external_identity_tenant_provider_subject",
        ),
        UniqueConstraint(
            "tenant_id",
            "provider_binding",
            "person_id",
            name="uq_academy_external_identity_tenant_provider_person",
        ),
        UniqueConstraint(
            "tenant_id",
            "person_id",
            "id",
            name="uq_academy_external_identity_tenant_person_id",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_academy_external_identity_tenant_person",
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
    provider_binding: Mapped[str] = mapped_column(String(80), nullable=False)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    bound_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    bound_by: Mapped[str] = mapped_column(String(120), nullable=False)
    bind_reason: Mapped[str] = mapped_column(String(500), nullable=False)
    last_authenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


__all__ = ["ExternalIdentityBinding"]

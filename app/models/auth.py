"""Tenant-scoped auth models."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, ForeignKeyConstraint, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class UserCredential(Base, TimestampMixin):
    __tablename__ = "user_credentials"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_user_credentials_tenant_email"),
        ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_user_credentials_tenant_person",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    person_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthSession(Base, TimestampMixin):
    __tablename__ = "auth_sessions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "token_hash", name="uq_auth_sessions_tenant_token_hash"),
        ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_auth_sessions_tenant_person",
        ),
        # Provenance is absent for password sessions, never unknown. RESTRICT
        # prevents a binding delete from silently converting known provenance
        # into NULL while leaving the session live. Carrying person_id prevents
        # a session from citing another person's binding in the same tenant.
        ForeignKeyConstraint(
            ["tenant_id", "person_id", "external_identity_binding_id"],
            [
                "external_identity_bindings.tenant_id",
                "external_identity_bindings.person_id",
                "external_identity_bindings.id",
            ],
            ondelete="RESTRICT",
            name="fk_auth_sessions_tenant_person_external_identity_binding",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    person_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    external_identity_binding_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

"""Account tokens: tenant-scoped single-use tokens for account flows.

Creates ``account_tokens`` backing :class:`app.models.auth.AccountToken` —
email verification / password-reset style tokens. Tenant-scoped with RLS
isolation and the same CRUD grants as the other auth tables.

Revision ID: 0010_account_tokens
Revises: 0009_course_lifecycle
Create Date: 2026-06-30
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0010_account_tokens"
down_revision = "0009_course_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "account_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "person_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "token_hash",
            name="uq_account_tokens_tenant_token_hash",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_account_tokens_tenant_person",
        ),
    )
    op.create_index("ix_account_tokens_tenant_id", "account_tokens", ["tenant_id"])
    op.create_index("ix_account_tokens_person_id", "account_tokens", ["person_id"])

    op.execute("ALTER TABLE account_tokens ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE account_tokens FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY account_tokens_tenant_isolation ON account_tokens
            USING (tenant_id = app_current_tenant_id())
            WITH CHECK (tenant_id = app_current_tenant_id());
        """
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON account_tokens TO app_user, platform_api;"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS account_tokens_tenant_isolation ON account_tokens;")
    op.drop_table("account_tokens")

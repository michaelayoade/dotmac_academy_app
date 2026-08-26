"""Academy-local external identity, session provenance and OIDC state.

Revision ID: 0055_external_identity
Revises: 0054_managed_app_lifecycle

The Academy is the one owner of these rows.  This migration does not install
the Starter kernel's Party/AuthSession schema and no foreign key crosses into
another application's database.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0055_external_identity"
down_revision = "0054_managed_app_lifecycle"
branch_labels = None
depends_on = None

_BINDINGS = "external_identity_bindings"
_SESSIONS = "auth_sessions"
_STATES = "academy_oidc_login_states"


def _tenant_rls(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"CREATE POLICY {table}_tenant_isolation ON {table} "
        "USING (tenant_id = app_current_tenant_id()) "
        "WITH CHECK (tenant_id = app_current_tenant_id());"
    )


def upgrade() -> None:
    op.create_table(
        _BINDINGS,
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("person_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_binding", sa.String(80), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("bound_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("bound_by", sa.String(120), nullable=False),
        sa.Column("bind_reason", sa.String(500), nullable=False),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_academy_external_identity_bindings"),
        sa.UniqueConstraint(
            "tenant_id",
            "provider_binding",
            "issuer",
            "subject",
            name="uq_academy_external_identity_tenant_provider_subject",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "provider_binding",
            "person_id",
            name="uq_academy_external_identity_tenant_provider_person",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "person_id",
            "id",
            name="uq_academy_external_identity_tenant_person_id",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_academy_external_identity_tenant_person",
        ),
        sa.CheckConstraint("btrim(provider_binding) <> ''", name="ck_academy_external_identity_provider"),
        sa.CheckConstraint("btrim(issuer) <> ''", name="ck_academy_external_identity_issuer"),
        sa.CheckConstraint("btrim(subject) <> ''", name="ck_academy_external_identity_subject"),
        sa.CheckConstraint("btrim(bound_by) <> ''", name="ck_academy_external_identity_bound_by"),
        sa.CheckConstraint("btrim(bind_reason) <> ''", name="ck_academy_external_identity_reason"),
    )
    op.create_index("ix_academy_external_identity_tenant", _BINDINGS, ["tenant_id"])
    op.create_index("ix_academy_external_identity_person", _BINDINGS, ["person_id"])
    _tenant_rls(_BINDINGS)
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_BINDINGS} TO app_user, platform_api;")

    op.add_column(
        _SESSIONS,
        sa.Column("external_identity_binding_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    # ON DELETE RESTRICT is deliberate: NULL means a password session, never
    # provenance that was known and later erased while the session stayed live.
    op.create_foreign_key(
        "fk_auth_sessions_tenant_person_external_identity_binding",
        _SESSIONS,
        _BINDINGS,
        ["tenant_id", "person_id", "external_identity_binding_id"],
        ["tenant_id", "person_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_auth_sessions_tenant_external_identity_binding",
        _SESSIONS,
        ["tenant_id", "external_identity_binding_id"],
        postgresql_where=sa.text("external_identity_binding_id IS NOT NULL"),
    )

    op.create_table(
        _STATES,
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("code_verifier", sa.String(128), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False),
        sa.Column("redirect_uri", sa.String(500), nullable=False),
        sa.Column("return_to", sa.String(500), nullable=False),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("provider_binding", sa.String(80), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_academy_oidc_login_states"),
        sa.UniqueConstraint(
            "tenant_id",
            "state_hash",
            name="uq_academy_oidc_login_states_tenant_state",
        ),
    )
    op.create_index(
        "ix_academy_oidc_login_states_tenant_expiry",
        _STATES,
        ["tenant_id", "expires_at"],
    )
    _tenant_rls(_STATES)
    # Atomic consume is DELETE; ceremonies are never amended.
    op.execute(f"GRANT SELECT, INSERT, DELETE ON {_STATES} TO app_user, platform_api;")


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS {_STATES}_tenant_isolation ON {_STATES};")
    op.drop_table(_STATES)
    op.drop_index("ix_auth_sessions_tenant_external_identity_binding", table_name=_SESSIONS)
    op.drop_constraint(
        "fk_auth_sessions_tenant_person_external_identity_binding",
        _SESSIONS,
        type_="foreignkey",
    )
    op.drop_column(_SESSIONS, "external_identity_binding_id")
    op.execute(f"DROP POLICY IF EXISTS {_BINDINGS}_tenant_isolation ON {_BINDINGS};")
    op.drop_table(_BINDINGS)

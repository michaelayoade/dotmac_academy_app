"""Unpublished Academy host assembly base, after genuine canonical replay.

Legacy 62 revisions remain in their relocated immutable history. This new
assembly lineage is composed with installed Kernel versions, never the old
lineage in public. No publication floor or namespace allocation is claimed.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "a001_identity_extensions"
down_revision = None
branch_labels = ("assembly",)
depends_on = "0030_credential_tenant_key"


def _credential_key_preflight() -> None:
    # A stamped version or partial/expression/nonvalid index is insufficient.
    present = op.get_bind().scalar(
        sa.text("""
        SELECT EXISTS (
          SELECT 1 FROM pg_index i
          WHERE i.indrelid=to_regclass('public.user_credentials')
            AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
            AND i.indpred IS NULL AND i.indexprs IS NULL
            AND i.indnkeyatts=2 AND i.indnatts=2
            AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
                 FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ordinality)
                 JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
                = ARRAY['tenant_id','id']::text[]
        )
    """)
    )
    if present is not True:
        raise ValueError("canonical credential tenant key prerequisite missing")


def upgrade() -> None:
    if op.get_bind().scalar(sa.text("SELECT current_user")) != "app_admin":
        raise ValueError("Academy assembly migration requires app_admin")
    _credential_key_preflight()
    op.create_table(
        "academy_account_profiles",
        sa.Column("party_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("avatar_path", sa.String(255), nullable=True),
        sa.Column("prefs", postgresql.JSONB(none_as_null=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "party_id"],
            ["public.parties.tenant_id", "public.parties.id"],
            name="fk_academy_account_tenant_party",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["party_id"],
            ["public.party_persons.party_id"],
            name="fk_academy_account_person",
            ondelete="CASCADE",
        ),
        schema="public",
    )
    op.create_table(
        "academy_credential_policies",
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False),
        sa.Column("lifecycle_version", sa.BigInteger(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "credential_id"],
            ["public.user_credentials.tenant_id", "public.user_credentials.id"],
            name="fk_academy_policy_tenant_credential",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "email", name="uq_academy_policy_tenant_email"),
        sa.CheckConstraint("lifecycle_version >= 0", name="ck_academy_policy_lifecycle_version"),
        schema="public",
    )
    for table in ("academy_account_profiles", "academy_credential_policies"):
        # Closed assembly-owned table names, fully qualified for every effect.
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {table}_tenant_isolation ON public.{table} "
            "USING (tenant_id = public.app_current_tenant_id()) "
            "WITH CHECK (tenant_id = public.app_current_tenant_id())"
        )
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO app_user, platform_api")


def downgrade() -> None:
    # Reversal with new product facts requires a separately reviewed export;
    # refusing prevents accidental policy loss from a generic Alembic command.
    raise RuntimeError("Academy identity policy reversal requires a reviewed new-facts disposition")

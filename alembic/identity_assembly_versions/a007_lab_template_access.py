"""Add `lab_templates.access` — per-node device login info for the lab owner.

An optional list (see ``app.services.lab_content.parse_access``) of documented,
disposable lab-device defaults: node, protocol, username, default password and
a short note. It is imported from ``lab.yaml`` only, never from env or secrets,
and is shown only to the owner of a live instance of the lab.

Additive and online-safe: a NOT NULL column with a constant server default
(``'[]'::jsonb``) is a metadata-only change on PostgreSQL 11+, and existing
rows read as "no access info". Neither the web role nor the lab worker needs a
new grant (both already hold table-level access to ``lab_templates``).

Revision ID: a007_lab_template_access
Revises: a006_lab_claim_lease
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "a007_lab_template_access"
down_revision = "a006_lab_claim_lease"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().scalar(sa.text("SELECT current_user")) != "app_admin":
        raise ValueError("Academy assembly migration requires app_admin")
    if op.get_bind().scalar(sa.text("""
        SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
          WHERE attrelid=pg_catalog.to_regclass('public.lab_templates')
            AND attname='access' AND NOT attisdropped)
    """)):
        raise ValueError("public.lab_templates.access already exists")
    op.add_column(
        "lab_templates",
        sa.Column(
            "access",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        schema="public",
    )



def downgrade() -> None:
    raise RuntimeError("Academy assembly reversal requires a reviewed new-facts disposition")

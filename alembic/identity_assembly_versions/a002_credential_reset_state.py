"""Explicit Academy credential recovery state after the unpublished base.

Existing policies currently have no lifecycle recovery restriction. Initializing
False preserves that behavior; it is not evidence of historical recovery proof.
The schema requires every subsequent writer to choose state explicitly.
"""

import sqlalchemy as sa

from alembic import op

revision = "a002_credential_reset_state"
down_revision = "a001_identity_extensions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Same privileged assembly migration posture as a001; no new policy knob.
    if op.get_bind().scalar(sa.text("SELECT current_user")) != "app_admin":
        raise ValueError("Academy assembly migration requires app_admin")
    op.execute("LOCK TABLE public.academy_credential_policies IN ACCESS EXCLUSIVE MODE")
    op.add_column(
        "academy_credential_policies",
        sa.Column("reset_required", sa.Boolean(), nullable=True),
        schema="public",
    )
    # This new column cannot contain accepted newer state. A rerun fails at ADD
    # COLUMN rather than overwriting a later True. Never install a default.
    op.execute("UPDATE public.academy_credential_policies SET reset_required = FALSE")
    op.alter_column(
        "academy_credential_policies",
        "reset_required",
        existing_type=sa.Boolean(),
        nullable=False,
        schema="public",
    )


def downgrade() -> None:
    raise RuntimeError("Academy credential reset state reversal requires a reviewed new-facts disposition")

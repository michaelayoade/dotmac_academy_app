"""Constrain lab instance names per tenant.

Revision ID: 0008_lab_instance_name_unique
Revises: 0007_person_profile
Create Date: 2026-06-27
"""

from __future__ import annotations

from alembic import op

revision = "0008_lab_instance_name_unique"
down_revision = "0007_person_profile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_lab_instances_tenant_instance_name",
        "lab_instances",
        ["tenant_id", "instance_name"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_lab_instances_tenant_instance_name",
        "lab_instances",
        type_="unique",
    )

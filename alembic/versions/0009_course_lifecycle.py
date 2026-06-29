"""Add course lifecycle fields.

Revision ID: 0009_course_lifecycle
Revises: 0008_lab_instance_name_unique
Create Date: 2026-06-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009_course_lifecycle"
down_revision = "0008_lab_instance_name_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE courses "
        "ADD COLUMN IF NOT EXISTS status varchar(20) NOT NULL DEFAULT 'active'"
    )
    op.execute(
        "ALTER TABLE courses "
        "ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT ''"
    )
    op.execute("ALTER TABLE courses ADD COLUMN IF NOT EXISTS finished_at timestamptz")
    op.execute("UPDATE courses SET status = 'active' WHERE status = 'published'")
    op.execute("ALTER TABLE courses ALTER COLUMN status SET DEFAULT 'active'")
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'ck_courses_status'
            ) THEN
                ALTER TABLE courses ADD CONSTRAINT ck_courses_status
                CHECK (status in ('draft', 'active', 'finished', 'archived'));
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.drop_constraint("ck_courses_status", "courses", type_="check")
    op.drop_column("courses", "finished_at")
    op.drop_column("courses", "description")
    op.drop_column("courses", "status")

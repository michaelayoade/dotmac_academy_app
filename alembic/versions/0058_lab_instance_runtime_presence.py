"""Add a worker-owned `lab_instances.runtime_presence` column.

`_capacity_available` (`app/services/lab_operations.py`) used to derive
capacity entirely from `LabInstance.status IN ("provisioning", "active",
"resetting")` — a field that ALSO carries lifecycle/UI meaning and cannot
simultaneously and correctly express "operation failed, runtime presence
uncertain" (previously overloaded onto `status="active"` conservatively) vs
"escalated for human review, but runtime might still exist" (previously
`status="error"`, NOT capacity-counted, even when it should be).

This migration adds `runtime_presence`, a worker-owned column independent of
`status`, restricted by CHECK to exactly three values: `absent` (proven
absent), `present` (observed or successfully created), `unknown` (external
mutation began, result uncertain). Application code (`app/services/
lab_operations.py`, `app/services/lab_lifecycle.py`, `app/services/
lab_jobs.py`) is responsible for the transitions; this migration only adds
the column, its constraint, and a conservative backfill.

Backfill is deliberately conservative, not accurate: `status == "reaped"`
rows become `absent` (already destroyed); every other existing status
becomes `unknown` (provenance is ambiguous for pre-cutover rows — treating
them as `unknown` keeps them capacity-counted, identical to today's
behavior for an active row, rather than silently under-counting). No
special one-time reconciliation pass is required or wanted: a backfilled
`unknown` row that never goes through another worker action may stay
`unknown` indefinitely — this is safe, not a bug — and rows converge
naturally as they cycle through real deploy/destroy/reconcile actions.

`ADD COLUMN ... server_default` in Postgres populates every existing row
with that default at add time — so the column is added with
`server_default='absent'` (populating every row `absent` first), and then a
single explicit `UPDATE` repaints every non-reaped row to `unknown`. The
CHECK constraint is added afterward: both values already present at that
point ("absent", "unknown") are within its allowed set, so there is no
NOT VALID/VALIDATE split to worry about here (unlike 0056's
`ck_lab_operations_kind`/`ck_lab_operations_state`, which retrofitted a
constraint onto a table that could already hold a value outside the new
allow-list) — this table only ever holds values this migration itself
wrote or the fixed server default, so a straightforward validated ADD
CONSTRAINT is safe and simpler.

Grants: `academy_lab_worker` already holds a table-wide `GRANT SELECT,
UPDATE ON lab_instances` from migration 0056, and `platform_api` already
holds table-wide `SELECT` — both privileges already extend automatically to
this new column with no further statement needed, since PostgreSQL table-
level grants are not scoped to the column set that existed at grant time.
`app_user`'s INSERT grant on this table, however, IS column-scoped (see
0056), so a new column is excluded from it by construction unless
explicitly added — this migration must NOT add `runtime_presence` to that
list. To make this ACL posture explicit and durably recorded at this
revision (mirroring 0056's own explicit-grant pattern) rather than relying
on an inherited, undocumented side effect of table-level grants, this
migration re-issues the exact same `lab_instances` grant statements 0056
established: `REVOKE ALL ... FROM app_user, platform_api` followed by the
same `SELECT`/column-scoped-`INSERT`/`SELECT, UPDATE` grants. `app_admin`'s
migration/offline privileges are untouched (never revoked by 0056 either).

Revision ID: 0058_lab_instance_runtime_presence
Revises: 0057_lab_instance_name_unique
"""

from __future__ import annotations

from alembic import op

revision = "0058_lab_instance_runtime_presence"
down_revision = "0057_lab_instance_name_unique"
branch_labels = None
depends_on = None

TABLE = "lab_instances"
CHECK_CONSTRAINT = "ck_lab_instances_runtime_presence"
# Exactly 0056's app_user INSERT column list for this table — runtime_presence
# is deliberately NOT included; it is worker-owned like status/consoles/error.
APP_USER_INSERT_COLUMNS = "id, tenant_id, activity_id, person_id, instance_name, seed"


def upgrade() -> None:
    op.execute(
        f"ALTER TABLE {TABLE} ADD COLUMN runtime_presence VARCHAR(16) "
        f"NOT NULL DEFAULT 'absent';"
    )
    # `ADD COLUMN ... DEFAULT` above already populated every existing row
    # (including "reaped" ones) with 'absent'. Repaint every non-reaped row
    # to 'unknown' — conservative backfill, see module docstring.
    op.execute(f"UPDATE {TABLE} SET runtime_presence = 'unknown' WHERE status != 'reaped';")  # noqa: S608
    op.execute(
        f"ALTER TABLE {TABLE} ADD CONSTRAINT {CHECK_CONSTRAINT} "
        f"CHECK (runtime_presence IN ('absent', 'present', 'unknown'));"
    )
    # Re-establish the exact grant posture 0056 established for this table —
    # see module docstring for why this is a no-op in effect but made
    # explicit and durably recorded at this revision.
    op.execute(f"REVOKE ALL PRIVILEGES ON {TABLE} FROM app_user, platform_api;")
    op.execute(f"GRANT SELECT ON {TABLE} TO app_user, platform_api;")
    op.execute(f"GRANT INSERT ({APP_USER_INSERT_COLUMNS}) ON {TABLE} TO app_user;")
    op.execute(f"GRANT SELECT, UPDATE ON {TABLE} TO academy_lab_worker;")


def downgrade() -> None:
    op.drop_constraint(CHECK_CONSTRAINT, TABLE, type_="check")
    op.execute(f"ALTER TABLE {TABLE} DROP COLUMN runtime_presence;")
    # No grant changes here: dropping the column removes any privilege
    # specific to it, and the table-level grants below are byte-for-byte the
    # same statements 0056 already established at 0057 — restating them
    # keeps this migration's downgrade self-contained without depending on
    # 0056's downgrade never having run, but changes nothing that wasn't
    # already true at 0057.
    op.execute(f"REVOKE ALL PRIVILEGES ON {TABLE} FROM app_user, platform_api;")
    op.execute(f"GRANT SELECT ON {TABLE} TO app_user, platform_api;")
    op.execute(f"GRANT INSERT ({APP_USER_INSERT_COLUMNS}) ON {TABLE} TO app_user;")
    op.execute(f"GRANT SELECT, UPDATE ON {TABLE} TO academy_lab_worker;")

"""Make lab-instance runtime state worker-owned.

Revision ID: 0056_lab_instance_worker
Revises: 0055_lab_operations
"""

from __future__ import annotations

from alembic import op

revision = "0056_lab_instance_worker"
down_revision = "0055_lab_operations"
branch_labels = None
depends_on = None

TABLE = "lab_instances"
OPERATIONS_TABLE = "lab_operations"


def upgrade() -> None:
    # Phase 1 deliberately left these enums unconstrained while the worker
    # contract was still settling. The worker now exists, so make its defensive
    # application checks a database invariant too.
    #
    # These are added NOT VALID + validated as separate statements rather than
    # a single ``op.create_check_constraint`` so the constraint is visible to
    # planners/other sessions immediately without holding the stronger lock a
    # validated add-and-check requires for the whole scan. That split only
    # matters if each half actually gets its own transaction, though: alembic's
    # env.py wraps the whole migration in one ``context.begin_transaction()``,
    # and Postgres locks are transaction-scoped, so two ``op.execute()`` calls
    # in the same migration would still hold the ADD's AccessExclusiveLock
    # through the VALIDATE scan — identical to a single validated ADD. Each
    # statement below therefore runs in its own ``autocommit_block()``, which
    # commits the ambient transaction, runs in autocommit mode, and resumes
    # afterward — this is the one place in this repo that needs it; don't
    # "simplify" it back to ``create_check_constraint`` or a plain ``execute``.
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TABLE lab_operations ADD CONSTRAINT ck_lab_operations_kind "
            "CHECK (kind IN ('deploy', 'destroy', 'check')) NOT VALID;"
        )
    with op.get_context().autocommit_block():
        op.execute("ALTER TABLE lab_operations VALIDATE CONSTRAINT ck_lab_operations_kind;")
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TABLE lab_operations ADD CONSTRAINT ck_lab_operations_state "
            "CHECK (state IN ('queued', 'claimed', 'succeeded', 'failed', 'cancelled')) "
            "NOT VALID;"
        )
    with op.get_context().autocommit_block():
        op.execute("ALTER TABLE lab_operations VALIDATE CONSTRAINT ck_lab_operations_state;")
    # The web tier may create a queued instance request and observe it. Runtime
    # state (status/consoles/error/timestamps) is written only by app_admin's
    # lab worker. platform_api has no lab-instance mutation responsibility.
    op.execute(f"REVOKE ALL PRIVILEGES ON {TABLE} FROM app_user, platform_api;")
    op.execute(f"GRANT SELECT ON {TABLE} TO app_user, platform_api;")
    op.execute(
        f"GRANT INSERT (id, tenant_id, activity_id, person_id, instance_name, seed) "
        f"ON {TABLE} TO app_user;"
    )
    # Production migrations run as app_admin (the owner); CI migrations run as
    # postgres, so spell out the worker grant for environment parity. The same
    # rationale extends to every supporting table the worker touches below:
    # ``GRANT ALL ON SCHEMA public TO app_admin`` in scripts/initdb-roles.sql is
    # a schema-level grant and does not cascade to table-level ACLs, so each
    # table app_admin must read or write in production (where it does not own
    # the schema) needs its own explicit grant here, mirroring what CI's
    # postgres superuser can already do implicitly.
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {TABLE} TO app_admin;")
    # Read-only supporting data the worker looks up while executing operations
    # (templates, effective settings, activities/people for grading and
    # notification, tenants for cross-tenant reconciliation).
    op.execute(
        "GRANT SELECT ON lab_templates, platform_settings, activities, people, tenants "
        "TO app_admin;"
    )
    # Consequences the worker writes as part of settling a check operation:
    # the graded submission/score, the learning-events ledger entry, the
    # in-app notification, and the outbound email intent.
    op.execute(
        "GRANT SELECT, INSERT ON submissions, scores, learning_events, notifications, "
        "email_outbox TO app_admin;"
    )


def downgrade() -> None:
    op.execute(f"REVOKE ALL PRIVILEGES ON {TABLE} FROM app_user, platform_api, app_admin;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {TABLE} TO app_user, platform_api;")
    # Restore app_admin's lab_instances grant to exactly what upgrade() left:
    # the REVOKE ALL above also stripped it, and the re-grant right after only
    # covered app_user/platform_api.
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {TABLE} TO app_admin;")
    # Revoke only what this migration granted app_admin on the supporting
    # tables — never REVOKE ALL, since earlier migrations may grant other
    # roles their own privileges on these same tables.
    op.execute(
        "REVOKE SELECT, INSERT ON submissions, scores, learning_events, notifications, "
        "email_outbox FROM app_admin;"
    )
    op.execute(
        "REVOKE SELECT ON lab_templates, platform_settings, activities, people, tenants "
        "FROM app_admin;"
    )
    op.drop_constraint("ck_lab_operations_state", OPERATIONS_TABLE, type_="check")
    op.drop_constraint("ck_lab_operations_kind", OPERATIONS_TABLE, type_="check")

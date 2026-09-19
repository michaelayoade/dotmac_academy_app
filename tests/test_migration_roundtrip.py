"""Migration ``0056`` durably commits before Alembic marks itself applied.

``0056_lab_instance_worker_grants.py`` wraps each of its four constraint
statements (two ``ADD CONSTRAINT ... NOT VALID``, two ``VALIDATE
CONSTRAINT``) in its own ``op.get_context().autocommit_block()`` to avoid
holding a table-wide lock for the whole validation scan. Each block commits
the database durably, and Alembic only records the revision as applied at
the very end of ``upgrade()`` — so a failure partway through leaves the
first ``ADD CONSTRAINT`` durably in place while ``alembic_version`` still
shows the previous revision. The ``ADD CONSTRAINT`` statements are guarded
by a ``pg_constraint`` existence check specifically so a rerun after that
kind of partial failure is safe.

Nothing in CI exercises either property today. This module proves both:

* ``test_0056_downgrade_upgrade_roundtrip_is_idempotent`` (D1) — two
  downgrade/upgrade cycles leave constraints, grants, and
  ``alembic_version`` exactly as they started, AND each intermediate
  downgrade to 0055 is independently asserted to have actually revoked
  ``academy_lab_worker``'s grants on every one of the ten supporting tables
  (and restored ``app_user``/``platform_api``'s prior grants on
  ``lab_instances``) — a full-cycle-only comparison can't catch a downgrade
  that fails to revoke, since the following upgrade would just silently
  re-grant everything and paper over it. Grant checks go down to the exact
  *column* set for ``app_user``'s INSERT on ``lab_operations``/
  ``lab_instances``, not just table-level ``has_table_privilege`` — that
  column list, not "no UPDATE", is the actual boundary stopping ``app_user``
  from forging worker-owned columns at row creation.
* ``test_0056_interrupted_upgrade_is_resumable`` (D2) — a simulated crash
  between the first ``ADD CONSTRAINT`` and the first ``VALIDATE CONSTRAINT``
  leaves a partial, ``alembic_version``-unbumped state that a plain,
  unmodified ``alembic upgrade`` then repairs and completes.

Both tests use Alembic's own ``Config``/``ScriptDirectory``/
``MigrationContext``/``Operations`` APIs — never a hand-rolled
reimplementation of the migration's SQL — and require a real Postgres via
``TEST_MIGRATION_DATABASE_URL``, matching the ``admin_engine`` fixture's skip
convention in ``tests/conftest.py``. They cannot be run on this workstation
(no live Postgres here); see the accompanying report for what to
double-check once CI actually executes them.
"""

from __future__ import annotations

import os
import pathlib
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import text

from alembic import command
from alembic.config import Config
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ALEMBIC_INI = REPO_ROOT / "alembic.ini"

# Fixed anchor points for this specific migration's round trip — not derived
# from "head", because the whole point is to exercise exactly the 0055/0056
# boundary regardless of what head is. These two constants are pinned to that
# boundary specifically and must NOT be read as "head" anywhere below — the
# repo head is now 0058 (see HEAD_REVISION), and the 0055/0056 and 0056/0057
# tests are updated to assert against that instead of assuming an earlier
# revision is still head.
DOWN_REVISION = "0055_lab_operations"
TARGET_REVISION = "0056_lab_instance_worker"

# The actual current repo head. Kept as its own constant (rather than reusing
# TARGET_REVISION/TARGET_REVISION_0057) specifically so the 0055/0056 and
# 0056/0057 tests below stop silently assuming an earlier revision is head
# once a later one exists.
HEAD_REVISION = "0058_lab_runtime_presence"

# 0056 <-> 0057 boundary, for the 0057-specific tests further down this file.
DOWN_REVISION_0057 = TARGET_REVISION  # "0056_lab_instance_worker"
TARGET_REVISION_0057 = "0057_lab_instance_name_unique"

# 0057 <-> 0058 boundary, for the new tests further down this file.
DOWN_REVISION_0058 = TARGET_REVISION_0057  # "0057_lab_instance_name_unique"
TARGET_REVISION_0058 = HEAD_REVISION  # "0058_lab_runtime_presence"

INSTANCE_NAME_INDEX = "uq_lab_instances_instance_name"
RUNTIME_PRESENCE_CHECK = "ck_lab_instances_runtime_presence"

WORKER_ROLE = "academy_lab_worker"

# Exactly what 0056 itself is responsible for granting/revoking on the worker
# role — used to make a strong, non-brittle assertion at the intermediate
# 0055 state, rather than every cell of _grant_snapshot()'s full matrix (most
# of which — e.g. app_user's/platform_api's privileges on the supporting
# tables — is owned by migrations 0056 never touches, and asserting fixed
# values there would couple this test to unrelated schema history).
WORKER_ONLY_SELECT_TABLES = ("lab_templates", "platform_settings", "activities", "people", "tenants")
WORKER_SELECT_INSERT_TABLES = ("submissions", "scores", "learning_events", "notifications", "email_outbox")
LAB_INSTANCES_WORKER_PRIVILEGES = ("SELECT", "UPDATE")
LAB_INSTANCES_APP_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE")

# has_table_privilege('app_user', table, 'INSERT') is True as soon as ANY
# column is granted — it cannot distinguish "narrowed to the request columns"
# from "app_user can forge every worker-owned column at row creation". These
# are the exact column sets 0055/0056 establish for that INSERT grant; see
# 0055_lab_operations.py's module docstring for why this exact column list is
# the actual security boundary, not "no UPDATE".
LAB_OPERATIONS_APP_USER_INSERT_COLUMNS = frozenset({"id", "tenant_id", "instance_id", "kind", "requested_by"})
LAB_INSTANCES_APP_USER_INSERT_COLUMNS_AT_HEAD = frozenset(
    {"id", "tenant_id", "activity_id", "person_id", "instance_name", "seed"}
)


def _migration_url() -> str:
    url = os.getenv("TEST_MIGRATION_DATABASE_URL")
    if not url:
        pytest.skip("TEST_MIGRATION_DATABASE_URL not set — migration round-trip tests skipped")
    return url


def _make_config() -> Config:
    cfg = Config(str(ALEMBIC_INI))
    # Set absolute so this works regardless of pytest's invocation cwd.
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    return cfg


@contextmanager
def _migration_env(url: str) -> Iterator[None]:
    """Point ``alembic/env.py``'s ``get_url()`` at the test database.

    ``env.py`` reads ``MIGRATION_DATABASE_URL`` (falling back to
    ``DATABASE_URL``) itself, rather than accepting a live connection through
    ``Config`` — so ``command.upgrade``/``command.downgrade`` (which run
    ``env.py`` as a script) need the env var set for the duration.
    """
    previous = os.environ.get("MIGRATION_DATABASE_URL")
    os.environ["MIGRATION_DATABASE_URL"] = url
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("MIGRATION_DATABASE_URL", None)
        else:
            os.environ["MIGRATION_DATABASE_URL"] = previous


def _head_revision(cfg: Config) -> str | None:
    return ScriptDirectory.from_config(cfg).get_current_head()


def _constraint_snapshot(conn) -> dict[str, dict[str, object]]:
    rows = conn.execute(
        text(
            """SELECT conname, pg_get_constraintdef(oid), convalidated
               FROM pg_constraint
               WHERE conrelid = 'lab_operations'::regclass
                 AND conname IN ('ck_lab_operations_kind', 'ck_lab_operations_state')"""
        )
    ).all()
    return {row[0]: {"definition": row[1], "validated": row[2]} for row in rows}


def _grant_snapshot(conn) -> dict[tuple[str, str, str], bool]:
    """``has_table_privilege`` for every (role, table, privilege) 0056 (and the
    migrations around it) govern, across every table 0056's upgrade/downgrade
    actually touches — not just ``lab_operations``/``lab_instances``. A
    downgrade that fails to revoke ``academy_lab_worker``'s grant on any one
    of the ten supporting tables would otherwise be invisible to a snapshot
    scoped to only those two tables.
    """
    rows = conn.execute(
        text(
            """SELECT r.role_name, t.table_name, p.privilege,
                      has_table_privilege(r.role_name, t.table_name, p.privilege) AS granted
               FROM unnest(ARRAY['app_user', 'platform_api', 'academy_lab_worker']) AS r(role_name)
               CROSS JOIN unnest(ARRAY['lab_instances', 'lab_operations', 'lab_templates',
                   'platform_settings', 'activities', 'people', 'tenants', 'submissions',
                   'scores', 'learning_events', 'notifications', 'email_outbox']) AS t(table_name)
               CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']) AS p(privilege)"""
        )
    ).all()
    return {(row[0], row[1], row[2]): bool(row[3]) for row in rows}


def _column_insert_grant(conn, table: str, role: str = "app_user") -> frozenset[str]:
    """Exact columns ``role`` may INSERT on ``table`` — ``has_table_privilege``
    can only see that *some* column is grantable, not which ones, and the
    whole point of 0055's column-scoped INSERT grant is which columns."""
    rows = conn.execute(
        text(
            """SELECT column_name
               FROM information_schema.column_privileges
               WHERE grantee = :role
                 AND table_schema = 'public'
                 AND table_name = :table
                 AND privilege_type = 'INSERT'"""
        ),
        {"role": role, "table": table},
    ).all()
    return frozenset(row[0] for row in rows)


def _all_columns(conn, table: str) -> frozenset[str]:
    rows = conn.execute(
        text(
            """SELECT column_name
               FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = :table"""
        ),
        {"table": table},
    ).all()
    return frozenset(row[0] for row in rows)


def _column_insert_snapshot(conn) -> dict[str, frozenset[str]]:
    return {
        "lab_operations": _column_insert_grant(conn, "lab_operations"),
        "lab_instances": _column_insert_grant(conn, "lab_instances"),
    }


def _current_version(conn) -> str | None:
    return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


def _full_snapshot(conn) -> dict[str, object]:
    return {
        "constraints": _constraint_snapshot(conn),
        "grants": _grant_snapshot(conn),
        "column_insert": _column_insert_snapshot(conn),
    }


def _assert_at_0055_grants(conn) -> None:
    """0056's own supporting-table and ``lab_instances`` grants must be fully
    revoked at 0055 — the property a full-cycle-only comparison can't catch,
    since a downgrade that fails to revoke would just get silently papered
    over by the following upgrade re-granting everything.
    """
    grants = _grant_snapshot(conn)
    for table in WORKER_ONLY_SELECT_TABLES:
        assert (
            grants[(WORKER_ROLE, table, "SELECT")] is False
        ), f"downgrade left {WORKER_ROLE} with SELECT on {table} at 0055"
    for table in WORKER_SELECT_INSERT_TABLES:
        assert (
            grants[(WORKER_ROLE, table, "SELECT")] is False
        ), f"downgrade left {WORKER_ROLE} with SELECT on {table} at 0055"
        assert (
            grants[(WORKER_ROLE, table, "INSERT")] is False
        ), f"downgrade left {WORKER_ROLE} with INSERT on {table} at 0055"
    for priv in LAB_INSTANCES_WORKER_PRIVILEGES:
        assert (
            grants[(WORKER_ROLE, "lab_instances", priv)] is False
        ), f"downgrade left {WORKER_ROLE} with {priv} on lab_instances at 0055"
    for role in ("app_user", "platform_api"):
        for priv in LAB_INSTANCES_APP_PRIVILEGES:
            assert (
                grants[(role, "lab_instances", priv)] is True
            ), f"downgrade failed to restore {role}'s {priv} on lab_instances at 0055"

    # 0055 alone establishes lab_operations' column-scoped INSERT grant, and
    # 0056 never touches it, so it must hold at 0055 exactly as at head.
    assert _column_insert_grant(conn, "lab_operations") == LAB_OPERATIONS_APP_USER_INSERT_COLUMNS, (
        "app_user's column-scoped INSERT grant on lab_operations at 0055 does "
        "not match the exact column set 0055 establishes"
    )
    # 0056's downgrade explicitly restores an unrestricted, table-wide INSERT
    # on lab_instances ("GRANT SELECT, INSERT, UPDATE, DELETE ON lab_instances
    # TO app_user, platform_api") — not the column-scoped grant 0056's upgrade
    # narrows it to. At 0055 that must mean every current column, not 0056's
    # 6-column subset.
    assert _column_insert_grant(conn, "lab_instances") == _all_columns(conn, "lab_instances"), (
        "downgrade should leave app_user with an unrestricted, table-wide "
        "INSERT on lab_instances, not a column-restricted one"
    )


def test_0056_downgrade_upgrade_roundtrip_is_idempotent(admin_engine):
    """Two downgrade/upgrade cycles across 0056 reproduce the exact starting
    state — constraints, grants, and the recorded ``alembic_version``."""
    cfg = _make_config()
    url = _migration_url()

    head = _head_revision(cfg)
    assert head == HEAD_REVISION, (
        f"expected repo head to be {HEAD_REVISION!r}, got {head!r} — a "
        "migration was added after 0057 without updating this test's fixed "
        "anchor revisions"
    )

    with admin_engine.connect() as conn:
        assert (
            _current_version(conn) == HEAD_REVISION
        ), "expected the CI database to already be migrated to head before this test runs"
        baseline = _full_snapshot(conn)
        assert baseline["column_insert"] == {
            "lab_operations": LAB_OPERATIONS_APP_USER_INSERT_COLUMNS,
            "lab_instances": LAB_INSTANCES_APP_USER_INSERT_COLUMNS_AT_HEAD,
        }, "app_user's column-scoped INSERT grants at head don't match 0055/0056's exact column lists"

    with _migration_env(url):
        try:
            # command.downgrade(cfg, DOWN_REVISION) from real head (0057)
            # downgrades through 0057 first and then 0056, landing at 0055 —
            # this test's snapshots (_full_snapshot/_assert_at_0055_grants)
            # only cover grants/check-constraints that 0057 never touches, so
            # passing through it en route doesn't affect what's asserted here.
            command.downgrade(cfg, DOWN_REVISION)
            with admin_engine.connect() as conn:
                _assert_at_0055_grants(conn)
            command.upgrade(cfg, TARGET_REVISION)
            command.downgrade(cfg, DOWN_REVISION)
            with admin_engine.connect() as conn:
                _assert_at_0055_grants(conn)
            command.upgrade(cfg, TARGET_REVISION)
        finally:
            # Regardless of outcome, leave the database at head so a failing
            # or interrupted run here doesn't poison later tests in the same
            # CI job.
            command.upgrade(cfg, "head")

    with admin_engine.connect() as conn:
        final = _full_snapshot(conn)
        final_version = _current_version(conn)

    assert final == baseline, (
        "constraint/grant state after a downgrade/upgrade round trip does not "
        "match the pre-cycle baseline — 0056 leaks or loses state across cycles"
    )
    assert final_version == HEAD_REVISION


class _SimulatedCrash(RuntimeError):
    """Raised in place of 0056's second ``op.execute()`` call.

    Stands in for a process crash/failure between the first ``ADD
    CONSTRAINT ... NOT VALID`` (already durably committed by its own
    ``autocommit_block()``) and the first ``VALIDATE CONSTRAINT``.
    """


def test_0056_interrupted_upgrade_is_resumable(admin_engine):
    """A crash after the first ``ADD CONSTRAINT`` commits, but before
    ``upgrade()`` returns, leaves a partial state that a plain, unmodified
    rerun of ``alembic upgrade`` must repair rather than hard-fail on."""
    cfg = _make_config()
    url = _migration_url()

    head = _head_revision(cfg)
    assert head == HEAD_REVISION, (
        f"expected repo head to be {HEAD_REVISION!r}, got {head!r} — a "
        "migration was added after 0057 without updating this test's fixed "
        "anchor revisions"
    )

    with admin_engine.connect() as conn:
        assert _current_version(conn) == HEAD_REVISION
        # A same-run reference: the state a normal, uninterrupted migration
        # produces, captured before this test disturbs anything.
        reference = _full_snapshot(conn)
        assert reference["column_insert"] == {
            "lab_operations": LAB_OPERATIONS_APP_USER_INSERT_COLUMNS,
            "lab_instances": LAB_INSTANCES_APP_USER_INSERT_COLUMNS_AT_HEAD,
        }, "app_user's column-scoped INSERT grants at head don't match 0055/0056's exact column lists"

    script = ScriptDirectory.from_config(cfg)
    revision_script = script.get_revision(TARGET_REVISION)
    assert revision_script is not None
    upgrade_fn = revision_script.module.upgrade

    recovered: dict[str, object] | None = None
    recovered_version: str | None = None

    with _migration_env(url):
        try:
            command.downgrade(cfg, DOWN_REVISION)
            with admin_engine.connect() as conn:
                _assert_at_0055_grants(conn)

            # --- simulate a crash between the two halves of the "kind" ------
            # constraint: op.execute() call #1 (the guarded ADD CONSTRAINT ...
            # NOT VALID) runs for real and durably commits via its own
            # autocommit_block(); call #2 (the first VALIDATE CONSTRAINT)
            # raises instead of executing, standing in for the process dying
            # right there.
            with admin_engine.connect() as conn:
                migration_context = MigrationContext.configure(connection=conn)
                original_execute = Operations.execute
                call_count = {"n": 0}

                def _fake_execute(self, sqltext, *, execution_options=None):
                    call_count["n"] += 1
                    if call_count["n"] == 2:
                        raise _SimulatedCrash("simulated crash before VALIDATE CONSTRAINT ck_lab_operations_kind")
                    return original_execute(self, sqltext, execution_options=execution_options)

                # Patch the class before installing the `alembic.op` proxy —
                # `_install_proxy()` binds `getattr(self, "execute")` once, at
                # install time, so the patch must already be in place.
                Operations.execute = _fake_execute
                ops = Operations(migration_context)
                ops._install_proxy()
                try:
                    with pytest.raises(_SimulatedCrash):
                        upgrade_fn()
                finally:
                    # Operations.context()'s own contextmanager has no
                    # try/finally around _remove_proxy(), so do it explicitly
                    # here rather than relying on that path.
                    ops._remove_proxy()
                    Operations.execute = original_execute

            with admin_engine.connect() as conn:
                partial = _constraint_snapshot(conn)
                assert "ck_lab_operations_kind" in partial, (
                    "the first ADD CONSTRAINT's autocommit_block should have "
                    "durably committed before the simulated crash"
                )
                assert (
                    partial["ck_lab_operations_kind"]["validated"] is False
                ), "the simulated crash happened before VALIDATE CONSTRAINT ran"
                assert "ck_lab_operations_state" not in partial, "the second constraint's ADD statement never ran"
                assert _current_version(conn) == DOWN_REVISION, (
                    "upgrade() never returned, so alembic must not have " "recorded 0056 as applied"
                )

            # --- recovery: the real, unmodified migration code, no patching -
            command.upgrade(cfg, TARGET_REVISION)

            with admin_engine.connect() as conn:
                recovered = _full_snapshot(conn)
                recovered_version = _current_version(conn)
        finally:
            # Regardless of outcome, leave the database at head so a failing
            # or interrupted run here doesn't poison later tests in the same
            # CI job.
            command.upgrade(cfg, "head")

    assert recovered == reference, (
        "recovering from the simulated crash did not converge on the same "
        "state a normal, uninterrupted migration produces — the existence "
        "guard did not make the rerun safe"
    )
    assert recovered_version == TARGET_REVISION


# --- 0057: global unique index on lab_instances.instance_name --------------


def _instance_name_index_snapshot(conn) -> dict[str, object] | None:
    """``None`` when ``uq_lab_instances_instance_name`` doesn't exist (0056
    state); otherwise proves it is unique and covers exactly the
    ``instance_name`` column — not more, not fewer."""
    row = conn.execute(
        text(
            """SELECT ix.indisunique, array_agg(a.attname ORDER BY k.ordinality)
               FROM pg_index ix
               JOIN pg_class i ON i.oid = ix.indexrelid
               JOIN unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ordinality) ON true
               JOIN pg_attribute a ON a.attrelid = ix.indrelid AND a.attnum = k.attnum
               WHERE i.relname = :index_name
               GROUP BY ix.indisunique"""
        ),
        {"index_name": INSTANCE_NAME_INDEX},
    ).first()
    if row is None:
        return None
    return {"unique": bool(row[0]), "columns": list(row[1])}


def _insert_tenant(conn, slug: str) -> str:
    """Raw-SQL tenant insert — this module has no ``tenant_a``/``tenant_b``
    fixture (those are ``admin_session``-scoped; this file drives Alembic
    directly against ``admin_engine`` connections instead). Self-heals a
    leftover row from an interrupted prior run the same way
    ``tests/conftest.py``'s ``_make_tenant`` does."""
    conn.execute(text("DELETE FROM tenants WHERE slug = :slug"), {"slug": slug})
    row = conn.execute(
        text(
            "INSERT INTO tenants (id, slug, name) "
            "VALUES (gen_random_uuid(), :slug, :name) RETURNING id"
        ),
        {"slug": slug, "name": slug},
    ).first()
    conn.commit()
    return str(row[0])


def _delete_tenant(conn, tenant_id: str) -> None:
    conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
    conn.commit()


def _insert_lab_instance(conn, *, instance_id: str, tenant_id: str, instance_name: str) -> None:
    conn.execute(
        text(
            "INSERT INTO lab_instances "
            "(id, tenant_id, activity_id, person_id, instance_name, seed) "
            "VALUES (:id, :tenant_id, gen_random_uuid(), gen_random_uuid(), :name, '{}'::jsonb)"
        ),
        {"id": instance_id, "tenant_id": tenant_id, "name": instance_name},
    )
    conn.commit()


def test_0057_downgrade_upgrade_roundtrip_is_idempotent(admin_engine):
    """0056 <-> 0057 round trip: the unique index on ``instance_name`` is
    added and removed cleanly across repeated cycles, mirroring the
    0055/0056 round-trip test's shape (D1 above).

    No "interrupted mid-migration" test exists for 0057 the way 0056 has one
    (D2 above): 0057 keeps duplicate-checking, index creation, and Alembic's
    version stamp all in one ordinary transaction — no ``autocommit_block()``
    — so a crash partway through cannot leave a durable half-applied state
    the way 0056's ``autocommit_block`` statements could; there is nothing
    analogous to prove resumable here.
    """
    cfg = _make_config()
    url = _migration_url()

    # Checks the actual repo head (now 0058, not 0057 — see HEAD_REVISION):
    # this test's own upgrade/downgrade calls stay pinned to the 0056/0057
    # boundary specifically via DOWN_REVISION_0057/TARGET_REVISION_0057, but
    # the sanity check that the CI database starts at head must track
    # whatever head actually is, or it would silently stop verifying anything
    # the moment a later migration (0058+) is added.
    head = _head_revision(cfg)
    assert head == HEAD_REVISION, (
        f"expected repo head to be {HEAD_REVISION!r}, got {head!r} — a "
        "migration was added without updating this test's fixed anchor "
        "revisions"
    )

    with admin_engine.connect() as conn:
        assert (
            _current_version(conn) == HEAD_REVISION
        ), "expected the CI database to already be migrated to head before this test runs"
        baseline_index = _instance_name_index_snapshot(conn)
        assert baseline_index == {"unique": True, "columns": ["instance_name"]}

    with _migration_env(url):
        try:
            command.downgrade(cfg, DOWN_REVISION_0057)
            with admin_engine.connect() as conn:
                assert _instance_name_index_snapshot(conn) is None, (
                    "downgrade must drop the unique index, not just rename it"
                )
            command.upgrade(cfg, TARGET_REVISION_0057)
            command.downgrade(cfg, DOWN_REVISION_0057)
            with admin_engine.connect() as conn:
                assert _instance_name_index_snapshot(conn) is None
            command.upgrade(cfg, TARGET_REVISION_0057)
        finally:
            # Regardless of outcome, leave the database at head so a failing
            # or interrupted run here doesn't poison later tests in the same
            # CI job.
            command.upgrade(cfg, "head")

    with admin_engine.connect() as conn:
        final_index = _instance_name_index_snapshot(conn)
        final_version = _current_version(conn)

    assert final_index == baseline_index, (
        "the unique index's shape after a downgrade/upgrade round trip does "
        "not match the pre-cycle baseline — 0057 leaks or loses state across cycles"
    )
    # The `finally` block above always ends at real head (now 0058), not at
    # the 0057 boundary this test's own round trip exercises.
    assert final_version == HEAD_REVISION


def test_0057_never_rewrites_an_existing_instance_name(admin_engine):
    """A row seeded with the OLD ``dal-<t8>-<p8>-<a8>-<n>`` name format must
    survive a 0056<->0057 downgrade/upgrade cycle with its id and
    ``instance_name`` byte-for-byte unchanged — 0057 only adds a constraint
    on future rows, it never touches existing values."""
    cfg = _make_config()
    url = _migration_url()
    legacy_name = "dal-1a2b3c4d-5e6f7a8b-9c0d1e2f-3"

    with admin_engine.connect() as conn:
        assert _current_version(conn) == HEAD_REVISION
        tenant_id = _insert_tenant(conn, "roundtrip-0057-legacy")
        instance_row = conn.execute(
            text("SELECT gen_random_uuid()")
        ).scalar()
        instance_id = str(instance_row)
        _insert_lab_instance(
            conn, instance_id=instance_id, tenant_id=tenant_id, instance_name=legacy_name
        )

    try:
        with _migration_env(url):
            try:
                command.downgrade(cfg, DOWN_REVISION_0057)
                command.upgrade(cfg, TARGET_REVISION_0057)
                command.downgrade(cfg, DOWN_REVISION_0057)
                command.upgrade(cfg, TARGET_REVISION_0057)
            finally:
                command.upgrade(cfg, "head")

        with admin_engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, instance_name FROM lab_instances WHERE id = :id"),
                {"id": instance_id},
            ).first()
            assert row is not None, "the migration cycle must not delete the pre-existing row"
            assert str(row[0]) == instance_id
            assert row[1] == legacy_name, (
                "0057 must never rewrite an existing instance_name, even the "
                "old count-derived format"
            )
    finally:
        with admin_engine.connect() as conn:
            _delete_tenant(conn, tenant_id)


def test_0057_upgrade_fails_on_existing_duplicate_names_and_leaves_no_partial_state(
    admin_engine,
):
    """At 0056, two rows sharing an ``instance_name`` (impossible to persist
    at head once 0057's index exists, hence seeding directly at 0056) must
    block the 0057 upgrade with both the duplicate name and its count named
    in the error, leave ``alembic_version`` at 0056, and leave no
    ``uq_lab_instances_instance_name`` index behind. Removing one of the two
    duplicate rows must then let the same upgrade succeed normally."""
    cfg = _make_config()
    url = _migration_url()
    dup_name = "dal-duplicate-preexisting-name"

    with admin_engine.connect() as conn:
        assert _current_version(conn) == HEAD_REVISION
        tenant_id = _insert_tenant(conn, "roundtrip-0057-dupe")

    with _migration_env(url):
        try:
            command.downgrade(cfg, DOWN_REVISION_0057)

            with admin_engine.connect() as conn:
                first_id = str(conn.execute(text("SELECT gen_random_uuid()")).scalar())
                second_id = str(conn.execute(text("SELECT gen_random_uuid()")).scalar())
                _insert_lab_instance(
                    conn, instance_id=first_id, tenant_id=tenant_id, instance_name=dup_name
                )
                _insert_lab_instance(
                    conn, instance_id=second_id, tenant_id=tenant_id, instance_name=dup_name
                )

            with pytest.raises(Exception) as excinfo:
                command.upgrade(cfg, TARGET_REVISION_0057)
            message = str(excinfo.value)
            assert dup_name in message, "the raised error must name the actual duplicate value"
            # A bare "2" in message is not guard-sensitive — SQLAlchemy
            # exception text commonly contains unrelated digits (e.g. a
            # trailing `/e/20/...` documentation-link suffix), so assert the
            # exact fragment the migration's `format('%s (x%s)', ...)` shape
            # actually produces instead.
            assert f"{dup_name} (x2)" in message, (
                "the raised error must name the actual duplicate value's count "
                "in the exact shape the migration's DO $$ block produces"
            )

            with admin_engine.connect() as conn:
                assert _current_version(conn) == DOWN_REVISION_0057, (
                    "a failed upgrade must not leave alembic_version at 0057"
                )
                assert _instance_name_index_snapshot(conn) is None, (
                    "a failed upgrade must not leave the unique index behind"
                )

            # Remove one of the two duplicates and retry — must now succeed.
            with admin_engine.connect() as conn:
                conn.execute(text("DELETE FROM lab_instances WHERE id = :id"), {"id": second_id})
                conn.commit()

            command.upgrade(cfg, TARGET_REVISION_0057)

            with admin_engine.connect() as conn:
                assert _current_version(conn) == TARGET_REVISION_0057
                assert _instance_name_index_snapshot(conn) == {
                    "unique": True,
                    "columns": ["instance_name"],
                }
        finally:
            with admin_engine.connect() as conn:
                conn.execute(text("DELETE FROM lab_instances WHERE tenant_id = :id"), {"id": tenant_id})
                conn.commit()
            command.upgrade(cfg, "head")
            with admin_engine.connect() as conn:
                _delete_tenant(conn, tenant_id)


# --- 0058: worker-owned `lab_instances.runtime_presence` --------------------


RUNTIME_PRESENCE_ROLES = ("app_user", "platform_api", "academy_lab_worker")
RUNTIME_PRESENCE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE")


def _runtime_presence_column_snapshot(conn) -> dict[str, object] | None:
    """``None`` when the column doesn't exist (0057 state); otherwise its
    nullability and column default expression."""
    row = conn.execute(
        text(
            """SELECT is_nullable, column_default
               FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'lab_instances'
                 AND column_name = 'runtime_presence'"""
        )
    ).first()
    if row is None:
        return None
    return {"nullable": row[0], "default": row[1]}


def _runtime_presence_constraint_snapshot(conn) -> dict[str, object] | None:
    row = conn.execute(
        text(
            """SELECT pg_get_constraintdef(oid), convalidated
               FROM pg_constraint
               WHERE conname = :name AND conrelid = 'lab_instances'::regclass"""
        ),
        {"name": RUNTIME_PRESENCE_CHECK},
    ).first()
    if row is None:
        return None
    return {"definition": row[0], "validated": row[1]}


def _runtime_presence_grant_snapshot(conn) -> dict[tuple[str, str], bool]:
    """``has_column_privilege`` for every (role, privilege) this migration
    governs on ``runtime_presence`` specifically — table-wide grants (e.g.
    academy_lab_worker's SELECT/UPDATE from 0056) already extend to it
    automatically, so this is what actually proves the column-level ACL
    posture, not just the table-wide one."""
    result: dict[tuple[str, str], bool] = {}
    for role in RUNTIME_PRESENCE_ROLES:
        for privilege in RUNTIME_PRESENCE_PRIVILEGES:
            result[(role, privilege)] = bool(
                conn.execute(
                    text(
                        "SELECT has_column_privilege(:role, 'lab_instances', "
                        "'runtime_presence', :priv)"
                    ),
                    {"role": role, "priv": privilege},
                ).scalar()
            )
    return result


def _runtime_presence_full_snapshot(conn) -> dict[str, object]:
    return {
        "column": _runtime_presence_column_snapshot(conn),
        "constraint": _runtime_presence_constraint_snapshot(conn),
        "grants": _runtime_presence_grant_snapshot(conn),
    }


def _select_runtime_presence(conn, instance_id: str) -> str:
    return conn.execute(
        text("SELECT runtime_presence FROM lab_instances WHERE id = :id"),
        {"id": instance_id},
    ).scalar()


def test_0058_downgrade_upgrade_roundtrip_is_idempotent(admin_engine):
    """0057 <-> 0058 round trip: the column, its CHECK constraint, and the
    explicit grant posture are added and removed cleanly across repeated
    cycles, mirroring the 0055/0056 round-trip test's shape (D1 above)."""
    cfg = _make_config()
    url = _migration_url()

    head = _head_revision(cfg)
    assert head == HEAD_REVISION, (
        f"expected repo head to be {HEAD_REVISION!r}, got {head!r} — a "
        "migration was added without updating this test's fixed anchor "
        "revisions"
    )

    with admin_engine.connect() as conn:
        assert _current_version(conn) == HEAD_REVISION
        baseline = _runtime_presence_full_snapshot(conn)
        assert baseline["column"] is not None
        assert baseline["column"]["nullable"] == "NO"
        # Exact Postgres cast formatting of a VARCHAR default isn't asserted
        # here (brittle across versions) — just that the literal default
        # value is actually "absent", not merely present.
        assert baseline["column"]["default"] is not None and "'absent'" in baseline["column"]["default"]
        assert baseline["constraint"] is not None and baseline["constraint"]["validated"] is True
        for role in ("app_user", "platform_api"):
            assert baseline["grants"][(role, "INSERT")] is False
            assert baseline["grants"][(role, "UPDATE")] is False
            assert baseline["grants"][(role, "SELECT")] is True
        assert baseline["grants"][("academy_lab_worker", "SELECT")] is True
        assert baseline["grants"][("academy_lab_worker", "UPDATE")] is True

    with _migration_env(url):
        try:
            command.downgrade(cfg, DOWN_REVISION_0058)
            with admin_engine.connect() as conn:
                assert _runtime_presence_column_snapshot(conn) is None, (
                    "downgrade must drop the column, not just rename it"
                )
                assert _runtime_presence_constraint_snapshot(conn) is None
            command.upgrade(cfg, TARGET_REVISION_0058)
            command.downgrade(cfg, DOWN_REVISION_0058)
            with admin_engine.connect() as conn:
                assert _runtime_presence_column_snapshot(conn) is None
            command.upgrade(cfg, TARGET_REVISION_0058)
        finally:
            command.upgrade(cfg, "head")

    with admin_engine.connect() as conn:
        final = _runtime_presence_full_snapshot(conn)
        final_version = _current_version(conn)

    assert final == baseline, (
        "column/constraint/grant state after a downgrade/upgrade round trip "
        "does not match the pre-cycle baseline — 0058 leaks or loses state "
        "across cycles"
    )
    assert final_version == HEAD_REVISION


def test_0058_backfill_is_exact_for_reaped_vs_every_other_status(admin_engine):
    """`status == "reaped"` rows become "absent"; every other existing status
    becomes "unknown" — proven across a representative spread, not just one
    status each."""
    cfg = _make_config()
    url = _migration_url()
    reaped_statuses = ("reaped",)
    non_reaped_statuses = ("queued", "provisioning", "active", "resetting", "error")

    with admin_engine.connect() as conn:
        assert _current_version(conn) == HEAD_REVISION
        tenant_id = _insert_tenant(conn, "roundtrip-0058-backfill")

    ids_by_status: dict[str, str] = {}
    try:
        with _migration_env(url):
            try:
                command.downgrade(cfg, DOWN_REVISION_0058)
                with admin_engine.connect() as conn:
                    for status in (*reaped_statuses, *non_reaped_statuses):
                        instance_id = str(conn.execute(text("SELECT gen_random_uuid()")).scalar())
                        conn.execute(
                            text(
                                "INSERT INTO lab_instances "
                                "(id, tenant_id, activity_id, person_id, instance_name, "
                                "seed, status) VALUES "
                                "(:id, :tenant_id, gen_random_uuid(), gen_random_uuid(), "
                                ":name, '{}'::jsonb, :status)"
                            ),
                            {
                                "id": instance_id,
                                "tenant_id": tenant_id,
                                "name": f"dal-backfill-{status}",
                                "status": status,
                            },
                        )
                        ids_by_status[status] = instance_id
                    conn.commit()

                command.upgrade(cfg, TARGET_REVISION_0058)

                with admin_engine.connect() as conn:
                    for status in reaped_statuses:
                        assert _select_runtime_presence(conn, ids_by_status[status]) == "absent", (
                            f"status={status!r} must backfill to 'absent'"
                        )
                    for status in non_reaped_statuses:
                        assert _select_runtime_presence(conn, ids_by_status[status]) == "unknown", (
                            f"status={status!r} must backfill to 'unknown'"
                        )
            finally:
                command.upgrade(cfg, "head")
    finally:
        with admin_engine.connect() as conn:
            conn.execute(text("DELETE FROM lab_instances WHERE tenant_id = :id"), {"id": tenant_id})
            conn.commit()
            _delete_tenant(conn, tenant_id)


def test_0058_new_insert_omitting_column_defaults_to_absent(admin_engine):
    with admin_engine.connect() as conn:
        assert _current_version(conn) == HEAD_REVISION
        tenant_id = _insert_tenant(conn, "roundtrip-0058-default")

    try:
        with admin_engine.connect() as conn:
            instance_id = str(conn.execute(text("SELECT gen_random_uuid()")).scalar())
            _insert_lab_instance(
                conn, instance_id=instance_id, tenant_id=tenant_id, instance_name="dal-0058-default"
            )
            assert _select_runtime_presence(conn, instance_id) == "absent"
    finally:
        with admin_engine.connect() as conn:
            _delete_tenant(conn, tenant_id)


def test_0058_check_constraint_rejects_a_value_outside_the_allowed_set(admin_engine):
    with admin_engine.connect() as conn:
        assert _current_version(conn) == HEAD_REVISION
        tenant_id = _insert_tenant(conn, "roundtrip-0058-check")

    try:
        with admin_engine.connect() as conn:
            instance_id = str(conn.execute(text("SELECT gen_random_uuid()")).scalar())
            with pytest.raises(Exception) as excinfo:
                conn.execute(
                    text(
                        "INSERT INTO lab_instances "
                        "(id, tenant_id, activity_id, person_id, instance_name, seed, "
                        "runtime_presence) VALUES "
                        "(:id, :tenant_id, gen_random_uuid(), gen_random_uuid(), :name, "
                        "'{}'::jsonb, 'bogus')"
                    ),
                    {"id": instance_id, "tenant_id": tenant_id, "name": "dal-0058-bogus"},
                )
            assert RUNTIME_PRESENCE_CHECK in str(excinfo.value)
            conn.rollback()
    finally:
        with admin_engine.connect() as conn:
            _delete_tenant(conn, tenant_id)


def test_0058_grant_posture_matches_academy_lab_worker_ownership(admin_engine):
    """`app_user`/`platform_api` may read but never write `runtime_presence`;
    `academy_lab_worker` may read and write it — the same posture 0056
    established for every other worker-owned column on this table."""
    with admin_engine.connect() as conn:
        assert _current_version(conn) == HEAD_REVISION
        grants = _runtime_presence_grant_snapshot(conn)

    for role in ("app_user", "platform_api"):
        assert grants[(role, "SELECT")] is True, f"{role} should be able to SELECT runtime_presence"
        assert grants[(role, "INSERT")] is False, f"{role} must not INSERT runtime_presence"
        assert grants[(role, "UPDATE")] is False, f"{role} must not UPDATE runtime_presence"
    assert grants[("academy_lab_worker", "SELECT")] is True
    assert grants[("academy_lab_worker", "UPDATE")] is True

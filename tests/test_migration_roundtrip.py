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
  re-grant everything and paper over it.
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
# boundary regardless of what head is. If a later migration changes head
# beyond 0056, the head-equality assertions below will fail loudly and name
# what to update, rather than silently exercising the wrong boundary.
DOWN_REVISION = "0055_lab_operations"
TARGET_REVISION = "0056_lab_instance_worker"

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


def _current_version(conn) -> str | None:
    return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


def _full_snapshot(conn) -> dict[str, object]:
    return {"constraints": _constraint_snapshot(conn), "grants": _grant_snapshot(conn)}


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


def test_0056_downgrade_upgrade_roundtrip_is_idempotent(admin_engine):
    """Two downgrade/upgrade cycles across 0056 reproduce the exact starting
    state — constraints, grants, and the recorded ``alembic_version``."""
    cfg = _make_config()
    url = _migration_url()

    head = _head_revision(cfg)
    assert head == TARGET_REVISION, (
        f"expected repo head to be {TARGET_REVISION!r}, got {head!r} — a "
        "migration was added after 0056 without updating this test's fixed "
        "anchor revisions"
    )

    with admin_engine.connect() as conn:
        assert (
            _current_version(conn) == TARGET_REVISION
        ), "expected the CI database to already be migrated to head before this test runs"
        baseline = _full_snapshot(conn)

    with _migration_env(url):
        try:
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
    assert final_version == TARGET_REVISION


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
    assert head == TARGET_REVISION, (
        f"expected repo head to be {TARGET_REVISION!r}, got {head!r} — a "
        "migration was added after 0056 without updating this test's fixed "
        "anchor revisions"
    )

    with admin_engine.connect() as conn:
        assert _current_version(conn) == TARGET_REVISION
        # A same-run reference: the state a normal, uninterrupted migration
        # produces, captured before this test disturbs anything.
        reference = _full_snapshot(conn)

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

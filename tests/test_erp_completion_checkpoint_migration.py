"""Hosted CI only: real full-chain 0065/0066 transfer and reversal."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from alembic import command
from tests.test_migration_roundtrip import (
    _current_version,
    _delete_tenant,
    _grant_snapshot,
    _insert_tenant,
    _make_config,
    _migration_env,
    _migration_url,
)

HEAD = "0066_erp_completion_checkpoint"
BASE = "0065_erp_progress_projection"
TABLE = "academy_erp_completion_checkpoints"


def _completion(conn, tenant, *, ack=None, status="in_progress"):
    course, completion = uuid4(), uuid4()
    conn.execute(
        text("""INSERT INTO courses (id, tenant_id, slug, title, discipline, source_ref, version)
        VALUES (:id, :tenant, :slug, 'checkpoint', 'fiber', 'test', 1)"""),
        {"id": course, "tenant": tenant, "slug": str(course)},
    )
    conn.execute(
        text("""INSERT INTO course_completions
        (id, tenant_id, person_id, course_id, status, pct, erp_synced_at)
        VALUES (:id, :tenant, :person, :course, :status, 0, :ack)"""),
        {"id": completion, "tenant": tenant, "person": uuid4(), "course": course, "status": status, "ack": ack},
    )
    conn.commit()
    return completion


def _rows(conn, tenant):
    return conn.execute(
        text("""SELECT row_to_json(c)::jsonb - 'erp_synced_at'
        FROM course_completions c WHERE tenant_id=:tenant ORDER BY id"""),
        {"tenant": tenant},
    ).all()


@pytest.mark.parametrize("conflict", [False, True])
def test_populated_transfer_reversal_preserves_current_facts(admin_engine, conflict):
    cfg = _make_config()
    with _migration_env(_migration_url()):
        command.downgrade(cfg, BASE)
        with admin_engine.connect() as conn:
            tenant = _insert_tenant(conn, f"checkpoint-roundtrip-{uuid4().hex}")
            old_ack = "2026-07-11T12:00:00+00:00"
            acknowledged = _completion(conn, tenant, ack=old_ack, status="completed")
            pending = _completion(conn, tenant)
            baseline = _rows(conn, tenant)
            grants = _grant_snapshot(conn)
        try:
            command.upgrade(cfg, HEAD)
            with admin_engine.connect() as conn:
                assert _rows(conn, tenant) == baseline
                assert _grant_snapshot(conn) == grants
                assert (
                    conn.execute(
                        text("SELECT count(*) FROM academy_erp_completion_checkpoints WHERE tenant_id=:t"),
                        {"t": tenant},
                    ).scalar_one()
                    == 2
                )
                assert (
                    conn.execute(
                        text("SELECT erp_synced_at FROM academy_erp_completion_checkpoints WHERE completion_id=:id"),
                        {"id": pending},
                    ).scalar_one()
                    is None
                )
                new = _completion(conn, tenant, status="completed")
                unsent = _completion(conn, tenant)
                conn.execute(
                    text("INSERT INTO academy_erp_completion_checkpoints VALUES (:t, :id, '2026-10-17T12:00:00Z')"),
                    {"t": tenant, "id": new},
                )
                conn.execute(
                    text(
                        "UPDATE academy_erp_completion_checkpoints SET erp_synced_at='2026-10-17T12:00:00Z' WHERE completion_id=:id"
                    ),
                    {"id": pending},
                )
                if conflict:
                    conn.execute(
                        text(
                            "UPDATE academy_erp_completion_checkpoints SET erp_synced_at=NULL WHERE completion_id=:id"
                        ),
                        {"id": acknowledged},
                    )
                conn.commit()
                full_before = _rows(conn, tenant)
            if conflict:
                with pytest.raises(Exception, match="conflicting legacy acknowledgement"):
                    command.downgrade(cfg, BASE)
                with admin_engine.connect() as conn:
                    assert _current_version(conn) == HEAD
                    assert _rows(conn, tenant) == full_before
                    assert (
                        conn.execute(
                            text(
                                "SELECT erp_synced_at FROM academy_erp_completion_checkpoints WHERE completion_id=:id"
                            ),
                            {"id": acknowledged},
                        ).scalar_one()
                        is None
                    )
                    conn.execute(
                        text(
                            "UPDATE academy_erp_completion_checkpoints SET erp_synced_at=:ack WHERE completion_id=:id"
                        ),
                        {"ack": old_ack, "id": acknowledged},
                    )
                    conn.commit()
            command.downgrade(cfg, BASE)
            with admin_engine.connect() as conn:
                assert _rows(conn, tenant) == full_before
                assert (
                    conn.execute(
                        text("SELECT erp_synced_at FROM course_completions WHERE id=:id"), {"id": unsent}
                    ).scalar_one()
                    is None
                )
                for delivered in (new, pending):
                    assert (
                        conn.execute(
                            text("SELECT erp_synced_at FROM course_completions WHERE id=:id"), {"id": delivered}
                        )
                        .scalar_one()
                        .isoformat()
                        == "2026-10-17T12:00:00+00:00"
                    )
            command.upgrade(cfg, HEAD)
            with admin_engine.connect() as conn:
                assert _rows(conn, tenant) == full_before
                assert _grant_snapshot(conn) == grants
                assert (
                    conn.execute(
                        text("SELECT count(*) FROM academy_erp_completion_checkpoints WHERE tenant_id=:t"),
                        {"t": tenant},
                    ).scalar_one()
                    == 4
                )
        finally:
            with admin_engine.connect() as conn:
                _delete_tenant(conn, tenant)
            command.upgrade(cfg, HEAD)


def _probe_completion(conn, tenant):
    """Insert a valid completion inside the caller's transaction; never commit."""
    course, completion = uuid4(), uuid4()
    conn.execute(
        text("""INSERT INTO courses (id, tenant_id, slug, title, discipline, source_ref, version)
        VALUES (:c, :t, :slug, 'probe', 'fiber', 'test', 1)"""),
        {"c": course, "t": tenant, "slug": str(course)},
    )
    conn.execute(
        text("""INSERT INTO course_completions (id, tenant_id, person_id, course_id, pct, status)
        VALUES (:id, :t, :p, :c, 0, 'in_progress')"""),
        {"id": completion, "t": tenant, "p": uuid4(), "c": course},
    )
    return completion


def test_real_role_rls_tenant_fk_cascade_and_worker_exclusion(admin_engine):
    role = f"checkpoint_probe_{uuid4().hex}"
    with admin_engine.connect() as conn:
        # All role/grant mutations and sacrificial data roll back together.
        tx = conn.begin()
        try:
            tenant_a, tenant_b = uuid4(), uuid4()
            conn.execute(
                text("INSERT INTO tenants (id, slug, name) VALUES (:a, :sa, 'a'), (:b, :sb, 'b')"),
                {"a": tenant_a, "b": tenant_b, "sa": str(tenant_a), "sb": str(tenant_b)},
            )
            course, completion = uuid4(), uuid4()
            conn.execute(
                text("""INSERT INTO courses (id, tenant_id, slug, title, discipline, source_ref, version)
                VALUES (:c, :t, :slug, 'probe', 'fiber', 'test', 1)"""),
                {"c": course, "t": tenant_a, "slug": str(course)},
            )
            conn.execute(
                text("""INSERT INTO course_completions (id, tenant_id, person_id, course_id, pct, status)
                VALUES (:id, :t, :p, :c, 0, 'in_progress')"""),
                {"id": completion, "t": tenant_a, "p": uuid4(), "c": course},
            )
            conn.execute(
                text("INSERT INTO academy_erp_completion_checkpoints VALUES (:t, :id, NULL)"),
                {"t": tenant_a, "id": completion},
            )
            with pytest.raises(DBAPIError) as fk_error:
                with conn.begin_nested():
                    conn.execute(
                        text("INSERT INTO academy_erp_completion_checkpoints VALUES (:t, :id, NULL)"),
                        {"t": tenant_b, "id": completion},
                    )
            assert fk_error.value.orig.sqlstate == "23503"
            assert "foreign key" in str(fk_error.value.orig).lower()
            same_tenant_completion = _probe_completion(conn, tenant_a)
            other_tenant_completion = _probe_completion(conn, tenant_b)
            assert conn.execute(
                text(
                    "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='academy_erp_completion_checkpoints'::regclass"
                )
            ).scalar_one()
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                assert not conn.execute(
                    text("SELECT has_table_privilege('academy_lab_worker', :table, :p)"),
                    {"table": TABLE, "p": privilege},
                ).scalar_one()
            conn.execute(text(f'CREATE ROLE "{role}" NOLOGIN NOSUPERUSER NOBYPASSRLS'))
            conn.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role}"'))
            conn.execute(text(f'GRANT SELECT, INSERT ON academy_erp_completion_checkpoints TO "{role}"'))
            conn.execute(text(f'GRANT EXECUTE ON FUNCTION app_current_tenant_id() TO "{role}"'))
            conn.execute(text(f'SET LOCAL ROLE "{role}"'))
            conn.execute(text("SELECT set_config('app.current_tenant', :tenant, true)"), {"tenant": str(tenant_a)})
            # A successful restricted-role write establishes INSERT permission
            # before the negative test exercises WITH CHECK with a real FK.
            conn.execute(
                text("INSERT INTO academy_erp_completion_checkpoints VALUES (:t, :id, NULL)"),
                {"t": tenant_a, "id": same_tenant_completion},
            )
            for tenant_context, count in ((str(tenant_a), 2), (str(tenant_b), 0), ("", 0)):
                conn.execute(text("SELECT set_config('app.current_tenant', :tenant, true)"), {"tenant": tenant_context})
                assert (
                    conn.execute(text("SELECT count(*) FROM academy_erp_completion_checkpoints")).scalar_one() == count
                )
            conn.execute(text("SELECT set_config('app.current_tenant', :tenant, true)"), {"tenant": str(tenant_a)})
            with pytest.raises(DBAPIError) as rls_error:
                with conn.begin_nested():
                    conn.execute(
                        text("INSERT INTO academy_erp_completion_checkpoints VALUES (:t, :id, NULL)"),
                        {"t": tenant_b, "id": other_tenant_completion},
                    )
            assert rls_error.value.orig.sqlstate == "42501"
            assert "row-level security" in str(rls_error.value.orig).lower()
            conn.execute(text("RESET ROLE"))
            conn.execute(text("DELETE FROM course_completions WHERE id=:id"), {"id": completion})
            assert (
                conn.execute(
                    text("SELECT count(*) FROM academy_erp_completion_checkpoints WHERE completion_id=:id"),
                    {"id": completion},
                ).scalar_one()
                == 0
            )
        finally:
            tx.rollback()


def test_upgrade_verification_failure_rolls_back_all_ddl_and_source(admin_engine, monkeypatch):
    """Inject a suppressed copy row; exact-key verification must refuse atomically."""
    from alembic import op

    cfg = _make_config()
    with _migration_env(_migration_url()):
        command.downgrade(cfg, BASE)
        with admin_engine.connect() as conn:
            tenant = _insert_tenant(conn, f"checkpoint-fault-{uuid4().hex}")
            completion = _completion(conn, tenant)
            before = _rows(conn, tenant)
        execute = op.execute

        def suppress_one_copy(statement, *args, **kwargs):
            result = execute(statement, *args, **kwargs)
            if isinstance(statement, str) and statement.startswith(
                "INSERT INTO public.academy_erp_completion_checkpoints"
            ):
                op.get_bind().execute(
                    text("DELETE FROM academy_erp_completion_checkpoints WHERE completion_id=:id"), {"id": completion}
                )
            return result

        try:
            with monkeypatch.context() as patch:
                patch.setattr(op, "execute", suppress_one_copy)
                with pytest.raises(Exception, match="key or timestamp mismatch"):
                    command.upgrade(cfg, HEAD)
            with admin_engine.connect() as conn:
                assert _current_version(conn) == BASE
                assert conn.execute(text("SELECT to_regclass(:table)"), {"table": TABLE}).scalar_one() is None
                assert _rows(conn, tenant) == before
        finally:
            command.upgrade(cfg, HEAD)
            with admin_engine.connect() as conn:
                _delete_tenant(conn, tenant)


def _refusal_snapshot(conn):
    """Admin-visible rows, history, ownership, RLS and fixture-relevant ACLs."""
    return {
        "version": _current_version(conn),
        "tenants": conn.execute(text("SELECT row_to_json(t)::text FROM tenants t ORDER BY id")).all(),
        "courses": conn.execute(text("SELECT row_to_json(c)::text FROM courses c ORDER BY id")).all(),
        "policies": conn.execute(
            text("""SELECT oid, polname, polrelid, polcmd, polroles::text,
                pg_get_expr(polqual, polrelid), pg_get_expr(polwithcheck, polrelid)
            FROM pg_policy WHERE polrelid IN ('course_completions'::regclass,
                'academy_erp_completion_checkpoints'::regclass) ORDER BY oid""")
        ).all(),
        "completions": conn.execute(
            text("SELECT row_to_json(c)::text FROM course_completions c ORDER BY tenant_id, id")
        ).all(),
        "checkpoints": conn.execute(
            text(
                "SELECT row_to_json(p)::text FROM academy_erp_completion_checkpoints p ORDER BY tenant_id, completion_id"
            )
        ).all(),
        "relations": conn.execute(
            text("""SELECT oid, relname, relowner, relacl::text,
                relrowsecurity, relforcerowsecurity
            FROM pg_class WHERE oid IN ('course_completions'::regclass,
                'academy_erp_completion_checkpoints'::regclass, 'tenants'::regclass)
            ORDER BY oid""")
        ).all(),
        "constraints": conn.execute(
            text("""SELECT oid, conname, pg_get_constraintdef(oid)
            FROM pg_constraint WHERE conrelid IN ('course_completions'::regclass,
                'academy_erp_completion_checkpoints'::regclass) ORDER BY oid""")
        ).all(),
        "schema_acl": conn.execute(text("SELECT nspacl::text FROM pg_namespace WHERE nspname='public'")).all(),
        "helper_acl": conn.execute(
            text("SELECT proacl::text FROM pg_proc WHERE oid='app_current_tenant_id()'::regprocedure")
        ).all(),
        "worker_grants": _grant_snapshot(conn),
    }


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_actual_migration_refuses_rls_filtered_inspection_atomically(admin_engine, direction):
    """Run the actual 0066 body, with DDL-capable owner lacking BYPASSRLS.

    The caller owns the root rollback. There are no migration savepoints or
    migration transaction completions; refusal aborts the caller transaction.
    """
    from alembic.operations import Operations
    from alembic.runtime.environment import EnvironmentContext
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    cfg = _make_config()
    script = ScriptDirectory.from_config(cfg)
    migration = script.get_revision(HEAD).module
    role = f"checkpoint_migration_probe_{uuid4().hex}"
    with admin_engine.connect() as conn:
        before = _refusal_snapshot(conn)
        conn.rollback()  # end the admin baseline read before the caller root
        root = conn.begin()
        try:
            tenant = uuid4()
            conn.execute(
                text("INSERT INTO tenants (id, slug, name) VALUES (:id, :slug, 'migration probe')"),
                {"id": tenant, "slug": str(tenant)},
            )
            completion = _probe_completion(conn, tenant)
            conn.execute(
                text("INSERT INTO academy_erp_completion_checkpoints VALUES (:t, :id, NULL)"),
                {"t": tenant, "id": completion},
            )
            with EnvironmentContext(cfg, script, as_sql=False):
                ops = Operations(MigrationContext.configure(connection=conn))
                ops._install_proxy()
                try:
                    if direction == "upgrade":
                        migration.downgrade()
                    conn.execute(text(f'CREATE ROLE "{role}" NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT'))
                    conn.execute(text(f'GRANT USAGE, CREATE ON SCHEMA public TO "{role}"'))
                    conn.execute(text(f'GRANT SELECT, REFERENCES ON tenants TO "{role}"'))
                    conn.execute(text(f'GRANT EXECUTE ON FUNCTION app_current_tenant_id() TO "{role}"'))
                    # Ownership supplies all LOCK/ALTER/DROP privileges, and
                    # FORCE RLS still applies to a nonsuperuser table owner.
                    conn.execute(text(f'ALTER TABLE course_completions OWNER TO "{role}"'))
                    if direction == "downgrade":
                        conn.execute(text(f'ALTER TABLE academy_erp_completion_checkpoints OWNER TO "{role}"'))
                    conn.execute(text(f'SET LOCAL ROLE "{role}"'))
                    assert conn.execute(
                        text("SELECT NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=current_user")
                    ).scalar_one()
                    conn.execute(text("SELECT set_config('app.current_tenant', :t, true)"), {"t": str(tenant)})
                    # Prove ordinary policy-filtered reads succeed. The same
                    # read must refuse when the migration sets row_security=off.
                    assert conn.execute(text("SELECT count(*) FROM course_completions")).scalar_one() == 1
                    if direction == "downgrade":
                        assert (
                            conn.execute(text("SELECT count(*) FROM academy_erp_completion_checkpoints")).scalar_one()
                            == 1
                        )
                    with pytest.raises(DBAPIError) as denied:
                        getattr(migration, direction)()
                    assert denied.value.orig.sqlstate == "42501"
                    assert "would be affected by row-level security policy" in str(denied.value.orig).lower()
                finally:
                    ops._remove_proxy()
        finally:
            root.rollback()
        assert _refusal_snapshot(conn) == before
        assert conn.execute(text("SELECT count(*) FROM pg_roles WHERE rolname=:role"), {"role": role}).scalar_one() == 0

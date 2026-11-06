"""0067 narrows the lab worker's email_outbox SELECT and pins the 0064 definer.

Round-trip contract: at 0066 the worker holds table-wide SELECT on
``email_outbox`` and the definer is pinned to ``search_path=pg_catalog``
only; at 0067 the worker holds INSERT plus SELECT on exactly
``id``/``tenant_id``/``idempotency_key`` and the definer is pinned to
``search_path=pg_catalog, pg_temp``. Downgrade restores the 0066 state
exactly (an explicit re-widening), and a second upgrade re-narrows it —
the production hotfix of 2026-11-06 already applied these statements, so
the migration must also be a clean no-op applied over that state.
"""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from alembic import command
from alembic.script import ScriptDirectory
from tests.test_migration_roundtrip import _make_config, _migration_env, _migration_url

REVISION = "0067_worker_outbox_narrowing"
DOWN_REVISION = "0066_erp_completion_checkpoint"
WORKER = "academy_lab_worker"
CAPABILITY = "public.activate_eligible_facilitator_nominations(uuid,uuid,uuid,uuid,integer,uuid)"
READABLE_COLUMNS = ("id", "tenant_id", "idempotency_key")
SECRET_COLUMNS = (
    "kind",
    "recipient",
    "subject",
    "html_body",
    "text_body",
    "payload",
    "status",
    "attempts",
    "available_at",
    "sent_at",
    "last_error",
    "created_at",
    "updated_at",
)


def _table_privilege(conn, privilege: str) -> bool:
    return bool(
        conn.scalar(
            text("SELECT has_table_privilege(:role, 'public.email_outbox', :privilege)"),
            {"role": WORKER, "privilege": privilege},
        )
    )


def _column_select(conn, column: str) -> bool:
    return bool(
        conn.scalar(
            text("SELECT has_column_privilege(:role, 'public.email_outbox', :column, 'SELECT')"),
            {"role": WORKER, "column": column},
        )
    )


def _proconfig(conn) -> list[str] | None:
    return conn.scalar(
        text("SELECT p.proconfig FROM pg_proc p " "WHERE p.oid = CAST(:capability AS regprocedure)"),
        {"capability": CAPABILITY},
    )


def _assert_widened(conn) -> None:
    assert _table_privilege(conn, "SELECT") is True
    assert _table_privilege(conn, "INSERT") is True
    assert _proconfig(conn) == ["search_path=pg_catalog"]


def _assert_narrowed(conn) -> None:
    assert _table_privilege(conn, "SELECT") is False
    assert _table_privilege(conn, "INSERT") is True
    for column in READABLE_COLUMNS:
        assert _column_select(conn, column) is True, column
    for column in SECRET_COLUMNS:
        assert _column_select(conn, column) is False, column
    assert _proconfig(conn) == ["search_path=pg_catalog, pg_temp"]


def test_0067_roundtrip_narrows_restores_and_renarrows():
    url = _migration_url()
    cfg = _make_config()
    assert ScriptDirectory.from_config(cfg).get_revision(REVISION) is not None
    engine = create_engine(url, future=True)
    try:
        with _migration_env(url):
            command.downgrade(cfg, DOWN_REVISION)
        with engine.connect() as conn:
            _assert_widened(conn)
        with _migration_env(url):
            command.upgrade(cfg, REVISION)
        with engine.connect() as conn:
            _assert_narrowed(conn)
        with _migration_env(url):
            command.downgrade(cfg, DOWN_REVISION)
        with engine.connect() as conn:
            _assert_widened(conn)
        with _migration_env(url):
            command.upgrade(cfg, REVISION)
        with engine.connect() as conn:
            _assert_narrowed(conn)
    finally:
        with _migration_env(url):
            command.upgrade(cfg, "head")
        engine.dispose()


def test_0064_definer_pg_temp_domain_trap_never_fires(app_user_session, tenant_a):
    """A same-named pg_temp DOMAIN in the caller session must not be resolved.

    The 0064 definer is pinned ``search_path=pg_catalog, pg_temp`` by 0067,
    so its unqualified ``uuid`` types resolve in pg_catalog even when the
    calling session carries trap domains whose CHECK always fails. The call
    must behave identically with and without the traps: any refusal is the
    function's own business refusal, never a domain check (23514).
    """
    session = app_user_session
    session.execute(
        text("SELECT set_config('app.current_tenant', :tenant, true)"),
        {"tenant": str(tenant_a.id)},
    )

    def call_outcome() -> tuple[str, object]:
        try:
            rows = session.execute(
                text(
                    "SELECT * FROM public.activate_eligible_facilitator_nominations("
                    "CAST(:tenant AS pg_catalog.uuid), "
                    "CAST(:nomination AS pg_catalog.uuid), NULL, NULL, NULL, NULL)"
                ),
                {"tenant": str(tenant_a.id), "nomination": str(uuid4())},
            ).all()
            return ("rows", len(rows))
        except DBAPIError as exc:
            session.rollback()
            session.execute(
                text("SELECT set_config('app.current_tenant', :tenant, true)"),
                {"tenant": str(tenant_a.id)},
            )
            return ("sqlstate", exc.orig.sqlstate if exc.orig else None)

    assert session.scalar(
        text(
            "SELECT p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[] "
            "FROM pg_proc p WHERE p.oid = CAST(:capability AS regprocedure)"
        ),
        {"capability": CAPABILITY},
    )
    baseline = call_outcome()
    assert baseline != ("sqlstate", "23514")
    for name in ("uuid", "text"):
        session.execute(text(f'CREATE DOMAIN pg_temp."{name}" AS pg_catalog.text CHECK (false)'))
    trapped = call_outcome()
    assert trapped == baseline, (baseline, trapped)
    session.rollback()

"""0063 adds ``lab_console_activity`` (+ stamp trigger); downgrade removes all of it."""

from __future__ import annotations

from sqlalchemy import create_engine, text

from alembic import command
from alembic.script import ScriptDirectory
from tests.test_migration_roundtrip import _make_config, _migration_env, _migration_url

REVISION = "0063_lab_console_activity"


def _objects(conn):
    table = conn.scalar(text("SELECT to_regclass('lab_console_activity') IS NOT NULL"))
    func = conn.scalar(text("SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'lab_console_activity_stamp')"))
    trig = conn.scalar(text("SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'lab_console_activity_stamp')"))
    return bool(table), bool(func), bool(trig)


def test_0063_downgrade_upgrade_roundtrip():
    url = _migration_url()
    cfg = _make_config()
    assert ScriptDirectory.from_config(cfg).get_revision(REVISION) is not None
    engine = create_engine(url, future=True)
    try:
        with _migration_env(url):
            command.upgrade(cfg, "head")
            with engine.connect() as conn:
                assert _objects(conn) == (True, True, False) or _objects(conn)[0:2] == (True, True)
                assert conn.scalar(text(
                    "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'lab_console_activity'::regclass "
                    "AND NOT tgisinternal")) == 1

            command.downgrade(cfg, "0062_lab_template_access")
            with engine.connect() as conn:
                assert _objects(conn) == (False, False, False)

            command.upgrade(cfg, "head")
            with engine.connect() as conn:
                assert _objects(conn)[0:2] == (True, True)
    finally:
        with _migration_env(url):
            command.upgrade(cfg, "head")
        engine.dispose()

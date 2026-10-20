"""0062 adds ``lab_templates.access``; its downgrade must remove it cleanly."""

from __future__ import annotations

from sqlalchemy import create_engine, text

from alembic import command
from alembic.script import ScriptDirectory
from tests.test_migration_roundtrip import _make_config, _migration_env, _migration_url

REVISION = "0062_lab_template_access"


def _column(conn):
    return conn.execute(
        text(
            "SELECT is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name = 'lab_templates' AND column_name = 'access'"
        )
    ).first()


def test_0062_downgrade_upgrade_roundtrip():
    url = _migration_url()
    cfg = _make_config()
    assert ScriptDirectory.from_config(cfg).get_revision(REVISION) is not None
    engine = create_engine(url, future=True)
    try:
        with _migration_env(url):
            command.upgrade(cfg, "head")
            with engine.connect() as conn:
                nullable, default = _column(conn)
            assert nullable == "NO" and "'[]'" in default

            command.downgrade(cfg, "0061_lab_completion_grants")
            with engine.connect() as conn:
                assert _column(conn) is None

            command.upgrade(cfg, "head")
            with engine.connect() as conn:
                assert _column(conn) is not None
    finally:
        with _migration_env(url):
            command.upgrade(cfg, "head")
        engine.dispose()

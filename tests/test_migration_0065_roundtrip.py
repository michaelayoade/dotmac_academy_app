"""0065 pin applicant sittings to an immutable bank version; downgrade unpins.

The composite FK targets Learning's ``question_bank_versions`` — this
roundtrip therefore requires the composed migration graph's Learning tables
to already exist in the test database (the hosted CI order: composed
``app.migration_cli upgrade`` first, then pytest). Without that table the
upgrade leg fails loudly at FK creation, which is the honest signal.
"""

from __future__ import annotations

from sqlalchemy import create_engine, text

from alembic import command
from alembic.script import ScriptDirectory
from tests.test_migration_roundtrip import _make_config, _migration_env, _migration_url

REVISION = "0065_applicant_bank_version_pin"
DOWN_REVISION = "0064_facilitator_nominations"
FK_NAME = "fk_applicants_tenant_assessment_bank_version"
INDEX_NAME = "ix_applicants_assessment_bank_version_id"


def _column(conn):
    return conn.execute(
        text(
            "SELECT is_nullable, data_type FROM information_schema.columns "
            "WHERE table_name = 'applicants' AND column_name = 'assessment_bank_version_id'"
        )
    ).first()


def _fk_definition(conn):
    return conn.scalar(
        text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :name"),
        {"name": FK_NAME},
    )


def _index_exists(conn) -> bool:
    return bool(conn.scalar(text("SELECT to_regclass(:name) IS NOT NULL"), {"name": INDEX_NAME}))


def test_0065_downgrade_upgrade_roundtrip():
    url = _migration_url()
    cfg = _make_config()
    assert ScriptDirectory.from_config(cfg).get_revision(REVISION) is not None
    engine = create_engine(url, future=True)
    try:
        with _migration_env(url):
            command.upgrade(cfg, "head")
            with engine.connect() as conn:
                nullable, data_type = _column(conn)
                assert nullable == "YES" and data_type == "uuid"
                fk = _fk_definition(conn)
                assert fk is not None
                assert "FOREIGN KEY (tenant_id, assessment_bank_version_id)" in fk
                assert "question_bank_versions" in fk
                assert _index_exists(conn)

            command.downgrade(cfg, DOWN_REVISION)
            with engine.connect() as conn:
                assert _column(conn) is None
                assert _fk_definition(conn) is None
                assert not _index_exists(conn)

            command.upgrade(cfg, "head")
            with engine.connect() as conn:
                assert _column(conn) is not None
                assert _fk_definition(conn) is not None
                assert _index_exists(conn)
    finally:
        with _migration_env(url):
            command.upgrade(cfg, "head")
        engine.dispose()

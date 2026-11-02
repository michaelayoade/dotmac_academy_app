"""Session-scoped shared canonical-entry legacy database fixture.

Every consumer module (kernel entry, identity history, learning history,
credential reset state, account-token adoption) is rollback-only against the
single separately provisioned EMPTY ``KERNEL_ENTRY_DATABASE_URL`` database.
The fixture body is the original module-scoped one, unchanged except for its
scope: it migrates the frozen 62 legacy chain and seeds once, asserting the
database is empty on that first use. Registered via ``pytest_plugins``.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from alembic import command
from alembic.script import ScriptDirectory


@pytest.fixture(scope="session")
def legacy_engine(tmp_path_factory):
    # Imported here, not at plugin load, so the heavy rehearsal/test-module imports
    # happen only for sessions that actually use the shared entry database.
    from tests.fixtures.kernel_identity_entry.rehearsal import (
        FIXTURE,
        LEGACY_HEAD,
        config_for,
        verify_legacy_source,
    )
    from tests.test_kernel_identity_entry import _seed_populated_legacy

    # No silent skip: CI must provision and run this prerequisite explicitly.
    assert os.environ.get("CI") == "true", "canonical-entry DB rehearsals are hosted CI only"
    url = os.environ.get("KERNEL_ENTRY_DATABASE_URL")
    assert url, "CI must provision KERNEL_ENTRY_DATABASE_URL"
    target = make_url(url)
    assert target.get_backend_name() == "postgresql"
    for name in ("TEST_DATABASE_URL", "TEST_MIGRATION_DATABASE_URL", "MIGRATION_DATABASE_URL"):
        other = os.environ.get(name)
        if other:
            assert target.database != make_url(other).database, "entry DB must be separate from app tests"
    engine = create_engine(url, hide_parameters=True)
    verify_legacy_source()
    with engine.connect() as connection:
        assert connection.execute(text("""
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
        """)).scalar_one() == 0, "entry DB must start empty"
        assert connection.execute(text("""
            SELECT count(*) FROM pg_roles WHERE rolname IN
            ('app_admin','app_user','platform_api','academy_lab_worker',
             'outbox_dispatcher','platform_outbox_dispatcher')
        """)).scalar_one() == 6, "CI must provision unchanged Kernel/legacy cluster roles"
        assert connection.execute(text("""
            SELECT rolbypassrls FROM pg_roles WHERE rolname='app_admin'
        """)).scalar_one()
        # Session role survives legacy 0056 autocommit blocks. No cluster role
        # mutation, object-owner rewriting or custom legacy table DDL.
        connection.rollback()
        with connection.begin():
            connection.execute(text("SET ROLE app_admin"))
        applied = []
        cfg = config_for(connection, FIXTURE / "alembic/versions",
                         tmp_path_factory.mktemp("legacy-entry-env"), applied)
        scripts = ScriptDirectory.from_config(cfg)
        assert scripts.get_heads() == [LEGACY_HEAD]
        command.upgrade(cfg, "heads")
        assert len(applied) == 62
        assert {item.revision for item in applied} == {item.revision for item in scripts.walk_revisions()}
        assert not connection.in_transaction()
        with connection.begin():
            _seed_populated_legacy(connection)
    yield engine
    engine.dispose()

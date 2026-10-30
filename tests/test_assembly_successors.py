"""Composed replacements for legacy 0062, 0063 and 0065 assertions.

0062 column/default -> a007; 0063 objects -> a008 (plus RLS, trigger and
column grants); 0065 nullable UUID, composite FK and index -> a009.
Legacy destructive roundtrips become explicit assembly reversal refusals.
Every database assertion runs in a rolled-back root on the dedicated fresh DB.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from app.migration_graph import ordinary_migration_config

SUCCESSORS = (
    "a007_lab_template_access",
    "a008_lab_console_activity",
    "a009_applicant_bank_version_pin",
)


@pytest.fixture
def composed_successors():
    from app.maintenance.fresh_product import run_fresh_composed_entry

    assert os.environ.get("CI") == "true", "fresh successor rehearsals are hosted CI only"
    raw = os.environ.get("ACADEMY_FRESH_ENTRY_DATABASE_URL")
    assert raw, "CI must provision ACADEMY_FRESH_ENTRY_DATABASE_URL"
    url = make_url(raw)
    assert url.drivername == "postgresql+psycopg" and url.username == "app_admin"
    assert url.database
    for name, value in os.environ.items():
        if name.endswith("DATABASE_URL") and name != "ACADEMY_FRESH_ENTRY_DATABASE_URL" and value:
            assert url.database != make_url(value).database, "fresh rehearsal DB must be isolated"
    engine = create_engine(url, hide_parameters=True, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            root = connection.begin()
            try:
                run_fresh_composed_entry(connection, decision_ref="C4 hosted assembly successor rehearsal")
                cfg = ordinary_migration_config()
                cfg.attributes["connection"] = connection
                yield connection, ScriptDirectory.from_config(cfg)
                assert connection.get_transaction() is root and root.is_active
            finally:
                root.rollback()
    finally:
        engine.dispose()


def test_a007_access_column_preserves_0062_contract(composed_successors):
    connection, _ = composed_successors
    nullable, default, data_type = connection.execute(text("""
        SELECT is_nullable, column_default, data_type FROM information_schema.columns
        WHERE table_schema='public' AND table_name='lab_templates' AND column_name='access'
    """)).one()
    assert nullable == "NO" and "'[]'" in default and data_type == "jsonb"


def test_a008_console_objects_rls_trigger_and_narrow_grants(composed_successors):
    connection, _ = composed_successors
    assert connection.execute(text("""
        SELECT relrowsecurity, relforcerowsecurity FROM pg_catalog.pg_class
        WHERE oid='public.lab_console_activity'::regclass
    """)).one() == (True, True)
    policy = connection.execute(text("""
        SELECT qual, with_check FROM pg_catalog.pg_policies
        WHERE schemaname='public' AND tablename='lab_console_activity'
    """)).one()
    assert all("tenant_id" in expr and "app_current_tenant_id()" in expr for expr in policy)
    function, trigger = connection.execute(text("""
        SELECT p.prosrc, pg_catalog.pg_get_triggerdef(t.oid)
        FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
        WHERE t.tgrelid='public.lab_console_activity'::regclass AND NOT t.tgisinternal
    """)).one()
    assert "pg_catalog.now()" in function
    assert "BEFORE INSERT OR UPDATE" in trigger and "lab_console_activity_stamp()" in trigger
    fk = connection.scalar(text("""
        SELECT pg_catalog.pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint
        WHERE conrelid='public.lab_console_activity'::regclass AND contype='f'
    """))
    assert "FOREIGN KEY (tenant_id, instance_id)" in fk and "ON DELETE CASCADE" in fk
    assert connection.scalar(text("SELECT pg_catalog.to_regclass('public.ix_lab_console_activity_tenant_id')"))
    grants = connection.execute(text("""
        SELECT grantee, privilege_type, column_name FROM information_schema.column_privileges
        WHERE table_schema='public' AND table_name='lab_console_activity'
          AND grantee IN ('app_user','platform_api','academy_lab_worker','PUBLIC')
    """)).all()
    expected = {("app_user", "SELECT", column) for column in ("instance_id", "tenant_id", "last_seen_at")}
    expected |= {("app_user", "INSERT", column) for column in ("instance_id", "tenant_id", "last_seen_at")}
    expected.add(("app_user", "UPDATE", "last_seen_at"))
    assert set(grants) == expected
    for role in ("app_user", "platform_api", "academy_lab_worker"):
        assert not connection.scalar(text("SELECT has_table_privilege(:role, 'public.lab_console_activity', 'DELETE')"),
                                     {"role": role})


def test_a009_bank_pin_targets_canonical_learning_tenant_key(composed_successors):
    connection, scripts = composed_successors
    nullable, data_type = connection.execute(text("""
        SELECT is_nullable, data_type FROM information_schema.columns
        WHERE table_schema='public' AND table_name='applicants' AND column_name='assessment_bank_version_id'
    """)).one()
    assert nullable == "YES" and data_type == "uuid"
    schema, target, definition = connection.execute(text("""
        SELECT n.nspname, c.relname, pg_catalog.pg_get_constraintdef(f.oid)
        FROM pg_catalog.pg_constraint f JOIN pg_catalog.pg_class c ON c.oid=f.confrelid
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE f.conrelid='public.applicants'::regclass
          AND f.conname='fk_applicants_tenant_assessment_bank_version'
    """)).one()
    assert schema == scripts.get_revision("lr_0010_question_bank_versions").module._SCHEMA
    assert target == "question_bank_versions"
    assert "FOREIGN KEY (tenant_id, assessment_bank_version_id)" in definition
    assert "(tenant_id, id)" in definition
    assert connection.scalar(text("SELECT pg_catalog.to_regclass('public.ix_applicants_assessment_bank_version_id')"))


@pytest.mark.parametrize("revision", SUCCESSORS)
def test_successors_refuse_existing_objects_and_downgrade(composed_successors, revision):
    connection, scripts = composed_successors
    module = scripts.get_revision(revision).module
    with Operations.context(MigrationContext.configure(connection)):
        with pytest.raises(ValueError, match="already exist"):
            module.upgrade()
        with pytest.raises(RuntimeError, match="reviewed new-facts disposition"):
            module.downgrade()


@pytest.mark.parametrize("revision", SUCCESSORS)
def test_successors_require_migration_owner(revision):
    raw = os.environ.get("TEST_DATABASE_URL")
    assert raw, "CI must provision the genuine app_user login"
    url = make_url(raw)
    assert url.drivername == "postgresql+psycopg" and url.username == "app_user"
    engine = create_engine(url, hide_parameters=True, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT session_user, current_user")).one() == ("app_user", "app_user")
            scripts = ScriptDirectory.from_config(ordinary_migration_config())
            with Operations.context(MigrationContext.configure(connection)):
                with pytest.raises(ValueError, match="requires app_admin"):
                    scripts.get_revision(revision).module.upgrade()
    finally:
        engine.dispose()

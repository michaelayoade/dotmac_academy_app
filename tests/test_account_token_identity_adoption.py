"""Authored hosted-only gates, UNEXECUTED. Genuine full fixture and packages.

No source directory slicing, fake installed package, Person shim, stamping or
local DB. The private TEMP oracle holds synthetic hosted rows only; all value
comparisons return booleans, never token values or their fingerprints.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from copy import copy
from dataclasses import replace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from dotmac_kernel import security
from dotmac_kernel.migrations import versions_dir
from dotmac_kernel.migrations.identity_history import IdentityHistoryImportRefused
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from alembic import command
from alembic.script import ScriptDirectory
from app.maintenance import account_token_identity as token_owner
from app.maintenance.account_token_identity import (
    _catalog,
    account_token_identity_receipt,
    authorize_historical_account_token_adoption,
    capture_historical_account_tokens,
    prepare_fresh_account_token_identity,
)
from app.maintenance.identity_history import import_academy_identity_history
from tests import test_academy_identity_history as history
from tests.fixtures.kernel_identity_entry.rehearsal import config_for, replay_kernel, verify_legacy_source
from tests.test_kernel_identity_entry import entry_transaction, legacy_engine, public_footprint

assert legacy_engine  # Genuine unchanged, separately provisioned full 62 fixture.
ASSEMBLY = history.ASSEMBLY
REVISION = "a003_account_token_identity"
KINDS = ("password_reset", "invite", "email_verify", "ical_feed")


def _synthetic_tokens(connection):
    for person, tenant in connection.execute(sa.text("SELECT id,tenant_id FROM public.people ORDER BY id")):
        for kind in KINDS:
            for state in ("future", "expired", "used"):
                identifier = uuid4()
                connection.execute(
                    sa.text(
                        "INSERT INTO public.account_tokens(id,tenant_id,person_id,kind,token_hash,expires_at,used_at) "
                        "VALUES (:id,:tenant,:person,:kind,:material, "
                        "CASE WHEN :state='expired' THEN now()-interval '1 hour' ELSE now()+interval '1 hour' END, "
                        "CASE WHEN :state='used' THEN now()-interval '2 hours' ELSE NULL END)"
                    ),
                    {
                        "id": identifier,
                        "tenant": tenant,
                        "person": person,
                        "kind": kind,
                        "material": security.hash_token("synthetic-hosted-account-token-" + str(identifier)),
                        "state": state,
                    },
                )
    # Same-root server-only oracle, no credential/token values leave PostgreSQL.
    connection.execute(
        sa.text("CREATE TEMP TABLE token_value_oracle ON COMMIT DROP AS SELECT * FROM public.account_tokens")
    )


@contextmanager
def _historical(engine, tmp_path, monkeypatch):
    captured = []
    original = history._synthetic_source_setup

    def setup(connection):
        original(connection)
        _synthetic_tokens(connection)
        captured.append(capture_historical_account_tokens(connection))

    monkeypatch.setattr(history, "_synthetic_source_setup", setup)
    with history._prepared(engine, tmp_path, monkeypatch) as (connection, expected, operation):
        assert len(captured) == 1
        yield connection, expected, operation, captured[0]


def _heads(connection, tmp_path, *, fail_after=None):
    applied = []
    cfg = config_for(connection, ASSEMBLY, tmp_path, applied, fail_after)
    # ALL source files stay composed, including a003 while importer runs at a002.
    cfg.set_main_option("version_locations", str(versions_dir()) + " " + str(ASSEMBLY))
    command.upgrade(cfg, "heads")
    scripts = ScriptDirectory.from_config(cfg)
    actual = set(connection.scalars(sa.text("SELECT version_num FROM public.alembic_version")))
    assert actual == set(scripts.get_heads())
    return applied


def _import_and_bind(connection, expected, operation, entry):
    receipt = import_academy_identity_history(connection, expected, operation)
    authorize_historical_account_token_adoption(connection, entry, receipt)
    return receipt


def _values_preserved(connection):
    assert (
        connection.scalar(
            sa.text(
                "SELECT NOT EXISTS ((SELECT * FROM public.account_tokens EXCEPT ALL SELECT * FROM token_value_oracle) "
                "UNION ALL (SELECT * FROM token_value_oracle EXCEPT ALL SELECT * FROM public.account_tokens))"
            )
        )
        is True
    )


def test_populated_all_kinds_states_full_source_heads_preserve_values_and_oids(
    legacy_engine,
    tmp_path,
    monkeypatch,
):
    verify_legacy_source()
    with _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, entry):
        root = connection.get_transaction()
        before = _catalog(connection)
        imported = _import_and_bind(connection, expected, operation, entry)
        applied = _heads(connection, tmp_path / "finish")
        assert [r.revision for r in applied] == [REVISION]
        after = _catalog(connection)
        assert replace(after, foreign_keys=before.foreign_keys) == before
        _values_preserved(connection)
        assert connection.scalar(sa.text("SELECT count(DISTINCT kind)=4 FROM public.account_tokens")) is True
        assert connection.scalar(sa.text("SELECT count(*)=24 FROM public.account_tokens")) is True
        result = account_token_identity_receipt(connection, entry)
        assert result.identity_import_receipt is imported
        assert result.token_relation_oid == before.relation[0]
        assert result.token_count == 24 and result.validated_canonical_foreign_keys == 3
        assert result.applied_revision == REVISION
        assert connection.get_transaction() is root and root.is_active
        with pytest.raises(IdentityHistoryImportRefused):
            account_token_identity_receipt(connection, entry)


def test_early_full_heads_without_import_refuses_and_rolls_back_entire_root(legacy_engine, tmp_path, monkeypatch):
    with legacy_engine.connect() as check:
        before = public_footprint(check)
    with (
        pytest.raises(IdentityHistoryImportRefused),
        _historical(legacy_engine, tmp_path, monkeypatch) as (
            connection,
            _expected,
            _operation,
            _entry,
        ),
    ):
        _heads(connection, tmp_path / "too_early")
    with legacy_engine.connect() as check:
        assert public_footprint(check) == before
        assert check.scalar(sa.text("SELECT to_regclass('academy_identity_compat.people') IS NULL")) is True


@pytest.mark.parametrize(
    "attack",
    [
        "copied_entry",
        "copied_receipt",
        "forged_entry",
        "partial_token_cohort",
        "wrong_connection",
        "unimported",
        "reused",
    ],
)
def test_exact_single_use_context_and_actual_receipt_required(legacy_engine, tmp_path, monkeypatch, attack):
    with _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, entry):
        receipt = None if attack == "unimported" else import_academy_identity_history(connection, expected, operation)
        if attack == "copied_entry":
            entry = copy(entry)
        if attack == "copied_receipt":
            receipt = replace(receipt)
        if attack == "forged_entry":
            entry = replace(entry)
        if attack == "partial_token_cohort":
            entry = replace(entry, catalog=replace(entry.catalog, ids=entry.catalog.ids[:-1]))
        if attack == "reused":
            authorize_historical_account_token_adoption(connection, entry, receipt)
        if attack == "wrong_connection":
            with entry_transaction(legacy_engine) as other, pytest.raises(IdentityHistoryImportRefused):
                authorize_historical_account_token_adoption(other, entry, receipt)
        else:
            with pytest.raises(IdentityHistoryImportRefused):
                authorize_historical_account_token_adoption(connection, entry, receipt)


def test_wrong_root_is_not_import_proof(legacy_engine, tmp_path, monkeypatch):
    with _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, entry):
        receipt = import_academy_identity_history(connection, expected, operation)
        connection.get_transaction().rollback()
        connection.begin()
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        with pytest.raises(IdentityHistoryImportRefused):
            authorize_historical_account_token_adoption(connection, entry, receipt)


@pytest.mark.parametrize(
    "damage",
    [
        "privilege",
        "extra_index",
        "wrong_source_oid",
        "unvalidated_fk",
        "missing_subtype",
        "missing_token_table",
    ],
)
def test_catalog_and_canonical_population_drift_refuses_before_rebind(
    legacy_engine,
    tmp_path,
    monkeypatch,
    damage,
):
    with _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, entry):
        _import_and_bind(connection, expected, operation, entry)
        if damage == "privilege":
            connection.execute(sa.text("GRANT REFERENCES ON public.account_tokens TO app_user"))
        elif damage == "extra_index":
            connection.execute(sa.text("CREATE INDEX unexpected_token_kind ON public.account_tokens(kind)"))
        elif damage == "wrong_source_oid":
            connection.execute(sa.text("ALTER TABLE academy_identity_compat.roles RENAME TO displaced_roles"))
        elif damage == "unvalidated_fk":
            connection.execute(
                sa.text("ALTER TABLE public.account_tokens DROP CONSTRAINT fk_account_tokens_tenant_person")
            )
            connection.execute(
                sa.text(
                    "ALTER TABLE public.account_tokens ADD CONSTRAINT fk_account_tokens_tenant_person "
                    "FOREIGN KEY(tenant_id,person_id) REFERENCES academy_identity_compat.people(tenant_id,id) "
                    "ON DELETE CASCADE NOT VALID"
                )
            )
        elif damage == "missing_subtype":
            connection.execute(
                sa.text(
                    "DELETE FROM public.party_persons WHERE party_id=(SELECT person_id FROM "
                    "public.account_tokens ORDER BY id LIMIT 1)"
                )
            )
        else:
            connection.execute(sa.text("DROP TABLE public.account_tokens"))
        with pytest.raises(IdentityHistoryImportRefused):
            _heads(connection, tmp_path / "refused")
        assert connection.get_transaction().is_active


def test_incomplete_source_cohort_is_not_accepted_token_import(legacy_engine, tmp_path, monkeypatch):
    with _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, _entry):
        incomplete = replace(expected, cohort=replace(expected.cohort, people=frozenset()))
        with pytest.raises(IdentityHistoryImportRefused):
            import_academy_identity_history(connection, incomplete, operation)


@pytest.mark.parametrize("phase", ["after_import", "after_a003", "after_version", "after_postflight"])
def test_failures_rollback_relocation_replay_import_audit_tokens_and_version(
    legacy_engine,
    tmp_path,
    monkeypatch,
    phase,
):
    with legacy_engine.connect() as check:
        before = public_footprint(check)
    with (
        pytest.raises(RuntimeError, match="synthetic phase failure"),
        _historical(
            legacy_engine,
            tmp_path,
            monkeypatch,
        ) as (connection, expected, operation, entry),
    ):
        _import_and_bind(connection, expected, operation, entry)
        if phase == "after_import":
            raise RuntimeError("synthetic phase failure")
        if phase == "after_a003":
            # Genuine migration fully executes; failure in real Alembic apply
            # callback rolls back before it can become a committed head.
            with pytest.raises(RuntimeError, match="injected canonical replay failure"):
                _heads(connection, tmp_path / "finish", fail_after=1)
            raise RuntimeError("synthetic phase failure")
        _heads(connection, tmp_path / "finish")
        if phase == "after_version":
            raise RuntimeError("synthetic phase failure")
        account_token_identity_receipt(connection, entry)
        raise RuntimeError("synthetic phase failure")
    with legacy_engine.connect() as check:
        assert public_footprint(check) == before
        assert check.scalar(sa.text("SELECT count(*)=0 FROM public.account_tokens")) is True
        assert check.scalar(sa.text("SELECT to_regclass('academy_identity_compat.people') IS NULL")) is True


def test_canonical_fk_person_tenant_cascade_and_real_app_user_rls(legacy_engine, tmp_path, monkeypatch):
    with _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, entry):
        _import_and_bind(connection, expected, operation, entry)
        _heads(connection, tmp_path / "finish")
        people = connection.execute(sa.text("SELECT id,tenant_id FROM public.parties ORDER BY id")).all()
        person, tenant = people[0]
        other_person, other_tenant = people[1]
        assert tenant != other_tenant
        for supplied_tenant, supplied_person in ((tenant, other_person), (tenant, uuid4())):
            with pytest.raises(DBAPIError), connection.begin_nested():
                connection.execute(
                    sa.text(
                        "INSERT INTO public.account_tokens(id,tenant_id,person_id,kind,token_hash,expires_at) "
                        "VALUES (gen_random_uuid(),:tenant,:person,'ical_feed',repeat('a',64),now())"
                    ),
                    {"tenant": supplied_tenant, "person": supplied_person},
                )
        with pytest.raises(DBAPIError) as refusal, connection.begin_nested():
            party = connection.scalar(
                sa.text(
                    "INSERT INTO public.parties(id,tenant_id,party_type,display_name,email) "
                    "VALUES(gen_random_uuid(),:tenant,'organization','Synthetic token nonperson',NULL) RETURNING id"
                ),
                {"tenant": tenant},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO public.account_tokens(id,tenant_id,person_id,kind,token_hash,expires_at) "
                    "VALUES(gen_random_uuid(),:tenant,:person,'ical_feed',repeat('a',64),now())"
                ),
                {"tenant": tenant, "person": party},
            )
        assert refusal.value.orig.sqlstate == "23503"
        # Real authenticated DB role, tenant context and online ACL, no owner bypass.
        with connection.begin_nested():
            connection.execute(sa.text("SET LOCAL ROLE app_user"))
            connection.execute(sa.text("SELECT set_config('app.current_tenant',:tenant,true)"), {"tenant": str(tenant)})
            assert connection.scalar(sa.text("SELECT count(*)=12 FROM public.account_tokens")) is True
            assert (
                connection.scalar(
                    sa.text("SELECT bool_and(tenant_id=CAST(:tenant AS uuid)) FROM public.account_tokens"),
                    {"tenant": str(tenant)},
                )
                is True
            )
            connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        with connection.begin_nested() as savepoint:
            connection.execute(sa.text("DELETE FROM public.party_persons WHERE party_id=:person"), {"person": person})
            assert (
                connection.scalar(
                    sa.text("SELECT count(*)=0 FROM public.account_tokens WHERE person_id=:person"), {"person": person}
                )
                is True
            )
            savepoint.rollback()
        with connection.begin_nested() as savepoint:
            connection.execute(sa.text("DELETE FROM public.tenants WHERE id=:tenant"), {"tenant": tenant})
            assert (
                connection.scalar(
                    sa.text("SELECT count(*)=0 FROM public.account_tokens WHERE tenant_id=:tenant"), {"tenant": tenant}
                )
                is True
            )
            savepoint.rollback()


@pytest.fixture(scope="module")
def fresh_engine():
    assert os.environ.get("CI") == "true", "token fresh-entry DB gates are hosted CI only"
    url = os.environ.get("ACCOUNT_TOKEN_FRESH_DATABASE_URL")
    assert url, "CI must provision a separate empty ACCOUNT_TOKEN_FRESH_DATABASE_URL"
    target = make_url(url)
    assert target.get_backend_name() == "postgresql"
    for name in (
        "KERNEL_ENTRY_DATABASE_URL",
        "TEST_DATABASE_URL",
        "TEST_MIGRATION_DATABASE_URL",
        "MIGRATION_DATABASE_URL",
    ):
        if os.environ.get(name):
            assert target.database != make_url(os.environ[name]).database
    engine = sa.create_engine(url, hide_parameters=True)
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.text(
                    "SELECT count(*)=0 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                    "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')"
                )
            )
            is True
        )
    yield engine
    engine.dispose()


def test_genuine_fresh_entry_same_recorded_canonical_contract(fresh_engine, tmp_path):
    with entry_transaction(fresh_engine) as connection:
        root = connection.get_transaction()
        replay_kernel(connection, tmp_path / "kernel", [])
        cfg = config_for(connection, ASSEMBLY, tmp_path / "assembly", [])
        cfg.set_main_option("version_locations", str(versions_dir()) + " " + str(ASSEMBLY))
        command.upgrade(cfg, "a002_credential_reset_state")
        entry = prepare_fresh_account_token_identity(connection, decision_ref="reviewed-hosted-fresh-entry-canary")
        _heads(connection, tmp_path / "finish")
        result = account_token_identity_receipt(connection, entry)
        assert result.identity_import_receipt is None
        assert result.token_count == 0 and result.validated_canonical_foreign_keys == 3
        assert result.applied_revision == REVISION
        assert connection.get_transaction() is root and root.is_active


def test_existing_canonical_relation_cannot_be_fresh_fallback(legacy_engine, tmp_path, monkeypatch):
    with _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, entry):
        _import_and_bind(connection, expected, operation, entry)
        _heads(connection, tmp_path / "finish")
        account_token_identity_receipt(connection, entry)
        with pytest.raises(IdentityHistoryImportRefused):
            prepare_fresh_account_token_identity(connection, decision_ref="cannot-authorize-existing-table")


@pytest.mark.parametrize("phase", ["after_capture", "after_relocation", "after_replay", "after_a002"])
def test_early_phase_failures_roll_back_same_root(legacy_engine, tmp_path, monkeypatch, phase):
    with legacy_engine.connect() as check:
        before = public_footprint(check)
    if phase == "after_capture":
        owner = capture_historical_account_tokens

        def fail(connection):
            owner(connection)
            raise RuntimeError("synthetic early phase failure")

        monkeypatch.setitem(globals(), "capture_historical_account_tokens", fail)
    elif phase in {"after_relocation", "after_replay"}:
        name = "relocate" if phase == "after_relocation" else "replay_kernel"
        owner = getattr(history, name)

        def fail(*args, **kwargs):
            owner(*args, **kwargs)
            raise RuntimeError("synthetic early phase failure")

        monkeypatch.setattr(history, name, fail)
    else:
        owner = command.upgrade

        def fail(config, revision):
            owner(config, revision)
            if revision == "a002_credential_reset_state":
                raise RuntimeError("synthetic early phase failure")

        monkeypatch.setattr(command, "upgrade", fail)
    with (
        pytest.raises(RuntimeError, match="synthetic early phase failure"),
        _historical(
            legacy_engine,
            tmp_path,
            monkeypatch,
        ),
    ):
        pytest.fail("phase injection must precede import")
    with legacy_engine.connect() as check:
        assert public_footprint(check) == before
        assert check.scalar(sa.text("SELECT count(*)=0 FROM public.account_tokens")) is True
        assert check.scalar(sa.text("SELECT to_regclass('academy_identity_compat.people') IS NULL")) is True


def test_fresh_and_historical_converge_on_column_key_index_security_contract(
    legacy_engine,
    fresh_engine,
    tmp_path,
    monkeypatch,
):
    with _historical(legacy_engine, tmp_path / "historical", monkeypatch) as (
        connection,
        expected,
        operation,
        entry,
    ):
        _import_and_bind(connection, expected, operation, entry)
        _heads(connection, tmp_path / "historical-finish")
        historical = _catalog(connection)
        _values_preserved(connection)
    with entry_transaction(fresh_engine) as connection:
        replay_kernel(connection, tmp_path / "fresh-kernel", [])
        cfg = config_for(connection, ASSEMBLY, tmp_path / "fresh-assembly", [])
        cfg.set_main_option("version_locations", str(versions_dir()) + " " + str(ASSEMBLY))
        command.upgrade(cfg, "a002_credential_reset_state")
        prepare_fresh_account_token_identity(connection, decision_ref="reviewed-hosted-convergence-canary")
        _heads(connection, tmp_path / "fresh-finish")
        fresh = _catalog(connection)
        assert historical.relation[1:] == fresh.relation[1:]
        assert historical.columns == fresh.columns
        assert historical.keys == fresh.keys
        assert tuple(index[1:] for index in historical.indexes) == tuple(index[1:] for index in fresh.indexes)
        assert tuple(policy[1:] for policy in historical.policies) == tuple(policy[1:] for policy in fresh.policies)
        assert historical.acl == fresh.acl and historical.column_acl == fresh.column_acl
        assert tuple((f[0], f[1], *f[4:]) for f in historical.foreign_keys) == tuple(
            (f[0], f[1], *f[4:]) for f in fresh.foreign_keys
        )


@pytest.mark.parametrize("intrusion", ["token_relation", "compatibility_relation"])
def test_fresh_live_absence_rechecked_and_no_implicit_fallback(fresh_engine, tmp_path, intrusion):
    with entry_transaction(fresh_engine) as connection:
        replay_kernel(connection, tmp_path / "kernel", [])
        cfg = config_for(connection, ASSEMBLY, tmp_path / "assembly", [])
        cfg.set_main_option("version_locations", str(versions_dir()) + " " + str(ASSEMBLY))
        command.upgrade(cfg, "a002_credential_reset_state")
        prepare_fresh_account_token_identity(connection, decision_ref="reviewed-hosted-absence-canary")
        if intrusion == "token_relation":
            connection.execute(sa.text("CREATE TABLE public.account_tokens(unexpected integer)"))
        else:
            connection.execute(sa.text("CREATE SCHEMA academy_identity_compat AUTHORIZATION app_admin"))
            connection.execute(sa.text("CREATE TABLE academy_identity_compat.tenants(unexpected integer)"))
        with pytest.raises(IdentityHistoryImportRefused):
            _heads(connection, tmp_path / "refused")


# Each counterfactual keeps IDs/tenant/person/OIDs and catalog unchanged.
# Fields are fixed test SQL, never caller input or live credential material.
_VALUE_DAMAGE = {
    "kind": "UPDATE public.account_tokens SET kind='future_opaque_kind' WHERE id=(SELECT id FROM public.account_tokens WHERE used_at IS NULL ORDER BY id LIMIT 1)",
    "token_hash": "UPDATE public.account_tokens SET token_hash=repeat('f',64) WHERE id=(SELECT id FROM public.account_tokens WHERE used_at IS NULL ORDER BY id LIMIT 1)",
    "expires_at": "UPDATE public.account_tokens SET expires_at=expires_at+interval '1 microsecond' WHERE id=(SELECT id FROM public.account_tokens WHERE used_at IS NULL ORDER BY id LIMIT 1)",
    "used_at": "UPDATE public.account_tokens SET used_at=created_at-interval '1 microsecond' WHERE id=(SELECT id FROM public.account_tokens WHERE used_at IS NULL ORDER BY id LIMIT 1)",
    "used_at_to_null": "UPDATE public.account_tokens SET used_at=NULL WHERE id=(SELECT id FROM public.account_tokens WHERE used_at IS NOT NULL ORDER BY id LIMIT 1)",
    "created_at": "UPDATE public.account_tokens SET created_at=created_at+interval '1 microsecond' WHERE id=(SELECT id FROM public.account_tokens WHERE used_at IS NULL ORDER BY id LIMIT 1)",
    "updated_at": "UPDATE public.account_tokens SET updated_at=updated_at+interval '1 microsecond' WHERE id=(SELECT id FROM public.account_tokens WHERE used_at IS NULL ORDER BY id LIMIT 1)",
}


def _damage_value(connection, field):
    connection.execute(sa.text(_VALUE_DAMAGE[field]))


@pytest.mark.parametrize("field", tuple(_VALUE_DAMAGE))
@pytest.mark.parametrize("phase", ["before_a003", "a003_catalog_record", "immediate_receipt"])
def test_private_owner_refuses_each_value_drift_and_caught_refusal_rolls_back_root(
    legacy_engine,
    tmp_path,
    monkeypatch,
    field,
    phase,
):
    with legacy_engine.connect() as check:
        before = public_footprint(check)
    # Catch the owner refusal inside the live root, then propagate an outer
    # failure: genuine relocation/replay/import/a003/rows must ALL roll back.
    with (
        pytest.raises(RuntimeError, match="caught token conservation refusal"),
        _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, entry),
    ):
        _import_and_bind(connection, expected, operation, entry)
        before_values = _catalog(connection)
        if phase == "a003_catalog_record":
            record = token_owner._record_migration_catalog

            def damage_then_record(actual_connection, actual_entry, actual_catalog):
                _damage_value(actual_connection, field)
                record(actual_connection, actual_entry, actual_catalog)

            monkeypatch.setattr(token_owner, "_record_migration_catalog", damage_then_record)
        if phase == "before_a003":
            _damage_value(connection, field)
        if phase == "immediate_receipt":
            _heads(connection, tmp_path / "finish")
            _damage_value(connection, field)
        with pytest.raises(IdentityHistoryImportRefused):
            if phase == "immediate_receipt":
                account_token_identity_receipt(connection, entry)
            else:
                _heads(connection, tmp_path / "refused")
        assert connection.get_transaction().is_active
        after_values = _catalog(connection)
        assert after_values.ids == before_values.ids
        assert after_values.relation == before_values.relation
        assert after_values.columns == before_values.columns
        assert after_values.indexes == before_values.indexes
        if phase == "immediate_receipt":
            # Even restoration after an observed violation cannot turn a
            # caught refusal back into an issued conservation receipt.
            connection.execute(
                sa.text(
                    "UPDATE public.account_tokens t SET (kind,token_hash,expires_at,used_at,created_at,updated_at)="
                    "(SELECT kind,token_hash,expires_at,used_at,created_at,updated_at "
                    "FROM token_value_oracle o WHERE o.id=t.id)"
                )
            )
            _values_preserved(connection)
            with pytest.raises(IdentityHistoryImportRefused):
                account_token_identity_receipt(connection, entry)
        raise RuntimeError("caught token conservation refusal")
    with legacy_engine.connect() as check:
        assert public_footprint(check) == before
        assert check.scalar(sa.text("SELECT count(*)=0 FROM public.account_tokens")) is True
        assert check.scalar(sa.text("SELECT to_regclass('academy_identity_compat.people') IS NULL")) is True


@pytest.mark.parametrize("setting", ["DateStyle", "TimeZone", "extra_float_digits"])
def test_serialization_context_drift_refuses_same_root(legacy_engine, tmp_path, monkeypatch, setting):
    with _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, entry):
        _import_and_bind(connection, expected, operation, entry)
        values = {"DateStyle": "SQL, DMY", "TimeZone": "Pacific/Honolulu", "extra_float_digits": "0"}
        before = connection.scalar(sa.text("SELECT pg_catalog.current_setting(:name)"), {"name": setting})
        alternate = values[setting]
        if before == alternate:
            alternate = {"DateStyle": "ISO, MDY", "TimeZone": "UTC", "extra_float_digits": "3"}[setting]
        connection.execute(
            sa.text("SELECT pg_catalog.set_config(:name,:value,true)"), {"name": setting, "value": alternate}
        )
        with pytest.raises(IdentityHistoryImportRefused):
            _heads(connection, tmp_path / "refused")


def test_owner_conserves_raw_kind_null_use_and_infinite_microsecond_timestamps(
    legacy_engine,
    tmp_path,
    monkeypatch,
):
    original = _synthetic_tokens

    def unusual_rows(connection):
        original(connection)
        # Keep original canaries unchanged. This separate positive exercises
        # exact native timestamp extremes and unknown open-vocabulary kind.
        connection.execute(
            sa.text(
                "UPDATE public.account_tokens SET kind='opaque_kind',expires_at='infinity'::timestamptz,"
                "used_at=NULL,created_at='-infinity'::timestamptz,"
                "updated_at='2000-01-01 00:00:00.123456+00'::timestamptz"
            )
        )
        connection.execute(sa.text("TRUNCATE token_value_oracle"))
        connection.execute(sa.text("INSERT INTO token_value_oracle SELECT * FROM public.account_tokens"))

    monkeypatch.setitem(globals(), "_synthetic_tokens", unusual_rows)
    with _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, entry):
        _import_and_bind(connection, expected, operation, entry)
        _heads(connection, tmp_path / "finish")
        _values_preserved(connection)
        result = account_token_identity_receipt(connection, entry)
        assert result.token_count == 24
        assert set(result.__dataclass_fields__) == {
            "identity_import_receipt",
            "token_relation_oid",
            "token_count",
            "applied_revision",
            "validated_canonical_foreign_keys",
        }


def test_physical_rollback_cannot_preserve_python_root_authority(legacy_engine, tmp_path, monkeypatch):
    with _historical(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation, entry):
        _import_and_bind(connection, expected, operation, entry)
        root = connection.get_transaction()
        # Deliberately bypass the SQLAlchemy transaction wrapper, keeping its
        # Python object active while the actual PostgreSQL root ends.
        connection.connection.driver_connection.rollback()
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        assert connection.get_transaction() is root and root.is_active
        with pytest.raises(IdentityHistoryImportRefused, match="token conservation refused"):
            token_owner._consume_migration_entry(connection)

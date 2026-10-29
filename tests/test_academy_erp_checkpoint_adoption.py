"""Actual populated historical a005 hosted canaries; AUTHORED, NOT RUN.

Every fixture reuses the genuine a004 sealed/adopted sequence under one
disposable caller root. No commit, sender, receipt, role substitution, shim
or fresh issuer. The checkpoint is inert nullable ACK storage only.
"""

from contextlib import contextmanager
from copy import copy

import pytest
import sqlalchemy as sa

from alembic import command
from alembic.script import ScriptDirectory
from app.maintenance import checkpoint_transition as checkpoint
from app.maintenance import learning_history as history
from app.maintenance import product_adoption as product
from app.maintenance import retained_transition as transition
from tests import test_academy_learning_history as learning_tests
from tests import test_academy_product_adoption as product_tests
from tests import test_academy_retained_adoption as retained_tests
from tests.fixtures.hosted_genesis import hosted_declaration

_actual_application_object = product_tests._actual_application_object
pytestmark = pytest.mark.usefixtures("_actual_application_object")
assert hosted_declaration


def _seed_acks(monkeypatch):
    original = learning_tests._seed_all_source_fields

    def seed(connection):
        result = original(connection)
        # Deterministic microsecond non-NULL ACKs before capture; the seeded
        # population already carries NULL ACKs and unfinished completions.
        connection.execute(
            sa.text(
                "UPDATE public.course_completions "
                "SET erp_synced_at='2001-02-03 04:05:06.123456+00'::timestamptz "
                "WHERE erp_synced_at IS NOT NULL"
            )
        )
        counts = connection.execute(
            sa.text(
                "SELECT count(*) FILTER (WHERE erp_synced_at IS NULL),"
                "count(*) FILTER (WHERE erp_synced_at IS NOT NULL),"
                "count(*) FILTER (WHERE completed_at IS NULL) FROM public.course_completions"
            )
        ).one()
        assert all(count > 0 for count in counts)
        return result

    monkeypatch.setattr(learning_tests, "_seed_all_source_fields", seed)


@contextmanager
def _adopted(declaration, tmp_path, monkeypatch):
    _seed_acks(monkeypatch)
    with retained_tests._sealed(declaration, tmp_path, monkeypatch) as (connection, handle):
        product._run_retained_transition(connection, handle)
        state = product._state_for(handle)
        assert state.phase == "retained adopted, checkpoint pending"
        assert state.retained_schema_unverified is False and state.checkpoint_unverified is True
        yield connection, handle


def _effects(connection):
    statements = []

    def before(_conn, _cursor, statement, _parameters, _context, _many):
        upper = statement.lstrip().upper()
        if "ACADEMY_ERP_COMPLETION_CHECKPOINTS" in upper and upper.split(" ", 1)[0] in {
            "CREATE",
            "ALTER",
            "REVOKE",
            "INSERT",
        }:
            statements.append(statement)

    sa.event.listen(connection, "before_cursor_execute", before)
    return statements, before


def _assert_sticky(connection, handle):
    state = product._state_for(handle)
    assert state.poisoned is True
    assert state.checkpoint_unverified is True
    with pytest.raises(product.ProductAdoptionRefused):
        product._observe_checkpoint_transition(connection, handle)
    with pytest.raises(product.ProductAdoptionRefused):
        product._run_checkpoint_transition(connection, handle)


def test_actual_ordinary_a005_copies_every_raw_ack_and_conserves_all_owners(hosted_declaration, tmp_path, monkeypatch):
    with _adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        state = product._state_for(handle)
        root = connection.get_transaction()
        retained_entry = state.retained_transition
        a004_final = retained_entry.final
        raw, acks = state.learning_raw, state.completion_acks
        assert len(acks) >= 2
        assert any(row.erp_synced_at is None for row in acks)
        assert any(row.erp_synced_at is not None and row.erp_synced_at.microsecond == 123456 for row in acks)
        assert history._oid(connection, checkpoint._TABLE) is None
        statements, listener = _effects(connection)
        try:
            product._run_checkpoint_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        entry = state.checkpoint_transition
        assert entry.consumed is True and state.checkpoint_runner is None
        assert state.phase == "checkpoint adopted, final admission pending"
        assert state.checkpoint_unverified is False and state.retained_schema_unverified is False
        assert entry.retained_entry is retained_entry and entry.connection is connection
        assert entry.root is root and connection.get_transaction() is root and root.is_active
        assert retained_entry.final is a004_final
        assert state.learning_raw == raw and state.completion_acks == acks
        assert tuple((spec.name, history._raw_projection(connection, spec)) for spec in history._TABLES) == raw
        assert checkpoint._original_acks(state) == entry.raw_acks
        assert checkpoint._source_acks(connection) == entry.raw_acks
        assert checkpoint._checkpoint_rows(connection) == entry.raw_acks
        assert checkpoint._canonical_keys(connection) == tuple((t, i) for t, i, _ in entry.raw_acks)
        assert len(entry.new_fks) == 2 and len(entry.new_triggers) == 8
        relation = connection.execute(
            sa.text(
                "SELECT relrowsecurity,relforcerowsecurity FROM pg_catalog.pg_class "
                "WHERE oid='public.academy_erp_completion_checkpoints'::regclass"
            )
        ).one()
        assert tuple(relation) == (True, True)
        for role in (*checkpoint._RUNTIME_ROLES, "public"):
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT NOT (pg_catalog.has_table_privilege(:role,"
                        "'public.academy_erp_completion_checkpoints'::regclass,'SELECT') OR "
                        "pg_catalog.has_table_privilege(:role,"
                        "'public.academy_erp_completion_checkpoints'::regclass,'INSERT') OR "
                        "pg_catalog.has_table_privilege(:role,"
                        "'public.academy_erp_completion_checkpoints'::regclass,'UPDATE') OR "
                        "pg_catalog.has_table_privilege(:role,"
                        "'public.academy_erp_completion_checkpoints'::regclass,'DELETE'))"
                    ),
                    {"role": role},
                )
                is True
            )
        assert entry.before_versions == retained_entry.after_versions
        assert (checkpoint._A005,) in entry.after_versions
        assert (transition._A004,) not in entry.after_versions
        assert transition._version_rows(connection) == entry.after_versions
        assert len(statements) == 11
        assert statements[0].lstrip().upper().startswith("CREATE TABLE")
        assert "ENABLE ROW LEVEL SECURITY" in statements[1]
        assert "FORCE ROW LEVEL SECURITY" in statements[2]
        assert statements[3].lstrip().upper().startswith("CREATE POLICY")
        assert all(sql.lstrip().upper().startswith("REVOKE ALL") for sql in statements[4:10])
        assert statements[10].lstrip().upper().startswith("INSERT INTO PUBLIC.ACADEMY_ERP_COMPLETION_CHECKPOINTS")
        product._continuity(connection, state)


@pytest.mark.parametrize("ordinal", range(1, 12))
def test_fault_after_each_actual_checkpoint_effect_poisons_root(hosted_declaration, tmp_path, monkeypatch, ordinal):
    with _adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        changes = []

        def after(_conn, _cursor, statement, _parameters, _context, _many):
            upper = statement.lstrip().upper()
            if "ACADEMY_ERP_COMPLETION_CHECKPOINTS" in upper and upper.split(" ", 1)[0] in {
                "CREATE",
                "ALTER",
                "REVOKE",
                "INSERT",
            }:
                changes.append(statement)
                if len(changes) == ordinal:
                    if upper.startswith("INSERT"):
                        # The fixed copy really landed inside this root first.
                        assert checkpoint._checkpoint_rows(connection) == checkpoint._source_acks(connection)
                    raise RuntimeError("synthetic driver material must be suppressed")

        sa.event.listen(connection, "after_cursor_execute", after)
        try:
            with pytest.raises(product.ProductAdoptionRefused) as raised:
                product._run_checkpoint_transition(connection, handle)
        finally:
            sa.event.remove(connection, "after_cursor_execute", after)
        assert "synthetic driver material" not in str(raised.value)
        assert len(changes) == ordinal
        assert product._state_for(handle).checkpoint_transition.consumed is True
        _assert_sticky(connection, handle)
        # _prepared_product's independent same-resource rollback oracle proves
        # the checkpoint and every canonical creation are absent after rollback.


@pytest.mark.parametrize("boundary", ["record", "version", "observe"])
@pytest.mark.parametrize("cancellation", [False, True])
def test_postmigration_and_native_cancellation_windows_cannot_be_retried(
    hosted_declaration, tmp_path, monkeypatch, boundary, cancellation
):
    class Cancelled(BaseException):
        pass

    error = Cancelled if cancellation else RuntimeError
    with _adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        seen = []
        if boundary == "version":
            ordinary = product.ordinary_migration_config

            def configuration():
                config = ordinary()

                def on_version_apply(*, ctx, step, heads, run_args):
                    if checkpoint._A005 in heads:
                        assert product._state_for(handle).phase == "a005 recorded"
                        assert (
                            transition._version_rows(connection)
                            == product._state_for(handle).checkpoint_transition.after_versions
                        )
                        seen.append(True)
                        raise error("synthetic post-version fault")

                config.attributes["on_version_apply"] = (on_version_apply,)
                return config

            monkeypatch.setattr(product, "ordinary_migration_config", configuration)
        else:
            name = "_record_checkpoint_transition" if boundary == "record" else "_observe_checkpoint_transition"
            actual = getattr(product, name)

            def fail_after(*args):
                actual(*args)
                seen.append(True)
                raise error("synthetic post-owner fault")

            monkeypatch.setattr(product, name, fail_after)
        expected = Cancelled if cancellation else product.ProductAdoptionRefused
        with pytest.raises(expected):
            product._run_checkpoint_transition(connection, handle)
        assert seen == [True]
        state = product._state_for(handle)
        assert state.poisoned is True and state.checkpoint_runner is None
        with pytest.raises(product.ProductAdoptionRefused):
            product._run_checkpoint_transition(connection, handle)


@pytest.mark.parametrize(
    "attack", ["raw_prepare", "raw_consume", "raw_upgrade", "early_heads", "observe", "forged", "nested", "xid"]
)
def test_no_unobserved_direct_entry_or_early_head_can_create_checkpoint(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    with _adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        statements, listener = _effects(connection)
        nested = connection.begin_nested() if attack == "nested" else None
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                if attack == "raw_prepare":
                    product._prepare_checkpoint_transition(connection, handle)
                elif attack == "raw_consume":
                    product._consume_checkpoint_transition(connection)
                elif attack in ("raw_upgrade", "early_heads"):
                    config = product.ordinary_migration_config()
                    config.attributes["connection"] = connection
                    command.upgrade(config, checkpoint._A005 if attack == "raw_upgrade" else "heads")
                elif attack == "observe":
                    product._observe_checkpoint_transition(connection, handle)
                elif attack == "forged":
                    product._run_checkpoint_transition(connection, object.__new__(product._Capture))
                else:
                    if attack == "xid":
                        product._state_for(handle).xid = "wrong-physical-xid"
                    product._run_checkpoint_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
            if nested is not None:
                nested.rollback()
        assert statements == []
        _assert_sticky(connection, handle)


def test_unobserved_a004_cannot_enter_a005(hosted_declaration, tmp_path, monkeypatch):
    _seed_acks(monkeypatch)
    with retained_tests._sealed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        statements, listener = _effects(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_checkpoint_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        _assert_sticky(connection, handle)


@pytest.mark.parametrize(
    "attack", ["table", "type", "stamp", "parent_key", "source_ack", "canonical_target", "source_extra"]
)
def test_preexisting_destination_or_parent_drift_refuses_before_effects(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    with _adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        if attack == "table":
            connection.execute(
                sa.text(
                    "CREATE TABLE public.academy_erp_completion_checkpoints"
                    "(tenant_id uuid, completion_id uuid, erp_synced_at timestamptz)"
                )
            )
        elif attack == "type":
            connection.execute(sa.text("CREATE TYPE public.academy_erp_completion_checkpoints AS (tenant_id uuid)"))
        elif attack == "stamp":
            connection.execute(
                sa.text("INSERT INTO public.alembic_version(version_num) VALUES ('a005_erp_completion_checkpoint')")
            )
        elif attack == "parent_key":
            connection.execute(
                sa.text(
                    "ALTER INDEX mod_learning.uq_course_completions_tenant_id_id RENAME TO hidden_completion_tenant_key"
                )
            )
        elif attack == "source_ack":
            connection.execute(
                sa.text("UPDATE public.course_completions SET erp_synced_at=now() WHERE erp_synced_at IS NULL")
            )
        elif attack == "canonical_target":
            connection.execute(
                sa.text("ALTER TABLE mod_learning.course_completions RENAME TO hidden_canonical_completions")
            )
        else:
            connection.execute(
                sa.text(
                    "INSERT INTO public.course_completions"
                    "(id,tenant_id,person_id,course_id,status,pct,completed_at,erp_synced_at,created_at,updated_at) "
                    "SELECT gen_random_uuid(),tenant_id,gen_random_uuid(),course_id,status,pct,NULL,NULL,"
                    "created_at,updated_at FROM public.course_completions LIMIT 1"
                )
            )
        statements, listener = _effects(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_checkpoint_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        _assert_sticky(connection, handle)


@pytest.mark.parametrize(
    "attack",
    ["missing_row", "null_to_value", "microsecond", "grant", "column_grant", "default", "trigger", "parent_extra"],
)
def test_checkpoint_tamper_refuses_continuity_without_rebasing_a004_final(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    with _adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        product._run_checkpoint_transition(connection, handle)
        state = product._state_for(handle)
        entry = state.checkpoint_transition
        final, fks, triggers = entry.final, entry.new_fks, entry.new_triggers
        a004_final = state.retained_transition.final
        if attack == "missing_row":
            connection.execute(
                sa.text(
                    "DELETE FROM public.academy_erp_completion_checkpoints WHERE (tenant_id,completion_id) IN "
                    "(SELECT tenant_id,completion_id FROM public.academy_erp_completion_checkpoints "
                    "ORDER BY tenant_id,completion_id LIMIT 1)"
                )
            )
        elif attack == "null_to_value":
            result = connection.execute(
                sa.text(
                    "UPDATE public.academy_erp_completion_checkpoints SET erp_synced_at=now() "
                    "WHERE erp_synced_at IS NULL"
                )
            )
            assert result.rowcount > 0
        elif attack == "microsecond":
            result = connection.execute(
                sa.text(
                    "UPDATE public.academy_erp_completion_checkpoints "
                    "SET erp_synced_at=erp_synced_at+interval '1 microsecond' WHERE erp_synced_at IS NOT NULL"
                )
            )
            assert result.rowcount > 0
        elif attack == "grant":
            connection.execute(sa.text("GRANT SELECT ON public.academy_erp_completion_checkpoints TO app_user"))
        elif attack == "column_grant":
            connection.execute(
                sa.text("GRANT SELECT(erp_synced_at) ON public.academy_erp_completion_checkpoints TO platform_api")
            )
        elif attack == "default":
            connection.execute(
                sa.text(
                    "ALTER TABLE public.academy_erp_completion_checkpoints ALTER COLUMN erp_synced_at SET DEFAULT now()"
                )
            )
        elif attack == "trigger":
            connection.execute(
                sa.text(
                    "CREATE FUNCTION public.a005_drift_trigger() RETURNS trigger "
                    "LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END;'"
                )
            )
            connection.execute(
                sa.text(
                    "CREATE TRIGGER a005_unexpected_trigger BEFORE INSERT "
                    "ON public.academy_erp_completion_checkpoints "
                    "FOR EACH ROW EXECUTE FUNCTION public.a005_drift_trigger()"
                )
            )
        else:
            connection.execute(
                sa.text("CREATE TABLE public.a005_extra_tenant_ref(tenant_id uuid REFERENCES public.tenants(id))")
            )
        with pytest.raises(product.ProductAdoptionRefused):
            product._continuity(connection, state)
        assert entry.final is final and entry.new_fks is fks and entry.new_triggers is triggers
        assert state.retained_transition.final is a004_final


def test_copied_pending_entry_refuses_before_first_effect(hosted_declaration, tmp_path, monkeypatch):
    with _adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        actual = product._consume_checkpoint_transition

        def consume_copy(conn):
            issued = actual(conn)
            copied = copy(issued)
            assert copied is not issued
            return copied

        monkeypatch.setattr(product, "_consume_checkpoint_transition", consume_copy)
        statements, listener = _effects(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_checkpoint_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        _assert_sticky(connection, handle)


def test_downgrade_refuses_without_effects(hosted_declaration, tmp_path, monkeypatch):
    with _adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        product._run_checkpoint_transition(connection, handle)
        rows = checkpoint._checkpoint_rows(connection)
        versions = transition._version_rows(connection)
        scripts = ScriptDirectory.from_config(product.ordinary_migration_config())
        with pytest.raises(product.ProductAdoptionRefused, match="downgrade unsupported"):
            scripts.get_revision(checkpoint._A005).module.downgrade()
        assert checkpoint._checkpoint_rows(connection) == rows
        assert transition._version_rows(connection) == versions


def test_actual_driver_abort_is_suppressed_without_replacing_or_repairing_root(
    hosted_declaration, tmp_path, monkeypatch
):
    with _adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        root = connection.get_transaction()
        seen = []

        def after(conn, _cursor, statement, _parameters, _context, _many):
            if statement.lstrip().upper().startswith("CREATE TABLE") and not seen:
                seen.append(True)
                conn.execute(sa.text("SELECT 1/0"))

        sa.event.listen(connection, "after_cursor_execute", after)
        try:
            with pytest.raises(product.ProductAdoptionRefused) as raised:
                product._run_checkpoint_transition(connection, handle)
        finally:
            sa.event.remove(connection, "after_cursor_execute", after)
        assert seen == [True]
        assert "division by zero" not in str(raised.value)
        assert connection.get_transaction() is root
        _assert_sticky(connection, handle)


@pytest.mark.parametrize(
    "statement",
    [
        "REVOKE USAGE ON SCHEMA public FROM outbox_dispatcher",
        "GRANT CREATE ON SCHEMA public TO platform_outbox_dispatcher",
    ],
)
@pytest.mark.parametrize("boundary", ["prepare", "pre_ddl", "recorded"])
def test_successor_public_acl_custody_refuses_checkpoint_missing_extra_and_late_grants(
    hosted_declaration, tmp_path, monkeypatch, statement, boundary
):
    with _adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        state = product._state_for(handle)
        envelope = state.retained_transition.public_schema
        transition._verify_successor_cluster(connection, envelope)
        if boundary == "recorded":
            product._run_checkpoint_transition(connection, handle)
            product._continuity(connection, state)
            connection.execute(sa.text(statement))
            with pytest.raises(product.ProductAdoptionRefused):
                product._continuity(connection, state)
            return
        if boundary == "pre_ddl":
            original = product._consume_checkpoint_transition

            def mutate_after_capture(conn):
                pending = original(conn)
                connection.execute(sa.text(statement))
                return pending

            monkeypatch.setattr(product, "_consume_checkpoint_transition", mutate_after_capture)
        else:
            connection.execute(sa.text(statement))
        effects, listener = _effects(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_checkpoint_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert effects == []
        _assert_sticky(connection, handle)

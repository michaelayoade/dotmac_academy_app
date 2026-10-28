"""Actual populated historical a004 hosted canaries; AUTHORED, NOT RUN.

Every fixture uses the existing full62 replay and genuine installed owners under
one disposable caller root. No commit, role substitution, shim or fresh issuer.
"""

from contextlib import contextmanager
from copy import copy

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.script import ScriptDirectory
from app.config import settings
from app.maintenance import learning_history as history
from app.maintenance import product_adoption as product
from app.maintenance import retained_history as retained
from app.maintenance import retained_schema as schema
from app.maintenance import retained_transition as transition
from tests import test_academy_product_adoption as product_tests
from tests.fixtures import product_adoption_entry as entry
from tests.fixtures.hosted_genesis import hosted_declaration

_actual_application_object = product_tests._actual_application_object
pytestmark = pytest.mark.usefixtures("_actual_application_object")
assert hosted_declaration


def _rich_retained(monkeypatch):
    original = entry._populate_retained

    def populate(connection):
        original(connection)
        # Deliberately different native SQLNULL/JSONnull, float8 and microsecond
        # timestamp payloads. Partial compounds remain legal under MATCH SIMPLE.
        connection.execute(
            sa.text(
                "UPDATE public.applicants SET assessment_score='-0'::float8,"
                "assessment_profile='null'::jsonb,assessment_answers=NULL,"
                "assessment_taken_at='2001-02-03 04:05:06.123456+00'::timestamptz,"
                "cohort_id=NULL,track_id=gen_random_uuid(),assessment_bank_id=NULL"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO public.applicants(id,tenant_id,email,first_name,last_name,cohort_id,track_id,"
                "assessment_bank_id,assessment_profile,assessment_answers) "
                "SELECT gen_random_uuid(),tenant_id,'partial@example.invalid','Partial','Compound',"
                "gen_random_uuid(),NULL,NULL,NULL,'null'::jsonb FROM public.applicants LIMIT 1"
            )
        )
        result = connection.execute(
            sa.text(
                "INSERT INTO public.applicants(id,tenant_id,email,first_name,last_name,cohort_id,track_id,assessment_bank_id) "
                "SELECT gen_random_uuid(),a.tenant_id,'complete@example.invalid','Complete','Compound',"
                "ct.cohort_id,ct.track_id,q.id FROM public.applicants a "
                "JOIN public.cohort_tracks ct ON ct.tenant_id=a.tenant_id "
                "JOIN public.question_banks q ON q.tenant_id=a.tenant_id LIMIT 1"
            )
        )
        assert result.rowcount == 1

    monkeypatch.setattr(entry, "_populate_retained", populate)


@contextmanager
def _sealed(declaration, tmp_path, monkeypatch):
    _rich_retained(monkeypatch)
    with product_tests._token_observed(declaration, tmp_path, monkeypatch) as (connection, handle):
        product._import_and_seal_learning(connection, handle)
        state = product._state_for(handle)
        login, effective = connection.execute(sa.text("SELECT session_user,current_user")).one()
        monkeypatch.setattr(settings, "migration_login_role", login)
        monkeypatch.setattr(settings, "migration_effective_role", effective)
        assert len(state.learning_association[0].tenant_ids) >= 2
        snapshot = state.learning_association[0]
        assert any(
            all(row.tenant_id != tenant for spec in history._TABLES for row in getattr(snapshot, spec.name))
            for tenant in snapshot.tenant_ids
        )
        assert all(table.rows for table in state.retained_fragment.tables)
        yield connection, handle


def _retained_ddl(connection):
    statements = []

    def before(_conn, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith('ALTER TABLE "PUBLIC".'):
            statements.append(statement)

    sa.event.listen(connection, "before_cursor_execute", before)
    return statements, before


def _assert_sticky(connection, handle):
    state = product._state_for(handle)
    assert state.poisoned is True
    assert state.retained_schema_unverified is True
    with pytest.raises(product.ProductAdoptionRefused):
        product._observe_retained_transition(connection, handle)
    with pytest.raises(product.ProductAdoptionRefused):
        product._run_retained_transition(connection, handle)


def test_actual_ordinary_a004_preserves_166_native_cells_47_catalogs_and_exact20_80(
    hosted_declaration, tmp_path, monkeypatch
):
    with _sealed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        state = product._state_for(handle)
        root = connection.get_transaction()
        fragment, raw, acks = state.retained_fragment, state.learning_raw, state.completion_acks
        before = schema._observe_historical_catalog(connection)
        old = transition._records(before, "ri_foreign_keys", schema._RI_FK_FIELDS)
        old_triggers = transition._records(before, "ri_triggers", schema._RI_TRIGGER_FIELDS)
        assert len(old) == 17 and len(old_triggers) == 68
        assert len(fragment.tables) == 11
        assert sum(len(columns) for _, _, columns in retained._ROW_SPEC) == 166
        assert len(before["indexes"]) == 49
        assert (
            connection.scalar(
                sa.text(
                    "SELECT count(*) FROM public.applicants WHERE assessment_profile='null'::jsonb "
                    "AND assessment_answers IS NULL AND encode(float8send(assessment_score),'hex')='8000000000000000'"
                )
            )
            > 0
        )
        statements, listener = _retained_ddl(connection)
        try:
            product._run_retained_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        pending = state.retained_transition
        assert pending.consumed is True and state.retained_runner is None
        assert state.phase == "retained adopted, checkpoint pending"
        assert state.retained_schema_unverified is False
        assert pending.fragment is fragment and pending.connection is connection and pending.root is root
        assert connection.get_transaction() is root and root.is_active
        assert retained._read_fixed_rows(connection) == fragment.tables
        assert state.learning_raw == raw and state.completion_acks == acks
        assert tuple((spec.name, history._raw_projection(connection, spec)) for spec in history._TABLES) == raw
        assert state.learning_capture is None and connection.info.get(history._STATE_KEY) is None
        assert len(pending.final["ri_foreign_keys"]) == 20 and len(pending.final["ri_triggers"]) == 80
        assert len(pending.new_fks) == 18 and len(pending.new_triggers) == 72
        final = transition._records(pending.final, "ri_foreign_keys", schema._RI_FK_FIELDS)
        preserved = {fk["oid"] for fk in old if fk["name"] in transition._PRESERVED}
        assert len(preserved) == 2
        assert tuple(fk for fk in final if fk["oid"] in preserved) == tuple(fk for fk in old if fk["oid"] in preserved)
        assert tuple(row for row in pending.final["ri_triggers"] if row[20] in preserved) == tuple(
            row for row in before["ri_triggers"] if row[20] in preserved
        )
        assert transition._version_rows(connection) == pending.after_versions
        assert (transition._A004,) in pending.after_versions and (transition._LR7,) not in pending.after_versions
        assert len(statements) == 33
        assert all(" DROP CONSTRAINT " in sql for sql in statements[:15])
        assert all(" ADD CONSTRAINT " in sql for sql in statements[15:])
        assert all('"party_persons"' in sql for sql in statements[-3:])
        product._continuity(connection, state)


@pytest.mark.parametrize("ordinal", range(1, 34))
def test_fault_after_each_actual_fk_ddl_poison_and_full_root_rollback(
    hosted_declaration, tmp_path, monkeypatch, ordinal
):
    with _sealed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        changes = []

        def after(_conn, _cursor, statement, _parameters, _context, _many):
            if statement.lstrip().upper().startswith('ALTER TABLE "PUBLIC".'):
                changes.append(statement)
                if len(changes) == ordinal:
                    raise RuntimeError("synthetic driver material must be suppressed")

        sa.event.listen(connection, "after_cursor_execute", after)
        try:
            with pytest.raises(product.ProductAdoptionRefused) as raised:
                product._run_retained_transition(connection, handle)
        finally:
            sa.event.remove(connection, "after_cursor_execute", after)
        assert "synthetic driver material" not in str(raised.value)
        assert len(changes) == ordinal
        state = product._state_for(handle)
        assert state.retained_transition.consumed is True
        _assert_sticky(connection, handle)
        # _prepared_product's independent same-resource rollback oracle checks
        # original public catalogs/rows/versions and absence of canonical schema.


@pytest.mark.parametrize("boundary", ["record", "version", "observe"])
@pytest.mark.parametrize("cancellation", [False, True])
def test_postmigration_and_native_cancellation_windows_cannot_be_retried(
    hosted_declaration, tmp_path, monkeypatch, boundary, cancellation
):
    class Cancelled(BaseException):
        pass

    error = Cancelled if cancellation else RuntimeError
    with _sealed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        seen = []
        if boundary == "version":
            ordinary = product.ordinary_migration_config

            def configuration():
                config = ordinary()

                def on_version_apply(*, ctx, step, heads, run_args):
                    if transition._A004 in heads:
                        assert product._state_for(handle).phase == "a004 recorded"
                        assert (
                            transition._version_rows(connection)
                            == product._state_for(handle).retained_transition.after_versions
                        )
                        seen.append(True)
                        raise error("synthetic post-version fault")

                config.attributes["on_version_apply"] = (on_version_apply,)
                return config

            monkeypatch.setattr(product, "ordinary_migration_config", configuration)
        else:
            name = "_record_retained_transition" if boundary == "record" else "_observe_retained_transition"
            actual = getattr(product, name)

            def fail_after(*args):
                actual(*args)
                seen.append(True)
                raise error("synthetic post-owner fault")

            monkeypatch.setattr(product, name, fail_after)
        expected = Cancelled if cancellation else product.ProductAdoptionRefused
        with pytest.raises(expected):
            product._run_retained_transition(connection, handle)
        assert seen == [True]
        state = product._state_for(handle)
        assert state.poisoned is True and state.retained_runner is None
        with pytest.raises(product.ProductAdoptionRefused):
            product._run_retained_transition(connection, handle)


@pytest.mark.parametrize(
    "attack", ["raw_prepare", "raw_consume", "raw_upgrade", "early_heads", "observe", "forged", "nested", "xid"]
)
def test_no_unobserved_direct_entry_or_early_head_can_mutate_retained_fks(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    with _sealed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        statements, listener = _retained_ddl(connection)
        nested = connection.begin_nested() if attack == "nested" else None
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                if attack == "raw_prepare":
                    product._prepare_retained_transition(connection, handle)
                elif attack == "raw_consume":
                    product._consume_retained_transition(connection)
                elif attack in ("raw_upgrade", "early_heads"):
                    config = product.ordinary_migration_config()
                    config.attributes["connection"] = connection
                    command.upgrade(config, transition._A004 if attack == "raw_upgrade" else "heads")
                elif attack == "observe":
                    product._observe_retained_transition(connection, handle)
                elif attack == "forged":
                    product._run_retained_transition(connection, object.__new__(product._Capture))
                else:
                    if attack == "xid":
                        product._state_for(handle).xid = "wrong-physical-xid"
                    product._run_retained_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
            if nested is not None:
                nested.rollback()
        assert statements == []
        _assert_sticky(connection, handle)


@pytest.mark.parametrize(
    "attack",
    [
        "retained_value",
        "learning_value",
        "nullable_ack",
        "target",
        "key",
        "role",
        "unrelated_ri",
        "extra_trigger",
        "canonical_trigger",
    ],
)
def test_data_target_security_or_unrelated_catalog_drift_refuses_before_ddl(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    with _sealed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        sql = {
            "retained_value": "UPDATE public.applicants SET assessment_profile='{}'::jsonb",
            "learning_value": "UPDATE public.course_completions SET updated_at=updated_at+interval '1 second'",
            "nullable_ack": "UPDATE public.course_completions SET erp_synced_at=now() WHERE erp_synced_at IS NULL",
            "target": "ALTER TABLE public.party_persons RENAME TO hidden_person_subtype",
            "key": "ALTER INDEX public.uq_parties_tenant_id_id RENAME TO hidden_tenant_party_key",
            "role": "GRANT SELECT ON public.notifications TO lab_worker",
            "unrelated_ri": "ALTER TABLE public.account_tokens ADD CONSTRAINT unexpected_retained_ri FOREIGN KEY(person_id) REFERENCES public.party_persons(party_id)",
            "extra_trigger": "CREATE TRIGGER a004_unexpected_trigger BEFORE INSERT ON public.notifications FOR EACH ROW EXECUTE FUNCTION public.a004_drift_trigger()",
            "canonical_trigger": "CREATE TRIGGER a004_unexpected_trigger BEFORE INSERT ON public.parties FOR EACH ROW EXECUTE FUNCTION public.a004_drift_trigger()",
        }[attack]
        if attack in ("extra_trigger", "canonical_trigger"):
            connection.execute(
                sa.text(
                    "CREATE FUNCTION public.a004_drift_trigger() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END;'"
                )
            )
        connection.execute(sa.text(sql))
        statements, listener = _retained_ddl(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_retained_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        _assert_sticky(connection, handle)


def test_copied_pending_entry_refuses_before_first_ddl(hosted_declaration, tmp_path, monkeypatch):
    with _sealed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        actual = product._consume_retained_transition

        def consume_copy(conn):
            issued = actual(conn)
            copied = copy(issued)
            assert copied is not issued
            return copied

        monkeypatch.setattr(product, "_consume_retained_transition", consume_copy)
        statements, listener = _retained_ddl(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_retained_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        _assert_sticky(connection, handle)


def test_downgrade_refuses_without_effects(hosted_declaration, tmp_path, monkeypatch):
    with _sealed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        product._run_retained_transition(connection, handle)
        before = schema._observe_historical_catalog(connection)
        versions = transition._version_rows(connection)
        scripts = ScriptDirectory.from_config(product.ordinary_migration_config())
        with pytest.raises(product.ProductAdoptionRefused, match="downgrade unsupported"):
            scripts.get_revision(transition._A004).module.downgrade()
        assert schema._observe_historical_catalog(connection) == before
        assert transition._version_rows(connection) == versions


def test_learning_unsealed_cannot_enter_a004(hosted_declaration, tmp_path, monkeypatch):
    with product_tests._token_observed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        statements, listener = _retained_ddl(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_retained_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        _assert_sticky(connection, handle)


def test_partial_history_refuses_capture_without_fresh_fallback(hosted_declaration, tmp_path, monkeypatch):
    original = entry._populate_retained
    entered = []

    def partial(connection):
        original(connection)
        connection.execute(sa.text("DROP TABLE public.platform_settings"))

    def forbidden(*args):
        entered.append(True)
        pytest.fail("partial history entered a004")

    monkeypatch.setattr(entry, "_populate_retained", partial)
    monkeypatch.setattr(transition, "_apply_retained_transition", forbidden)
    with pytest.raises(product.ProductAdoptionRefused):
        with product_tests._prepared_product(hosted_declaration, tmp_path, monkeypatch):
            pytest.fail("partial history issued a product handle")
    assert entered == []


def test_actual_driver_abort_is_suppressed_without_replacing_or_repairing_root(
    hosted_declaration, tmp_path, monkeypatch
):
    with _sealed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        root = connection.get_transaction()
        seen = []

        def after(conn, _cursor, statement, _parameters, _context, _many):
            if statement.lstrip().upper().startswith('ALTER TABLE "PUBLIC".') and not seen:
                seen.append(True)
                conn.execute(sa.text("SELECT 1/0"))

        sa.event.listen(connection, "after_cursor_execute", after)
        try:
            with pytest.raises(product.ProductAdoptionRefused) as raised:
                product._run_retained_transition(connection, handle)
        finally:
            sa.event.remove(connection, "after_cursor_execute", after)
        assert seen == [True]
        assert "division by zero" not in str(raised.value)
        assert connection.get_transaction() is root
        _assert_sticky(connection, handle)

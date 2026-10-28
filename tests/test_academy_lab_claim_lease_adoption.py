"""Actual populated historical a006 hosted canaries; AUTHORED, NOT RUN.

Every fixture reuses the genuine a004 sealed/adopted and a005 checkpoint
sequence under one disposable caller root. No commit, role substitution,
shim, drain or fresh issuer. The claim lease is one nullable column only.
"""

from contextlib import contextmanager
from copy import copy

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.script import ScriptDirectory
from app.maintenance import checkpoint_transition as checkpoint
from app.maintenance import lab_claim_lease_transition as lab_claim
from app.maintenance import learning_history as history
from app.maintenance import product_adoption as product
from app.maintenance import retained_history as retained_rows
from app.maintenance import retained_transition as transition
from sqlalchemy.exc import IntegrityError
from tests import test_academy_erp_checkpoint_adoption as checkpoint_tests
from tests import test_academy_product_adoption as product_tests
from tests import test_academy_retained_adoption as retained_tests
from tests.fixtures import product_adoption_entry as entry
from tests.fixtures.hosted_genesis import hosted_declaration

_actual_application_object = product_tests._actual_application_object
pytestmark = pytest.mark.usefixtures("_actual_application_object")
assert hosted_declaration


def _seed_lab_states(monkeypatch, *, claimed=False):
    original = entry._populate_retained

    def populate(connection):
        original(connection)
        # Terminal rows on distinct instances exist BEFORE capture, so the
        # original fragment/166 baseline already includes them.
        states = ("succeeded", "failed", "cancelled") + (("claimed",) if claimed else ())
        for state in states:
            name = f"a006-{state}"
            connection.execute(
                sa.text(
                    "INSERT INTO public.lab_instances(id,tenant_id,activity_id,person_id,instance_name) "
                    "SELECT gen_random_uuid(),tenant_id,gen_random_uuid(),person_id,:name "
                    "FROM public.lab_instances LIMIT 1"
                ),
                {"name": name},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO public.lab_operations(id,tenant_id,instance_id,kind,state) "
                    "SELECT gen_random_uuid(),tenant_id,id,'check',:state "
                    "FROM public.lab_instances WHERE instance_name=:name"
                ),
                {"state": state, "name": name},
            )
        counts = dict(
            connection.execute(sa.text("SELECT state,count(*) FROM public.lab_operations GROUP BY state")).all()
        )
        assert counts.get("queued", 0) > 0
        assert all(counts.get(state, 0) > 0 for state in ("succeeded", "failed", "cancelled"))
        assert counts.get("claimed", 0) == (1 if claimed else 0)

    monkeypatch.setattr(entry, "_populate_retained", populate)


@contextmanager
def _checkpoint_adopted(declaration, tmp_path, monkeypatch, *, claimed=False):
    _seed_lab_states(monkeypatch, claimed=claimed)
    with checkpoint_tests._adopted(declaration, tmp_path, monkeypatch) as (connection, handle):
        product._run_checkpoint_transition(connection, handle)
        state = product._state_for(handle)
        assert state.phase == "checkpoint adopted, final admission pending"
        assert state.checkpoint_unverified is False and state.lab_claim_unverified is True
        yield connection, handle


def _effects(connection):
    statements = []

    def before(_conn, _cursor, statement, _parameters, _context, _many):
        upper = statement.lstrip().upper()
        if upper.startswith("ALTER TABLE") and "LAB_OPERATIONS" in upper:
            statements.append(statement)

    sa.event.listen(connection, "before_cursor_execute", before)
    return statements, before


def _assert_sticky(connection, handle):
    state = product._state_for(handle)
    assert state.poisoned is True
    assert state.lab_claim_unverified is True
    with pytest.raises(product.ProductAdoptionRefused):
        product._observe_lab_claim_lease_transition(connection, handle)
    with pytest.raises(product.ProductAdoptionRefused):
        product._run_lab_claim_lease_transition(connection, handle)


def test_actual_ordinary_a006_adds_nullable_claim_lease_and_conserves_all_owners(
    hosted_declaration, tmp_path, monkeypatch
):
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        state = product._state_for(handle)
        root = connection.get_transaction()
        checkpoint_entry = state.checkpoint_transition
        retained_entry = state.retained_transition
        a004_final, a005_final = retained_entry.final, checkpoint_entry.final
        lab_oid = dict(state.oids)["lab_operations"]
        before_catalog = history._catalog(connection, lab_oid)
        raw_before = lab_claim._raw_rows(connection)
        assert sum(len(columns) for _, _, columns in retained_rows._ROW_SPEC) == 166
        assert len(state.catalogs) == 47
        statements, listener = _effects(connection)
        try:
            product._run_lab_claim_lease_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        entry = state.lab_claim_transition
        assert entry.consumed is True and state.lab_claim_runner is None
        assert state.phase == "lab claim lease adopted, final admission pending"
        assert state.lab_claim_unverified is False and state.checkpoint_unverified is False
        assert entry.checkpoint_entry is checkpoint_entry and entry.connection is connection
        assert entry.root is root and connection.get_transaction() is root and root.is_active
        assert retained_entry.final is a004_final and checkpoint_entry.final is a005_final
        assert entry.lab_catalog_before == before_catalog and entry.raw_lab_rows == raw_before
        assert entry.new_attnum == 21 and len(entry.new_check_oids) == 2
        catalog = history._catalog(connection, lab_oid)
        assert catalog.columns[20] == (21, "claim_lease_seconds", "integer", False, False, None, "", "", 0)
        assert catalog.columns[:20] == before_catalog.columns
        assert catalog.relation == before_catalog.relation
        assert catalog.relation[3:5] == (True, True)
        renderings = dict(
            connection.execute(
                sa.text(
                    "SELECT conname,pg_catalog.pg_get_expr(conbin,conrelid,false) "
                    "FROM pg_catalog.pg_constraint WHERE conrelid=:oid AND contype='c' "
                    "AND conname LIKE 'ck_lab_operations_claim_lease%'"
                ),
                {"oid": lab_oid},
            ).all()
        )
        assert renderings == lab_claim._RENDERINGS
        stamped = lab_claim._stamped_rows(connection)
        assert tuple(row[:20] for row in stamped) == raw_before
        assert all(row[20] is None for row in stamped)
        assert lab_claim._state_cohorts(raw_before)["claimed"] == frozenset()
        assert retained_rows._read_fixed_rows(connection) == state.retained_fragment.tables
        assert catalog.acl == before_catalog.acl and catalog.column_acl == before_catalog.column_acl
        expected_acl = {
            "academy_lab_worker": {"SELECT", "INSERT", "UPDATE"},
            "app_user": {"SELECT"},
            "platform_api": {"SELECT"},
            "outbox_dispatcher": set(),
            "platform_outbox_dispatcher": set(),
            "public": set(),
        }
        for role, expected in expected_acl.items():
            held = {
                priv
                for priv in ("SELECT", "INSERT", "UPDATE", "REFERENCES")
                if connection.scalar(
                    sa.text(
                        "SELECT pg_catalog.has_column_privilege(:role,"
                        "'public.lab_operations'::regclass,'claim_lease_seconds',:priv)"
                    ),
                    {"role": role, "priv": priv},
                )
            }
            assert held == expected
        assert entry.before_versions == checkpoint_entry.after_versions
        assert (lab_claim._A006,) in entry.after_versions
        assert (checkpoint._A005,) not in entry.after_versions
        assert transition._version_rows(connection) == entry.after_versions
        assert len(statements) == 3
        assert 'ADD COLUMN "claim_lease_seconds" integer NULL' in statements[0]
        assert "ck_lab_operations_claim_lease_positive" in statements[1]
        assert "ck_lab_operations_claim_lease_required" in statements[2]
        product._continuity(connection, state)


@pytest.mark.parametrize("ordinal", range(1, 4))
def test_fault_after_each_actual_lab_claim_effect_poisons_root(hosted_declaration, tmp_path, monkeypatch, ordinal):
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        changes = []

        def after(_conn, _cursor, statement, _parameters, _context, _many):
            upper = statement.lstrip().upper()
            if upper.startswith("ALTER TABLE") and "LAB_OPERATIONS" in upper:
                changes.append(statement)
                if len(changes) == ordinal:
                    raise RuntimeError("synthetic driver material must be suppressed")

        sa.event.listen(connection, "after_cursor_execute", after)
        try:
            with pytest.raises(product.ProductAdoptionRefused) as raised:
                product._run_lab_claim_lease_transition(connection, handle)
        finally:
            sa.event.remove(connection, "after_cursor_execute", after)
        assert "synthetic driver material" not in str(raised.value)
        assert len(changes) == ordinal
        assert product._state_for(handle).lab_claim_transition.consumed is True
        _assert_sticky(connection, handle)
        # _prepared_product's independent same-resource rollback oracle proves
        # the original 20-column lab_operations is restored after rollback.


@pytest.mark.parametrize("boundary", ["record", "version", "observe"])
@pytest.mark.parametrize("cancellation", [False, True])
def test_postmigration_and_native_cancellation_windows_cannot_be_retried(
    hosted_declaration, tmp_path, monkeypatch, boundary, cancellation
):
    class Cancelled(BaseException):
        pass

    error = Cancelled if cancellation else RuntimeError
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        seen = []
        if boundary == "version":
            ordinary = product.ordinary_migration_config

            def configuration():
                config = ordinary()

                def on_version_apply(*, ctx, step, heads, run_args):
                    if lab_claim._A006 in heads:
                        assert product._state_for(handle).phase == "a006 recorded"
                        assert (
                            transition._version_rows(connection)
                            == product._state_for(handle).lab_claim_transition.after_versions
                        )
                        seen.append(True)
                        raise error("synthetic post-version fault")

                config.attributes["on_version_apply"] = (on_version_apply,)
                return config

            monkeypatch.setattr(product, "ordinary_migration_config", configuration)
        else:
            name = (
                "_record_lab_claim_lease_transition" if boundary == "record" else "_observe_lab_claim_lease_transition"
            )
            actual = getattr(product, name)

            def fail_after(*args):
                actual(*args)
                seen.append(True)
                raise error("synthetic post-owner fault")

            monkeypatch.setattr(product, name, fail_after)
        expected = Cancelled if cancellation else product.ProductAdoptionRefused
        with pytest.raises(expected):
            product._run_lab_claim_lease_transition(connection, handle)
        assert seen == [True]
        state = product._state_for(handle)
        assert state.poisoned is True and state.lab_claim_runner is None
        with pytest.raises(product.ProductAdoptionRefused):
            product._run_lab_claim_lease_transition(connection, handle)


@pytest.mark.parametrize(
    "attack", ["raw_prepare", "raw_consume", "raw_upgrade", "early_heads", "observe", "forged", "nested", "xid"]
)
def test_no_unobserved_direct_entry_or_early_head_can_add_claim_lease(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        statements, listener = _effects(connection)
        nested = connection.begin_nested() if attack == "nested" else None
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                if attack == "raw_prepare":
                    product._prepare_lab_claim_lease_transition(connection, handle)
                elif attack == "raw_consume":
                    product._consume_lab_claim_lease_transition(connection)
                elif attack in ("raw_upgrade", "early_heads"):
                    config = product.ordinary_migration_config()
                    config.attributes["connection"] = connection
                    command.upgrade(config, lab_claim._A006 if attack == "raw_upgrade" else "heads")
                elif attack == "observe":
                    product._observe_lab_claim_lease_transition(connection, handle)
                elif attack == "forged":
                    product._run_lab_claim_lease_transition(connection, object.__new__(product._Capture))
                else:
                    if attack == "xid":
                        product._state_for(handle).xid = "wrong-physical-xid"
                    product._run_lab_claim_lease_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
            if nested is not None:
                nested.rollback()
        assert statements == []
        _assert_sticky(connection, handle)


def test_unobserved_a005_cannot_enter_a006(hosted_declaration, tmp_path, monkeypatch):
    with retained_tests._sealed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        statements, listener = _effects(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_lab_claim_lease_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        _assert_sticky(connection, handle)
    with checkpoint_tests._adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        statements, listener = _effects(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_lab_claim_lease_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        _assert_sticky(connection, handle)


def test_claimed_row_refuses_before_ddl_without_backfill(hosted_declaration, tmp_path, monkeypatch):
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch, claimed=True) as (connection, handle):
        statements, listener = _effects(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_lab_claim_lease_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        claimed = connection.scalar(sa.text("SELECT count(*) FROM public.lab_operations WHERE state='claimed'"))
        assert claimed == 1
        _assert_sticky(connection, handle)


@pytest.mark.parametrize(
    "attack",
    ["column", "column_wrong_type", "column_default", "check_name", "dropped_check", "row_mutation", "stamp"],
)
def test_preexisting_column_or_check_or_lab_drift_refuses_before_effects(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        if attack == "column":
            connection.execute(sa.text("ALTER TABLE public.lab_operations ADD COLUMN claim_lease_seconds integer"))
        elif attack == "column_wrong_type":
            connection.execute(sa.text("ALTER TABLE public.lab_operations ADD COLUMN claim_lease_seconds text"))
        elif attack == "column_default":
            connection.execute(
                sa.text("ALTER TABLE public.lab_operations ADD COLUMN claim_lease_seconds integer DEFAULT 7")
            )
        elif attack == "check_name":
            connection.execute(
                sa.text(
                    "ALTER TABLE public.lab_operations ADD CONSTRAINT ck_lab_operations_claim_lease_positive "
                    "CHECK (attempts >= 0)"
                )
            )
        elif attack == "dropped_check":
            connection.execute(sa.text("ALTER TABLE public.lab_operations DROP CONSTRAINT ck_lab_operations_kind"))
        elif attack == "row_mutation":
            connection.execute(sa.text("UPDATE public.lab_operations SET kind='destroy' WHERE state='queued'"))
        else:
            connection.execute(
                sa.text("INSERT INTO public.alembic_version(version_num) VALUES ('a006_lab_claim_lease')")
            )
        statements, listener = _effects(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_lab_claim_lease_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        _assert_sticky(connection, handle)


@pytest.mark.parametrize(
    "attack",
    ["queued_stamp", "terminal_stamp", "default", "type", "drop_check", "replace_check", "column_grant", "index"],
)
def test_lab_claim_tamper_refuses_continuity_without_rebasing_a004_a005_finals(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        product._run_lab_claim_lease_transition(connection, handle)
        state = product._state_for(handle)
        entry = state.lab_claim_transition
        final, attnum, check_oids = entry.final, entry.new_attnum, entry.new_check_oids
        a004_final = state.retained_transition.final
        a005_final = state.checkpoint_transition.final
        if attack == "queued_stamp":
            result = connection.execute(
                sa.text("UPDATE public.lab_operations SET claim_lease_seconds=5 WHERE state='queued'")
            )
            assert result.rowcount > 0
        elif attack == "terminal_stamp":
            result = connection.execute(
                sa.text("UPDATE public.lab_operations SET claim_lease_seconds=5 WHERE state='succeeded'")
            )
            assert result.rowcount > 0
        elif attack == "default":
            connection.execute(
                sa.text("ALTER TABLE public.lab_operations ALTER COLUMN claim_lease_seconds SET DEFAULT 7")
            )
        elif attack == "type":
            connection.execute(
                sa.text("ALTER TABLE public.lab_operations ALTER COLUMN claim_lease_seconds TYPE bigint")
            )
        elif attack == "drop_check":
            connection.execute(
                sa.text("ALTER TABLE public.lab_operations DROP CONSTRAINT ck_lab_operations_claim_lease_positive")
            )
        elif attack == "replace_check":
            connection.execute(
                sa.text("ALTER TABLE public.lab_operations DROP CONSTRAINT ck_lab_operations_claim_lease_positive")
            )
            connection.execute(
                sa.text(
                    "ALTER TABLE public.lab_operations ADD CONSTRAINT ck_lab_operations_claim_lease_positive "
                    "CHECK (claim_lease_seconds IS NULL OR claim_lease_seconds > 1)"
                )
            )
        elif attack == "column_grant":
            connection.execute(sa.text("GRANT INSERT(claim_lease_seconds) ON public.lab_operations TO app_user"))
        else:
            connection.execute(sa.text("CREATE INDEX a006_drift_index ON public.lab_operations(claim_lease_seconds)"))
        with pytest.raises(product.ProductAdoptionRefused):
            product._continuity(connection, state)
        assert entry.final is final and entry.new_attnum is attnum and entry.new_check_oids is check_oids
        assert state.retained_transition.final is a004_final
        assert state.checkpoint_transition.final is a005_final


def test_check_semantics_and_web_worker_column_boundaries(hosted_declaration, tmp_path, monkeypatch):
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        product._run_lab_claim_lease_transition(connection, handle)
        state = product._state_for(handle)
        insert = (
            "INSERT INTO public.lab_operations(id,tenant_id,instance_id,kind,state,claim_lease_seconds) "
            "SELECT gen_random_uuid(),tenant_id,id,'check',:state,:stamp FROM public.lab_instances "
            "WHERE instance_name='a006-succeeded'"
        )
        for row_state, stamp in (("claimed", None), ("queued", 0), ("queued", -1)):
            with pytest.raises(IntegrityError):
                with connection.begin_nested():
                    connection.execute(sa.text(insert), {"state": row_state, "stamp": stamp})
        for row_state, stamp in (("claimed", 600), ("queued", None), ("succeeded", 600)):
            nested = connection.begin_nested()
            result = connection.execute(sa.text(insert), {"state": row_state, "stamp": stamp})
            assert result.rowcount == 1
            nested.rollback()
        expected_acl = {
            "academy_lab_worker": {"SELECT", "INSERT", "UPDATE"},
            "app_user": {"SELECT"},
            "platform_api": {"SELECT"},
            "outbox_dispatcher": set(),
            "platform_outbox_dispatcher": set(),
        }
        for role, expected in expected_acl.items():
            held = {
                priv
                for priv in ("SELECT", "INSERT", "UPDATE", "REFERENCES")
                if connection.scalar(
                    sa.text(
                        "SELECT pg_catalog.has_column_privilege(:role,"
                        "'public.lab_operations'::regclass,'claim_lease_seconds',:priv)"
                    ),
                    {"role": role, "priv": priv},
                )
            }
            assert held == expected
        product._continuity(connection, state)


def test_copied_pending_entry_refuses_before_first_effect(hosted_declaration, tmp_path, monkeypatch):
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        actual = product._consume_lab_claim_lease_transition

        def consume_copy(conn):
            issued = actual(conn)
            copied = copy(issued)
            assert copied is not issued
            return copied

        monkeypatch.setattr(product, "_consume_lab_claim_lease_transition", consume_copy)
        statements, listener = _effects(connection)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._run_lab_claim_lease_transition(connection, handle)
        finally:
            sa.event.remove(connection, "before_cursor_execute", listener)
        assert statements == []
        _assert_sticky(connection, handle)


def test_downgrade_refuses_without_effects(hosted_declaration, tmp_path, monkeypatch):
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        product._run_lab_claim_lease_transition(connection, handle)
        rows = lab_claim._stamped_rows(connection)
        versions = transition._version_rows(connection)
        scripts = ScriptDirectory.from_config(product.ordinary_migration_config())
        with pytest.raises(product.ProductAdoptionRefused, match="downgrade unsupported"):
            scripts.get_revision(lab_claim._A006).module.downgrade()
        assert lab_claim._stamped_rows(connection) == rows
        assert transition._version_rows(connection) == versions


def test_actual_driver_abort_is_suppressed_without_replacing_or_repairing_root(
    hosted_declaration, tmp_path, monkeypatch
):
    with _checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        root = connection.get_transaction()
        seen = []

        def after(conn, _cursor, statement, _parameters, _context, _many):
            upper = statement.lstrip().upper()
            if upper.startswith("ALTER TABLE") and "ADD COLUMN" in upper and not seen:
                seen.append(True)
                conn.execute(sa.text("SELECT 1/0"))

        sa.event.listen(connection, "after_cursor_execute", after)
        try:
            with pytest.raises(product.ProductAdoptionRefused) as raised:
                product._run_lab_claim_lease_transition(connection, handle)
        finally:
            sa.event.remove(connection, "after_cursor_execute", after)
        assert seen == [True]
        assert "division by zero" not in str(raised.value)
        assert connection.get_transaction() is root
        _assert_sticky(connection, handle)

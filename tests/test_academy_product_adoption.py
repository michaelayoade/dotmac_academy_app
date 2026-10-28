"""Actual frozen62/installed owner hosted canaries; AUTHORED, NOT RUN.

The real replay fixture supplies synthetic populations on actual PostgreSQL.
No source Person shim, replacement package, stamp/create_all or local Docker.
"""

from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import dotmac_learning as learning
import pytest
import sqlalchemy as sa
from dotmac_kernel.migrations import versions_dir as kernel_versions
from dotmac_kernel.prerequisites import (
    MODULE_DATABASE_ROLES_V1,
    PARTY_PERSON_CATALOG_V1,
    TENANT_AUDIT_LOG_V1,
    TENANT_SCOPE_CATALOG_V1,
    PrerequisiteBinding,
    install_prerequisite_bindings,
    installed_bindings,
)
from dotmac_learning.migrations import versions_dir as learning_versions

from alembic import command
from app.maintenance import account_token_identity as tokens
from app.maintenance import learning_history as history
from app.maintenance import product_adoption as product
from app.maintenance import retained_history as retained
from app.maintenance import retained_hosted_genesis as hosted
from app.maintenance.identity_history import IdentityHistoryImportRefused, import_academy_identity_history
from tests import test_academy_identity_history as identity_tests
from tests import test_academy_learning_history as learning_tests
from tests.fixtures import product_adoption_entry as entry
from tests.fixtures.hosted_genesis import hosted_declaration, qualified_root, replayed_owner
from tests.fixtures.kernel_identity_entry.rehearsal import config_for, plan_entry, verify_legacy_source
from tests.test_kernel_identity_entry import public_footprint

assert hosted_declaration


def _actual_bindings():
    return (
        PrerequisiteBinding(TENANT_SCOPE_CATALOG_V1.name, "0001_initial_tenant_schema", "kernel"),
        PrerequisiteBinding(MODULE_DATABASE_ROLES_V1.name, "0001_initial_tenant_schema", "kernel"),
        PrerequisiteBinding(PARTY_PERSON_CATALOG_V1.name, "0003_party_identity", "kernel"),
        PrerequisiteBinding(TENANT_AUDIT_LOG_V1.name, "0029_audit_history_shape", "kernel"),
    )


@pytest.fixture(autouse=True)
def _actual_application_object():
    # Ordinary fixture evaluation precedes every test and every resource creation.
    # Retain the plain app only; no client, lifespan entry, HTTP or DSN retarget.
    from dotmac_kernel import audit_actions

    from app.kernel_runtime import create_academy_app

    app = create_academy_app()
    registry = audit_actions.active_audit_actions()
    registry.require("identity.history_imported")
    assert registry.owner("identity.history_imported") == "kernel"
    return app


@contextmanager
def _prepared_product(declaration, tmp_path, monkeypatch):
    verify_legacy_source()
    prior = installed_bindings()
    bindings = _actual_bindings()
    before = None

    def rollback_oracle(connection):
        assert before is not None
        assert public_footprint(connection) == before
        assert connection.scalar(sa.text("SELECT to_regnamespace('mod_learning')")) is None
        assert connection.scalar(sa.text("SELECT to_regclass('public.parties')")) is None

    install_prerequisite_bindings(bindings)
    try:
        with replayed_owner(declaration, "assembly", tmp_path / "replay") as owner:
            with qualified_root(owner, _after_rollback=rollback_oracle) as (connection, root, context, environment):
                # Baseline belongs to this exact still-open resource, BEFORE canaries.
                before = public_footprint(connection)
                entry._synthetic_source_setup(connection)
                learning_tests._seed_all_source_fields(connection)
                entry._synthetic_tokens(connection)
                entry._populate_retained(connection)
                seeded_token_ids = tuple(
                    connection.scalars(sa.text("SELECT id FROM public.account_tokens ORDER BY id"))
                )
                assert seeded_token_ids
                learning_tests._lock_complete_source(connection)
                plan = plan_entry(connection)
                handle = product._capture_product_history(connection, environment, _hosted_context=context)
                state = product._state_for(handle)
                try:
                    assert state.token_entry.catalog.ids
                    assert tuple(row[0] for row in state.token_entry.catalog.ids) == seeded_token_ids
                    assert dict(state.cohorts)["account_tokens"] == tuple(
                        (identifier,) for identifier in seeded_token_ids
                    )
                    entry.create_token_oracle(connection)
                    expected, operation = entry.prepare_relocated_identity(connection, plan, tmp_path)
                    assert connection.get_transaction() is root and root.is_active
                    yield connection, handle, expected, operation
                finally:
                    entry.clear_value_oracle(connection)
                    if product._HANDLES.get(handle) is not None:
                        product._dispose_product_history(connection, handle)
    finally:
        install_prerequisite_bindings(prior)


def _import_identity(connection, handle, expected, operation):
    receipt = import_academy_identity_history(connection, expected, operation)
    product._observe_identity_import(connection, handle)
    state = product._state_for(handle)
    assert state.identity_association[1] is receipt
    tokens.authorize_historical_account_token_adoption(connection, state.token_entry, receipt)


def _upgrade_tokens(connection, tmp_path):
    applied = []
    cfg = config_for(connection, identity_tests.ASSEMBLY, tmp_path / "product-learning", applied)
    cfg.set_main_option(
        "version_locations", " ".join(map(str, (kernel_versions(), identity_tests.ASSEMBLY, learning_versions())))
    )
    command.upgrade(cfg, "a003_account_token_identity")
    return cfg, applied


@contextmanager
def _token_observed(declaration, tmp_path, monkeypatch):
    with _prepared_product(declaration, tmp_path, monkeypatch) as (connection, handle, expected, operation):
        _import_identity(connection, handle, expected, operation)
        cfg, applied = _upgrade_tokens(connection, tmp_path)
        product._observe_account_token_adoption(connection, handle)
        assert tokens._issued(connection) is None
        command.upgrade(cfg, "learning@head")
        assert any(item.revision == "lr_0006_delivery_support" for item in applied)
        yield connection, handle


def test_real47_identity_immediate_a003_public_import_and_independent_learning_seal(
    hosted_declaration, tmp_path, monkeypatch
):
    with _token_observed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        root = connection.get_transaction()
        state = product._state_for(handle)
        assert len(state.oids) == len(state.catalogs) == len(state.cohorts) == 47
        assert len(state.provenance[0]) == 62
        fragment = state.retained_fragment
        assert len(fragment.tables) == 11
        assert sum(len(columns) for _, _, columns in retained._ROW_SPEC) == 166
        assert all(table.rows for table in fragment.tables)
        assert retained._read_fixed_rows(connection) == fragment.tables
        capture = state.learning_capture
        raw = history._verify_source(connection, capture).raw_rows
        acks = history._completion_ack_history(connection, capture)
        assert any(row.erp_synced_at is None for row in acks)
        assert any(row.erp_synced_at is not None for row in acks)
        product._import_and_seal_learning(connection, handle)
        assert state.phase == "Learning sealed, retained adoption pending"
        assert state.retained_schema_unverified is True
        assert state.learning_capture is None
        assert retained._read_fixed_rows(connection) == fragment.tables
        assert state.learning_raw == raw and state.completion_acks == acks
        assert connection.info.get(history._STATE_KEY) is None
        assert len(state.learning_association[2].row_counts) == 27
        assert connection.get_transaction() is root and root.is_active
        with pytest.raises(product.ProductAdoptionRefused):
            product._import_and_seal_learning(connection, handle)
        assert state.poisoned is True


@pytest.mark.parametrize("attack", ["forged", "dto", "phase", "wrong_connection", "nested", "xid"])
def test_forged_context_phase_or_driver_root_refuses_and_poison_is_sticky(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    with _prepared_product(hosted_declaration, tmp_path, monkeypatch) as (connection, handle, expected, operation):
        if attack == "forged":
            supplied = object.__new__(product._Capture)
        elif attack == "dto":
            supplied = SimpleNamespace(verified=True, phase="captured", root=connection.get_transaction())
        else:
            supplied = handle
        nested = connection.begin_nested() if attack == "nested" else None
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                if attack == "wrong_connection":
                    with replayed_owner(hosted_declaration, "history", tmp_path / "wrong-connection") as other_owner:
                        with qualified_root(other_owner) as (other, _, __, ___):
                            product._observe_identity_import(other, supplied)
                elif attack == "phase":
                    product._import_and_seal_learning(connection, supplied)
                elif attack == "xid":
                    # No root commit: inject observed physical-XID mismatch.
                    state = product._state_for(handle)
                    state.xid = "deliberately-wrong-physical-xid"
                    product._observe_identity_import(connection, supplied)
                else:
                    product._observe_identity_import(connection, supplied)
        finally:
            if nested is not None:
                nested.rollback()
        assert product._state_for(handle).poisoned is True
        writes = []
        registrations = []
        root = connection.get_transaction()
        actual_registration = product._register_identity_import

        def register_then_refuse(*args, **kwargs):
            registrations.append(True)
            return actual_registration(*args, **kwargs)

        monkeypatch.setattr(product, "_register_identity_import", register_then_refuse)

        def before_cursor_execute(_connection, _cursor, statement, _parameters, _context, _executemany):
            if statement.lstrip().split(None, 1)[0].upper() in {"INSERT", "UPDATE", "DELETE", "MERGE", "COPY"}:
                writes.append(True)

        sa.event.listen(connection, "before_cursor_execute", before_cursor_execute)
        try:
            # The genuine pre-write registration refuses this poisoned handle.
            with pytest.raises(IdentityHistoryImportRefused):
                import_academy_identity_history(connection, expected, operation)
        finally:
            sa.event.remove(connection, "before_cursor_execute", before_cursor_execute)
        assert writes == []
        assert registrations == [True]
        assert connection.get_transaction() is root and root.is_active
        assert product._state_for(handle).identity_verification is None
        assert product._state_for(handle).poisoned is True
        with pytest.raises(product.ProductAdoptionRefused):
            product._observe_identity_import(connection, handle)
        assert product._state_for(handle).poisoned is True


def test_receipt_consumed_outside_product_cannot_be_replayed(hosted_declaration, tmp_path, monkeypatch):
    with _prepared_product(hosted_declaration, tmp_path, monkeypatch) as (connection, handle, expected, operation):
        _import_identity(connection, handle, expected, operation)
        _upgrade_tokens(connection, tmp_path)
        state = product._state_for(handle)
        receipt = tokens.account_token_identity_receipt(connection, state.token_entry)
        assert receipt.identity_import_receipt is state.identity_association[1]
        with pytest.raises(product.ProductAdoptionRefused):
            product._observe_account_token_adoption(connection, handle)
        assert state.poisoned is True


@pytest.mark.parametrize("mutation", ["learning_catalog", "retained_catalog", "ack", "token_cohort", "fake_dto"])
def test_late_failure_rolls_back_real_owners_and_all_canonical_storage(
    hosted_declaration, tmp_path, monkeypatch, mutation
):
    with pytest.raises(product.ProductAdoptionRefused):
        with _token_observed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
            state = product._state_for(handle)
            if mutation == "learning_catalog":
                connection.execute(sa.text("ALTER TABLE public.learning_events ADD COLUMN unexpected integer"))
            elif mutation == "retained_catalog":
                connection.execute(sa.text("ALTER TABLE public.notifications ADD COLUMN unexpected integer"))
            elif mutation == "ack":
                connection.execute(sa.text("UPDATE public.course_completions SET erp_synced_at=now()"))
            elif mutation == "token_cohort":
                captured_ids = {row[0] for row in dict(state.cohorts)["account_tokens"]}
                assert captured_ids
                removed_ids = set(connection.scalars(sa.text("DELETE FROM public.account_tokens RETURNING id")))
                assert removed_ids == captured_ids
                assert len(removed_ids) > 0
            else:
                # A complete public DTO without actual writes must fail the
                # independent real canonical verifier, despite valid-looking facts.
                snapshot = history._export_learning_history(connection, state.learning_capture)
                fake_verification = learning.VerificationObservationV5(
                    version=5,
                    tenant_ids=snapshot.tenant_ids,
                    row_counts=tuple(
                        learning.RowCountObservation(table=name, count=len(getattr(snapshot, name)))
                        for name in history._SOURCE_NAMES
                    ),
                )
                fake = learning.ImportObservationV5(
                    version=5, verification=fake_verification, inserted_rows=fake_verification.row_counts
                )
                monkeypatch.setattr(learning, "import_snapshot_v5", lambda *_: replace(fake))
            product._import_and_seal_learning(connection, handle)


@pytest.mark.parametrize("boundary", ["receipt_return", "before_import", "after_import", "after_verify"])
def test_postreceipt_token_field_drift_refuses_and_repair_cannot_clear_poison(
    hosted_declaration, tmp_path, monkeypatch, boundary
):
    completed = False
    drifted = False
    with pytest.raises(product.ProductAdoptionRefused):
        with _prepared_product(hosted_declaration, tmp_path, monkeypatch) as (connection, handle, expected, operation):
            _import_identity(connection, handle, expected, operation)
            cfg, _ = _upgrade_tokens(connection, tmp_path)
            state = product._state_for(handle)
            issued = tokens._issued(connection)
            assert issued is state.identity_association[2]
            root = connection.get_transaction()
            captured_ids = tuple(row[0] for row in dict(state.cohorts)["account_tokens"])
            assert captured_ids

            def drift(connection):
                nonlocal drifted
                # Synthetic fixture rows only; no token material leaves PostgreSQL.
                changed = tuple(
                    sorted(
                        connection.scalars(
                            sa.text(
                                "UPDATE public.account_tokens "
                                "SET updated_at=COALESCE(updated_at,now())+interval '1 microsecond' RETURNING id"
                            )
                        )
                    )
                )
                assert changed == captured_ids
                assert (
                    tuple(connection.scalars(sa.text("SELECT id FROM public.account_tokens ORDER BY id")))
                    == captured_ids
                )

                drifted = True

            if boundary == "receipt_return":
                real_receipt = tokens.account_token_identity_receipt

                def receipt_then_drift(connection, entry):
                    receipt = real_receipt(connection, entry)
                    assert tokens._issued(connection) is None
                    drift(connection)
                    return receipt

                monkeypatch.setattr(tokens, "account_token_identity_receipt", receipt_then_drift)
            try:
                product._observe_account_token_adoption(connection, handle)
                assert tokens._issued(connection) is None
                command.upgrade(cfg, "learning@head")
                if boundary == "before_import":
                    drift(connection)
                elif boundary == "after_import":
                    real_import = learning.import_snapshot_v5

                    def import_then_drift(connection, snapshot):
                        observation = real_import(connection, snapshot)
                        drift(connection)
                        return observation

                    monkeypatch.setattr(learning, "import_snapshot_v5", import_then_drift)
                elif boundary == "after_verify":
                    real_verify = history._verify_canonical_learning_history

                    def verify_then_drift(connection, capture):
                        observation = real_verify(connection, capture)
                        drift(connection)
                        return observation

                    monkeypatch.setattr(history, "_verify_canonical_learning_history", verify_then_drift)
                product._import_and_seal_learning(connection, handle)
            except product.ProductAdoptionRefused:
                assert drifted is True
                assert state.token_association[0] is issued
                assert issued.refused is True and state.poisoned is True
                assert connection.get_transaction() is root and root.is_active
                entry.restore_token_oracle(connection)
                assert entry.token_rows_match(connection, issued)
                retry = (
                    product._observe_account_token_adoption
                    if boundary == "receipt_return"
                    else product._import_and_seal_learning
                )
                with pytest.raises(product.ProductAdoptionRefused):
                    retry(connection, handle)
                assert issued.refused is True and state.poisoned is True
                completed = True
                raise
    assert completed is True


def test_disposal_clears_material_without_ending_root_or_allowing_recapture(hosted_declaration, tmp_path, monkeypatch):
    with _token_observed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        state = product._state_for(handle)
        product._import_and_seal_learning(connection, handle)
        root = connection.get_transaction()
        product._dispose_product_history(connection, handle)
        assert all(getattr(state, name) is None for name in product._State.__dataclass_fields__)
        assert connection.get_transaction() is root and root.is_active
        with pytest.raises(product.ProductAdoptionRefused):
            product._capture_product_history(connection)
        # The enclosing fixture disposes only an outstanding issued handle.


@pytest.mark.parametrize("restart", ["sqlalchemy_root", "physical_xid"])
def test_actual_root_rollback_new_capture_and_readonly_physical_restart(
    hosted_declaration, tmp_path, monkeypatch, restart
):
    with _prepared_product(hosted_declaration, tmp_path / "old", monkeypatch) as (connection, old, _, __):
        state = product._state_for(old)
        environment, context = state.hosted_bindings, state.hosted_context
        root = connection.get_transaction()
        if restart == "sqlalchemy_root":
            root.rollback()
            root = connection.begin()
        else:
            # Roll back at the driver too: this test never commits adoption.
            connection.connection.driver_connection.rollback()
            assert connection.get_transaction() is root and root.is_active
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._observe_identity_import(connection, old)
            assert state.poisoned is True
            with pytest.raises(product.ProductAdoptionRefused):
                product._capture_product_history(connection, environment, _hosted_context=context)
        finally:
            if root.is_active:
                root.rollback()
    # One-root owner cannot renew qualification. Success requires a FRESH resource.
    with _prepared_product(hosted_declaration, tmp_path / "fresh", monkeypatch) as (_, new, __, ___):
        assert new is not old
        assert product._state_for(new).poisoned is False


@pytest.mark.parametrize("mutation", ["catalog_after_import", "ack_after_verify"])
def test_drift_inside_actual_owner_calls_refuses_after_real_learning_writes(
    hosted_declaration, tmp_path, monkeypatch, mutation
):
    with pytest.raises(product.ProductAdoptionRefused):
        with _token_observed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
            if mutation == "catalog_after_import":
                real_import = learning.import_snapshot_v5

                def import_then_drift(connection, snapshot):
                    observation = real_import(connection, snapshot)
                    connection.execute(sa.text("ALTER TABLE public.learning_events ADD COLUMN late_drift integer"))
                    return observation

                monkeypatch.setattr(learning, "import_snapshot_v5", import_then_drift)
            else:
                real_verify = history._verify_canonical_learning_history

                def verify_then_drift(connection, capture):
                    observation = real_verify(connection, capture)
                    connection.execute(sa.text("UPDATE public.course_completions SET erp_synced_at=now()"))
                    return observation

                monkeypatch.setattr(history, "_verify_canonical_learning_history", verify_then_drift)
            product._import_and_seal_learning(connection, handle)


def test_actual_complete_composed_graph_resolves_installed_learning_prerequisites(
    hosted_declaration, tmp_path, monkeypatch
):
    with _prepared_product(hosted_declaration, tmp_path, monkeypatch) as (_, handle, __, ___):
        state = product._state_for(handle)
        assert state.provenance == product._provenance()
        graph, heads = state.provenance[4]
        by_revision = {row[0]: row for row in graph}
        expected = {
            dict(row[3])["revision"]
            for inventory in (state.provenance[2][2], state.provenance[1], state.provenance[3][2])
            for row in inventory
            if row[0] != "__init__.py"
        }
        assert set(by_revision) == expected
        assert {"0001_initial_tenant_schema", "0003_party_identity", "0029_audit_history_shape"} <= expected
        assert "a003_account_token_identity" in expected and "lr_0006_delivery_support" in expected
        assert "a004_retained_learning_refs" in expected and "lr_0007_enrollment_state_policy" in expected
        assert by_revision["a004_retained_learning_refs"][1:] == (
            "a003_account_token_identity", "lr_0007_enrollment_state_policy"
        )
        assert "a005_erp_completion_checkpoint" in expected
        assert by_revision["a005_erp_completion_checkpoint"][1:] == ("a004_retained_learning_refs", None)
        assert "a006_lab_claim_lease" in expected
        assert by_revision["a006_lab_claim_lease"][1:] == ("a005_erp_completion_checkpoint", None)
        assert heads
        assert installed_bindings() == tuple(sorted(_actual_bindings(), key=lambda binding: binding.prerequisite))
        assert any(row[2] for row in graph if row[0].startswith("lr_"))


def test_missing_bound_provider_is_refused_by_actual_learning_graph(hosted_declaration, tmp_path, monkeypatch):
    with _prepared_product(hosted_declaration, tmp_path, monkeypatch) as (connection, handle, expected, operation):
        _import_identity(connection, handle, expected, operation)
        cfg, _ = _upgrade_tokens(connection, tmp_path)
        product._observe_account_token_adoption(connection, handle)
        command.upgrade(cfg, "learning@head")
        valid = installed_bindings()
        missing_provider = tuple(
            replace(binding, provider_revision="absent_bound_kernel_provider")
            if binding.prerequisite == PARTY_PERSON_CATALOG_V1.name
            else binding
            for binding in valid
        )
        install_prerequisite_bindings(missing_provider)
        try:
            with pytest.raises(product.ProductAdoptionRefused):
                product._import_and_seal_learning(connection, handle)
            assert product._state_for(handle).poisoned is True
        finally:
            install_prerequisite_bindings(valid)


@pytest.mark.parametrize(
    "attack", ["missing", "forged", "exchanged", "missing_lock", "schema", "environment", "cancel"]
)
def test_initial_gates_require_actual_hosted_context_and_failure_is_terminal(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    class CancelCapture(BaseException):
        pass

    prior = installed_bindings()
    install_prerequisite_bindings(_actual_bindings())
    try:
        with replayed_owner(hosted_declaration, "assembly", tmp_path / "capture") as owner:
            with qualified_root(owner) as (connection, root, context, bindings):
                names = product._LOCK_NAMES
                if attack == "missing_lock":
                    names = tuple(name for name in names if name != "notifications")
                connection.execute(
                    sa.text(
                        "LOCK TABLE "
                        + ",".join('public."' + name + '"' for name in names)
                        + " IN ACCESS EXCLUSIVE MODE"
                    )
                )
                supplied = None if attack == "missing" else SimpleNamespace() if attack == "forged" else context
                if attack == "schema":
                    connection.execute(sa.text("ALTER TABLE public.notifications ADD COLUMN forbidden integer"))
                if attack == "environment":
                    connection.execute(sa.text("GRANT SELECT ON public.notifications TO PUBLIC"))
                real_capture = retained._capture_retained_rows
                if attack == "cancel":

                    def capture_then_cancel(*args, **kwargs):
                        real_capture(*args, **kwargs)
                        raise CancelCapture()

                    monkeypatch.setattr(retained, "_capture_retained_rows", capture_then_cancel)
                expected_error = CancelCapture if attack == "cancel" else product.ProductAdoptionRefused
                if attack == "exchanged":
                    with replayed_owner(hosted_declaration, "history", tmp_path / "exchange") as other_owner:
                        with qualified_root(other_owner) as (_, __, other_context, ___):
                            with pytest.raises(expected_error):
                                product._capture_product_history(connection, bindings, _hosted_context=other_context)
                else:
                    with pytest.raises(expected_error):
                        product._capture_product_history(connection, bindings, _hosted_context=supplied)
                assert owner.poisoned is True
                assert connection.get_transaction() is root and root.is_active
                assert not any(
                    pointer() is not None and pointer().connection is connection
                    for pointer in product._HANDLES.values()
                )
                if attack == "schema":
                    connection.execute(sa.text("ALTER TABLE public.notifications DROP COLUMN forbidden"))
                if attack == "environment":
                    connection.execute(sa.text("REVOKE SELECT ON public.notifications FROM PUBLIC"))
                # Repair and exact genuine context never renew the same root.
                with pytest.raises(product.ProductAdoptionRefused):
                    product._capture_product_history(connection, bindings, _hosted_context=context)
                assert owner.poisoned is True
    finally:
        install_prerequisite_bindings(prior)


@pytest.mark.parametrize("boundary", ["identity", "a003", "learning_seal"])
@pytest.mark.parametrize(
    "column,expression",
    [
        ("notes", "'same-primary-key-drift'"),
        ("assessment_profile", "'null'::jsonb"),
        ("assessment_score", "'-0'::float8"),
        ("assessment_taken_at", "'infinity'::timestamptz"),
    ],
)
def test_retained_native_nonkey_drift_and_repair_poison_every_product_phase(
    hosted_declaration, tmp_path, monkeypatch, boundary, column, expression
):
    with _prepared_product(hosted_declaration, tmp_path, monkeypatch) as (connection, handle, expected, operation):
        state = product._state_for(handle)
        fragment = state.retained_fragment
        assert len(fragment.tables) == 11
        assert sum(len(columns) for _, _, columns in retained._ROW_SPEC) == 166
        assert all(table.rows for table in fragment.tables)
        if boundary == "identity":
            import_academy_identity_history(connection, expected, operation)
            observe = product._observe_identity_import
        else:
            _import_identity(connection, handle, expected, operation)
            cfg, _ = _upgrade_tokens(connection, tmp_path)
            if boundary == "a003":
                observe = product._observe_account_token_adoption
            else:
                product._observe_account_token_adoption(connection, handle)
                command.upgrade(cfg, "learning@head")
                observe = product._import_and_seal_learning
        assert retained._read_fixed_rows(connection) == fragment.tables
        ids = tuple(connection.scalars(sa.text("SELECT id FROM public.applicants ORDER BY id")))
        assert ids
        source = sa.table("applicants", sa.column("id", sa.Uuid), sa.column(column), schema="public")
        changed = tuple(
            sorted(
                connection.scalars(
                    sa.update(source).values({column: sa.literal_column(expression)}).returning(source.c.id)
                )
            )
        )
        assert changed == ids
        assert retained._read_fixed_rows(connection) != fragment.tables
        with pytest.raises(product.ProductAdoptionRefused):
            observe(connection, handle)
        assert state.poisoned is True
        assert hosted._ISSUED[state.hosted_context].poisoned is True
        entry.restore_retained_oracle(connection)
        assert retained._read_fixed_rows(connection) == fragment.tables
        with pytest.raises(product.ProductAdoptionRefused):
            observe(connection, handle)
        assert state.poisoned is True


@pytest.mark.parametrize("boundary", ["identity", "a003", "learning_seal"])
def test_actual_owner_cancellation_propagates_and_poisons_product_and_hosted_owner(
    hosted_declaration, tmp_path, monkeypatch, boundary
):
    class CancelPhase(BaseException):
        pass

    with _prepared_product(hosted_declaration, tmp_path, monkeypatch) as (connection, handle, expected, operation):
        state = product._state_for(handle)
        if boundary == "identity":
            import_academy_identity_history(connection, expected, operation)
            module, name, observe = history, "_observe_identity_relocation", product._observe_identity_import
        else:
            _import_identity(connection, handle, expected, operation)
            cfg, _ = _upgrade_tokens(connection, tmp_path)
            if boundary == "a003":
                module, name, observe = (
                    tokens,
                    "account_token_identity_receipt",
                    product._observe_account_token_adoption,
                )
            else:
                product._observe_account_token_adoption(connection, handle)
                command.upgrade(cfg, "learning@head")
                module, name, observe = learning, "import_snapshot_v5", product._import_and_seal_learning
        actual = getattr(module, name)
        completed = []

        def actual_then_cancel(*args, **kwargs):
            actual(*args, **kwargs)
            completed.append(True)
            raise CancelPhase()

        monkeypatch.setattr(module, name, actual_then_cancel)
        root = connection.get_transaction()
        with pytest.raises(CancelPhase):
            observe(connection, handle)
        assert completed == [True]
        assert state.poisoned is True
        assert hosted._ISSUED[state.hosted_context].poisoned is True
        assert connection.get_transaction() is root and root.is_active
        with pytest.raises(product.ProductAdoptionRefused):
            observe(connection, handle)


def test_plain_application_precedes_hosted_resource_without_lifespan(
    _actual_application_object, hosted_declaration, tmp_path
):
    from dotmac_kernel import audit_actions

    # The real factory has returned before any disposable creation below.
    # Keeping its plain object needs no client or lifecycle invocation.
    assert _actual_application_object is not None
    registry = audit_actions.active_audit_actions()
    registry.require("identity.history_imported")
    assert registry.owner("identity.history_imported") == "kernel"
    with replayed_owner(hosted_declaration, "assembly", tmp_path / "plain-app") as owner:
        with qualified_root(owner) as (connection, root, _, __):
            registry.require("identity.history_imported")
            assert registry.owner("identity.history_imported") == "kernel"
            assert connection.get_transaction() is root and root.is_active

"""Actual Unit3/private product identity binding canaries; AUTHORED NOT RUN.

Requires full frozen62 baseline composition and installed unreleased owners.
The existing rollback owner remains the sole resource/transaction authority.
"""

from dataclasses import replace

import pytest
import sqlalchemy as sa
from dotmac_kernel.migrations.identity_history import verify_identity_history

from app.maintenance import identity_history as identity
from app.maintenance import product_adoption as product
from tests.fixtures.hosted_genesis import hosted_declaration
from tests.test_academy_product_adoption import (
    _actual_application_object,
    _prepared_product,
    _token_observed,
    _upgrade_tokens,
    tokens,
)

assert hosted_declaration
assert _actual_application_object


def test_real_prewrite_registration_and_whole_phase_reverification(hosted_declaration, tmp_path, monkeypatch):
    original = identity.import_identity_history
    registered = []

    def before_kernel(connection, decoder, expected, operation, **kwargs):
        state = connection.info[product._STATE_KEY]
        association = state.identity_verification
        assert association.decoder is decoder
        assert association.snapshot is None and decoder._snapshot is None
        assert association.receipt is None and association.expected is expected
        registered.append(association)
        return original(connection, decoder, expected, operation, **kwargs)

    monkeypatch.setattr(identity, "import_identity_history", before_kernel)
    with _token_observed(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        state = product._state_for(handle)
        association = state.identity_verification
        assert registered == [association]
        assert association.snapshot is association.decoder._snapshot
        assert association.receipt is state.identity_association[1]
        assert product._verify_identity_import(connection, handle) is None
        product._import_and_seal_learning(connection, handle)
        assert product._verify_identity_import(connection, handle) is None
        assert state.phase == "Learning sealed, retained adoption pending"
        assert state.retained_schema_unverified is True
        product._dispose_product_history(connection, handle)
        assert state.identity_verification is None


@pytest.mark.parametrize("attack", ["receipt_copy", "expected_copy", "snapshot_replace", "wrong_connection", "xid"])
def test_public_data_and_copied_associations_cannot_advance_product(hosted_declaration, tmp_path, monkeypatch, attack):
    with _prepared_product(hosted_declaration, tmp_path, monkeypatch) as (connection, handle, expected, operation):
        identity.import_academy_identity_history(connection, expected, operation)
        state = product._state_for(handle)
        association = state.identity_verification
        if attack == "receipt_copy":
            association.receipt = replace(association.receipt)
        elif attack == "expected_copy":
            association.expected = replace(expected)
        elif attack == "snapshot_replace":
            association.decoder._snapshot = replace(association.snapshot)
        elif attack == "wrong_connection":
            association.decoder._connection = object()
        else:
            state.xid = "wrong-xid"
        with pytest.raises(product.ProductAdoptionRefused):
            product._observe_identity_import(connection, handle)
        assert state.poisoned and state.phase == "captured"
        with pytest.raises(product.ProductAdoptionRefused):
            product._observe_identity_import(connection, handle)


@pytest.mark.parametrize("stage", ["identity", "a003", "learning", "sealed"])
@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE academy_identity_compat.people SET first_name='changed'",
        "UPDATE public.party_persons SET first_name='changed'",
        "UPDATE public.academy_account_profiles SET avatar_path='changed'",
        "UPDATE public.academy_credential_policies SET lifecycle_version=1",
    ],
)
def test_drift_rechecks_poison_before_each_existing_phase_boundary(
    hosted_declaration, tmp_path, monkeypatch, stage, sql
):
    with _prepared_product(hosted_declaration, tmp_path, monkeypatch) as (connection, handle, expected, operation):
        receipt = identity.import_academy_identity_history(connection, expected, operation)
        state = product._state_for(handle)
        if stage != "identity":
            product._observe_identity_import(connection, handle)
            tokens.authorize_historical_account_token_adoption(connection, state.token_entry, receipt)
            cfg, _ = _upgrade_tokens(connection, tmp_path)
            if stage != "a003":
                product._observe_account_token_adoption(connection, handle)
                from alembic import command

                command.upgrade(cfg, "learning@head")
                if stage == "sealed":
                    product._import_and_seal_learning(connection, handle)
        connection.execute(sa.text(sql))
        observer = {
            "identity": product._observe_identity_import,
            "a003": product._observe_account_token_adoption,
            "learning": product._import_and_seal_learning,
            "sealed": product._verify_identity_import,
        }[stage]
        with pytest.raises(product.ProductAdoptionRefused):
            observer(connection, handle)
        assert state.poisoned
        with pytest.raises(product.ProductAdoptionRefused):
            product._verify_identity_import(connection, handle)


def test_public_success_with_fresh_expected_rows_never_replaces_private_expectations(
    hosted_declaration, tmp_path, monkeypatch
):
    with _prepared_product(hosted_declaration, tmp_path, monkeypatch) as (connection, handle, expected, operation):
        receipt = identity.import_academy_identity_history(connection, expected, operation)
        state = product._state_for(handle)
        captured = state.identity_verification.snapshot
        changed_rows = replace(
            captured.rows,
            tenants=(
                replace(captured.rows.tenants[0], name="changed"),
                *captured.rows.tenants[1:],
            ),
        )
        tenant = changed_rows.tenants[0]
        connection.execute(
            sa.text("UPDATE public.tenants SET name=:name WHERE id=:id"), {"name": tenant.name, "id": tenant.id}
        )
        assert (
            verify_identity_history(
                connection, changed_rows, expected, operation, receipt, assembly_versions=identity._ASSEMBLY_VERSIONS
            )
            is None
        )
        assert state.identity_verification.snapshot is captured
        with pytest.raises(product.ProductAdoptionRefused):
            product._observe_identity_import(connection, handle)
        assert state.poisoned

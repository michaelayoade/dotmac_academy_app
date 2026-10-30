"""Genuine frozen62 plus actual installed owner comparison; AUTHORED NOT RUN."""

from dataclasses import FrozenInstanceError

import pytest
import sqlalchemy as sa

from app.maintenance import identity_history as identity
from tests.test_academy_identity_history import _prepared, legacy_engine

assert legacy_engine


def _observed_decoder(monkeypatch):
    captured = []
    original = identity.AcademyIdentityHistoryDecoder.decode

    def observe(decoder, connection):
        result = original(decoder, connection)
        captured.append(decoder)
        return result

    monkeypatch.setattr(identity.AcademyIdentityHistoryDecoder, "decode", observe)
    return captured


def test_real_adapter_compares_original_immutable_snapshot_and_remains_standalone(legacy_engine, tmp_path, monkeypatch):
    captured = _observed_decoder(monkeypatch)
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation):
        root = connection.get_transaction()
        receipt = identity.import_academy_identity_history(connection, expected, operation)
        original = captured[0]
        assert original._snapshot is not None and len(captured) >= 2
        assert original is not captured[1] and original._snapshot == captured[1]._snapshot
        with pytest.raises(FrozenInstanceError):
            original._snapshot.rows = None
        assert identity._verify_identity_import_data(connection, original, expected, operation, receipt) is None
        assert connection.get_transaction() is root and root.is_active


@pytest.mark.parametrize(
    "table,column,value",
    [
        ("academy_account_profiles", "status", "changed"),
        ("academy_account_profiles", "avatar_path", "changed"),
        ("academy_account_profiles", "prefs", {"changed": True}),
        ("academy_account_profiles", "created_at", None),
        ("academy_account_profiles", "updated_at", None),
        ("academy_credential_policies", "email", "changed@example.test"),
        ("academy_credential_policies", "failed_login_attempts", 7),
        ("academy_credential_policies", "lifecycle_version", 1),
        ("academy_credential_policies", "reset_required", True),
        ("academy_credential_policies", "locked_until", None),
        ("academy_credential_policies", "created_at", None),
        ("academy_credential_policies", "updated_at", None),
    ],
)
def test_each_product_nonkey_field_is_compared_from_prewrite_values(
    legacy_engine, tmp_path, monkeypatch, table, column, value
):
    captured = _observed_decoder(monkeypatch)
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation):
        receipt = identity.import_academy_identity_history(connection, expected, operation)
        target = next(item for item in identity._TARGETS if item.name == table)
        key = next(iter(target.primary_key.columns))
        identifier = connection.scalar(sa.select(key).order_by(key).limit(1))
        replacement = sa.func.transaction_timestamp() if value is None else value
        connection.execute(sa.update(target).where(key == identifier).values({column: replacement}))
        with pytest.raises(identity.IdentityHistoryImportRefused):
            identity._verify_identity_import_data(connection, captured[0], expected, operation, receipt)


@pytest.mark.parametrize("attack", ["source", "canonical", "missing_profile", "same_count_policy", "catalog"])
def test_source_canonical_and_whole_product_extent_are_independent(legacy_engine, tmp_path, monkeypatch, attack):
    captured = _observed_decoder(monkeypatch)
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (connection, expected, operation):
        receipt = identity.import_academy_identity_history(connection, expected, operation)
        statements = {
            "source": "UPDATE academy_identity_compat.people SET first_name='changed'",
            "canonical": "UPDATE public.party_persons SET first_name='changed'",
            "missing_profile": "DELETE FROM public.academy_account_profiles",
            "same_count_policy": "UPDATE public.academy_credential_policies SET email='changed@example.test'",
            "catalog": "REVOKE SELECT ON public.academy_account_profiles FROM app_user",
        }
        connection.execute(sa.text(statements[attack]))
        with pytest.raises(identity.IdentityHistoryImportRefused):
            identity._verify_identity_import_data(connection, captured[0], expected, operation, receipt)
        assert captured[0]._snapshot is not captured[-1]._snapshot

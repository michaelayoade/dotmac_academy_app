"""Pure projection/custody tests; no database or historical qualification."""

from dataclasses import FrozenInstanceError, replace

import pytest
from sqlalchemy.engine import Engine

from app.maintenance import retained_history as retained
from app.maintenance import retained_schema as schema
from app.maintenance import retained_transition as transition


@pytest.fixture(autouse=True)
def no_connections(monkeypatch):
    monkeypatch.setattr(Engine, "connect", lambda *a, **k: pytest.fail("pure packet test cannot connect"))


def _envelope(acl=None):
    return retained._PublicSchemaEnvelope(
        123, 456, "private raw ACL", transition._SUCCESSOR_PUBLIC_ACL if acl is None else acl
    )


@pytest.mark.parametrize("attack", ["old", "missing", "extra", "grantor", "grant_option", "duplicate"])
def test_successor_requires_exact_multiplicity_and_all_four_acl_fields(monkeypatch, attack):
    rows = list(transition._SUCCESSOR_PUBLIC_ACL)
    if attack == "old":
        rows = list(transition._HISTORICAL_PUBLIC_ACL)
    elif attack == "missing":
        rows.pop()
    elif attack == "extra":
        rows.append(("pg_database_owner", "unexpected", "USAGE", False))
    elif attack == "grantor":
        rows[0] = ("app_admin", *rows[0][1:])
    elif attack == "grant_option":
        rows[0] = (*rows[0][:3], True)
    else:
        rows.append(rows[0])
    acl = tuple(sorted(rows))
    monkeypatch.setattr(
        schema, "_check_cluster_authority", lambda _: pytest.fail("invalid ACL cannot reach frozen gate")
    )
    with pytest.raises(Exception, match="Academy retained transition refused"):
        transition._successor_cluster({"cluster_schema_acl": acl}, _envelope(acl))


def test_projection_is_defensive_and_preserves_every_other_packet_field(monkeypatch):
    other = (("unchanged", False),)
    packet = {"cluster_schema_acl": transition._SUCCESSOR_PUBLIC_ACL, "other_cluster_field": other}
    snapshot = dict(packet)
    seen = []

    def frozen_gate(projected):
        assert projected is not packet
        assert projected == {**snapshot, "cluster_schema_acl": transition._HISTORICAL_PUBLIC_ACL}
        assert projected["other_cluster_field"] is other
        seen.append(projected)
        projected["other_cluster_field"] = ()

    monkeypatch.setattr(schema, "_check_cluster_authority", frozen_gate)
    transition._successor_cluster(packet, _envelope())
    assert seen and packet == snapshot


def test_other_cluster_authority_still_reaches_real_frozen_refusal():
    packet = {"cluster_schema_acl": transition._SUCCESSOR_PUBLIC_ACL, "cluster_roles": ()}
    with pytest.raises(schema.RetainedSchemaRefused):
        transition._successor_cluster(packet, _envelope())


@pytest.mark.parametrize("field,value", [("oid", 124), ("owner_oid", 457), ("acl", ())])
def test_successor_preserves_qualified_identity_and_fixed_profile(monkeypatch, field, value):
    original = _envelope(transition._HISTORICAL_PUBLIC_ACL)
    monkeypatch.setattr(retained, "_public_schema_envelope", lambda _: replace(_envelope(), **{field: value}))
    with pytest.raises(Exception, match="Academy retained transition refused"):
        transition._successor_envelope(object(), original)


def test_historical_profile_cannot_be_selected_from_observations(monkeypatch):
    monkeypatch.setattr(retained, "_public_schema_envelope", lambda _: _envelope())
    with pytest.raises(Exception, match="Academy retained transition refused"):
        transition._successor_envelope(object(), _envelope())
    original = _envelope(transition._HISTORICAL_PUBLIC_ACL)
    assert transition._successor_envelope(object(), original) == _envelope()
    with pytest.raises(FrozenInstanceError):
        original.raw_acl = "mutated"
    assert "private raw ACL" not in repr(original)


@pytest.mark.parametrize("change", ["raw_acl", "oid", "owner_oid", "acl"])
def test_real_before_verifier_rejects_late_full_envelope_drift(monkeypatch, change):
    from types import SimpleNamespace

    captured = _envelope()
    changes = {"raw_acl": "changed raw ordering", "oid": 124, "owner_oid": 457, "acl": ()}
    entry = SimpleNamespace(before={}, canonical=(), version_oid=12, before_versions=(), public_schema=captured)
    monkeypatch.setattr(schema, "_observe_historical_catalog", lambda _: {})
    monkeypatch.setattr(transition.history, "_oid", lambda *a: 12)
    monkeypatch.setattr(transition, "_version_rows", lambda _: ())
    monkeypatch.setattr(retained, "_public_schema_envelope", lambda _: replace(captured, **{change: changes[change]}))
    monkeypatch.setattr(schema, "_observe_cluster_authority", lambda _: pytest.fail("envelope drift must refuse first"))
    with pytest.raises(Exception, match="Academy retained transition refused"):
        transition._verify_before(object(), entry)


def test_packet_and_envelope_cannot_describe_different_reads(monkeypatch):
    monkeypatch.setattr(schema, "_check_cluster_authority", lambda _: pytest.fail("mismatched reads cannot reach gate"))
    with pytest.raises(Exception, match="Academy retained transition refused"):
        transition._successor_cluster({"cluster_schema_acl": transition._SUCCESSOR_PUBLIC_ACL}, _envelope(()))


@pytest.mark.parametrize("change", ["replace_root", "deactivate_root"])
def test_capture_checks_root_after_last_schema_observation(monkeypatch, change):
    from types import SimpleNamespace

    root = SimpleNamespace(is_active=True)
    connection = SimpleNamespace(get_transaction=lambda: root)
    monkeypatch.setattr(retained, "_qualify", lambda *a, **k: None)
    monkeypatch.setattr(retained, "_locked_context", lambda _: (root, "fixed-xid", ()))
    monkeypatch.setattr(retained, "_observe_rows", lambda _: ())
    monkeypatch.setattr(schema, "_observe_historical_catalog", lambda _: {})
    observations = []

    def final_observation(actual):
        assert actual is connection
        observations.append("schema")
        if change == "replace_root":
            connection.get_transaction = lambda: object()
        else:
            root.is_active = False
        return _envelope(transition._HISTORICAL_PUBLIC_ACL)

    monkeypatch.setattr(retained, "_public_schema_envelope", final_observation)
    with pytest.raises(retained.RetainedHistoryRefused):
        # Exercise the real capture orchestration with resource-free source
        # observations; no hosted qualification or database is simulated.
        retained._capture_retained_rows(connection, object())
    assert observations == ["schema"]

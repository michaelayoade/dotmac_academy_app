"""Pure successor custody/delegation; never database qualification."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from sqlalchemy.engine import Engine

from app.maintenance import checkpoint_transition as checkpoint
from app.maintenance import erp_progress_transition as erp
from app.maintenance import fresh_product as fresh
from app.maintenance import lab_claim_lease_transition as lab
from app.maintenance import product_adoption as product
from app.maintenance import retained_history as rows
from app.maintenance import retained_schema as schema
from app.maintenance import retained_transition as retained


@pytest.fixture(autouse=True)
def no_connections(monkeypatch):
    monkeypatch.setattr(Engine, "connect", lambda *a, **k: pytest.fail("no connections in pure custody tests"))


def _envelope():
    return rows._PublicSchemaEnvelope(123, 456, "private raw ACL", retained._SUCCESSOR_PUBLIC_ACL)


@pytest.mark.parametrize("field,value", [("oid", 124), ("owner_oid", 457), ("raw_acl", "changed"), ("acl", ())])
def test_shared_verification_refuses_full_envelope_drift_before_frozen_gate(monkeypatch, field, value):
    original = _envelope()
    monkeypatch.setattr(rows, "_public_schema_envelope", lambda _: replace(original, **{field: value}))
    monkeypatch.setattr(schema, "_observe_cluster_authority", lambda _: pytest.fail("drift must refuse first"))
    with pytest.raises(product.ProductAdoptionRefused):
        retained._verify_successor_cluster(object(), original)


def test_shared_verification_preserves_supplied_projected_cluster_and_custody(monkeypatch):
    envelope, cluster, db = _envelope(), {"projected a006 columns": ()}, object()
    monkeypatch.setattr(rows, "_public_schema_envelope", lambda connection: envelope)
    monkeypatch.setattr(schema, "_observe_cluster_authority", lambda _: pytest.fail("must reuse projected packet"))
    seen = []
    monkeypatch.setattr(retained, "_successor_cluster", lambda packet, captured: seen.append((packet, captured)))
    retained._verify_successor_cluster(db, envelope, cluster=cluster)
    assert seen[0][0] is cluster and seen[0][1] is envelope


@pytest.mark.parametrize("module", [checkpoint, lab])
def test_real_historical_before_verifier_uses_original_retained_entry_chain(monkeypatch, module):
    envelope, db = _envelope(), object()
    retained_entry = SimpleNamespace(public_schema=envelope)
    entry = SimpleNamespace(
        retained_entry=retained_entry,
        checkpoint_entry=SimpleNamespace(retained_entry=retained_entry),
        parent_keys={},
        parent_catalogs=(),
        raw_acks=(),
        version_oid=1,
        before_versions=(),
        lab_oid=1,
        lab_catalog_before=(),
        raw_lab_rows=(),
    )
    monkeypatch.setattr(module, "_refuse_destination", lambda _: None)
    monkeypatch.setattr(module, "_held", lambda *a: None)
    monkeypatch.setattr(module.history, "_oid", lambda *a: 1)
    monkeypatch.setattr(module.history, "_catalog", lambda *a: ())
    monkeypatch.setattr(retained, "_version_rows", lambda _: ())
    if module is checkpoint:
        monkeypatch.setattr(module, "_parent_keys", lambda _: {})
        monkeypatch.setattr(module, "_source_acks", lambda _: ())
        monkeypatch.setattr(module, "_canonical_keys", lambda _: ())
    else:
        monkeypatch.setattr(module, "_raw_rows", lambda _: ())
        monkeypatch.setattr(module, "_zero_claimed", lambda _: None)
    seen = []
    monkeypatch.setattr(retained, "_verify_successor_cluster", lambda conn, captured: seen.append((conn, captured)))
    module._verify_before(db, entry)
    assert seen[0][0] is db and seen[0][1] is envelope


def _fresh_preparation(monkeypatch):
    owner = SimpleNamespace(prepared=False, next_stage=0, graph=())
    root, physical = object(), ("physical",)
    db = SimpleNamespace(info={})
    provenance = (None, None, None, None, ((), ()))
    monkeypatch.setattr(fresh, "_check", lambda *a: None)
    monkeypatch.setattr(fresh, "_issued", lambda _: owner)
    monkeypatch.setattr(fresh, "_versions", lambda _: ())
    monkeypatch.setattr(fresh, "_cut", lambda *a, **k: ())
    monkeypatch.setattr(product, "_provenance", lambda: provenance)
    monkeypatch.setattr(retained, "_parent_specs", lambda **k: ())
    monkeypatch.setattr(checkpoint, "_held", lambda *a: None)
    monkeypatch.setattr(erp.history, "_oid", lambda *a: 1)
    monkeypatch.setattr(erp, "_connection_preflight", lambda _: root)
    monkeypatch.setattr(erp.tokens, "_physical_context", lambda _: physical)
    monkeypatch.setattr(erp, "_roles", lambda _: ())
    monkeypatch.setattr(erp.catalog, "observe", lambda _: {})
    envelope = _envelope()
    monkeypatch.setattr(rows, "_public_schema_envelope", lambda _: envelope)
    return db, owner, root, physical, envelope


def test_real_fresh_private_stage_captures_own_envelope_and_rejects_late_change(monkeypatch):
    db, owner, root, physical, envelope = _fresh_preparation(monkeypatch)
    stage = erp._prepare_fresh_stages(db, owner)
    assert stage.public_schema is envelope
    assert erp._check_fresh_stages(db, owner) is stage
    monkeypatch.setattr(rows, "_public_schema_envelope", lambda _: replace(envelope, raw_acl="changed"))
    with pytest.raises(product.ProductAdoptionRefused):
        erp._check_fresh_stages(db, owner)


@pytest.mark.parametrize("change", ["root", "physical", "missing_grant"])
def test_fresh_stage_last_observation_cannot_publish_after_context_or_acl_drift(monkeypatch, change):
    db, owner, root, physical, envelope = _fresh_preparation(monkeypatch)

    def final_observation(_):
        if change == "root":
            monkeypatch.setattr(erp, "_connection_preflight", lambda _: object())
        elif change == "physical":
            monkeypatch.setattr(erp.tokens, "_physical_context", lambda _: ("different",))
        return replace(envelope, acl=()) if change == "missing_grant" else envelope

    monkeypatch.setattr(rows, "_public_schema_envelope", final_observation)
    with pytest.raises(product.ProductAdoptionRefused):
        erp._prepare_fresh_stages(db, owner)
    assert erp._FRESH_KEY not in db.info


@pytest.mark.parametrize("change", ["root", "physical"])
def test_fresh_stage_check_guards_context_after_last_envelope_read(monkeypatch, change):
    db, owner, root, physical, envelope = _fresh_preparation(monkeypatch)
    erp._prepare_fresh_stages(db, owner)

    def final_read(_):
        if change == "root":
            monkeypatch.setattr(erp, "_connection_preflight", lambda _: object())
        else:
            monkeypatch.setattr(erp.tokens, "_physical_context", lambda _: ("changed",))
        return envelope

    monkeypatch.setattr(rows, "_public_schema_envelope", final_read)
    with pytest.raises(product.ProductAdoptionRefused):
        erp._check_fresh_stages(db, owner)


@pytest.mark.parametrize("stage", ["a004_retained_learning_refs", "a006_lab_claim_lease"])
def test_real_fresh_validator_forwards_captured_envelope_after_independent_projection(monkeypatch, stage):
    db, envelope = object(), _envelope()
    raw, projected = {"raw cluster": ()}, {"projected cluster": ()}
    monkeypatch.setattr(fresh, "_authority", lambda _: None)
    monkeypatch.setattr(schema, "_observe_historical_catalog", lambda _: {})
    monkeypatch.setattr(schema, "_observe_cluster_authority", lambda _: raw)
    monkeypatch.setattr(erp.catalog, "_fresh_lease_checks", lambda _: None)
    monkeypatch.setattr(retained, "_normalize_lab_claim_packet", lambda p: p)
    monkeypatch.setattr(
        retained, "_normalize_lab_claim_cluster", lambda p: projected if p is raw else pytest.fail("packet")
    )
    monkeypatch.setattr(erp.catalog, "_check_non_ri_structure", lambda _: None)
    monkeypatch.setattr(schema, "_check_security", lambda _: None)
    seen = []

    class ReachedCustodyCheck(Exception):
        pass

    def custody(connection, captured, *, cluster):
        seen.append((connection, captured, cluster))
        raise ReachedCustodyCheck

    monkeypatch.setattr(retained, "_verify_successor_cluster", custody)
    with pytest.raises(ReachedCustodyCheck):
        erp.catalog.validate_fresh_stage(
            db, {}, {}, stage, original_rows=(), parent_keys={}, checkpoint_keys={}, public_schema=envelope
        )
    assert seen[0][0] is db and seen[0][1] is envelope
    assert seen[0][2] is (projected if stage == "a006_lab_claim_lease" else raw)

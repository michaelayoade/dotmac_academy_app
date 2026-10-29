"""Pure bounded lab catalog comparison; no hosted admission or SQL."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from sqlalchemy.engine import Engine

from app.maintenance import checkpoint_transition as checkpoint
from app.maintenance import lab_claim_lease_transition as lab
from app.maintenance import learning_history as history
from app.maintenance import product_adoption as product
from app.maintenance import retained_schema as schema
from app.maintenance import retained_transition as retained

NAME = "lab_operations_tenant_id_fkey"


@pytest.fixture(autouse=True)
def no_connections(monkeypatch):
    monkeypatch.setattr(Engine, "connect", lambda *a, **k: pytest.fail("pure catalog test cannot connect"))


def _record(fields, **values):
    return tuple(values.get(field) for field in fields)


def _packet(fk, triggers, namespace):
    return {
        "ri_foreign_keys": (
            _record(
                schema._RI_FK_FIELDS,
                oid=fk,
                child_oid=100,
                child_namespace="public",
                child="lab_operations",
                name=NAME,
                kind="f",
                parent_namespace=namespace,
                parent="tenants",
            ),
        ),
        "ri_triggers": tuple(
            _record(schema._RI_TRIGGER_FIELDS, oid=oid, relation_oid=100, constraint_oid=fk) for oid in triggers
        ),
    }


def _state():
    original = history._Catalog(
        (100,),
        (),
        ((NAME, "f", "old tenant"), ("fk_lab_operations_tenant_instance", "f", "fixed")),
        (),
        (),
        (),
        (),
        (),
        (),
        (),
        ((11,), (12,), (99,)),
    )
    current = replace(
        original, constraints=((NAME, "f", "new tenant"), original.constraints[1]), triggers=((21,), (22,), (99,))
    )
    entry = object.__new__(retained._RetainedTransition)
    # Deliberately only private fields consumed by this comparison seam. These
    # resource-free packets cannot authenticate a product phase.
    state = SimpleNamespace(
        handle=object(),
        connection=object(),
        root=object(),
        xid="fixed",
        oids=(("lab_operations", 100),),
        catalogs=(("lab_operations", original),),
        retained_transition=entry,
    )
    for field, value in {
        "handle": state.handle,
        "connection": state.connection,
        "root": state.root,
        "xid": state.xid,
        "consumed": True,
        "before": _packet(1, (11, 12), "academy_identity_compat"),
        "final": _packet(2, (21, 22), "public"),
        "new_fks": frozenset({2}),
        "new_triggers": frozenset({21, 22}),
    }.items():
        setattr(entry, field, value)
    cp = object.__new__(checkpoint._CheckpointTransition)
    cp.retained_entry, cp.final = entry, ()
    state.checkpoint_transition = cp
    return state, current


def test_exact_approved_fk_and_child_pair_are_the_only_projected_difference():
    state, current = _state()
    assert current != dict(state.catalogs)["lab_operations"]
    lab._compare_retained_lab_catalog(state, current)


@pytest.mark.parametrize(
    "field",
    [
        "relation",
        "columns",
        "constraints",
        "incoming",
        "indexes",
        "policies",
        "dependencies",
        "acl",
        "column_acl",
        "rules",
        "triggers",
    ],
)
def test_unrelated_catalog_fields_remain_comparison_sensitive(field):
    state, current = _state()
    values = getattr(current, field)
    changed = replace(current, **{field: (*values, ("unexpected", "c"))})
    with pytest.raises(product.ProductAdoptionRefused):
        lab._compare_retained_lab_catalog(state, changed)


@pytest.mark.parametrize(
    "attack",
    [
        "chain",
        "handle",
        "connection",
        "root",
        "xid",
        "consumed",
        "final",
        "new_fk",
        "new_trigger",
        "duplicate_fk",
        "missing_trigger",
        "wrong_parent",
        "same_fk",
        "preserved_fk",
        "retained_type",
        "overlapping_triggers",
        "duplicate_constraint",
        "missing_catalog_trigger",
        "incoming_same_fk",
    ],
)
def test_private_chain_and_exact_recorded_fk_pair_cannot_be_broadened(attack):
    state, current = _state()
    entry = state.retained_transition
    if attack == "chain":
        state.retained_transition = object()
    elif attack in ("handle", "connection", "root", "xid"):
        setattr(entry, attack, object())
    elif attack == "consumed":
        entry.consumed = False
    elif attack == "final":
        entry.final = None
    elif attack == "new_fk":
        entry.new_fks = frozenset()
    elif attack == "new_trigger":
        entry.new_triggers = frozenset({21})
    elif attack == "duplicate_fk":
        entry.final["ri_foreign_keys"] *= 2
    elif attack == "missing_trigger":
        entry.final["ri_triggers"] = entry.final["ri_triggers"][:1]
    elif attack == "wrong_parent":
        entry.final = _packet(2, (21, 22), "unreviewed")
    elif attack == "same_fk":
        entry.final = _packet(1, (21, 22), "public")
        entry.new_fks = frozenset({1})
    elif attack == "retained_type":
        state.retained_transition = state.checkpoint_transition.retained_entry = object()
    elif attack == "overlapping_triggers":
        entry.final = _packet(2, (11, 22), "public")
        entry.new_triggers = frozenset({11, 22})
    elif attack == "duplicate_constraint":
        current = replace(current, constraints=(*current.constraints, current.constraints[0]))
    elif attack == "missing_catalog_trigger":
        current = replace(current, triggers=current.triggers[1:])
    elif attack == "incoming_same_fk":
        current = replace(current, incoming=((2,),))
    else:
        current = replace(
            current, constraints=current.constraints[:1] + (("fk_lab_operations_tenant_instance", "f", "changed"),)
        )
    with pytest.raises(product.ProductAdoptionRefused):
        lab._compare_retained_lab_catalog(state, current)

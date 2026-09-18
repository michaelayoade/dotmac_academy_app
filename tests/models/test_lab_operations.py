"""Schema-shape and ownership-boundary tests for `lab_operations` (Phase 1).

Nothing reads or writes this table yet — these tests exist to prove the table
itself is exactly what the design commits to: a claimable work queue where
the web tier may request and observe, but only `app_admin` may settle a row.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.models.lab import LabInstance, LabOperation
from app.models.tenant import Tenant


def _make_instance(db, tenant: Tenant) -> LabInstance:
    li = LabInstance(
        tenant_id=tenant.id,
        activity_id=uuid4(),
        person_id=uuid4(),
        instance_name=f"dal-{uuid4().hex[:8]}",
        seed={},
        status="queued",
        consoles={},
    )
    db.add(li)
    db.flush()
    return li


def _make_operation(tenant, instance, *, kind="deploy", state="queued"):
    return LabOperation(
        tenant_id=tenant.id,
        instance_id=instance.id,
        kind=kind,
        state=state,
    )


# --- schema shape -----------------------------------------------------


def test_columns_match_contract(admin_engine):
    inspector = inspect(admin_engine)
    columns = {c["name"]: c for c in inspector.get_columns("lab_operations")}

    expected_not_null = {
        "id", "tenant_id", "instance_id", "kind", "state",
        "requested_at", "not_before", "attempts",
    }
    expected_nullable = {
        "requested_by", "claimed_by", "claimed_at", "heartbeat_at",
        "finished_at", "last_error",
    }
    for name in expected_not_null:
        assert name in columns, f"missing column {name}"
        assert columns[name]["nullable"] is False, f"{name} should be NOT NULL"
    for name in expected_nullable:
        assert name in columns, f"missing column {name}"
        assert columns[name]["nullable"] is True, f"{name} should be nullable"

    assert "queued" in str(columns["state"]["default"])
    assert "0" in str(columns["attempts"]["default"])
    assert "now()" in str(columns["requested_at"]["default"])
    assert "now()" in str(columns["not_before"]["default"])
    assert columns["kind"]["type"].length == 16
    assert columns["state"]["type"].length == 16
    assert columns["claimed_by"]["type"].length == 200


def test_foreign_keys_cascade(admin_engine):
    inspector = inspect(admin_engine)
    fks = inspector.get_foreign_keys("lab_operations")
    by_referred = {fk["referred_table"]: fk for fk in fks}

    tenants_fk = by_referred["tenants"]
    assert tenants_fk["constrained_columns"] == ["tenant_id"]
    assert tenants_fk["options"].get("ondelete") == "CASCADE"

    instances_fk = by_referred["lab_instances"]
    assert set(instances_fk["constrained_columns"]) == {"tenant_id", "instance_id"}
    assert set(instances_fk["referred_columns"]) == {"tenant_id", "id"}
    assert instances_fk["options"].get("ondelete") == "CASCADE"


def test_rls_enabled_forced_with_tenant_policy(admin_session):
    row = admin_session.execute(
        text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
             "WHERE relname = 'lab_operations'")
    ).one()
    assert row.relrowsecurity is True
    assert row.relforcerowsecurity is True

    policies = admin_session.execute(
        text("SELECT policyname FROM pg_policies WHERE tablename = 'lab_operations'")
    ).scalars().all()
    assert "lab_operations_tenant_isolation" in policies


def test_grants_are_exactly_the_ownership_boundary(admin_session):
    rows = admin_session.execute(
        text("SELECT grantee, privilege_type FROM information_schema.role_table_grants "
             "WHERE table_name = 'lab_operations' AND grantee IN ('app_user', 'platform_api')")
    ).all()
    by_grantee: dict[str, set[str]] = {}
    for grantee, privilege in rows:
        by_grantee.setdefault(grantee, set()).add(privilege)

    # The web tier may request (INSERT) and observe (SELECT) an operation, but
    # never settle one — no UPDATE, no DELETE. This is the load-bearing
    # invariant of the whole design.
    assert by_grantee.get("app_user") == {"SELECT", "INSERT"}
    assert by_grantee.get("platform_api") == {"SELECT"}


# --- the core guarantee: one open operation per instance ----------------


def test_second_queued_operation_for_same_instance_is_rejected(admin_session, tenant_a):
    instance = _make_instance(admin_session, tenant_a)
    admin_session.add(_make_operation(tenant_a, instance, state="queued"))
    admin_session.flush()

    admin_session.add(_make_operation(tenant_a, instance, state="queued"))
    with pytest.raises(IntegrityError):
        admin_session.flush()
    admin_session.rollback()


def test_claimed_operation_also_blocks_a_new_queued_one(admin_session, tenant_a):
    instance = _make_instance(admin_session, tenant_a)
    admin_session.add(_make_operation(tenant_a, instance, state="claimed"))
    admin_session.flush()

    admin_session.add(_make_operation(tenant_a, instance, state="queued"))
    with pytest.raises(IntegrityError):
        admin_session.flush()
    admin_session.rollback()


def test_closed_operation_does_not_block_a_new_queued_one(admin_session, tenant_a):
    instance = _make_instance(admin_session, tenant_a)
    for closed_state in ("succeeded", "cancelled", "failed"):
        admin_session.add(_make_operation(tenant_a, instance, state=closed_state))
    admin_session.flush()

    # A fresh queued request for the same instance is fine — the partial
    # index only guards 'queued'/'claimed', not every state.
    admin_session.add(_make_operation(tenant_a, instance, state="queued"))
    admin_session.flush()
    admin_session.rollback()


def test_deleting_instance_cascades_to_its_operations(admin_session, tenant_a):
    instance = _make_instance(admin_session, tenant_a)
    op_row = _make_operation(tenant_a, instance, state="queued")
    admin_session.add(op_row)
    admin_session.flush()
    op_id = op_row.id

    admin_session.execute(
        text("DELETE FROM lab_instances WHERE id = :id"), {"id": str(instance.id)}
    )
    admin_session.flush()

    remaining = admin_session.execute(
        text("SELECT id FROM lab_operations WHERE id = :id"), {"id": str(op_id)}
    ).first()
    assert remaining is None
    admin_session.rollback()

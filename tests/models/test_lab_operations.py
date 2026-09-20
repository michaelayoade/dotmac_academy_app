"""Schema-shape and ownership-boundary tests for `lab_operations`.

These tests prove the durable queue remains exactly what the design commits
to: the web tier may request and observe, but only `academy_lab_worker` may claim or
settle a row. Worker behavior is covered separately in the service tests.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError, ProgrammingError

from app.models.lab import LabInstance, LabOperation
from app.models.tenant import Tenant


def _set_tenant(session, tenant_id) -> None:
    # SET does not accept bound parameters in PostgreSQL — safe to interpolate
    # a UUID (matches the existing pattern in tests/test_lab_isolation.py).
    session.execute(text(f"SET app.current_tenant = '{tenant_id}'"))


def _reset_tenant(session) -> None:
    session.execute(text("RESET app.current_tenant"))


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
        "requested_by", "claimed_by", "claimed_host", "claimed_epoch",
        "claimed_at", "heartbeat_at", "finished_at", "last_error",
        "origin", "runtime_precondition",
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
    assert columns["claimed_host"]["type"].length == 255
    assert columns["claimed_epoch"]["type"].length == 64
    # No DDL default and no new index for either column (see 0059's module
    # docstring): the existing ix_lab_operations_claim scan is sufficient for
    # the ordinary claim-queue path, and the startup reclaim scan runs once
    # per worker process lifetime, not per poll.
    assert columns["claimed_host"]["default"] is None
    assert columns["claimed_epoch"]["default"] is None
    # Migration 0060: reconciler conditional operations, also with no DDL
    # default (no backfill — every existing row already satisfies the
    # "both NULL" CHECK branch trivially).
    assert columns["origin"]["type"].length == 32
    assert columns["runtime_precondition"]["type"].length == 16
    assert columns["origin"]["default"] is None
    assert columns["runtime_precondition"]["default"] is None

    checks = {
        row["name"]: str(row["sqltext"])
        for row in inspector.get_check_constraints("lab_operations")
    }
    assert set(checks) == {
        "ck_lab_operations_kind", "ck_lab_operations_state",
        "ck_lab_operations_conditional_runtime",
    }
    assert all(kind in checks["ck_lab_operations_kind"] for kind in ("deploy", "destroy", "check"))
    assert all(
        state in checks["ck_lab_operations_state"]
        for state in ("queued", "claimed", "succeeded", "failed", "cancelled")
    )
    conditional_check = checks["ck_lab_operations_conditional_runtime"]
    assert "runtime_repair" in conditional_check
    assert "runtime_cleanup" in conditional_check
    assert "absent" in conditional_check
    assert "present" in conditional_check


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
             "WHERE table_name = 'lab_operations' "
             "AND grantee IN ('app_user', 'platform_api', 'app_admin', 'academy_lab_worker')")
    ).all()
    by_grantee: dict[str, set[str]] = {}
    for grantee, privilege in rows:
        by_grantee.setdefault(grantee, set()).add(privilege)

    # app_user's table-wide grant is SELECT only — its INSERT is column-level
    # (checked below), never a table-wide INSERT that would let it set every
    # column, including worker-owned ones like `state`.
    assert by_grantee.get("app_user") == {"SELECT"}
    assert by_grantee.get("platform_api") == {"SELECT"}
    # Explicit for CI parity: CI migrates as the `postgres` superuser (see
    # .github/workflows/ci.yml), which owns lab_operations there, so app_admin
    # gets nothing on this table in CI without this grant, even though it is
    # the table owner (and needs nothing extra) in production.
    assert by_grantee.get("app_admin") == {"SELECT", "INSERT", "UPDATE", "DELETE"}
    assert by_grantee.get("academy_lab_worker") == {"SELECT", "INSERT", "UPDATE"}

    insert_columns = set(
        admin_session.execute(
            text("SELECT column_name FROM information_schema.column_privileges "
                 "WHERE table_name = 'lab_operations' AND grantee = 'app_user' "
                 "AND privilege_type = 'INSERT'")
        ).scalars().all()
    )
    # Exactly the "request" columns. Every worker-owned column (state,
    # claimed_by, claimed_host, claimed_epoch, claimed_at, heartbeat_at,
    # attempts, finished_at, last_error) must be absent — otherwise app_user
    # could forge worker-owned state at INSERT time even though it can never
    # UPDATE a row afterwards.
    assert insert_columns == {"id", "tenant_id", "instance_id", "kind", "requested_by"}


def test_app_user_cannot_insert_or_update_structural_claim_ownership_columns(admin_session):
    """``claimed_host``/``claimed_epoch`` (migration 0059) get the exact same
    ACL treatment as every other worker-owned column added before them:
    ``app_user`` may never write either one, at INSERT or via UPDATE."""
    for column in ("claimed_host", "claimed_epoch"):
        assert not admin_session.scalar(
            text(
                "SELECT has_column_privilege('app_user', 'lab_operations', :column, 'INSERT')"
            ).bindparams(column=column)
        )
        assert not admin_session.scalar(
            text(
                "SELECT has_column_privilege('app_user', 'lab_operations', :column, 'UPDATE')"
            ).bindparams(column=column)
        )
        assert admin_session.scalar(
            text(
                "SELECT has_column_privilege('academy_lab_worker', 'lab_operations', "
                ":column, 'UPDATE')"
            ).bindparams(column=column)
        ), f"academy_lab_worker should be able to UPDATE {column}"


def test_app_user_cannot_insert_or_update_conditional_operation_columns(admin_session):
    """``origin``/``runtime_precondition`` (migration 0060) get the exact
    same ACL treatment as every other worker-owned column: ``app_user`` may
    never write either one, and ``academy_lab_worker`` may write both."""
    for column in ("origin", "runtime_precondition"):
        assert not admin_session.scalar(
            text(
                "SELECT has_column_privilege('app_user', 'lab_operations', :column, 'INSERT')"
            ).bindparams(column=column)
        )
        assert not admin_session.scalar(
            text(
                "SELECT has_column_privilege('app_user', 'lab_operations', :column, 'UPDATE')"
            ).bindparams(column=column)
        )
        assert admin_session.scalar(
            text(
                "SELECT has_column_privilege('academy_lab_worker', 'lab_operations', "
                ":column, 'UPDATE')"
            ).bindparams(column=column)
        ), f"academy_lab_worker should be able to UPDATE {column}"


def test_conditional_runtime_check_accepts_ordinary_and_valid_conditional_rows(
    admin_session, tenant_a
):
    instance = _make_instance(admin_session, tenant_a)
    ordinary = _make_operation(tenant_a, instance, kind="deploy", state="failed")
    admin_session.add(ordinary)
    admin_session.flush()  # both origin/runtime_precondition NULL — must be accepted

    conditional_deploy = _make_operation(tenant_a, instance, kind="deploy", state="failed")
    conditional_deploy.origin = "runtime_repair"
    conditional_deploy.runtime_precondition = "absent"
    admin_session.add(conditional_deploy)
    admin_session.flush()

    conditional_destroy = _make_operation(tenant_a, instance, kind="destroy", state="failed")
    conditional_destroy.origin = "runtime_cleanup"
    conditional_destroy.runtime_precondition = "present"
    admin_session.add(conditional_destroy)
    admin_session.flush()
    admin_session.rollback()


@pytest.mark.parametrize(
    "kind,origin,runtime_precondition",
    [
        ("deploy", "runtime_repair", None),  # half-null
        ("deploy", None, "absent"),  # half-null
        ("deploy", "runtime_cleanup", "present"),  # wrong origin/precondition for deploy
        ("destroy", "runtime_repair", "absent"),  # wrong origin/precondition for destroy
        ("deploy", "bogus_origin", "absent"),  # invalid origin
    ],
)
def test_conditional_runtime_check_rejects_half_null_and_mismatched_rows(
    admin_session, tenant_a, kind, origin, runtime_precondition
):
    instance = _make_instance(admin_session, tenant_a)
    op = _make_operation(tenant_a, instance, kind=kind, state="failed")
    op.origin = origin
    op.runtime_precondition = runtime_precondition
    admin_session.add(op)
    with pytest.raises(IntegrityError, match="ck_lab_operations_conditional_runtime"):
        admin_session.flush()
    admin_session.rollback()


def test_lab_instance_grants_make_runtime_state_worker_owned(admin_session):
    rows = admin_session.execute(
        text("SELECT grantee, privilege_type FROM information_schema.role_table_grants "
             "WHERE table_name = 'lab_instances' "
             "AND grantee IN ('app_user', 'platform_api', 'academy_lab_worker')")
    ).all()
    by_grantee: dict[str, set[str]] = {}
    for grantee, privilege in rows:
        by_grantee.setdefault(grantee, set()).add(privilege)
    assert by_grantee.get("app_user") == {"SELECT"}
    assert by_grantee.get("platform_api") == {"SELECT"}
    assert by_grantee.get("academy_lab_worker") == {"SELECT", "UPDATE"}

    insert_columns = set(
        admin_session.execute(
            text("SELECT column_name FROM information_schema.column_privileges "
                 "WHERE table_name = 'lab_instances' AND grantee = 'app_user' "
                 "AND privilege_type = 'INSERT'")
        ).scalars().all()
    )
    assert insert_columns == {
        "id", "tenant_id", "activity_id", "person_id", "instance_name", "seed",
    }


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


# --- enforcement from the actual restricted role ------------------------
#
# Everything above proves the grants/policies exist under the right names.
# It does not prove they enforce anything — a same-named policy using `true`
# would pass those tests too. These exercise a real `app_user`-scoped
# connection (RLS active, column-level grants active) rather than the
# unrestricted `admin_session`.


def test_app_user_can_request_an_operation_for_its_own_tenant_instance(
    admin_session, app_user_session, tenant_a
):
    instance = _make_instance(admin_session, tenant_a)
    admin_session.commit()

    _set_tenant(app_user_session, tenant_a.id)
    op_row = LabOperation(tenant_id=tenant_a.id, instance_id=instance.id, kind="deploy")
    app_user_session.add(op_row)
    # Deliberately no explicit state/attempts — app_user has no INSERT grant
    # on either column, so this only works if the ORM omits them and Postgres
    # fills them from server_default.
    app_user_session.commit()
    op_id = op_row.id
    _reset_tenant(app_user_session)

    row = admin_session.execute(
        text("SELECT state, attempts FROM lab_operations WHERE id = :id"), {"id": str(op_id)}
    ).one()
    assert row.state == "queued"
    assert row.attempts == 0


def test_app_user_can_create_only_queued_instance_state(
    admin_session, app_user_session, tenant_a
):
    _set_tenant(app_user_session, tenant_a.id)
    instance = LabInstance(
        tenant_id=tenant_a.id,
        activity_id=uuid4(),
        person_id=uuid4(),
        instance_name=f"dal-request-{uuid4().hex[:8]}",
        seed={},
    )
    app_user_session.add(instance)
    app_user_session.commit()
    instance_id = instance.id
    assert instance.status == "queued"
    assert instance.consoles == {}

    with pytest.raises(ProgrammingError):
        app_user_session.execute(
            text("UPDATE lab_instances SET status = 'active' WHERE id = :id"),
            {"id": str(instance_id)},
        )
    app_user_session.rollback()
    _reset_tenant(app_user_session)

    stored = admin_session.get(LabInstance, instance_id)
    assert stored is not None and stored.status == "queued"


def test_app_user_cannot_reference_an_instance_owned_by_another_tenant(
    admin_session, app_user_session, tenant_a, tenant_b
):
    """Own tenant_id, foreign instance_id — rejected by the composite FK, not
    RLS (there is no (tenant_a, instance_b) row in lab_instances for the
    FK to match). See the two tests below for RLS's WITH CHECK and USING
    clauses specifically — this one would still pass if RLS were replaced
    with `USING (true) WITH CHECK (true)`.
    """
    instance_b = _make_instance(admin_session, tenant_b)
    admin_session.commit()

    _set_tenant(app_user_session, tenant_a.id)
    op_id = uuid4()
    with pytest.raises(IntegrityError):
        app_user_session.execute(
            text("INSERT INTO lab_operations (id, tenant_id, instance_id, kind) "
                 "VALUES (:id, :tenant_id, :instance_id, 'deploy')"),
            {"id": str(op_id), "tenant_id": str(tenant_a.id), "instance_id": str(instance_b.id)},
        )
    app_user_session.rollback()
    _reset_tenant(app_user_session)


def test_rls_with_check_rejects_a_foreign_tenant_id_even_with_a_matching_instance(
    admin_session, app_user_session, tenant_a, tenant_b
):
    """Isolates RLS's WITH CHECK clause: tenant_id is the FOREIGN tenant
    (tenant_b) and instance_id genuinely belongs to that same tenant_b, so the
    composite FK matches cleanly — the only thing standing between this insert
    and success is the tenant_isolation policy's
    `WITH CHECK (tenant_id = app_current_tenant_id())`, which must reject a
    row asserting a tenant_id other than the session's own.
    """
    instance_b = _make_instance(admin_session, tenant_b)
    admin_session.commit()

    _set_tenant(app_user_session, tenant_a.id)
    op_id = uuid4()
    with pytest.raises(ProgrammingError) as exc_info:
        app_user_session.execute(
            text("INSERT INTO lab_operations (id, tenant_id, instance_id, kind) "
                 "VALUES (:id, :tenant_id, :instance_id, 'deploy')"),
            {"id": str(op_id), "tenant_id": str(tenant_b.id), "instance_id": str(instance_b.id)},
        )
    # Distinguish this from the column-privilege ProgrammingError elsewhere in
    # this file — Postgres raises SQLSTATE 42501 for both, but only a RLS
    # WITH CHECK failure says "row-level security policy" in its message.
    assert "row-level security policy" in str(exc_info.value).lower()
    app_user_session.rollback()
    _reset_tenant(app_user_session)


def test_rls_using_hides_another_tenants_operation_from_a_select(
    admin_session, app_user_session, tenant_a, tenant_b
):
    """Isolates RLS's USING clause (read-side): a real, fully-valid operation
    row exists for tenant_b. Under app_user scoped to tenant_a, it must be
    invisible to a plain SELECT — nothing about this row is malformed, so
    only the tenant_isolation policy's USING clause can be hiding it.
    """
    instance_b = _make_instance(admin_session, tenant_b)
    op_row = _make_operation(tenant_b, instance_b, state="queued")
    admin_session.add(op_row)
    admin_session.commit()
    op_id = op_row.id

    _set_tenant(app_user_session, tenant_a.id)
    visible = app_user_session.execute(
        text("SELECT id FROM lab_operations WHERE id = :id"), {"id": str(op_id)}
    ).first()
    assert visible is None
    _reset_tenant(app_user_session)


def test_app_user_cannot_set_a_worker_owned_column_at_insert(
    admin_session, app_user_session, tenant_a
):
    instance = _make_instance(admin_session, tenant_a)
    admin_session.commit()

    _set_tenant(app_user_session, tenant_a.id)
    op_id = uuid4()
    with pytest.raises(ProgrammingError):
        app_user_session.execute(
            text("INSERT INTO lab_operations (id, tenant_id, instance_id, kind, state) "
                 "VALUES (:id, :tenant_id, :instance_id, 'deploy', 'claimed')"),
            {"id": str(op_id), "tenant_id": str(tenant_a.id), "instance_id": str(instance.id)},
        )
    app_user_session.rollback()
    _reset_tenant(app_user_session)


def test_app_user_cannot_update_or_delete_any_row(admin_session, app_user_session, tenant_a):
    instance = _make_instance(admin_session, tenant_a)
    op_row = _make_operation(tenant_a, instance, state="queued")
    admin_session.add(op_row)
    admin_session.commit()
    op_id = op_row.id

    _set_tenant(app_user_session, tenant_a.id)
    with pytest.raises(ProgrammingError):
        app_user_session.execute(
            text("UPDATE lab_operations SET state = 'claimed' WHERE id = :id"),
            {"id": str(op_id)},
        )
    app_user_session.rollback()

    with pytest.raises(ProgrammingError):
        app_user_session.execute(
            text("DELETE FROM lab_operations WHERE id = :id"), {"id": str(op_id)}
        )
    app_user_session.rollback()
    _reset_tenant(app_user_session)

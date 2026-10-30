"""Private historical a006 mechanics; nullable claim lease, no admission authority.

The fixed column and its two checks copy the composed product model exactly.
Only the actual product State may select a phase. No claimed row is settled,
requeued or backfilled here, and no privilege statement is ever issued.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import sqlalchemy as sa

from app.maintenance import checkpoint_transition as checkpoint
from app.maintenance import learning_history as history
from app.maintenance import retained_history as retained_rows
from app.maintenance import retained_schema as schema
from app.maintenance import retained_transition as retained

_A006 = "a006_lab_claim_lease"
_TABLE = "lab_operations"
_COLUMN = "claim_lease_seconds"
_POSITIVE = "ck_lab_operations_claim_lease_positive"
_REQUIRED = "ck_lab_operations_claim_lease_required"
_CHECKS = (_POSITIVE, _REQUIRED)
# Fixed literal source spec only: the original 20 retained columns, in order.
_LAB_COLUMNS = tuple(name for name, _ in next(spec[2] for spec in retained_rows._ROW_SPEC if spec[0] == _TABLE))
_RENDERINGS = {
    _POSITIVE: "((claim_lease_seconds IS NULL) OR (claim_lease_seconds > 0))",
    _REQUIRED: "(((state)::text <> 'claimed'::text) OR (claim_lease_seconds IS NOT NULL))",
}
_STATES = ("queued", "claimed", "succeeded", "failed", "cancelled")


def _require(condition):
    if not condition:
        from app.maintenance.product_adoption import ProductAdoptionRefused

        raise ProductAdoptionRefused("Academy lab claim lease transition refused; root rollback required")


@dataclass(slots=True, repr=False)
class _LabClaimLeaseTransition:
    # Constructed only after genuine product owner checks. Identity, not equality,
    # binds this object beneath the existing weakly registered product State.
    handle: object = field(repr=False)
    connection: object = field(repr=False)
    root: object = field(repr=False)
    xid: object = field(repr=False)
    runner: object = field(repr=False)
    checkpoint_entry: object = field(repr=False)
    lab_oid: object = field(repr=False)
    lab_catalog_before: object = field(repr=False)
    raw_lab_rows: object = field(repr=False)
    version_oid: object = field(repr=False)
    before_versions: object = field(repr=False)
    after_versions: object = field(repr=False)
    consumed: bool = False
    final: object = field(default=None, repr=False)
    new_attnum: object = field(default=None, repr=False)
    new_check_oids: object = field(default=None, repr=False)


def _expected_versions(graph, *, final):
    # Fixed a006 stage cut over the complete provenance-checked graph.
    return retained._stage_versions(graph, _A006, final=final)


def _held(connection, oids):
    held = set(
        connection.scalars(
            sa.text(
                "SELECT relation FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() "
                "AND locktype='relation' AND mode='AccessExclusiveLock' AND granted"
            )
        )
    )
    _require(set(oids) <= held)


def _zero_claimed(connection):
    # Source-level custody precondition only; an actual drain is never inferred.
    _require(
        connection.scalar(sa.text("SELECT NOT EXISTS (SELECT 1 FROM public.lab_operations WHERE state='claimed')"))
        is True
    )


def _raw_rows(connection):
    columns = ",".join(f'"{name}"' for name in _LAB_COLUMNS)
    return history._query(connection, f"SELECT {columns} FROM public.lab_operations ORDER BY id")  # noqa: S608


def _stamped_rows(connection):
    columns = ",".join(f'"{name}"' for name in (*_LAB_COLUMNS, _COLUMN))
    return history._query(connection, f"SELECT {columns} FROM public.lab_operations ORDER BY id")  # noqa: S608


def _fragment_lab_rows(connection, state):
    # Native retained digest seam over the fixed 20 columns, fragment-bound.
    rows = history._query(connection, retained_rows._row_query(_TABLE))
    rows = tuple(sorted(rows, key=lambda row: row[0].encode("utf-8")))
    fragment = next(table for table in state.retained_fragment.tables if table.name == _TABLE)
    _require(rows == fragment.rows and fragment.oid == dict(state.oids)[_TABLE])


def _state_cohorts(raw):
    identifier = _LAB_COLUMNS.index("id")
    state_at = _LAB_COLUMNS.index("state")
    cohorts: dict[str, frozenset[object]] = {state: frozenset() for state in _STATES}
    for row in raw:
        _require(row[state_at] in cohorts)
        cohorts[row[state_at]] |= {row[identifier]}
    return cohorts


def _refuse_destination(connection):
    """No pre-existing constraint in public may carry either fixed check name."""
    _require(
        not history._query(
            connection,
            "SELECT k.conname FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_namespace n "
            "ON n.oid=k.connamespace WHERE n.nspname='public' AND k.conname=ANY(:names)",
            names=list(_CHECKS),
        )
    )


def _compare_retained_lab_catalog(state, current):
    """Project only a004's authenticated tenant FK and its child RI pair."""
    checkpoint_entry = state.checkpoint_transition
    _require(type(checkpoint_entry) is checkpoint._CheckpointTransition and checkpoint_entry.final is not None)
    entry = checkpoint_entry.retained_entry
    _require(entry is state.retained_transition and type(entry) is retained._RetainedTransition)
    _require(entry.consumed and entry.final is not None)
    _require(entry.handle is state.handle and entry.connection is state.connection)
    _require(entry.root is state.root and entry.xid == state.xid)
    lab_oid = dict(state.oids)[_TABLE]
    original = dict(state.catalogs)[_TABLE]
    _require(original.relation[0] == current.relation[0] == lab_oid)
    name = "lab_operations_tenant_id_fkey"
    sides = []
    for packet, namespace in ((entry.before, "academy_identity_compat"), (entry.final, "public")):
        fks = tuple(
            row
            for row in retained._records(packet, "ri_foreign_keys", schema._RI_FK_FIELDS)
            if row["child_oid"] == lab_oid and row["name"] == name
        )
        _require(len(fks) == 1)
        fk = fks[0]
        _require(fk["child_namespace"] == "public" and fk["child"] == _TABLE and fk["kind"] == "f")
        _require(fk["parent_namespace"] == namespace and fk["parent"] == "tenants")
        triggers = tuple(
            row
            for row in retained._records(packet, "ri_triggers", schema._RI_TRIGGER_FIELDS)
            if row["relation_oid"] == lab_oid and row["constraint_oid"] == fk["oid"]
        )
        ids = frozenset(row["oid"] for row in triggers)
        _require(len(triggers) == len(ids) == 2)
        _require(all(type(oid) is int and oid > 0 for oid in ids | {fk["oid"]}))
        sides.append((fk["oid"], ids))
    (old_fk, old_triggers), (new_fk, new_triggers) = sides
    _require(old_fk != new_fk and new_fk in entry.new_fks)
    _require(not old_triggers & new_triggers and new_triggers <= entry.new_triggers)
    projected = []
    for catalog, (fk, trigger_ids) in zip((original, current), sides, strict=True):
        normalized = retained._project_catalog(catalog, frozenset({fk}), trigger_ids, frozenset({name}))
        _require(
            tuple(
                len(getattr(catalog, field)) - len(getattr(normalized, field))
                for field in ("constraints", "incoming", "triggers")
            )
            == (1, 0, 2)
        )
        projected.append(normalized)
    _require(projected[0] == projected[1])


def _prepare(connection, state):
    checkpoint_entry = state.checkpoint_transition
    _require(type(checkpoint_entry) is checkpoint._CheckpointTransition and checkpoint_entry.final is not None)
    _require(state.lab_claim_runner is not None)
    # The untouched before-state passes the whole recorded a005/a004 chain.
    checkpoint._verify_after(connection, state, checkpoint_entry, recorded=True)
    _refuse_destination(connection)
    lab_oid = history._oid(connection, _TABLE)
    _require(type(lab_oid) is int and lab_oid > 0 and lab_oid == dict(state.oids)[_TABLE])
    _held(connection, {lab_oid})
    before = history._catalog(connection, lab_oid)
    _compare_retained_lab_catalog(state, before)
    _require(tuple(row[0] for row in before.columns) == tuple(range(1, 21)))
    _require(tuple(row[1] for row in before.columns) == _LAB_COLUMNS)
    _require(not {row[0] for row in before.constraints} & set(_CHECKS))
    raw = _raw_rows(connection)
    _fragment_lab_rows(connection, state)
    _zero_claimed(connection)
    cohorts = _state_cohorts(raw)
    _require(not cohorts["claimed"])
    _require(frozenset(row[0] for row in raw) == frozenset(row[0] for row in dict(state.cohorts)[_TABLE]))
    retained._verify_successor_cluster(connection, checkpoint_entry.retained_entry.public_schema)
    graph = state.provenance[4][0]
    before_versions = _expected_versions(graph, final=False)
    _require(retained._version_rows(connection) == before_versions == checkpoint_entry.after_versions)
    _require(history._oid(connection, "alembic_version") == checkpoint_entry.version_oid)
    return _LabClaimLeaseTransition(
        state.handle,
        connection,
        state.root,
        state.xid,
        state.lab_claim_runner,
        checkpoint_entry,
        lab_oid,
        before,
        raw,
        checkpoint_entry.version_oid,
        before_versions,
        _expected_versions(graph, final=True),
    )


def _verify_before(connection, entry):
    _refuse_destination(connection)
    _require(history._oid(connection, _TABLE) == entry.lab_oid)
    _held(connection, {entry.lab_oid})
    _require(history._catalog(connection, entry.lab_oid) == entry.lab_catalog_before)
    _require(_raw_rows(connection) == entry.raw_lab_rows)
    _zero_claimed(connection)
    _require(history._oid(connection, "alembic_version") == entry.version_oid)
    _require(retained._version_rows(connection) == entry.before_versions)
    retained._verify_successor_cluster(connection, entry.checkpoint_entry.retained_entry.public_schema)


def _check_acl(connection, entry, catalog):
    # No privilege statement exists in a006: exploded ACLs are byte-conserved
    # by the catalog delta, and effective rights derive only from the fixed
    # retained helpers. Any attacl on the new column changes column_acl.
    roles = history._query(connection, "SELECT oid,rolname,rolsuper FROM pg_catalog.pg_roles ORDER BY rolname")
    by_name = {row[1]: row for row in roles}
    _require("app_admin" in by_name and set(schema._ROLES) <= set(by_name))
    _require(catalog.acl == entry.lab_catalog_before.acl)
    _require(catalog.column_acl == entry.lab_catalog_before.column_acl)
    columns = ", ".join(
        f"pg_catalog.has_column_privilege(:role,:oid,'{_COLUMN}','{priv}')" for priv in schema._COLUMN_PRIVILEGES
    )
    request = dict(schema._REQUEST_COLUMNS).get(_TABLE, ())
    for role_oid, name, superuser in roles:
        if superuser and name != "postgres":
            continue  # Existing superuser exception; cluster authority is checked separately.
        held = history._query(connection, f"SELECT {columns}", role=role_oid, oid=entry.lab_oid)
        expected = tuple(
            priv in schema._cluster_privileges(_TABLE, name)
            or (name == "app_user" and priv == "INSERT" and _COLUMN in request)
            for priv in schema._COLUMN_PRIVILEGES
        )
        _require(held[0] == expected)
    public = history._query(connection, f"SELECT {columns}", role="public", oid=entry.lab_oid)
    _require(not any(public[0]))


def _check_constraints(connection, entry, state_attnum):
    rows = history._query(
        connection,
        "SELECT oid,conname,contype,conkey,convalidated,condeferrable,condeferred,"
        "connoinherit,conislocal,coninhcount,conparentid,"
        "pg_catalog.pg_get_expr(conbin,conrelid,false) "
        "FROM pg_catalog.pg_constraint WHERE conrelid=:oid AND conname=ANY(:names) ORDER BY conname",
        oid=entry.lab_oid,
        names=list(_CHECKS),
    )
    _require(len(rows) == 2 and {row[1] for row in rows} == set(_CHECKS))
    expected_keys = {_POSITIVE: {21}, _REQUIRED: {state_attnum, 21}}
    for oid, name, kind, conkey, *rest in rows:
        _require(type(oid) is int and oid > 0 and kind == "c")
        _require(set(conkey) == expected_keys[name])
        _require(tuple(rest[:7]) == (True, False, False, False, True, 0, 0))
        _require(rest[7] == _RENDERINGS[name])
    _require(len({row[0] for row in rows}) == 2)
    return frozenset(row[0] for row in rows)


def _observe_delta(connection, state):
    """Verify the exact private column/check delta; never calls continuity."""
    entry = state.lab_claim_transition
    _require(type(entry) is _LabClaimLeaseTransition and entry.consumed and entry.runner is not None)
    _require(entry.handle is state.handle and entry.connection is connection)
    _require(entry.root is state.root and entry.xid == state.xid)
    _require(entry.checkpoint_entry is state.checkpoint_transition)
    _require(entry.checkpoint_entry.retained_entry is state.retained_transition)
    _require(history._oid(connection, _TABLE) == entry.lab_oid)
    before = entry.lab_catalog_before
    after = history._catalog(connection, entry.lab_oid)
    _require(after.relation == before.relation)
    _require(after.incoming == before.incoming and after.indexes == before.indexes)
    _require(after.policies == before.policies and after.dependencies == before.dependencies)
    _require(after.acl == before.acl and after.column_acl == before.column_acl)
    _require(after.rules == before.rules and after.triggers == before.triggers)
    _require(len(after.columns) == 21 and after.columns[:20] == before.columns)
    _require(after.columns[20] == (21, _COLUMN, "integer", False, False, None, "", "", 0))
    attribute = history._query(
        connection,
        "SELECT tn.nspname,t.typname,a.atttypmod,a.attnotnull,a.attisdropped,"
        "a.attidentity,a.attgenerated,a.attcollation,a.attinhcount,a.attislocal "
        "FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type t ON t.oid=a.atttypid "
        "JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace "
        "WHERE a.attrelid=:oid AND a.attname=:column",
        oid=entry.lab_oid,
        column=_COLUMN,
    )
    _require(attribute == (("pg_catalog", "int4", -1, False, False, "", "", 0, 0, True),))
    added = tuple(row for row in after.constraints if row[0] in _CHECKS)
    _require(len(added) == 2 and {row[0] for row in added} == set(_CHECKS))
    _require(tuple(row for row in after.constraints if row[0] not in _CHECKS) == before.constraints)
    state_attnum = next(row[0] for row in before.columns if row[1] == "state")
    expected_keys = {_POSITIVE: {21}, _REQUIRED: {state_attnum, 21}}
    for row in added:
        _require(row[1] == "c" and set(row[2]) == expected_keys[row[0]] and row[3] == 0)
        _require(row[8:11] == (True, False, False))
    check_oids = _check_constraints(connection, entry, state_attnum)
    _check_acl(connection, entry, after)
    return after, 21, check_oids


def _verify_after(connection, state, entry, *, recorded):
    after_catalog, attnum, check_oids = _observe_delta(connection, state)
    raw_after = _stamped_rows(connection)
    _require(tuple(row[:20] for row in raw_after) == entry.raw_lab_rows)
    _require(all(row[20] is None for row in raw_after))
    _zero_claimed(connection)
    _require(_state_cohorts(tuple(row[:20] for row in raw_after)) == _state_cohorts(entry.raw_lab_rows))
    _fragment_lab_rows(connection, state)
    final = (after_catalog, raw_after, attnum, check_oids)
    if recorded:
        _require(entry.final == final and entry.new_attnum == attnum and entry.new_check_oids == check_oids)
    else:
        _require(entry.final is None and entry.new_attnum is None and entry.new_check_oids is None)
        # Stored before the retained verifier derives its exact a006 projection.
        entry.final, entry.new_attnum, entry.new_check_oids = final, attnum, check_oids
    checkpoint._verify_after(connection, state, entry.checkpoint_entry, recorded=True)
    return final, attnum, check_oids


def _apply_lab_claim_lease_transition(connection, entry):
    from app.maintenance import product_adoption as product

    state = product._check(connection, entry.handle, "a006 executing")
    _require(state.lab_claim_transition is entry and entry.consumed and entry.final is None)
    _require(state.lab_claim_runner is not None and entry.runner is state.lab_claim_runner)
    _require(entry.connection is connection and entry.root is state.root and entry.xid == state.xid)
    _require(entry.checkpoint_entry is state.checkpoint_transition)
    product._verify_retained_prerequisites(connection, state)
    _verify_before(connection, entry)
    statements = (
        'ALTER TABLE "public"."lab_operations" ADD COLUMN "claim_lease_seconds" integer NULL',
        'ALTER TABLE "public"."lab_operations" ADD CONSTRAINT "ck_lab_operations_claim_lease_positive" '
        "CHECK (claim_lease_seconds IS NULL OR claim_lease_seconds > 0)",
        'ALTER TABLE "public"."lab_operations" ADD CONSTRAINT "ck_lab_operations_claim_lease_required" '
        "CHECK (state <> 'claimed' OR claim_lease_seconds IS NOT NULL)",
    )
    for statement in statements:
        connection.execute(sa.text(statement))

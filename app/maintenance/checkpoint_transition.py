"""Private historical a005 mechanics; inert ACK storage, no admission authority.

The fixed checkpoint shape is a schema contract copied from the current product
model. Only the actual product State may select a phase. Observed OIDs never
select a target/spec, and a copied raw timestamp is never an ERP receipt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

import sqlalchemy as sa

from app.maintenance import learning_history as history
from app.maintenance import retained_schema as schema
from app.maintenance import retained_transition as retained

_A005 = "a005_erp_completion_checkpoint"
_TABLE = "academy_erp_completion_checkpoints"
_PK = "academy_erp_completion_checkpoints_pkey"
_TENANT_FK = "academy_erp_completion_checkpoints_tenant_id_fkey"
_COMPLETION_FK = "fk_erp_checkpoint_tenant_completion"
_POLICY = "academy_erp_completion_checkpoints_tenant_isolation"
_COLUMNS = ("tenant_id", "completion_id")
# Qualified names and key columns come from actual owner source, never input.
_PARENTS = (
    ("public", "tenants", ("id",), "tenants_pkey", "p"),
    ("mod_learning", "course_completions", ("tenant_id", "id"), "uq_course_completions_tenant_id_id", "u"),
)
# (name, child columns, parent namespace, parent table, parent columns)
_FK_SPECS = (
    (_TENANT_FK, ("tenant_id",), "public", "tenants", ("id",)),
    (_COMPLETION_FK, ("tenant_id", "completion_id"), "mod_learning", "course_completions", ("tenant_id", "id")),
)
_RUNTIME_ROLES = ("app_user", "platform_api", "academy_lab_worker", "outbox_dispatcher", "platform_outbox_dispatcher")
_IMPLICIT_TABLE = {
    "pg_read_all_data": frozenset({"SELECT"}),
    "pg_write_all_data": frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"}),
}
_IMPLICIT_COLUMN = {
    "pg_read_all_data": frozenset({"SELECT"}),
    "pg_write_all_data": frozenset({"SELECT", "INSERT", "UPDATE"}),
}


def _require(condition):
    if not condition:
        from app.maintenance.product_adoption import ProductAdoptionRefused

        raise ProductAdoptionRefused("Academy checkpoint transition refused; root rollback required")


@dataclass(slots=True, repr=False)
class _CheckpointTransition:
    # Constructed only after genuine product owner checks. Identity, not equality,
    # binds this object beneath the existing weakly registered product State.
    handle: object = field(repr=False)
    connection: object = field(repr=False)
    root: object = field(repr=False)
    xid: object = field(repr=False)
    runner: object = field(repr=False)
    retained_entry: object = field(repr=False)
    raw_acks: object = field(repr=False)
    parent_keys: object = field(repr=False)
    parent_catalogs: object = field(repr=False)
    version_oid: object = field(repr=False)
    before_versions: object = field(repr=False)
    after_versions: object = field(repr=False)
    consumed: bool = False
    final: object = field(default=None, repr=False)
    new_fks: object = field(default=None, repr=False)
    new_triggers: object = field(default=None, repr=False)


def _expected_versions(graph, *, final):
    # Fixed a005 stage cut over the complete provenance-checked graph.
    return retained._stage_versions(graph, _A005, final=final)


def _original_acks(state):
    """Every original (tenant_id, id, raw ACK hex/NULL) from private raw rows."""
    spec = next(item for item in history._TABLES if item.name == "course_completions")
    ordered = tuple(name for name, _, _ in sorted(spec.columns))
    tenant_at, id_at, ack_at = ordered.index("tenant_id"), ordered.index("id"), ordered.index("erp_synced_at")
    rows = dict(state.learning_raw)["course_completions"]
    acks = tuple(sorted((row[tenant_at], row[id_at], row[ack_at]) for row in rows))
    _require(all(type(tenant) is UUID and type(identifier) is UUID for tenant, identifier, _ in acks))
    _require(all(ack is None or (type(ack) is str and len(ack) == 16) for _, _, ack in acks))
    _require(len({(tenant, identifier) for tenant, identifier, _ in acks}) == len(acks))
    # Cross-check through the established native decoder; no decoded copy is kept.
    decoded = {(tenant, identifier): history._timestamp(ack) for tenant, identifier, ack in acks}
    _require(type(state.completion_acks) is tuple and len(state.completion_acks) == len(acks))
    _require(decoded == {(row.tenant_id, row.id): row.erp_synced_at for row in state.completion_acks})
    return acks


def _source_acks(connection):
    return history._query(
        connection,
        "SELECT tenant_id,id,encode(pg_catalog.timestamptz_send(erp_synced_at),'hex') "
        "FROM public.course_completions ORDER BY tenant_id,id",
    )


def _canonical_keys(connection):
    return history._query(connection, "SELECT tenant_id,id FROM mod_learning.course_completions ORDER BY tenant_id,id")


def _checkpoint_rows(connection):
    return history._query(
        connection,
        "SELECT tenant_id,completion_id,encode(pg_catalog.timestamptz_send(erp_synced_at),'hex') "
        "FROM public.academy_erp_completion_checkpoints ORDER BY tenant_id,completion_id",
    )


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


def _parent_keys(connection):
    return {(ns, t): retained._key(connection, ns, t, cols, name, kind) for ns, t, cols, name, kind in _PARENTS}


def _refuse_destination(connection):
    """No pre-existing relation, type, index, constraint or policy may collide."""
    _require(history._oid(connection, _TABLE) is None)
    _require(
        not history._query(
            connection,
            "SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
            "ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(:names)",
            names=[_TABLE, _PK],
        )
    )
    _require(
        not history._query(
            connection,
            "SELECT t.typname FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n "
            "ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typname=:name",
            name=_TABLE,
        )
    )
    _require(
        not history._query(
            connection,
            "SELECT k.conname FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_namespace n "
            "ON n.oid=k.connamespace WHERE n.nspname='public' AND k.conname=ANY(:names)",
            names=[_PK, _TENANT_FK, _COMPLETION_FK],
        )
    )
    _require(
        not history._query(
            connection, "SELECT p.polname FROM pg_catalog.pg_policy p WHERE p.polname=:name", name=_POLICY
        )
    )


def _capture_parents(connection, keys):
    parents = tuple((ns, t, history._catalog(connection, keys[(ns, t)][0])) for ns, t, *_ in _PARENTS)
    for _, _, captured in parents:
        _require(captured.relation[1:3] == ("r", "app_admin"))
        # Current selected owners declare no custom parent triggers or rules.
        _require(not captured.rules)
        _require(all(trigger[5] is True for trigger in captured.triggers))
        unexpected = history._query(
            connection,
            "SELECT t.oid FROM pg_catalog.pg_trigger t "
            "LEFT JOIN pg_catalog.pg_constraint k ON k.oid=t.tgconstraint "
            "WHERE t.tgrelid=:oid AND (k.contype IS DISTINCT FROM 'f' OR NOT t.tgisinternal "
            "OR NOT ((t.tgrelid=k.conrelid AND t.tgconstrrelid=k.confrelid) "
            "OR (t.tgrelid=k.confrelid AND t.tgconstrrelid=k.conrelid)))",
            oid=captured.relation[0],
        )
        _require(not unexpected)
    return parents


def _prepare(connection, state):
    retained_entry = state.retained_transition
    _require(type(retained_entry) is retained._RetainedTransition and retained_entry.final is not None)
    _require(state.checkpoint_runner is not None)
    _refuse_destination(connection)
    keys = _parent_keys(connection)
    original_oid = dict(state.oids)["course_completions"]
    _require(history._oid(connection, "course_completions") == original_oid)
    _held(connection, {key[0] for key in keys.values()} | {original_oid})
    parents = _capture_parents(connection, keys)
    raw = _original_acks(state)
    _require(_source_acks(connection) == raw)
    _require(_canonical_keys(connection) == tuple((tenant, identifier) for tenant, identifier, _ in raw))
    retained._verify_successor_cluster(connection, retained_entry.public_schema)
    graph = state.provenance[4][0]
    before_versions = _expected_versions(graph, final=False)
    _require(retained._version_rows(connection) == before_versions == retained_entry.after_versions)
    _require(history._oid(connection, "alembic_version") == retained_entry.version_oid)
    return _CheckpointTransition(
        state.handle,
        connection,
        state.root,
        state.xid,
        state.checkpoint_runner,
        retained_entry,
        raw,
        keys,
        parents,
        retained_entry.version_oid,
        before_versions,
        _expected_versions(graph, final=True),
    )


def _verify_before(connection, entry):
    _refuse_destination(connection)
    _require(_parent_keys(connection) == entry.parent_keys)
    original_oid = history._oid(connection, "course_completions")
    _require(type(original_oid) is int and original_oid > 0)
    _held(connection, {key[0] for key in entry.parent_keys.values()} | {original_oid})
    for namespace, table, captured in entry.parent_catalogs:
        _require(history._oid(connection, table, namespace) == captured.relation[0])
        _require(history._catalog(connection, captured.relation[0]) == captured)
    _require(_source_acks(connection) == entry.raw_acks)
    _require(_canonical_keys(connection) == tuple((tenant, identifier) for tenant, identifier, _ in entry.raw_acks))
    _require(history._oid(connection, "alembic_version") == entry.version_oid)
    _require(retained._version_rows(connection) == entry.before_versions)
    retained._verify_successor_cluster(connection, entry.retained_entry.public_schema)


def _records(rows, fields):
    return retained._records({"rows": rows}, "rows", fields)


def _foreign_keys(connection, child_oid, keys):
    rows = history._query(
        connection,
        "SELECT f.oid,kn.nspname,cn.nspname,c.relname,c.oid,f.conname,f.contype,"
        "ARRAY(SELECT a.attname FROM unnest(f.conkey) WITH ORDINALITY x(num,ord) "
        "LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=f.conrelid AND a.attnum=x.num ORDER BY x.ord),"
        "f.conkey,pn.nspname,p.relname,p.oid,"
        "ARRAY(SELECT a.attname FROM unnest(f.confkey) WITH ORDINALITY x(num,ord) "
        "LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=f.confrelid AND a.attnum=x.num ORDER BY x.ord),"
        "f.confkey,f.confdeltype,f.confupdtype,f.confmatchtype,f.convalidated,f.condeferrable,"
        "f.condeferred,f.connoinherit,f.conislocal,f.coninhcount,f.conparentid,f.conindid,"
        "f.confdelsetcols,f.conbin IS NULL "
        "FROM pg_catalog.pg_constraint f LEFT JOIN pg_catalog.pg_namespace kn ON kn.oid=f.connamespace "
        "LEFT JOIN pg_catalog.pg_class c ON c.oid=f.conrelid "
        "LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=c.relnamespace "
        "LEFT JOIN pg_catalog.pg_class p ON p.oid=f.confrelid "
        "LEFT JOIN pg_catalog.pg_namespace pn ON pn.oid=p.relnamespace "
        "WHERE f.conrelid=:oid AND f.contype='f' ORDER BY f.conname",
        oid=child_oid,
    )
    fks = _records(rows, schema._RI_FK_FIELDS)
    specs = {row[0]: row for row in _FK_SPECS}
    _require(len(fks) == 2 and {fk["name"] for fk in fks} == set(specs))
    for fk in fks:
        _, columns, namespace, parent, target = specs[fk["name"]]
        _, numbers = retained._attributes(connection, "public", _TABLE, columns)
        parent_oid, parent_numbers, _, index_oid = keys[(namespace, parent)]
        _require(fk["namespace"] == fk["child_namespace"] == "public" and fk["child"] == _TABLE)
        _require(
            (fk["child_oid"], fk["kind"], fk["columns"], fk["column_numbers"]) == (child_oid, "f", columns, numbers)
        )
        _require(
            (
                fk["parent_namespace"],
                fk["parent"],
                fk["parent_oid"],
                fk["parent_columns"],
                fk["parent_numbers"],
                fk["index_oid"],
            )
            == (namespace, parent, parent_oid, target, parent_numbers, index_oid)
        )
        _require(
            tuple(
                fk[key]
                for key in (
                    "delete_action",
                    "update_action",
                    "match",
                    "validated",
                    "deferrable",
                    "deferred",
                    "noinherit",
                    "local",
                    "inheritance_count",
                    "parent_constraint",
                    "delete_set_columns",
                    "expression_absent",
                )
            )
            == ("c", "a", "s", True, False, False, True, True, 0, 0, None, True)
        )
        _require(type(fk["oid"]) is int and fk["oid"] > 0)
    _require(len({fk["oid"] for fk in fks}) == 2)
    return {fk["oid"]: fk for fk in fks}


def _check_operators(connection, by_oid):
    rows = history._query(
        connection,
        "SELECT k.oid,k.conpfeqop,k.conppeqop,k.conffeqop FROM pg_catalog.pg_constraint k "
        "WHERE k.oid=ANY(:oids) ORDER BY k.oid",
        oids=sorted(by_oid),
    )
    _require(len(rows) == len(by_oid))
    operator = history._query(
        connection,
        "SELECT o.oid,n.nspname,o.oprname,o.oprkind,ln.nspname,lt.typname,rn.nspname,rt.typname,"
        "bn.nspname,bt.typname,o.oprcode,pn.nspname,p.proname "
        "FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_namespace n ON n.oid=o.oprnamespace "
        "JOIN pg_catalog.pg_type lt ON lt.oid=o.oprleft JOIN pg_catalog.pg_namespace ln ON ln.oid=lt.typnamespace "
        "JOIN pg_catalog.pg_type rt ON rt.oid=o.oprright JOIN pg_catalog.pg_namespace rn ON rn.oid=rt.typnamespace "
        "JOIN pg_catalog.pg_type bt ON bt.oid=o.oprresult JOIN pg_catalog.pg_namespace bn ON bn.oid=bt.typnamespace "
        "JOIN pg_catalog.pg_proc p ON p.oid=o.oprcode JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace "
        "WHERE o.oid='pg_catalog.=(uuid,uuid)'::regoperator",
    )
    _require(len(operator) == 1)
    expected_oid = operator[0][0]
    _require(type(expected_oid) is int and expected_oid > 0)
    _require(
        operator[0][1:10] == ("pg_catalog", "=", "b", "pg_catalog", "uuid", "pg_catalog", "uuid", "pg_catalog", "bool")
    )
    _require(type(operator[0][10]) is int and operator[0][10] > 0)
    _require(operator[0][11:] == ("pg_catalog", "uuid_eq"))
    for oid, pf, pp, ff in rows:
        count = len(by_oid[oid]["columns"])
        _require((len(pf), len(pp), len(ff)) == (count, count, count))
        _require(set(pf) | set(pp) | set(ff) == {expected_oid})


def _ri_triggers(connection, by_oid):
    rows = history._query(
        connection,
        "SELECT t.oid,t.tgrelid,n.nspname,c.relname,t.tgname,t.tgfoid,pn.nspname,p.proname,l.lanname,"
        "p.prosrc,p.pronargs,rn.nspname,rt.typname,p.prokind,p.proretset,t.tgtype,t.tgenabled,"
        "t.tgisinternal,t.tgconstrrelid,t.tgconstrindid,t.tgconstraint,t.tgparentid,"
        "t.tgdeferrable,t.tginitdeferred,t.tgnargs,octet_length(t.tgargs)=0,t.tgattr::text,"
        "t.tgqual IS NULL,t.tgoldtable,t.tgnewtable "
        "FROM pg_catalog.pg_trigger t LEFT JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid "
        "LEFT JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "LEFT JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid "
        "LEFT JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace "
        "LEFT JOIN pg_catalog.pg_language l ON l.oid=p.prolang "
        "LEFT JOIN pg_catalog.pg_type rt ON rt.oid=p.prorettype "
        "LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid=rt.typnamespace "
        "WHERE t.tgconstraint=ANY(:oids) ORDER BY t.tgconstraint,t.tgrelid,t.tgtype,t.oid",
        oids=sorted(by_oid),
    )
    triggers = _records(rows, schema._RI_TRIGGER_FIELDS)
    _require(len(triggers) == 8 and len({t["oid"] for t in triggers}) == 8)
    roles = []
    for trigger in triggers:
        fk = by_oid.get(trigger["constraint_oid"])
        _require(fk is not None)
        child = trigger["relation_oid"] == fk["child_oid"]
        side = "child" if child else "parent"
        function = (
            {5: "RI_FKey_check_ins", 17: "RI_FKey_check_upd"}
            if child
            else {9: "RI_FKey_cascade_del", 17: "RI_FKey_noaction_upd"}
        ).get(trigger["type"])
        _require(function is not None)
        _require(
            (trigger["relation_oid"], trigger["relation_namespace"], trigger["relation"])
            == (
                (fk["child_oid"], "public", fk["child"])
                if child
                else (fk["parent_oid"], fk["parent_namespace"], fk["parent"])
            )
        )
        _require(type(trigger["oid"]) is int and trigger["oid"] > 0)
        _require(
            trigger["name"] == ("RI_ConstraintTrigger_c_" if child else "RI_ConstraintTrigger_a_") + str(trigger["oid"])
        )
        _require(type(trigger["function_oid"]) is int and trigger["function_oid"] > 0)
        _require(
            tuple(
                trigger[key]
                for key in (
                    "function_namespace",
                    "function",
                    "function_language",
                    "function_source",
                    "function_arguments",
                    "function_return_namespace",
                    "function_return_type",
                    "function_kind",
                    "function_returns_set",
                )
            )
            == ("pg_catalog", function, "internal", function, 0, "pg_catalog", "trigger", "f", False)
        )
        _require(
            tuple(
                trigger[key]
                for key in (
                    "enabled",
                    "internal",
                    "constraint_relation_oid",
                    "index_oid",
                    "parent_trigger",
                    "deferrable",
                    "deferred",
                    "argument_count",
                    "arguments_absent",
                    "columns",
                    "qual_absent",
                    "old_table",
                    "new_table",
                )
            )
            == (
                "O",
                True,
                fk["parent_oid"] if child else fk["child_oid"],
                fk["index_oid"],
                0,
                False,
                False,
                0,
                True,
                "",
                True,
                None,
                None,
            )
        )
        roles.append((fk["oid"], side, trigger["type"]))
    _require(
        tuple(sorted(roles))
        == tuple(
            sorted(
                (oid, side, flag)
                for oid in by_oid
                for side, flag in (("child", 5), ("child", 17), ("parent", 9), ("parent", 17))
            )
        )
    )
    return triggers


def _check_dependencies(connection, by_oid, triggers, key_constraints):
    # key_constraints: constraint oid -> (relation oid, column numbers, index oid)
    rows = history._query(
        connection,
        "SELECT ns.nspname||'.'||cl.relname,d.objid,d.objsubid,rns.nspname||'.'||rcl.relname,"
        "d.refobjid,d.refobjsubid,d.deptype "
        "FROM pg_catalog.pg_depend d LEFT JOIN pg_catalog.pg_class cl ON cl.oid=d.classid "
        "LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid=cl.relnamespace "
        "LEFT JOIN pg_catalog.pg_class rcl ON rcl.oid=d.refclassid "
        "LEFT JOIN pg_catalog.pg_namespace rns ON rns.oid=rcl.relnamespace "
        "WHERE (d.classid='pg_catalog.pg_constraint'::regclass AND d.objid=ANY(:constraints)) "
        "OR (d.classid='pg_catalog.pg_trigger'::regclass AND d.objid=ANY(:triggers)) "
        "OR (d.classid='pg_catalog.pg_class'::regclass AND d.objid=ANY(:indexes)) "
        "OR (d.refclassid='pg_catalog.pg_constraint'::regclass AND d.refobjid=ANY(:fks)) "
        "OR (d.refclassid='pg_catalog.pg_trigger'::regclass AND d.refobjid=ANY(:triggers)) "
        "ORDER BY 1,2,3,4,5,6,7",
        constraints=sorted(set(by_oid) | set(key_constraints)),
        triggers=sorted(t["oid"] for t in triggers),
        indexes=sorted(index for _, _, index in key_constraints.values()),
        fks=sorted(by_oid),
    )
    parent_keys = {
        oid: {"parent_oid": relation, "constraint_numbers": numbers, "index_oid": index}
        for oid, (relation, numbers, index) in key_constraints.items()
    }
    # Exact dependency MULTISET; established PG16 semantics, no static OIDs.
    schema._check_ri_dependencies({"ri_dependencies": rows}, by_oid, parent_keys, triggers)


def _check_policy(connection, child_oid, catalog):
    rows = history._query(
        connection,
        "SELECT oid,polname,polcmd,polpermissive,polroles,"
        "pg_catalog.pg_get_expr(polqual,polrelid,false),pg_catalog.pg_get_expr(polwithcheck,polrelid,false) "
        "FROM pg_catalog.pg_policy WHERE polrelid=:oid ORDER BY polname",
        oid=child_oid,
    )
    _require(len(rows) == 1 and type(rows[0][0]) is int and rows[0][0] > 0)
    _require(
        rows[0][1:]
        == (_POLICY, "*", True, (0,), "(tenant_id = app_current_tenant_id())", "(tenant_id = app_current_tenant_id())")
    )
    _require(len(catalog.policies) == 1 and catalog.policies[0][0] == rows[0][0])
    helper_oid = schema._check_tenant_helper(schema._observe_historical_catalog(connection))
    classes = history._query(
        connection,
        "SELECT 'pg_catalog.pg_policy'::regclass::oid,'pg_catalog.pg_class'::regclass::oid,"
        "'pg_catalog.pg_proc'::regclass::oid",
    )
    _require(len(classes) == 1)
    policy_class, class_class, proc_class = classes[0]
    policy_oid = rows[0][0]
    # PG16 records USING and WITH CHECK separately; preserve both identical rows.
    expected = [(policy_class, policy_oid, 0, class_class, child_oid, 0, "a")]
    for _ in range(2):
        expected.append((policy_class, policy_oid, 0, class_class, child_oid, 1, "n"))
        expected.append((policy_class, policy_oid, 0, proc_class, helper_oid, 0, "n"))
    _require(catalog.dependencies == tuple(sorted(expected)))
    # Policies targeting PUBLIC record no shared role dependency in PG16.
    _require(
        not history._query(
            connection,
            "SELECT d.objid FROM pg_catalog.pg_shdepend d "
            "WHERE d.classid='pg_catalog.pg_policy'::regclass AND d.objid=:oid "
            "AND d.dbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())",
            oid=policy_oid,
        )
    )


def _check_acl(connection, child_oid, catalog):
    roles = history._query(connection, "SELECT oid,rolname,rolsuper FROM pg_catalog.pg_roles ORDER BY rolname")
    by_name = {row[1]: row for row in roles}
    _require("app_admin" in by_name and set(_RUNTIME_ROLES) <= set(by_name))
    admin_oid = by_name["app_admin"][0]
    _require(catalog.acl == tuple(sorted((admin_oid, admin_oid, priv, False) for priv in schema._PRIVILEGES)))
    _require(catalog.column_acl == ())
    table_columns = ", ".join(f"pg_catalog.has_table_privilege(:role,:oid,'{priv}')" for priv in schema._PRIVILEGES)
    column_columns = ", ".join(
        f"pg_catalog.has_column_privilege(:role,:oid,'{column}','{priv}')"
        for column in (*_COLUMNS, "erp_synced_at")
        for priv in schema._COLUMN_PRIVILEGES
    )
    for role_oid, name, superuser in roles:
        table = history._query(connection, f"SELECT {table_columns}", role=role_oid, oid=child_oid)
        columns = history._query(connection, f"SELECT {column_columns}", role=role_oid, oid=child_oid)
        held_table = {priv for priv, held in zip(schema._PRIVILEGES, table[0], strict=True) if held}
        held_column = {
            priv
            for (column, priv), held in zip(
                ((c, p) for c in (*_COLUMNS, "erp_synced_at") for p in schema._COLUMN_PRIVILEGES),
                columns[0],
                strict=True,
            )
            if held
        }
        if name == "app_admin":
            _require(held_table == set(schema._PRIVILEGES) and held_column == set(schema._COLUMN_PRIVILEGES))
        elif superuser:
            continue  # Existing superuser exception; cluster authority is checked separately.
        else:
            _require(held_table <= _IMPLICIT_TABLE.get(name, frozenset()))
            _require(held_column <= _IMPLICIT_COLUMN.get(name, frozenset()))
    public = history._query(connection, f"SELECT {table_columns}", role="public", oid=child_oid)
    _require(not any(public[0]))


def _observe_child(connection, entry):
    child_oid = history._oid(connection, _TABLE)
    _require(type(child_oid) is int and child_oid > 0)
    keys = _parent_keys(connection)
    _require(keys == entry.parent_keys)
    primary = retained._key(connection, "public", _TABLE, _COLUMNS, _PK, "p")
    _require(primary[0] == child_oid)
    catalog = history._catalog(connection, child_oid)
    _require(catalog.relation == (child_oid, "r", "app_admin", True, True, False, False, "p", None, "d", 0))
    _require(
        tuple(row[:4] for row in catalog.columns)
        == (
            (1, "tenant_id", "uuid", True),
            (2, "completion_id", "uuid", True),
            (3, "erp_synced_at", "timestamp with time zone", False),
        )
    )
    _require(all(row[4] is False and row[5] is None and row[6:8] == ("", "") for row in catalog.columns))
    _require(
        tuple((row[0], row[1], row[2]) for row in catalog.constraints)
        == ((_PK, "p", primary[1]), (_TENANT_FK, "f", (1,)), (_COMPLETION_FK, "f", (1, 2)))
    )
    _require(catalog.incoming == ())
    _require(len(catalog.indexes) == 1 and catalog.indexes[0][:2] == (primary[3], _PK))
    _require(catalog.rules == ())
    _require(len(catalog.triggers) == 4)
    _require(
        not history._query(
            connection,
            "SELECT inhrelid FROM pg_catalog.pg_inherits WHERE inhrelid=:oid OR inhparent=:oid",
            oid=child_oid,
        )
    )
    _require(
        not history._query(
            connection,
            "SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_depend d ON d.objid=c.oid "
            "WHERE c.relkind='S' AND d.refobjid=:oid",
            oid=child_oid,
        )
    )
    by_oid = _foreign_keys(connection, child_oid, keys)
    _check_operators(connection, by_oid)
    triggers = _ri_triggers(connection, by_oid)
    _require({row[0] for row in catalog.triggers} == {t["oid"] for t in triggers if t["relation_oid"] == child_oid})
    key_constraints = {constraint: (relation, numbers, index) for relation, numbers, constraint, index in keys.values()}
    key_constraints[primary[2]] = (child_oid, primary[1], primary[3])
    _check_dependencies(connection, by_oid, triggers, key_constraints)
    _check_policy(connection, child_oid, catalog)
    _check_acl(connection, child_oid, catalog)
    return catalog, frozenset(by_oid), frozenset(t["oid"] for t in triggers)


def _observe_delta(connection, state):
    """Verify the exact private child/parent delta; never calls continuity."""
    entry = state.checkpoint_transition
    _require(type(entry) is _CheckpointTransition and entry.consumed and entry.runner is not None)
    _require(entry.handle is state.handle and entry.connection is connection)
    _require(entry.root is state.root and entry.xid == state.xid)
    _require(entry.retained_entry is state.retained_transition)
    catalog, new_fks, new_triggers = _observe_child(connection, entry)
    child_oid = catalog.relation[0]
    expected_fk = {(ns, table): name for name, _, ns, table, _ in _FK_SPECS}
    for namespace, table, captured in entry.parent_catalogs:
        _require(history._oid(connection, table, namespace) == captured.relation[0])
        current = history._catalog(connection, captured.relation[0])
        added_incoming = tuple(row for row in current.incoming if row[0] in new_fks)
        added_triggers = tuple(row for row in current.triggers if row[0] in new_triggers)
        _require(len(added_incoming) == 1 and len(added_triggers) == 2)
        _require(added_incoming[0][1] == expected_fk[(namespace, table)] and added_incoming[0][2] == child_oid)
        _require(all(row[6] == added_incoming[0][0] for row in added_triggers))
        _require(retained._project_catalog(current, new_fks, new_triggers, frozenset()) == captured)
    _require(_source_acks(connection) == entry.raw_acks)
    _require(_canonical_keys(connection) == tuple((t, i) for t, i, _ in entry.raw_acks))
    rows = _checkpoint_rows(connection)
    _require(rows == entry.raw_acks)
    _require(
        connection.scalar(
            sa.text(
                "SELECT NOT EXISTS (SELECT 1 FROM public.course_completions s "
                "FULL JOIN public.academy_erp_completion_checkpoints c "
                "ON c.tenant_id=s.tenant_id AND c.completion_id=s.id "
                "WHERE s.id IS NULL OR c.completion_id IS NULL "
                "OR c.erp_synced_at IS DISTINCT FROM s.erp_synced_at)"
            )
        )
        is True
    )
    return catalog, rows, new_fks, new_triggers


def _verify_after(connection, state, entry, *, recorded):
    catalog, rows, new_fks, new_triggers = _observe_delta(connection, state)
    final = (catalog, rows)
    if recorded:
        _require(entry.final == final and entry.new_fks == new_fks and entry.new_triggers == new_triggers)
    else:
        _require(entry.final is None and entry.new_fks is None and entry.new_triggers is None)
        # Stored before the retained verifier derives its exact a005 projection.
        entry.final, entry.new_fks, entry.new_triggers = final, new_fks, new_triggers
    retained._verify_after(connection, state, entry.retained_entry, recorded=True)
    return final, new_fks, new_triggers


def _apply_checkpoint_transition(connection, entry):
    from app.maintenance import product_adoption as product

    state = product._check(connection, entry.handle, "a005 executing")
    _require(state.checkpoint_transition is entry and entry.consumed and entry.final is None)
    _require(state.checkpoint_runner is not None and entry.runner is state.checkpoint_runner)
    _require(entry.connection is connection and entry.root is state.root and entry.xid == state.xid)
    _require(entry.retained_entry is state.retained_transition)
    product._verify_retained_prerequisites(connection, state)
    _verify_before(connection, entry)
    statements = (
        'CREATE TABLE "public"."academy_erp_completion_checkpoints" '
        '("tenant_id" uuid NOT NULL, "completion_id" uuid NOT NULL, '
        '"erp_synced_at" timestamp with time zone NULL, '
        'CONSTRAINT "academy_erp_completion_checkpoints_pkey" '
        'PRIMARY KEY ("tenant_id", "completion_id"), '
        'CONSTRAINT "academy_erp_completion_checkpoints_tenant_id_fkey" '
        'FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants" ("id") '
        "MATCH SIMPLE ON DELETE CASCADE ON UPDATE NO ACTION NOT DEFERRABLE INITIALLY IMMEDIATE, "
        'CONSTRAINT "fk_erp_checkpoint_tenant_completion" '
        'FOREIGN KEY ("tenant_id", "completion_id") '
        'REFERENCES "mod_learning"."course_completions" ("tenant_id", "id") '
        "MATCH SIMPLE ON DELETE CASCADE ON UPDATE NO ACTION NOT DEFERRABLE INITIALLY IMMEDIATE)",
        'ALTER TABLE "public"."academy_erp_completion_checkpoints" ENABLE ROW LEVEL SECURITY',
        'ALTER TABLE "public"."academy_erp_completion_checkpoints" FORCE ROW LEVEL SECURITY',
        'CREATE POLICY "academy_erp_completion_checkpoints_tenant_isolation" '
        'ON "public"."academy_erp_completion_checkpoints" AS PERMISSIVE FOR ALL TO PUBLIC '
        'USING ("tenant_id" = public.app_current_tenant_id()) '
        'WITH CHECK ("tenant_id" = public.app_current_tenant_id())',
        'REVOKE ALL ON TABLE "public"."academy_erp_completion_checkpoints" FROM PUBLIC',
        'REVOKE ALL ON TABLE "public"."academy_erp_completion_checkpoints" FROM "app_user"',
        'REVOKE ALL ON TABLE "public"."academy_erp_completion_checkpoints" FROM "platform_api"',
        'REVOKE ALL ON TABLE "public"."academy_erp_completion_checkpoints" FROM "academy_lab_worker"',
        'REVOKE ALL ON TABLE "public"."academy_erp_completion_checkpoints" FROM "outbox_dispatcher"',
        'REVOKE ALL ON TABLE "public"."academy_erp_completion_checkpoints" FROM "platform_outbox_dispatcher"',
        "INSERT INTO public.academy_erp_completion_checkpoints(tenant_id,completion_id,erp_synced_at) "
        "SELECT tenant_id,id,erp_synced_at FROM public.course_completions",
    )
    for statement in statements:
        connection.execute(sa.text(statement))

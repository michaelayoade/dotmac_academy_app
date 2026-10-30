"""Private historical a004 mechanics; no fresh, commit or admission authority.

The fixed source17 and final20 graphs are schema contracts. Only the actual
product State may select a phase. Observed OIDs never select a target/spec.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, cast

import sqlalchemy as sa

from app.maintenance import learning_history as history
from app.maintenance import retained_history as retained
from app.maintenance import retained_schema as schema

if TYPE_CHECKING:
    from app.maintenance.checkpoint_transition import _CheckpointTransition

_A004 = "a004_retained_learning_refs"
_LR7 = "lr_0007_enrollment_state_policy"
_LAB_TABLE = "lab_operations"
_LAB_CLAIM_COLUMN = "claim_lease_seconds"
_LAB_CLAIM_CHECKS = ("ck_lab_operations_claim_lease_positive", "ck_lab_operations_claim_lease_required")
_PRESERVED = frozenset({"fk_onboarding_tasks_tenant_applicant", "fk_lab_operations_tenant_instance"})
_PERSON_CHILDREN = ("notifications", "reminder_log", "reminder_preferences")
# Qualified names and key columns come from actual owner source, never input.
_CANONICAL = (
    ("public", "tenants", ("id",), "tenants_pkey", "p"),
    ("public", "parties", ("tenant_id", "id"), "uq_parties_tenant_id_id", "u"),
    ("public", "party_persons", ("party_id",), "party_persons_pkey", "p"),
    ("mod_learning", "question_banks", ("tenant_id", "id"), "uq_question_banks_tenant_id_id", "u"),
    (
        "mod_learning",
        "cohort_tracks",
        ("tenant_id", "cohort_id", "track_id"),
        "uq_cohort_tracks_cohort_track",
        "u",
    ),
)


def _require(condition):
    if not condition:
        from app.maintenance.product_adoption import ProductAdoptionRefused

        raise ProductAdoptionRefused("Academy retained transition refused; root rollback required")


# Fixed frozen62 profile plus precisely Kernel 0011/0012's declared grants.
_HISTORICAL_PUBLIC_ACL = tuple(
    sorted(
        (
            ("pg_database_owner", "PUBLIC", "USAGE", False),
            ("pg_database_owner", "pg_database_owner", "CREATE", False),
            ("pg_database_owner", "pg_database_owner", "USAGE", False),
            ("pg_database_owner", "app_admin", "CREATE", False),
            ("pg_database_owner", "app_admin", "USAGE", False),
            ("pg_database_owner", "app_user", "USAGE", False),
            ("pg_database_owner", "platform_api", "USAGE", False),
        )
    )
)
_DISPATCHER_PUBLIC_ACL = (
    ("pg_database_owner", "outbox_dispatcher", "USAGE", False),
    ("pg_database_owner", "platform_outbox_dispatcher", "USAGE", False),
)
_SUCCESSOR_PUBLIC_ACL = tuple(sorted(_HISTORICAL_PUBLIC_ACL + _DISPATCHER_PUBLIC_ACL))


def _successor_cluster(packet, envelope):
    # Validate the entire fixed profile before projecting exactly its two rows.
    # A fresh packet preserves every other field for the unchanged frozen gate.
    _require(type(envelope) is retained._PublicSchemaEnvelope)
    acl = packet["cluster_schema_acl"]
    _require(
        type(acl) is tuple
        and all(
            type(row) is tuple
            and len(row) == 4
            and all(type(value) is str for value in row[:3])
            and type(row[3]) is bool
            for row in acl
        )
    )
    _require(acl == envelope.acl == _SUCCESSOR_PUBLIC_ACL)
    projected = {**packet, "cluster_schema_acl": tuple(row for row in acl if row not in _DISPATCHER_PUBLIC_ACL)}
    schema._check_cluster_authority(projected)


def _observe_successor_schema(connection):
    """Fixed source shape only; this observation issues no product authority."""
    envelope = retained._public_schema_envelope(connection)
    _require(envelope.acl == _SUCCESSOR_PUBLIC_ACL)
    return envelope


def _verify_successor_cluster(connection, envelope, *, cluster=None):
    _require(_observe_successor_schema(connection) == envelope)
    _successor_cluster(schema._observe_cluster_authority(connection) if cluster is None else cluster, envelope)


def _successor_envelope(connection, original):
    current = retained._public_schema_envelope(connection)
    _require(type(original) is retained._PublicSchemaEnvelope)
    _require(original.acl == _HISTORICAL_PUBLIC_ACL)
    _require(current.oid == original.oid and current.owner_oid == original.owner_oid)
    _require(current.acl == _SUCCESSOR_PUBLIC_ACL)
    return current


def _specs(*, final):
    rows = []
    for child, specs in schema._FOREIGN_KEYS:
        for name, columns, parent, parent_columns, action in specs:
            namespace = "academy_identity_compat" if parent in ("tenants", "people") else "public"
            if final:
                if parent == "people":
                    parent = "parties"
                namespace = "mod_learning" if parent in ("question_banks", "cohort_tracks") else "public"
            rows.append((child, name, columns, namespace, parent, parent_columns, action))
    if final:
        rows.extend(
            (child, "fk_" + child + "_person", ("person_id",), "public", "party_persons", ("party_id",), "CASCADE")
            for child in _PERSON_CHILDREN
        )
    return tuple(sorted(rows))


@dataclass(slots=True, repr=False)
class _RetainedTransition:
    # Constructed only after genuine product owner checks. Identity, not equality,
    # binds this object beneath the existing weakly registered product State.
    handle: object = field(repr=False)
    connection: object = field(repr=False)
    root: object = field(repr=False)
    xid: object = field(repr=False)
    fragment: object = field(repr=False)
    runner: object = field(repr=False)
    before: object = field(repr=False)
    canonical: object = field(repr=False)
    parent_keys: object = field(repr=False)
    version_oid: object = field(repr=False)
    before_versions: object = field(repr=False)
    after_versions: object = field(repr=False)
    public_schema: retained._PublicSchemaEnvelope = field(repr=False)
    consumed: bool = False
    final: object = field(default=None, repr=False)
    new_fks: object = field(default=None, repr=False)
    new_triggers: object = field(default=None, repr=False)


def _records(packet, name, fields):
    return schema._ri_records(packet, name, fields)


def _attributes(connection, namespace, table, columns):
    oid = history._oid(connection, table, namespace)
    _require(type(oid) is int and oid > 0)
    rows = history._query(
        connection,
        "SELECT a.attnum,a.attname,tn.nspname,t.typname,a.atttypmod,a.attisdropped,"
        "a.attidentity,a.attgenerated,a.attcollation,a.attinhcount,a.attislocal "
        "FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type t ON t.oid=a.atttypid "
        "JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace "
        "WHERE a.attrelid=:oid AND a.attname=ANY(:columns) ORDER BY a.attnum",
        oid=oid,
        columns=list(columns),
    )
    _require(len(rows) == len(columns) and {row[1] for row in rows} == set(columns))
    _require(all(row[2:] == ("pg_catalog", "uuid", -1, False, "", "", 0, 0, True) for row in rows))
    by_name = {row[1]: row[0] for row in rows}
    return oid, tuple(by_name[name] for name in columns)


def _key(connection, namespace, table, columns, name, kind):
    """Resolve owner-named full immediate UUID btree keys BEFORE mutation."""
    oid, numbers = _attributes(connection, namespace, table, columns)
    rows = history._query(
        connection,
        "SELECT k.oid,k.conindid,k.contype,k.conkey,k.convalidated,k.condeferrable,"
        "k.condeferred,k.connoinherit,k.conislocal,k.coninhcount,k.conparentid,"
        "n.nspname,c.relname,c.relkind,pg_catalog.pg_get_userbyid(c.relowner),"
        "c.reloptions,c.reltablespace,c.relispartition,am.amname,i.indisunique,i.indisprimary,"
        "i.indisvalid,i.indisready,i.indislive,i.indimmediate,i.indisexclusion,i.indnkeyatts,"
        "i.indnatts,i.indkey::text,i.indexprs IS NULL,i.indpred IS NULL,i.indoption::text,"
        "i.indnullsnotdistinct,"
        "ARRAY(SELECT ns.nspname||'.'||op.opcname FROM unnest(i.indclass) WITH ORDINALITY x(id,ord) "
        "JOIN pg_catalog.pg_opclass op ON op.oid=x.id JOIN pg_catalog.pg_namespace ns ON ns.oid=op.opcnamespace "
        "ORDER BY x.ord),i.indcollation::text,"
        "ARRAY(SELECT op.opcdefault FROM unnest(i.indclass) WITH ORDINALITY x(id,ord) "
        "JOIN pg_catalog.pg_opclass op ON op.oid=x.id ORDER BY x.ord),"
        "ARRAY(SELECT ns.nspname||'.'||t.typname FROM unnest(i.indclass) WITH ORDINALITY x(id,ord) "
        "JOIN pg_catalog.pg_opclass op ON op.oid=x.id JOIN pg_catalog.pg_type t ON t.oid=op.opcintype "
        "JOIN pg_catalog.pg_namespace ns ON ns.oid=t.typnamespace ORDER BY x.ord),"
        "ARRAY(SELECT a.amname FROM unnest(i.indclass) WITH ORDINALITY x(id,ord) "
        "JOIN pg_catalog.pg_opclass op ON op.oid=x.id JOIN pg_catalog.pg_am a ON a.oid=op.opcmethod ORDER BY x.ord),"
        "ARRAY(SELECT ns.nspname||'.'||f.opfname FROM unnest(i.indclass) WITH ORDINALITY x(id,ord) "
        "JOIN pg_catalog.pg_opclass op ON op.oid=x.id JOIN pg_catalog.pg_opfamily f ON f.oid=op.opcfamily "
        "JOIN pg_catalog.pg_namespace ns ON ns.oid=f.opfnamespace ORDER BY x.ord) "
        "FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conindid "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_catalog.pg_index i ON i.indexrelid=c.oid JOIN pg_catalog.pg_am am ON am.oid=c.relam "
        "WHERE k.conrelid=:oid AND k.conname=:name AND k.connamespace=c.relnamespace AND i.indrelid=:oid",
        oid=oid,
        name=name,
    )
    _require(len(rows) == 1)
    row = rows[0]
    _require(type(row[0]) is int and row[0] > 0 and type(row[1]) is int and row[1] > 0)
    _require(
        row[2:]
        == (
            kind,
            numbers,
            True,
            False,
            False,
            True,
            True,
            0,
            0,
            namespace,
            name,
            "i",
            "app_admin",
            None,
            0,
            False,
            "btree",
            True,
            kind == "p",
            True,
            True,
            True,
            True,
            False,
            len(columns),
            len(columns),
            " ".join(map(str, numbers)),
            True,
            True,
            " ".join("0" for _ in columns),
            False,
            tuple("pg_catalog.uuid_ops" for _ in columns),
            " ".join("0" for _ in columns),
            tuple(True for _ in columns),
            tuple("pg_catalog.uuid" for _ in columns),
            tuple("btree" for _ in columns),
            tuple("pg_catalog.uuid_ops" for _ in columns),
        )
    )
    return oid, numbers, row[0], row[1]


def _parent_specs(*, final):
    if final:
        return (
            *_CANONICAL,
            *(
                ("public", table, columns, name, kind)
                for table, columns, name, kind in schema._RI_PARENT_KEYS
                if table in ("applicants", "lab_instances")
            ),
        )
    return tuple(
        ("academy_identity_compat" if table in ("tenants", "people") else "public", table, columns, name, kind)
        for table, columns, name, kind in schema._RI_PARENT_KEYS
    )


def _check_ri(connection, packet, *, final, keys):
    """Private qualified phase validator; public historical checker is unchanged."""
    schema._check_rendering_context(packet)
    specs = {(row[0], row[1]): row for row in _specs(final=final)}
    fks = _records(packet, "ri_foreign_keys", schema._RI_FK_FIELDS)
    _require(len(fks) == len(specs) and {(fk["child"], fk["name"]) for fk in fks} == set(specs))
    relations = {(row[1], row[2]): row for row in packet["ri_relations"]}
    parents = {(s, t): (cols, name, kind) for s, t, cols, name, kind in _parent_specs(final=final)}
    _require(len(relations) == len(packet["ri_relations"]))
    _require(set(relations) == {("public", name) for name in schema._NAMES} | set(parents))
    _require(not packet["ri_inheritance"])
    for (namespace, table), row in relations.items():
        _require(history._oid(connection, table, namespace) == row[0])
        _require(row[3:8] == ("r", "app_admin", "p", False, False))
        _require(row[8] is (table != "platform_settings"))
    by_oid = {}
    expected_columns: set[tuple[str, str, str]] = set()
    for fk in fks:
        child, name, columns, namespace, parent, target, action = specs[(fk["child"], fk["name"])]
        child_oid, numbers = _attributes(connection, "public", child, columns)
        parent_oid, parent_numbers, _, index_oid = keys[(namespace, parent)]
        _require(fk["namespace"] == fk["child_namespace"] == "public")
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
            == ("c" if action == "CASCADE" else "a", "a", "s", True, False, False, True, True, 0, 0, None, True)
        )
        _require(type(fk["oid"]) is int and fk["oid"] > 0 and fk["oid"] not in by_oid)
        by_oid[fk["oid"]] = fk
        expected_columns.update(("public", child, column) for column in columns)
        expected_columns.update((namespace, parent, column) for column in target)
    _require(len(packet["ri_columns"]) == len(expected_columns))
    _require({row[1:3] + (row[4],) for row in packet["ri_columns"]} == expected_columns)
    retained_columns = {(table, col[0]): col for table, cols in schema._COLUMNS for col in cols}
    for row in packet["ri_columns"]:
        namespace, table, column = row[1:3] + (row[4],)
        oid, numbers = _attributes(connection, namespace, table, (column,))
        not_null = (
            not retained_columns[(table, column)][2] if namespace == "public" and table in schema._NAMES else True
        )
        # Native defaults on parent keys are owner-controlled and conserved by
        # their exact full catalog preimage. Retained FK columns have no default.
        _require(row[:9] == (oid, namespace, table, numbers[0], column, "pg_catalog", "uuid", -1, not_null))
        _require(row[9:16] == (False, "", "", None, None, 0, True))
        if namespace == "public" and table in schema._NAMES:
            _require(row[16] is True)
    key_records = _records(packet, "ri_parent_keys", schema._RI_KEY_FIELDS)
    _require(len(key_records) == len(fks) and {key["fk_oid"] for key in key_records} == set(by_oid))
    unique_keys = {}
    for key in key_records:
        fk = by_oid[key["fk_oid"]]
        namespace, table = fk["parent_namespace"], fk["parent"]
        columns, name, kind = parents[(namespace, table)]
        oid, numbers, constraint_oid, index_oid = keys[(namespace, table)]
        expected = {
            "parent_oid": oid,
            "index_oid": index_oid,
            "index_namespace": namespace,
            "index_name": name,
            "index_relation_oid": oid,
            "index_kind": "i",
            "index_owner": "app_admin",
            "index_options": None,
            "index_tablespace": 0,
            "index_partitioned": False,
            "method": "btree",
            "unique": True,
            "primary": kind == "p",
            "valid": True,
            "ready": True,
            "live": True,
            "immediate": True,
            "exclusion": False,
            "key_count": len(columns),
            "attribute_count": len(columns),
            "keys": columns,
            "numbers": numbers,
            "expression_absent": True,
            "predicate_absent": True,
            "ordering_options": " ".join("0" for _ in columns),
            "opclasses": tuple("pg_catalog.uuid_ops" for _ in columns),
            "collations": tuple(None for _ in columns),
            "constraint_oid": constraint_oid,
            "constraint_namespace": namespace,
            "constraint_name": name,
            "constraint_kind": kind,
            "constraint_relation_oid": oid,
            "constraint_index_oid": index_oid,
            "constraint_numbers": numbers,
            "constraint_valid": True,
            "constraint_deferrable": False,
            "constraint_deferred": False,
            "constraint_noinherit": True,
            "constraint_local": True,
            "constraint_inheritance_count": 0,
            "constraint_parent": 0,
            "nulls_not_distinct": False,
            "opclass_input_types": tuple("pg_catalog.uuid" for _ in columns),
            "opclass_methods": tuple("btree" for _ in columns),
            "opclass_families": tuple("pg_catalog.uuid_ops" for _ in columns),
            "opclass_defaults": tuple(True for _ in columns),
        }
        _require({k: v for k, v in key.items() if k != "fk_oid"} == expected)
        unique_keys[constraint_oid] = key
    _require(len(unique_keys) == len(parents))
    expected_operators = tuple(
        sorted(
            (oid, label, num)
            for oid, fk in by_oid.items()
            for label in ("pf", "pp", "ff")
            for num in range(1, len(fk["columns"]) + 1)
        )
    )
    _require(tuple(row[:3] for row in packet["ri_operators"]) == expected_operators)
    for row in packet["ri_operators"]:
        _require(type(row[3]) is int and row[3] > 0 and type(row[13]) is int and row[13] > 0)
        _require(
            row[4:13] == ("pg_catalog", "=", "b", "pg_catalog", "uuid", "pg_catalog", "uuid", "pg_catalog", "bool")
        )
        _require(
            row[14:]
            == (
                "pg_catalog",
                "uuid_eq",
                "internal",
                "uuid_eq",
                2,
                ("pg_catalog.uuid", "pg_catalog.uuid"),
                "pg_catalog",
                "bool",
                "f",
                False,
                True,
            )
        )
    triggers = _records(packet, "ri_triggers", schema._RI_TRIGGER_FIELDS)
    _require(len(triggers) == 4 * len(fks) and len({t["oid"] for t in triggers}) == len(triggers))
    roles = []
    for trigger in triggers:
        fk = by_oid.get(trigger["constraint_oid"])
        _require(fk is not None)
        fk = cast(dict[str, object], fk)
        child = trigger["relation_oid"] == fk["child_oid"]
        side = "child" if child else "parent"
        function = (
            {5: "RI_FKey_check_ins", 17: "RI_FKey_check_upd"}
            if child
            else {
                9: "RI_FKey_cascade_del" if fk["delete_action"] == "c" else "RI_FKey_noaction_del",
                17: "RI_FKey_noaction_upd",
            }
        ).get(trigger["type"])
        _require(function is not None)
        _require(
            (trigger["relation_oid"], trigger["relation_namespace"], trigger["relation"])
            == (fk["child_oid"], "public", fk["child"])
            if child
            else (trigger["relation_oid"], trigger["relation_namespace"], trigger["relation"])
            == (fk["parent_oid"], fk["parent_namespace"], fk["parent"])
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
    for trigger in _records(packet, "ri_external_parent_other_triggers", schema._RI_EXTERNAL_TRIGGER_FIELDS):
        _require(trigger["internal"] is True and trigger["constraint_kind"] == "f")
        _require(
            (trigger["relation_oid"], trigger["constraint_relation_oid"])
            in (
                (trigger["child_oid"], trigger["parent_oid"]),
                (trigger["parent_oid"], trigger["child_oid"]),
            )
        )
    # Exact dependency MULTISET; established PG16 semantics, no static OIDs.
    schema._check_ri_dependencies(packet, by_oid, unique_keys, triggers)
    return fks, triggers


def _non_ri(packet):
    # Only the exact outgoing FK component is removed here; every FK is checked
    # independently against the immutable phase spec and exact OID delta.
    return tuple(
        sorted(
            (name, tuple(row for row in rows if row[2] != "f") if name == "constraints" else rows)
            for name, rows in packet.items()
            if not name.startswith("ri_")
        )
    )


def _project_catalog(catalog, fks, triggers, names):
    # Projection is restricted to privately verified exact FK/trigger OIDs and
    # fixed child/name pairs. All other RI/non-RI facts remain byte-for-byte.
    return replace(
        catalog,
        constraints=tuple(row for row in catalog.constraints if not (row[1] == "f" and row[0] in names)),
        incoming=tuple(row for row in catalog.incoming if row[0] not in fks),
        triggers=tuple(row for row in catalog.triggers if row[0] not in triggers),
    )


def _version_rows(connection):
    return history._query(connection, "SELECT version_num FROM public.alembic_version ORDER BY version_num")


def _edges(edges):
    for edge in edges:
        yield from (edge,) if type(edge) is str else (() if edge is None else edge)


def _stage_versions(graph, target, *, final):
    # Private stage cut over lineage AND dependency edges: BEFORE excludes the
    # target and all descendants; AFTER excludes only proper descendants, so
    # independent installed branches remain selected at both stages.
    nodes = {revision: (down, depends) for revision, down, depends in graph}
    _require(target in nodes and _LR7 in nodes)
    children: dict[str, set[str]] = {revision: set() for revision in nodes}
    for revision, edges in nodes.items():
        for parent in _edges(edges):
            _require(parent in nodes)
            children[parent].add(revision)
    descendants = set()
    pending = list(children[target])
    while pending:
        revision = pending.pop()
        if revision not in descendants:
            descendants.add(revision)
            pending.extend(children[revision])
    excluded = descendants if final else descendants | {target}
    selected = {revision: edges for revision, edges in nodes.items() if revision not in excluded}
    _require(_LR7 in selected)
    parents = set()
    for edges in selected.values():
        parents.update(_edges(edges))
    _require(parents <= set(selected))
    return tuple((revision,) for revision in sorted(set(selected) - parents))


def _expected_versions(graph, *, final):
    # The complete installed graph is already provenance-checked. Alembic's
    # dependency predecessors are consumed alongside lineage predecessors.
    return _stage_versions(graph, _A004, final=final)


def _reference_closure(connection):
    # MATCH SIMPLE: a compound source row participates only when ALL parts are
    # non-NULL. Include subtype independently from tenant/person pair closure.
    for child, _, columns, namespace, parent, target, _ in _specs(final=True):
        participating = " AND ".join(f'c."{column}" IS NOT NULL' for column in columns)
        equality = " AND ".join(f'p."{right}"=c."{left}"' for left, right in zip(columns, target, strict=True))
        _require(
            connection.scalar(
                sa.text(
                    f'SELECT NOT EXISTS (SELECT 1 FROM "public"."{child}" c WHERE {participating} '  # noqa: S608
                    f'AND NOT EXISTS (SELECT 1 FROM "{namespace}"."{parent}" p WHERE {equality}))'
                )
            )
            is True
        )


def _prepare(connection, state):
    original = dict(state.retained_fragment.catalog)
    before = schema._observe_historical_catalog(connection)
    _require(_non_ri(before) == _non_ri(original))
    schema._check_security(before)
    public_schema = _successor_envelope(connection, state.retained_fragment.public_schema)
    _successor_cluster(schema._observe_cluster_authority(connection), public_schema)
    keys = {(s, t): _key(connection, s, t, cols, name, kind) for s, t, cols, name, kind in _parent_specs(final=False)}
    _check_ri(connection, before, final=False, keys=keys)
    # Original captured source17 identities survive relocation/a003 exactly.
    old_fks = _records(original, "ri_foreign_keys", schema._RI_FK_FIELDS)
    current_fks = _records(before, "ri_foreign_keys", schema._RI_FK_FIELDS)
    _require(
        tuple((fk["oid"], fk["child_oid"], fk["parent_oid"], fk["index_oid"]) for fk in old_fks)
        == tuple((fk["oid"], fk["child_oid"], fk["parent_oid"], fk["index_oid"]) for fk in current_fks)
    )
    _require({row[0] for row in original["ri_triggers"]} == {row[0] for row in before["ri_triggers"]})
    canonical_keys = {(s, t): _key(connection, s, t, cols, name, kind) for s, t, cols, name, kind in _CANONICAL}
    canonical = tuple((s, t, history._catalog(connection, canonical_keys[(s, t)][0])) for s, t, *_ in _CANONICAL)
    # Current selected owners declare no custom parent triggers or rules. Refuse
    # these BEFORE DDL rather than capturing a planted custom object as expected.
    for _, _, captured in canonical:
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
    held = set(
        connection.scalars(
            sa.text(
                "SELECT relation FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() "
                "AND locktype='relation' AND mode='AccessExclusiveLock' AND granted"
            )
        )
    )
    _require({key[0] for key in canonical_keys.values()} <= held)
    graph = state.provenance[4][0]
    before_versions = _expected_versions(graph, final=False)
    _require(_version_rows(connection) == before_versions)
    _reference_closure(connection)
    return _RetainedTransition(
        state.handle,
        connection,
        state.root,
        state.xid,
        state.retained_fragment,
        state.retained_runner,
        before,
        canonical,
        {**keys, **canonical_keys},
        history._oid(connection, "alembic_version"),
        before_versions,
        _expected_versions(graph, final=True),
        public_schema,
    )


def _verify_before(connection, entry):
    _require(schema._observe_historical_catalog(connection) == entry.before)
    for namespace, table, captured in entry.canonical:
        _require(history._oid(connection, table, namespace) == captured.relation[0])
        _require(history._catalog(connection, captured.relation[0]) == captured)
    _require(history._oid(connection, "alembic_version") == entry.version_oid)
    _require(_version_rows(connection) == entry.before_versions)
    _verify_successor_cluster(connection, entry.public_schema)
    _reference_closure(connection)


def _checkpoint_projection(state, entry):
    # Derived only from the privately stored a005 entry in an allowed a005
    # phase; no caller ignore map exists. A prepared-but-unapplied entry has
    # no final IDs and therefore projects nothing.
    pending = getattr(state, "checkpoint_transition", None)
    if pending is None or pending.final is None:
        _require(pending is None or state.phase == "retained adopted, checkpoint pending")
        return frozenset(), frozenset()
    _require(
        state.phase
        in (
            "a005 executing",
            "a005 recorded",
            "checkpoint adopted, final admission pending",
            "a006 executing",
            "a006 recorded",
            "lab claim lease adopted, final admission pending",
        )
    )
    _require(pending.retained_entry is entry and pending.consumed)
    _require(pending.handle is state.handle and pending.connection is state.connection)
    _require(pending.root is state.root and pending.xid == state.xid)
    _require(type(pending.new_fks) is frozenset and len(pending.new_fks) == 2)
    _require(type(pending.new_triggers) is frozenset and len(pending.new_triggers) == 8)
    _require(all(type(oid) is int and oid > 0 for oid in pending.new_fks | pending.new_triggers))
    return pending.new_fks, pending.new_triggers


def _lab_claim_projection(state, entry):
    # Derived only from the privately stored a006 entry in an allowed a006
    # phase; no caller ignore map exists. A prepared-but-unapplied entry has
    # no final column/check IDs and therefore projects nothing.
    pending = getattr(state, "lab_claim_transition", None)
    if pending is None or pending.final is None:
        _require(pending is None or state.phase == "checkpoint adopted, final admission pending")
        return None
    _require(state.phase in ("a006 executing", "a006 recorded", "lab claim lease adopted, final admission pending"))
    checkpoint_entry = getattr(pending, "checkpoint_entry", None)
    _require(checkpoint_entry is not None and checkpoint_entry is getattr(state, "checkpoint_transition", None))
    _require(cast("_CheckpointTransition", checkpoint_entry).retained_entry is entry and pending.consumed)
    _require(pending.handle is state.handle and pending.connection is state.connection)
    _require(pending.root is state.root and pending.xid == state.xid)
    _require(pending.new_attnum == 21)
    _require(type(pending.new_check_oids) is frozenset and len(pending.new_check_oids) == 2)
    _require(all(type(oid) is int and oid > 0 for oid in pending.new_check_oids))
    return pending


def _normalize_lab_claim_packet(packet):
    # Strip exactly the verified a006 rows; every stripped row is re-verified
    # in full by the a006 module on every recorded verification.
    columns = tuple(row for row in packet["columns"] if row[0] == _LAB_TABLE and row[2] == _LAB_CLAIM_COLUMN)
    _require(len(columns) == 1)
    column = columns[0]
    _require(column[1] == 21 and column[3] == "integer" and column[4] is True and column[5] is None)
    _require(column[6:9] == (False, "", "") and column[9:11] == (None, None) and column[11:] == (0, True))
    constraints = tuple(row for row in packet["constraints"] if row[0] == _LAB_TABLE and row[1] in _LAB_CLAIM_CHECKS)
    _require(len(constraints) == 2 and {row[1] for row in constraints} == set(_LAB_CLAIM_CHECKS))
    expected_columns = {
        "ck_lab_operations_claim_lease_positive": {_LAB_CLAIM_COLUMN},
        "ck_lab_operations_claim_lease_required": {"state", _LAB_CLAIM_COLUMN},
    }
    for row in constraints:
        _require(row[2] == "c" and set(row[3]) == expected_columns[row[1]])
        _require(row[10:14] == (True, False, False, False) and type(row[14]) is str and row[14] != "")
    request = dict(schema._REQUEST_COLUMNS)
    effective = tuple(
        row for row in packet["effective_columns"] if row[0] == _LAB_TABLE and row[1] == _LAB_CLAIM_COLUMN
    )
    _require(
        tuple(sorted(effective))
        == tuple(
            sorted(
                (
                    _LAB_TABLE,
                    _LAB_CLAIM_COLUMN,
                    role,
                    priv,
                    priv in schema._table_privileges(_LAB_TABLE, role)
                    or (role == "app_user" and priv == "INSERT" and _LAB_CLAIM_COLUMN in request.get(_LAB_TABLE, ())),
                )
                for role in schema._ROLES
                for priv in schema._COLUMN_PRIVILEGES
            )
        )
    )
    return {
        **packet,
        "columns": tuple(row for row in packet["columns"] if row not in columns),
        "constraints": tuple(row for row in packet["constraints"] if row not in constraints),
        "effective_columns": tuple(row for row in packet["effective_columns"] if row not in effective),
    }


def _normalize_lab_claim_cluster(packet):
    roles = tuple(row[1] for row in packet["cluster_roles"])
    stripped = tuple(row for row in packet["cluster_columns"] if row[0] == _LAB_TABLE and row[1] == _LAB_CLAIM_COLUMN)
    _require(
        tuple(sorted(stripped))
        == tuple(
            sorted(
                (
                    _LAB_TABLE,
                    _LAB_CLAIM_COLUMN,
                    role,
                    priv,
                    priv in schema._cluster_privileges(_LAB_TABLE, role)
                    or (
                        role == "app_user"
                        and priv == "INSERT"
                        and _LAB_CLAIM_COLUMN in dict(schema._REQUEST_COLUMNS).get(_LAB_TABLE, ())
                    ),
                )
                for role in roles
                for priv in schema._COLUMN_PRIVILEGES
            )
        )
    )
    return {
        **packet,
        "cluster_columns": tuple(row for row in packet["cluster_columns"] if row not in stripped),
    }


def _project_lab_claim_catalog(catalog):
    # Projection is restricted to the one verified appended column and the two
    # fixed check names. All other catalog facts remain byte-for-byte.
    columns = tuple(row for row in catalog.columns if row[1] == _LAB_CLAIM_COLUMN)
    _require(len(columns) == 1)
    _require(columns[0][0] == 21 and columns[0][2] == "integer" and columns[0][3] is False)
    _require(columns[0][5] is None)
    constraints = tuple(row for row in catalog.constraints if row[0] in _LAB_CLAIM_CHECKS)
    _require(len(constraints) == 2 and {row[0] for row in constraints} == set(_LAB_CLAIM_CHECKS))
    _require(all(row[1] == "c" for row in constraints))
    return replace(
        catalog,
        columns=tuple(row for row in catalog.columns if row not in columns),
        constraints=tuple(row for row in catalog.constraints if row not in constraints),
    )


def _verify_after(connection, state, entry, *, recorded):
    packet = schema._observe_historical_catalog(connection)
    keys = {(s, t): _key(connection, s, t, cols, name, kind) for s, t, cols, name, kind in _parent_specs(final=True)}
    _require(all(entry.parent_keys[key] == value for key, value in keys.items()))
    checkpoint_fks, checkpoint_triggers = _checkpoint_projection(state, entry)
    lab_claim_entry = _lab_claim_projection(state, entry)
    fks, triggers = _check_ri(connection, packet, final=True, keys=keys)
    old_fks = _records(entry.before, "ri_foreign_keys", schema._RI_FK_FIELDS)
    old_triggers = _records(entry.before, "ri_triggers", schema._RI_TRIGGER_FIELDS)
    preserved = {fk["oid"] for fk in old_fks if fk["name"] in _PRESERVED}
    _require(len(preserved) == 2)
    _require(
        tuple(fk for fk in fks if fk["name"] in _PRESERVED) == tuple(fk for fk in old_fks if fk["name"] in _PRESERVED)
    )
    _require(
        tuple(t for t in triggers if t["constraint_oid"] in preserved)
        == tuple(t for t in old_triggers if t["constraint_oid"] in preserved)
    )
    old_ids = frozenset(fk["oid"] for fk in old_fks if fk["oid"] not in preserved)
    new_ids = frozenset(fk["oid"] for fk in fks if fk["oid"] not in preserved)
    old_trigger_ids = frozenset(t["oid"] for t in old_triggers if t["constraint_oid"] in old_ids)
    new_trigger_ids = frozenset(t["oid"] for t in triggers if t["constraint_oid"] in new_ids)
    _require(len(old_ids) == 15 and len(new_ids) == 18 and not old_ids & new_ids)
    _require(len(old_trigger_ids) == 60 and len(new_trigger_ids) == 72 and not old_trigger_ids & new_trigger_ids)
    normalized = _normalize_lab_claim_packet(packet) if lab_claim_entry is not None else packet
    _require(_non_ri(normalized) == _non_ri(dict(entry.fragment.catalog)))
    schema._check_security(normalized)
    cluster = schema._observe_cluster_authority(connection)
    if lab_claim_entry is not None:
        cluster = _normalize_lab_claim_cluster(cluster)
    _verify_successor_cluster(connection, entry.public_schema, cluster=cluster)
    names = frozenset(row[1] for row in _specs(final=True) if row[1] not in _PRESERVED)
    for namespace, table, captured in entry.canonical:
        _require(history._oid(connection, table, namespace) == captured.relation[0])
        current = history._catalog(connection, captured.relation[0])
        if checkpoint_fks:
            # Only canonical tenants gains the verified checkpoint FK delta:
            # exactly one incoming FK and its two parent RI triggers.
            projected = _project_catalog(current, checkpoint_fks, checkpoint_triggers, frozenset())
            expected = (1, 2) if (namespace, table) == ("public", "tenants") else (0, 0)
            _require(
                (len(current.incoming) - len(projected.incoming), len(current.triggers) - len(projected.triggers))
                == expected
            )
        _require(
            _project_catalog(captured, old_ids, old_trigger_ids, frozenset())
            == _project_catalog(current, new_ids | checkpoint_fks, new_trigger_ids | checkpoint_triggers, frozenset())
        )
    # Validate all47 against ORIGINAL capture; only the explicit a003 and a004
    # deltas are projected. No new observed baseline replaces source authority.
    from app.maintenance import product_adoption as product

    for name, captured in state.catalogs:
        namespace = "academy_identity_compat" if name in product._IDENTITY else "public"
        current = history._catalog(connection, dict(state.oids)[name])
        _require(history._oid(connection, name, namespace) == dict(state.oids)[name])
        _require(product._cohort(connection, name, namespace) == dict(state.cohorts)[name])
        if name == "account_tokens":
            _require(current == state.token_association[3])
            continue
        if name in product._IDENTITY:
            captured = product._identity_catalog(captured, dict(state.oids)["account_tokens"])
            current = product._identity_catalog(current, dict(state.oids)["account_tokens"])
        if name == _LAB_TABLE and lab_claim_entry is not None:
            current = _project_lab_claim_catalog(current)
        child_names = frozenset(row[1] for row in _specs(final=True) if row[0] == name and row[1] in names)
        _require(
            _project_catalog(captured, old_ids, old_trigger_ids, child_names)
            == _project_catalog(current, new_ids, new_trigger_ids, child_names)
        )
    _require(history._oid(connection, "alembic_version") == entry.version_oid)
    if checkpoint_triggers:
        # The packet gains ONLY the two verified checkpoint parent triggers on
        # canonical tenants; the untouched a004 final remains the comparison.
        external = packet["ri_external_parent_other_triggers"]
        removed = tuple(row for row in external if row[0] in checkpoint_triggers)
        _require(len(removed) == 2)
        _require(all(row[1] == keys[("public", "tenants")][0] and row[6] in checkpoint_fks for row in removed))
        normalized = {
            **normalized,
            "ri_external_parent_other_triggers": tuple(row for row in external if row[0] not in checkpoint_triggers),
        }
    if recorded:
        _require(normalized == entry.final and new_ids == entry.new_fks and new_trigger_ids == entry.new_triggers)
    return packet, new_ids, new_trigger_ids


def _apply_retained_transition(connection, entry):
    from app.maintenance import product_adoption as product

    state = product._check(connection, entry.handle, "a004 executing")
    _require(state.retained_transition is entry and entry.consumed and entry.final is None)
    _require(state.retained_runner is not None and entry.runner is state.retained_runner)
    _require(entry.connection is connection and entry.root is state.root and entry.xid == state.xid)
    product._verify_retained_prerequisites(connection, state)
    _verify_before(connection, entry)
    for child, name, *_ in _specs(final=False):
        if name not in _PRESERVED:
            connection.execute(sa.text(f'ALTER TABLE "public"."{child}" DROP CONSTRAINT "{name}"'))
    replacements = frozenset(row[1] for row in _specs(final=False)) - _PRESERVED
    ordered = tuple(row for row in _specs(final=True) if row[1] in replacements) + tuple(
        row for row in _specs(final=True) if row[1] not in replacements | _PRESERVED
    )
    for child, name, columns, namespace, parent, target, action in ordered:
        if name not in _PRESERVED:
            left = ", ".join(f'"{column}"' for column in columns)
            right = ", ".join(f'"{column}"' for column in target)
            connection.execute(
                sa.text(
                    f'ALTER TABLE "public"."{child}" ADD CONSTRAINT "{name}" FOREIGN KEY ({left}) '
                    f'REFERENCES "{namespace}"."{parent}" ({right}) MATCH SIMPLE ON DELETE {action} '
                    "ON UPDATE NO ACTION NOT DEFERRABLE INITIALLY IMMEDIATE"
                )
            )

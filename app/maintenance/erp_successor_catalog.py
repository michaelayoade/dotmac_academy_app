"""Private finite a007-a011 catalog deltas; never a learned catalog baseline.

Only the guarded ERP continuation calls this observer. PostgreSQL 16 deparse
spellings are source contracts: an unknown spelling refuses for review.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass

import sqlalchemy as sa

from app.maintenance import checkpoint_transition as checkpoint
from app.maintenance import lab_claim_lease_transition as lab_claim
from app.maintenance import learning_history as history
from app.maintenance import retained_schema as schema
from app.maintenance import retained_transition as retained


def _require(condition):
    if not condition:
        from app.maintenance.product_adoption import ProductAdoptionRefused

        raise ProductAdoptionRefused("Academy ERP successor catalog refused; root rollback required")


@dataclass(frozen=True)
class TableSpec:
    name: str
    columns: tuple
    keys: tuple
    indexes: tuple
    fks: tuple
    checks: tuple = ()
    request_crud: bool = False


_TIMESTAMPS = (
    ("created_at", "timestamp with time zone", False, "now()"),
    ("updated_at", "timestamp with time zone", False, "now()"),
)
_NOM = "facilitator_nominations"
_REQ = "facilitator_requirements"
_MEMBER = "academy_erp_imported_completion_keys"
_TABLES = {
    "a008_lab_console_activity": (
        TableSpec(
            "lab_console_activity",
            (
                ("instance_id", "uuid", False, None),
                ("tenant_id", "uuid", False, None),
                ("last_seen_at", "timestamp with time zone", False, None),
            ),
            (("lab_console_activity_pkey", "p", ("instance_id",)),),
            (("ix_lab_console_activity_tenant_id", ("tenant_id",), False, None),),
            (
                (
                    "fk_lab_console_activity_instance",
                    ("tenant_id", "instance_id"),
                    "public",
                    "lab_instances",
                    ("tenant_id", "id"),
                    "c",
                ),
            ),
        ),
    ),
    "a010_facilitator_nominations": (
        TableSpec(
            _NOM,
            (
                ("id", "uuid", False, None),
                ("tenant_id", "uuid", False, None),
                ("person_id", "uuid", False, None),
                ("nominated_by_person_id", "uuid", True, None),
                ("scope_type", "character varying(20)", False, None),
                ("cohort_id", "uuid", True, None),
                ("offering_id", "uuid", True, None),
                ("status", "character varying(20)", False, "'pending'::character varying"),
                ("activated_at", "timestamp with time zone", True, None),
                ("revoked_at", "timestamp with time zone", True, None),
                ("activation_reason", "character varying(40)", True, None),
                *_TIMESTAMPS,
            ),
            ((f"{_NOM}_pkey", "p", ("id",)), (f"uq_{_NOM}_tenant_id_id", "u", ("tenant_id", "id"))),
            (
                *(
                    (f"ix_{_NOM}_{col}", (col,), False, None)
                    for col in ("tenant_id", "person_id", "cohort_id", "offering_id", "status")
                ),
                (
                    f"uq_{_NOM}_cohort_scope",
                    ("tenant_id", "person_id", "cohort_id"),
                    True,
                    "((scope_type)::text = 'cohort'::text)",
                ),
                (
                    f"uq_{_NOM}_course_scope",
                    ("tenant_id", "person_id", "offering_id"),
                    True,
                    "((scope_type)::text = 'course'::text)",
                ),
            ),
            (
                (f"{_NOM}_tenant_id_fkey", ("tenant_id",), "public", "tenants", ("id",), "c"),
                (f"fk_{_NOM}_person", ("tenant_id", "person_id"), "public", "parties", ("tenant_id", "id"), "c"),
                (f"fk_{_NOM}_person_subtype", ("person_id",), "public", "party_persons", ("party_id",), "c"),
                (
                    f"fk_{_NOM}_nominator_subtype",
                    ("nominated_by_person_id",),
                    "public",
                    "party_persons",
                    ("party_id",),
                    "a",
                ),
                (
                    f"fk_{_NOM}_nominator",
                    ("tenant_id", "nominated_by_person_id"),
                    "public",
                    "parties",
                    ("tenant_id", "id"),
                    "a",
                ),
                (f"fk_{_NOM}_cohort", ("tenant_id", "cohort_id"), "mod_learning", "cohorts", ("tenant_id", "id"), "c"),
                (
                    f"fk_{_NOM}_offering",
                    ("tenant_id", "offering_id"),
                    "mod_learning",
                    "course_offerings",
                    ("tenant_id", "id"),
                    "c",
                ),
            ),
            (
                (
                    "ck_facilitator_nominations_scope",
                    "((scope_type)::text = ANY (ARRAY['course'::character varying, "
                    "'cohort'::character varying]::text[]))",
                ),
                (
                    "ck_facilitator_nominations_status",
                    "((status)::text = ANY (ARRAY['pending'::character varying, 'active'::character "
                    "varying, 'revoked'::character varying]::text[]))",
                ),
                (
                    "ck_facilitator_nominations_target",
                    "((((scope_type)::text = 'cohort'::text) AND (cohort_id IS NOT NULL) AND "
                    "(offering_id IS NULL)) OR (((scope_type)::text = 'course'::text) AND (cohort_id "
                    "IS NULL) AND (offering_id IS NOT NULL)))",
                ),
            ),
            True,
        ),
        TableSpec(
            _REQ,
            (
                ("id", "uuid", False, None),
                ("tenant_id", "uuid", False, None),
                ("nomination_id", "uuid", False, None),
                ("course_id", "uuid", False, None),
                *_TIMESTAMPS,
            ),
            (
                (f"{_REQ}_pkey", "p", ("id",)),
                (f"uq_{_REQ}_tenant_id_id", "u", ("tenant_id", "id")),
                (f"uq_{_REQ}_nomination_course", "u", ("tenant_id", "nomination_id", "course_id")),
            ),
            tuple((f"ix_{_REQ}_{col}", (col,), False, None) for col in ("tenant_id", "nomination_id", "course_id")),
            (
                (f"{_REQ}_tenant_id_fkey", ("tenant_id",), "public", "tenants", ("id",), "c"),
                (f"fk_{_REQ}_nomination", ("tenant_id", "nomination_id"), "public", _NOM, ("tenant_id", "id"), "c"),
                (f"fk_{_REQ}_course", ("tenant_id", "course_id"), "mod_learning", "courses", ("tenant_id", "id"), "a"),
            ),
            request_crud=True,
        ),
    ),
    "a011_erp_progress_checkpoint": (
        TableSpec(
            _MEMBER,
            (("tenant_id", "uuid", False, None), ("completion_id", "uuid", False, None)),
            ((f"{_MEMBER}_pkey", "p", ("tenant_id", "completion_id")),),
            (),
            (
                (f"{_MEMBER}_tenant_id_fkey", ("tenant_id",), "public", "tenants", ("id",), "c"),
                (
                    "fk_erp_imported_key_tenant_completion",
                    ("tenant_id", "completion_id"),
                    "mod_learning",
                    "course_completions",
                    ("tenant_id", "id"),
                    "c",
                ),
            ),
        ),
    ),
}
_COLUMN_ADDITIONS = {
    "a007_lab_template_access": ("lab_templates", ("access", "jsonb", False, "'[]'::jsonb")),
    "a009_applicant_bank_version_pin": ("applicants", ("assessment_bank_version_id", "uuid", True, None)),
    "a011_erp_progress_checkpoint": (checkpoint._TABLE, ("erp_synced_pct", "double precision", True, None)),
}
_BANK_FK = (
    "fk_applicants_tenant_assessment_bank_version",
    ("tenant_id", "assessment_bank_version_id"),
    "mod_learning",
    "question_bank_versions",
    ("tenant_id", "id"),
    "a",
)
_FUNCTIONS = {
    "a008_lab_console_activity": (
        "lab_console_activity_stamp",
        "",
        False,
        "trigger",
        0,
        "2e5b434e084ebed5a9ea286f44c83a8b41c25ac7376f8e4fccd0398e638f386f",
    ),
    "a010_facilitator_nominations": (
        "activate_eligible_facilitator_nominations",
        "uuid,uuid,uuid,uuid,integer,uuid",
        True,
        "record",
        5,
        "01289135b1650924abfc3eea19c0349b7c5cc1767042402c52b3bc7f9bcd7f23",
    ),
}


# Fresh-only static predecessors. No object set is derived from an observation.
_TABLES["a004_retained_learning_refs"] = tuple(
    TableSpec(
        table,
        columns,
        dict(schema._KEYS)[table],
        tuple(
            (
                name,
                cols,
                unique,
                dict(((t, n), v) for t, n, v in schema._PARTIAL_PREDICATE_RENDERINGS).get((table, name)),
            )
            for name, cols, unique, primary, predicate in dict(schema._INDEXES)[table]
            if name not in {key[0] for key in dict(schema._KEYS)[table]}
        ),
        tuple(
            (name, cols, ns, parent, target, "c" if action == "CASCADE" else "a")
            for child, name, cols, ns, parent, target, action in retained._specs(final=True)
            if child == table
        ),
        tuple((name, expr) for child, name, expr in schema._CHECK_RENDERINGS if child == table),
    )
    for table, columns in schema._COLUMNS
)
_TABLES["a005_erp_completion_checkpoint"] = (
    TableSpec(
        checkpoint._TABLE,
        (
            ("tenant_id", "uuid", False, None),
            ("completion_id", "uuid", False, None),
            ("erp_synced_at", "timestamp with time zone", True, None),
        ),
        ((checkpoint._PK, "p", ("tenant_id", "completion_id")),),
        (),
        tuple((name, cols, ns, parent, target, "c") for name, cols, ns, parent, target in checkpoint._FK_SPECS),
    ),
)
_COLUMN_ADDITIONS["a006_lab_claim_lease"] = ("lab_operations", ("claim_lease_seconds", "integer", True, None))


def _rows(connection, query, **params):
    return history._query(connection, query, **params)


def _dicts(connection, query, **params):
    return tuple(dict(row._mapping) for row in connection.execute(sa.text(query), params))


def _raw(connection, catalog, predicate, **params):
    sql = f"SELECT oid,pg_catalog.to_jsonb(x)::text FROM pg_catalog.{catalog} x WHERE {predicate} ORDER BY oid"  # noqa: S608
    return {row[0]: row[1] for row in _rows(connection, sql, **params)}


def observe(connection):
    from app.maintenance import fresh_product as fresh

    fresh._no_undeclared_catalog_objects(connection)
    namespaces = _rows(
        connection,
        "SELECT oid,nspname,nspowner,nspacl::text FROM pg_catalog.pg_namespace "
        "WHERE pg_catalog.left(nspname,3)<>'pg_' AND nspname<>'information_schema' ORDER BY oid",
    )
    _require(all(row[1] in ("public", "mod_learning", "academy_identity_compat") for row in namespaces))
    nsids = [row[0] for row in namespaces]
    relation_scope = (
        "relnamespace=ANY(:ns) OR oid IN (SELECT reltoastrelid FROM pg_catalog.pg_class WHERE relnamespace=ANY(:ns)) "
        "OR oid IN (SELECT indexrelid FROM pg_catalog.pg_index WHERE indrelid IN "
        "(SELECT reltoastrelid FROM pg_catalog.pg_class WHERE relnamespace=ANY(:ns)))"
    )
    relations = _raw(connection, "pg_class", relation_scope, ns=nsids)
    relids = list(relations)
    immutables = {}
    for name, namespace_column in (
        ("pg_operator", "oprnamespace"),
        ("pg_opclass", "opcnamespace"),
        ("pg_opfamily", "opfnamespace"),
        ("pg_collation", "collnamespace"),
        ("pg_conversion", "connamespace"),
    ):
        immutables[name] = _raw(connection, name, namespace_column + "=ANY(:ns)", ns=nsids)
    packet = {
        "pg_class": relations,
        "pg_proc": _raw(connection, "pg_proc", "pronamespace=ANY(:ns)", ns=nsids),
        "pg_type": _raw(connection, "pg_type", "typnamespace=ANY(:ns)", ns=nsids),
        "pg_constraint": _raw(connection, "pg_constraint", "connamespace=ANY(:ns)", ns=nsids),
        "pg_attrdef": _raw(connection, "pg_attrdef", "adrelid=ANY(:rels)", rels=relids),
        "pg_policy": _raw(connection, "pg_policy", "polrelid=ANY(:rels)", rels=relids),
        "pg_trigger": _raw(connection, "pg_trigger", "tgrelid=ANY(:rels)", rels=relids),
        "pg_rewrite": _raw(connection, "pg_rewrite", "ev_class=ANY(:rels)", rels=relids),
    }
    packet["pg_attribute"] = {
        (r[0], r[1]): r[2]
        for r in _rows(
            connection,
            "SELECT attrelid,attnum,pg_catalog.to_jsonb(a)::text FROM "
            "pg_catalog.pg_attribute a WHERE attrelid=ANY(:rels) ORDER BY 1,2",
            rels=relids,
        )
    }
    packet["pg_index"] = {
        r[0]: r[1]
        for r in _rows(
            connection,
            "SELECT indexrelid,pg_catalog.to_jsonb(i)::text FROM pg_catalog.pg_index i WHERE "
            "indrelid=ANY(:rels) ORDER BY 1",
            rels=relids,
        )
    }
    packet["global"] = {
        "namespaces": namespaces,
        "immutable_objects": immutables,
        "languages": _rows(
            connection, "SELECT pg_catalog.to_jsonb(l)::text FROM pg_catalog.pg_language l ORDER BY oid"
        ),
        "temporary_relations": _rows(
            connection,
            "SELECT c.oid,pg_catalog.to_jsonb(c)::text FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "WHERE pg_catalog.left(n.nspname,8)='pg_temp_' ORDER BY c.oid",
        ),
        "inheritance": _rows(
            connection, "SELECT pg_catalog.to_jsonb(i)::text FROM pg_catalog.pg_inherits i ORDER BY inhrelid,inhseqno"
        ),
        "security_labels": _rows(
            connection,
            "SELECT pg_catalog.to_jsonb(l)::text FROM pg_catalog.pg_seclabel l "
            "ORDER BY classoid,objoid,objsubid,provider",
        ),
        "roles": _rows(
            connection,
            "SELECT "
            "oid,rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplica"
            "tion,rolconnlimit,rolvaliduntil,rolbypassrls,rolconfig FROM pg_catalog.pg_roles "
            "ORDER BY oid",
        ),
        "memberships": _rows(
            connection, "SELECT pg_catalog.to_jsonb(m)::text FROM pg_catalog.pg_auth_members m ORDER BY roleid,member"
        ),
        "defaults": _rows(
            connection, "SELECT pg_catalog.to_jsonb(d)::text FROM pg_catalog.pg_default_acl d ORDER BY oid"
        ),
        "extensions": _rows(
            connection, "SELECT pg_catalog.to_jsonb(e)::text FROM pg_catalog.pg_extension e ORDER BY oid"
        ),
    }
    ids = {cat: list(values) for cat, values in packet.items() if cat not in ("global", "pg_attribute", "pg_index")}
    clauses = []
    params: dict[str, object] = {}
    for index, (cat, oids) in enumerate(ids.items()):
        params[f"cat{index}"] = "pg_catalog." + cat
        params[f"ids{index}"] = oids
        clauses.append(
            f"(classid=CAST(:cat{index} AS regclass) AND objid=ANY(:ids{index})) OR "
            f"(refclassid=CAST(:cat{index} AS regclass) AND refobjid=ANY(:ids{index}))"
        )
    packet["dependencies"] = _rows(
        connection,
        "SELECT classid,objid,objsubid,refclassid,refobjid,refobjsubid,deptype FROM "  # noqa: S608
        "pg_catalog.pg_depend WHERE " + " OR ".join(clauses) + " ORDER BY 1,2,3,4,5,6,7",
        **params,
    )
    packet["global"]["shared_dependencies"] = _rows(
        connection,
        "SELECT classid,objid,objsubid,refclassid,refobjid,deptype FROM pg_catalog.pg_shdepend "
        "WHERE dbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) ORDER BY 1,2,3,4,5,6",
    )
    return packet


def _oid(connection, table, namespace="public"):
    result = history._oid(connection, table, namespace)
    _require(type(result) is int and result > 0)
    return result


def _expression(connection, expression, raw):
    _require(type(raw) is str and type(expression) is str)
    functions = {
        r[0]
        for r in _rows(
            connection,
            "SELECT oid FROM pg_catalog.pg_proc WHERE oid IN "
            "('pg_catalog.now()'::regprocedure,'public.app_current_tenant_id()'::regprocedure"
            ")",
        )
    }
    operators = {
        r[0]
        for r in _rows(
            connection,
            "SELECT oid FROM pg_catalog.pg_operator WHERE oid IN "
            "('pg_catalog.=(uuid,uuid)'::regoperator,'pg_catalog.=(text,text)'::regoperator,'"
            "pg_catalog.<>(text,text)'::regoperator,'pg_catalog.>(integer,integer)'::regopera"
            "tor)",
        )
    }
    types = {
        r[0]
        for r in _rows(
            connection,
            "SELECT oid FROM pg_catalog.pg_type WHERE "
            "typnamespace='pg_catalog'::regnamespace AND typname IN "
            "('uuid','text','varchar','jsonb','bool','_text','_varchar','int4')",
        )
    }
    operator_functions = {
        r[0]
        for r in _rows(
            connection,
            "SELECT oprcode::oid FROM pg_catalog.pg_operator WHERE oid IN "
            "('pg_catalog.=(uuid,uuid)'::regoperator,'pg_catalog.=(text,text)'::regoperator,'"
            "pg_catalog.<>(text,text)'::regoperator,'pg_catalog.>(integer,integer)'::regopera"
            "tor)",
        )
    }
    for key, allowed in (
        ("funcid", functions),
        ("opno", operators),
        ("opfuncid", operator_functions),
        ("consttype", types),
        ("vartype", types),
    ):
        _require(all(int(value) in allowed for value in re.findall(r":" + key + r" (\d+)", raw)))
    _require(not any(node in raw for node in ("SUBLINK", "PARAM", "AGGREF", "WINDOWFUNC", "COERCEVIAIO")))


def _columns(connection, table):
    return _rows(
        connection,
        "SELECT a.attnum,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),NOT a.attnotnull,"
        "pg_catalog.pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated,a.attacl::text,"
        "a.attisdropped,a.atthasmissing,a.attmissingval::text,d.adbin::text,a.attcollation "
        "FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum "
        "WHERE a.attrelid=:oid AND a.attnum>0 ORDER BY a.attnum",
        oid=_oid(connection, table),
    )


def _validate_column(connection, row, expected, *, appended=False, column_acl=False):
    _require(row[1:5] == expected and row[5:7] == ("", "") and row[8] is False)
    _require(column_acl or row[7] is None)
    if expected[3] is not None:
        _expression(connection, row[4], row[11])
    if row[9]:
        _require(appended and expected == ("access", "jsonb", False, "'[]'::jsonb") and row[10] in ("{[]}", '{"[]"}'))
    else:
        _require(row[10] is None)
    collation = connection.scalar(
        sa.text(
            "SELECT oid FROM pg_catalog.pg_collation WHERE collname='default' AND "
            "collnamespace='pg_catalog'::regnamespace"
        )
    )
    _require(row[12] == (collation if expected[1].startswith("character varying") else 0))


def _validate_indexes(connection, table, specs):
    rows = _dicts(
        connection,
        "SELECT c.oid,c.relname,i.indisunique,i.indisprimary,i.indisvalid,i.indisready,i.indislive,"
        "i.indnullsnotdistinct,i.indnkeyatts,i.indnatts,i.indkey::text,i.indoption::text,i.indcollation::text,"
        "i.indexprs::text,pg_catalog.pg_get_expr(i.indpred,i.indrelid) AS predicate,i.indpred::text AS rawpred,"
        "c.reloptions,c.reltablespace,c.relpersistence,c.relispartition,am.amname,"
        "ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY x(num,ord) "
        "JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=x.num ORDER BY x.ord) AS columns,"
        "ARRAY(SELECT n.nspname||'.'||o.opcname FROM unnest(i.indclass) WITH ORDINALITY x(num,ord) "
        "JOIN pg_catalog.pg_opclass o ON o.oid=x.num JOIN pg_catalog.pg_namespace n ON "
        "n.oid=o.opcnamespace ORDER BY x.ord) AS opclasses "
        "FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid "
        "JOIN pg_catalog.pg_am am ON am.oid=c.relam WHERE i.indrelid=:oid ORDER BY c.relname",
        oid=_oid(connection, table),
    )
    _require({row["relname"] for row in rows} == {spec[0] for spec in specs} and len(rows) == len(specs))
    by_name = {spec[0]: spec for spec in specs}
    for row in rows:
        name, columns, unique, primary, predicate = by_name[row["relname"]]
        _require(
            (tuple(row["columns"]), row["indisunique"], row["indisprimary"], row["predicate"])
            == (columns, unique, primary, predicate)
        )
        _require(
            (row["indisvalid"], row["indisready"], row["indislive"], row["indnullsnotdistinct"])
            == (True, True, True, False)
        )
        _require((row["indnkeyatts"], row["indnatts"]) == (len(columns), len(columns)))
        _require(
            (
                row["indexprs"],
                row["reloptions"],
                row["reltablespace"],
                row["relpersistence"],
                row["relispartition"],
                row["amname"],
            )
            == (None, None, 0, "p", False, "btree")
        )
        _require(set(row["indoption"].split()) <= {"0"})
        declared = {r[1]: r[2] for r in _columns(connection, table)}
        expected_classes = tuple("pg_catalog." + ("uuid_ops" if declared[c] == "uuid" else "text_ops") for c in columns)
        _require(tuple(row["opclasses"]) == expected_classes)
        collation = connection.scalar(
            sa.text(
                "SELECT oid FROM pg_catalog.pg_collation WHERE collname='default' AND "
                "collnamespace='pg_catalog'::regnamespace"
            )
        )
        _require(
            tuple(row["indcollation"].split())
            == tuple(str(collation) if declared[c].startswith("character varying") else "0" for c in columns)
        )
        if predicate is not None:
            _expression(connection, predicate, row["rawpred"])
    return {row["oid"] for row in rows}


def _records(rows, fields):
    return retained._records({"rows": rows}, "rows", fields)


def _foreign_keys(connection, child_oid, keys, table, expected_specs):
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
        "WHERE f.conrelid=:oid AND f.contype='f' AND f.conname=ANY(:names) ORDER BY f.conname",
        oid=child_oid,
        names=[spec[0] for spec in expected_specs],
    )
    fks = _records(rows, schema._RI_FK_FIELDS)
    specs = {row[0]: row for row in expected_specs}
    _require(len(fks) == len(specs) and {fk["name"] for fk in fks} == set(specs))
    for fk in fks:
        _, columns, namespace, parent, target, delete_action = specs[fk["name"]]
        _, numbers = retained._attributes(connection, "public", table, columns)
        parent_oid, parent_numbers, _, index_oid = keys[(namespace, parent)]
        _require(fk["namespace"] == fk["child_namespace"] == "public" and fk["child"] == table)
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
            == (delete_action, "a", "s", True, False, False, True, True, 0, 0, None, True)
        )
        _require(type(fk["oid"]) is int and fk["oid"] > 0)
    _require(len({fk["oid"] for fk in fks}) == len(specs))
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
        "bn.nspname,bt.typname,o.oprcode::oid,pn.nspname,p.proname "
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
    _require(len(triggers) == 4 * len(by_oid) and len({t["oid"] for t in triggers}) == 4 * len(by_oid))
    roles = []
    for trigger in triggers:
        fk = by_oid.get(trigger["constraint_oid"])
        _require(fk is not None)
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


def _keys(connection, specs):
    result = {}
    for _, _, namespace, parent, columns, _ in specs:
        if columns == ("tenant_id", "id"):
            name, kind = f"uq_{parent}_tenant_id_id", "u"
        else:
            name, kind = f"{parent}_pkey", "p"
        result[(namespace, parent)] = retained._key(connection, namespace, parent, columns, name, kind)
    return result


def _acl(connection, table, *, crud):
    oid = _oid(connection, table)
    actual = _rows(
        connection,
        "SELECT pg_catalog.pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' "
        "ELSE pg_catalog.pg_get_userbyid(a.grantee) END,"
        "a.privilege_type,a.is_grantable FROM pg_catalog.pg_class c CROSS JOIN LATERAL "
        "pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a "
        "WHERE c.oid=:oid ORDER BY 1,2,3,4",
        oid=oid,
    )
    grants: dict[str, tuple[str, ...]] = {"app_admin": schema._PRIVILEGES}
    if crud:
        grants.update({r: ("SELECT", "INSERT", "UPDATE", "DELETE") for r in ("app_user", "platform_api")})
    if table == "lab_console_activity":
        grants["app_user"] = ("SELECT",)
    expected_acl = tuple(sorted(("app_admin", role, priv, False) for role, privs in grants.items() for priv in privs))
    _require(actual == expected_acl)
    columns = _rows(
        connection,
        "SELECT "
        "a.attname,pg_catalog.pg_get_userbyid(x.grantor),pg_catalog.pg_get_userbyid(x.grantee)"
        ",x.privilege_type,x.is_grantable "
        "FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) x "
        "WHERE a.attrelid=:oid AND a.attnum>0 ORDER BY 1,2,3,4,5",
        oid=oid,
    )
    expected_columns: tuple[tuple[str, str, str, str, bool], ...] = ()
    if table == "lab_console_activity":
        expected_columns = tuple(
            sorted(
                (
                    *(
                        (c, "app_admin", "app_user", "INSERT", False)
                        for c in ("instance_id", "tenant_id", "last_seen_at")
                    ),
                    ("last_seen_at", "app_admin", "app_user", "UPDATE", False),
                )
            )
        )
    _require(columns == expected_columns)
    # The genuine predecessor pins the complete cluster membership graph.
    # Under that conserved authority, check each declared runtime role here.
    roles = _rows(
        connection,
        "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname=ANY(:roles) ORDER BY rolname",
        roles=list(checkpoint._RUNTIME_ROLES),
    )
    for (role,) in roles:
        for privilege in schema._PRIVILEGES:
            actual = connection.scalar(
                sa.text("SELECT pg_catalog.has_table_privilege(:role,:oid,:privilege)"),
                {"role": role, "oid": oid, "privilege": privilege},
            )
            _require(actual is (privilege in grants.get(role, ())))
        for column in _columns(connection, table):
            for privilege in ("SELECT", "INSERT", "UPDATE", "REFERENCES"):
                expected = privilege in grants.get(role, ()) or any(
                    row[0] == column[1] and row[2] == role and row[3] == privilege for row in expected_columns
                )
                actual = connection.scalar(
                    sa.text("SELECT pg_catalog.has_column_privilege(:role,:oid,:column,:privilege)"),
                    {"role": role, "oid": oid, "column": column[1], "privilege": privilege},
                )
                _require(actual is expected)


def _function(connection, stage):
    spec = _FUNCTIONS.get(stage)
    if spec is None:
        return set()
    name, args, definer, result, defaults, digest = spec
    rows = _dicts(
        connection,
        "SELECT p.*,n.nspname,l.lanname,pg_catalog.pg_get_userbyid(p.proowner) AS owner,"
        "pg_catalog.pg_get_expr(p.proargdefaults,0) AS defaults,pg_catalog.format_type(p.prorettype,NULL) AS result "
        "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
        "JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE n.nspname='public' AND p.proname=:name",
        name=name,
    )
    _require(len(rows) == 1)
    row = rows[0]
    oid = connection.scalar(
        sa.text("SELECT pg_catalog.to_regprocedure(:signature)::oid"), {"signature": f"public.{name}({args})"}
    )
    _require(row["oid"] == oid)
    _require(
        tuple(
            row[k]
            for k in (
                "owner",
                "lanname",
                "prosecdef",
                "provolatile",
                "proparallel",
                "proisstrict",
                "proleakproof",
                "prokind",
            )
        )
        == ("app_admin", "plpgsql", definer, "v", "u", False, False, "f")
    )
    _require(
        tuple(
            row[k]
            for k in ("proconfig", "result", "pronargdefaults", "probin", "prosqlbody", "prosupport", "provariadic")
        )
        == (["search_path=pg_catalog"], result, defaults, None, None, 0, 0)
    )
    _require(hashlib.sha256(row["prosrc"].encode()).hexdigest() == digest)
    _require(row["procost"] == 100 and row["prorows"] == (1000 if definer else 0))
    _require(row["protrftypes"] is None)
    if stage == "a008_lab_console_activity":
        _require(
            tuple(row[k] for k in ("pronargs", "proretset", "proargnames", "proargmodes", "proallargtypes", "defaults"))
            == (0, False, None, None, None, None)
        )
        allowed: tuple[str, ...] = ("app_admin", "PUBLIC")
    else:
        _require(
            (row["pronargs"], row["proretset"], tuple(row["proargnames"]), tuple(row["proargmodes"]))
            == (
                6,
                True,
                (
                    "p_tenant_id",
                    "p_nomination_id",
                    "p_person_id",
                    "p_course_id",
                    "p_limit",
                    "p_actor_person_id",
                    "candidate_nomination_id",
                    "activated_now",
                ),
                ("i", "i", "i", "i", "i", "i", "t", "t"),
            )
        )
        _require(row["defaults"] == "NULL::uuid, NULL::uuid, NULL::uuid, NULL::integer, NULL::uuid")
        _require(row["procost"] == 100 and row["prorows"] == 1000)
        u, i, b = connection.execute(
            sa.text("SELECT 'uuid'::regtype::oid,'integer'::regtype::oid,'boolean'::regtype::oid")
        ).one()
        _require(tuple(row["proallargtypes"]) == (u, u, u, u, i, u, u, b))
        allowed = ("app_admin", "app_user", "platform_api", "academy_lab_worker")
    acl = _rows(
        connection,
        "SELECT pg_catalog.pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' "
        "ELSE pg_catalog.pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable "
        "FROM pg_catalog.pg_proc p CROSS JOIN LATERAL "
        "pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a "
        "WHERE p.oid=:oid ORDER BY 1,2,3,4",
        oid=oid,
    )
    _require(acl == tuple(sorted(("app_admin", role, "EXECUTE", False) for role in allowed)))
    return {oid}


def _validate_table(connection, spec):
    oid = _oid(connection, spec.name)
    cat = history._catalog(connection, oid)
    _require(cat.relation == (oid, "r", "app_admin", True, True, False, False, "p", None, "d", 0))
    _require(not cat.rules)
    columns = _columns(connection, spec.name)
    _require(len(columns) == len(spec.columns))
    for number, (row, expected) in enumerate(zip(columns, spec.columns, strict=True), 1):
        _require(row[0] == number)
        _validate_column(connection, row, expected, column_acl=spec.name == "lab_console_activity")
    policies = _rows(
        connection,
        "SELECT polname,polcmd,polpermissive,polroles,pg_catalog.pg_get_expr(polqual,polrelid),"
        "pg_catalog.pg_get_expr(polwithcheck,polrelid),polqual::text,polwithcheck::text "
        "FROM pg_catalog.pg_policy WHERE polrelid=:oid ORDER BY polname",
        oid=oid,
    )
    _require(len(policies) == 1)
    p = policies[0]
    _require(
        p[:6]
        == (
            spec.name + "_tenant_isolation",
            "*",
            True,
            (0,),
            "(tenant_id = app_current_tenant_id())",
            "(tenant_id = app_current_tenant_id())",
        )
    )
    _expression(connection, p[4], p[6])
    _expression(connection, p[5], p[7])
    keys = _rows(
        connection,
        "SELECT conname,contype,ARRAY(SELECT a.attname FROM unnest(k.conkey) WITH ORDINALITY x(num,ord) "
        "JOIN pg_catalog.pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=x.num ORDER BY x.ord),"
        "convalidated,condeferrable,condeferred FROM pg_catalog.pg_constraint k WHERE "
        "conrelid=:oid AND contype IN ('p','u') ORDER BY conname",
        oid=oid,
    )
    _require(keys == tuple(sorted((*key, True, False, False) for key in spec.keys)))
    checks = _rows(
        connection,
        "SELECT "
        "conname,pg_catalog.pg_get_expr(conbin,conrelid),conbin::text,convalidated,condeferrab"
        "le,condeferred,connoinherit "
        "FROM pg_catalog.pg_constraint WHERE conrelid=:oid AND contype='c' ORDER BY conname",
        oid=oid,
    )
    _require(tuple((r[0], r[1]) for r in checks) == tuple(sorted(spec.checks)))
    for check in checks:
        _require(check[3:] == (True, False, False, False))
        _expression(connection, check[1], check[2])
    _require(len(cat.constraints) == len(spec.keys) + len(spec.fks) + len(spec.checks))
    indexes = [(name, cols, True, kind == "p", None) for name, kind, cols in spec.keys]
    indexes.extend((name, cols, unique, False, predicate) for name, cols, unique, predicate in spec.indexes)
    _validate_indexes(connection, spec.name, indexes)
    fks = _foreign_keys(connection, oid, _keys(connection, spec.fks), spec.name, spec.fks)
    _check_operators(connection, fks)
    triggers = _ri_triggers(connection, fks)
    _acl(connection, spec.name, crud=spec.request_crud)
    user_triggers = _rows(
        connection,
        "SELECT tgname,tgtype,tgenabled,tgnargs,tgargs,tgqual::text,tgoldtable,tgnewtable,tgfoid "
        "FROM pg_catalog.pg_trigger WHERE tgrelid=:oid AND NOT tgisinternal ORDER BY tgname",
        oid=oid,
    )
    if spec.name == "lab_console_activity":
        fn = connection.scalar(sa.text("SELECT 'public.lab_console_activity_stamp()'::regprocedure::oid"))
        _require(user_triggers == (("lab_console_activity_stamp", 23, "O", 0, b"", None, None, None, fn),))
    else:
        _require(not user_triggers)
    return fks, triggers


def row_evidence(connection, packet, *, omissions=()):
    """Server-side conservation digests; no application payload is returned."""
    omit = dict(omissions)
    result = []
    for oid, raw in sorted(packet["pg_class"].items()):
        rel = json.loads(raw)
        if rel["relkind"] != "r" or rel["relname"] == "alembic_version":
            continue
        namespace = connection.scalar(
            sa.text("SELECT nspname FROM pg_catalog.pg_namespace WHERE oid=:oid"), {"oid": rel["relnamespace"]}
        )
        if namespace == "pg_toast":
            continue  # Physical storage catalogs are conserved; owner rows are hashed once.
        _require(namespace in ("public", "mod_learning", "academy_identity_compat"))
        name = rel["relname"]
        _require(re.fullmatch("[a-z][a-z0-9_]*", name) is not None)
        sql = (
            f"SELECT pg_catalog.md5((pg_catalog.to_jsonb(t)-CAST(:omitted AS text[]))::text),count(*) "  # noqa: S608
            f'FROM "{namespace}"."{name}" t GROUP BY 1 ORDER BY 1'
        )
        result.append((oid, _rows(connection, sql, omitted=list(omit.get(name, ())))))
    return tuple(result)


def grandfather_keys(connection):
    return _rows(
        connection,
        "SELECT DISTINCT e.tenant_id,e.person_id,e.cohort_id FROM mod_learning.enrollments e "
        "JOIN public.parties p ON p.tenant_id=e.tenant_id AND p.id=e.person_id AND p.party_type='person' "
        "JOIN public.party_persons pp ON pp.party_id=p.id "
        "JOIN public.party_role_grants pr ON pr.tenant_id=e.tenant_id AND pr.party_id=e.person_id "
        "JOIN public.roles r ON r.tenant_id=pr.tenant_id AND r.id=pr.role_id AND r.slug='instructor' "
        "WHERE e.role_in_cohort='instructor' AND e.status='active' ORDER BY 1,2,3",
    )


def _validate_rows(connection, stage, expected_grandfathers):
    predicates = {
        "a007_lab_template_access": "SELECT NOT EXISTS (SELECT 1 FROM public.lab_templates WHERE access IS DISTINCT "
        "FROM '[]'::jsonb)",
        "a009_applicant_bank_version_pin": "SELECT NOT EXISTS (SELECT 1 FROM public.applicants WHERE "
        "assessment_bank_version_id IS NOT NULL)",
        "a008_lab_console_activity": "SELECT NOT EXISTS (SELECT 1 FROM public.lab_console_activity)",
    }
    if stage in predicates:
        _require(connection.scalar(sa.text(predicates[stage])) is True)
    if stage == "a010_facilitator_nominations":
        actual = _rows(
            connection, "SELECT tenant_id,person_id,cohort_id FROM public.facilitator_nominations ORDER BY 1,2,3"
        )
        _require(actual == expected_grandfathers)
        _require(
            connection.scalar(sa.text("SELECT NOT EXISTS (SELECT 1 FROM public.facilitator_requirements)")) is True
        )
        _require(
            connection.scalar(
                sa.text(
                    "SELECT NOT EXISTS (SELECT 1 FROM public.facilitator_nominations WHERE "
                    "scope_type IS DISTINCT FROM 'cohort' "
                    "OR offering_id IS NOT NULL OR nominated_by_person_id IS NOT NULL OR revoked_at IS NOT NULL "
                    "OR status IS DISTINCT FROM 'active' OR activation_reason IS DISTINCT FROM 'legacy_grandfathered' "
                    "OR activated_at IS DISTINCT FROM pg_catalog.now() OR created_at IS DISTINCT FROM pg_catalog.now() "
                    "OR updated_at IS DISTINCT FROM pg_catalog.now())"
                )
            )
            is True
        )


def _validate_new_raw(before, after, stage, fks, trigger_ids):
    """All new catalog identities must be subsidiary to the finite contract."""
    specs = _TABLES.get(stage, ())
    tables = {s.name for s in specs}
    indexnames = {name for s in specs for name, *_ in (*s.keys, *s.indexes)}
    if stage == "a009_applicant_bank_version_pin":
        indexnames.add("ix_applicants_assessment_bank_version_id")
    added_relations = {oid: json.loads(raw) for oid, raw in after["pg_class"].items() if oid not in before["pg_class"]}
    tableids = {oid for oid, r in added_relations.items() if r["relname"] in tables}
    _require(len(tableids) == len(tables))
    toastids = set()
    toastindexids = set()
    toastnames: set[str] = set()
    for oid in tableids:
        toast = added_relations[oid]["reltoastrelid"]
        if toast:
            _require(stage == "a004_retained_learning_refs" and toast in added_relations)
            t = added_relations[toast]
            _require(t["relname"] == f"pg_toast_{oid}" and t["relkind"] == "t" and t["reltoastrelid"] == 0)
            _require(not t["relrowsecurity"] and not t["relforcerowsecurity"] and t["relhasindex"])
            candidates = [i for i, r in added_relations.items() if r["relname"] == f"pg_toast_{oid}_index"]
            _require(len(candidates) == 1)
            index = candidates[0]
            meta = json.loads(after["pg_index"][index])
            _require(meta["indrelid"] == toast and meta["indisunique"] and not meta["indisprimary"])
            _require(meta["indisvalid"] and meta["indisready"] and meta["indislive"])
            _require(
                meta["indnkeyatts"] == meta["indnatts"] == 2 and meta["indexprs"] is None and meta["indpred"] is None
            )
            toastids.add(toast)
            toastindexids.add(index)
            toastnames.update((t["relname"], added_relations[index]["relname"]))
    expected_relations = tables | indexnames | toastnames
    _require(
        {r["relname"] for r in added_relations.values()} == expected_relations
        and len(added_relations) == len(expected_relations)
    )
    indexids = set(added_relations) - tableids - toastids
    for oid, r in added_relations.items():
        expected_kind = "t" if oid in toastids else ("r" if oid in tableids else "i")
        _require(
            r["relkind"] == expected_kind
            and r["relpersistence"] == "p"
            and not r["relispartition"]
            and not r["relhassubclass"]
        )
        _require(r["reloptions"] is None and r["reltablespace"] == 0 and r["relrewrite"] == 0)
    added_types = {oid: json.loads(raw) for oid, raw in after["pg_type"].items() if oid not in before["pg_type"]}
    _require(len(added_types) == 2 * len(tables))
    expected_typenames = tables | {"_" + name for name in tables}
    _require({t["typname"] for t in added_types.values()} == expected_typenames)
    for oid, t in added_types.items():
        _require(
            t["typisdefined"]
            and t["typnotnull"] is False
            and t["typbasetype"] == 0
            and t["typtypmod"] == -1
            and t["typndims"] == 0
        )
        _require(
            t["typdefault"] is None and t["typdefaultbin"] is None and t["typacl"] is None and t["typcollation"] == 0
        )
        if t["typname"] in tables:
            _require(
                t["typtype"] == "c" and t["typrelid"] in tableids and t["typelem"] == 0 and t["typarray"] in added_types
            )
            _require(added_relations[t["typrelid"]]["reltype"] == oid)
        else:
            _require(t["typtype"] == "b" and t["typrelid"] == 0 and t["typelem"] in added_types and t["typarray"] == 0)
            _require(added_types[t["typelem"]]["typarray"] == oid)
    added_constraints = {
        oid: json.loads(raw) for oid, raw in after["pg_constraint"].items() if oid not in before["pg_constraint"]
    }
    _require(set(fks) <= set(added_constraints))
    expected_constraints = {name for s in specs for name, *_ in (*s.keys, *s.fks, *s.checks)}
    if stage == "a009_applicant_bank_version_pin":
        expected_constraints.add(_BANK_FK[0])
    if stage == "a006_lab_claim_lease":
        expected_constraints.update(lab_claim._CHECKS)
    _require({r["conname"] for r in added_constraints.values()} == expected_constraints)
    _require(len(added_constraints) == len(expected_constraints))
    _require(
        all(
            r["contype"] in ("p", "u", "f", "c") and r["conparentid"] == 0 and r["conislocal"] and r["coninhcount"] == 0
            for r in added_constraints.values()
        )
    )
    added_triggers = {
        oid: json.loads(raw) for oid, raw in after["pg_trigger"].items() if oid not in before["pg_trigger"]
    }
    custom = (
        {oid for oid, r in added_triggers.items() if r["tgname"] == "lab_console_activity_stamp"}
        if stage == "a008_lab_console_activity"
        else set()
    )
    _require(set(added_triggers) == trigger_ids | custom)
    _require(len(custom) == (1 if stage == "a008_lab_console_activity" else 0))
    added_policies = {oid: json.loads(raw) for oid, raw in after["pg_policy"].items() if oid not in before["pg_policy"]}
    policy_tables = tables - {"platform_settings"}
    _require({r["polname"] for r in added_policies.values()} == {n + "_tenant_isolation" for n in policy_tables})
    _require(len(added_policies) == len(policy_tables))
    _require(all(r["polrelid"] in tableids for r in added_policies.values()))
    _require({oid for oid in after["pg_index"] if oid not in before["pg_index"]} == indexids)
    added_functions = {oid: json.loads(raw) for oid, raw in after["pg_proc"].items() if oid not in before["pg_proc"]}
    _require(
        {p["proname"] for p in added_functions.values()} == ({_FUNCTIONS[stage][0]} if stage in _FUNCTIONS else set())
    )
    _require(len(added_functions) == (1 if stage in _FUNCTIONS else 0))
    _require(after["pg_rewrite"] == before["pg_rewrite"])
    addition = _COLUMN_ADDITIONS.get(stage)
    appended = set()
    if addition is not None:
        table, col = addition
        relid = next(oid for oid, raw in before["pg_class"].items() if json.loads(raw)["relname"] == table)
        prior = [key[1] for key in before["pg_attribute"] if key[0] == relid and key[1] > 0]
        appended.add((relid, max(prior) + 1))
    attribute_additions = set(after["pg_attribute"]) - set(before["pg_attribute"])
    _require(attribute_additions == {key for key in after["pg_attribute"] if key[0] in set(added_relations)} | appended)
    added_defaults = {
        oid: json.loads(raw) for oid, raw in after["pg_attrdef"].items() if oid not in before["pg_attrdef"]
    }
    expected_defaults: set[tuple[int, int]] = set()
    for s in specs:
        oid = next(oid for oid, r in added_relations.items() if r["relname"] == s.name)
        expected_defaults.update((oid, i) for i, c in enumerate(s.columns, 1) if c[3] is not None)
    if addition is not None and addition[1][3] is not None:
        expected_defaults.update(appended)
    _require({(r["adrelid"], r["adnum"]) for r in added_defaults.values()} == expected_defaults)
    _require(len(added_defaults) == len(expected_defaults))
    return appended


def conserve(before, after, *, stage, appended):
    """Inverse-project only additions already validated by the stage contract."""
    _require(Counter(before["dependencies"]) <= Counter(after["dependencies"]))
    # Category additions have been independently classified; all prior raw rows
    # remain identical except narrowly enumerated relation flag/count changes.
    new_constraints = {
        oid: json.loads(raw) for oid, raw in after["pg_constraint"].items() if oid not in before["pg_constraint"]
    }
    affected_triggers = {
        json.loads(raw)["tgrelid"] for oid, raw in after["pg_trigger"].items() if oid not in before["pg_trigger"]
    }
    affected_indexes = {
        json.loads(raw)["indrelid"] for oid, raw in after["pg_index"].items() if oid not in before["pg_index"]
    }
    for category, old in before.items():
        if category in ("dependencies", "global"):
            continue
        for key, raw in old.items():
            _require(key in after[category])
            current = after[category][key]
            if category == "pg_class":
                a, b = json.loads(raw), json.loads(current)
                if any(relid == key for relid, _ in appended):
                    _require(b["relnatts"] == a["relnatts"] + 1)
                    b["relnatts"] = a["relnatts"]
                if key in affected_triggers:
                    _require(b["relhastriggers"] is True)
                    b["relhastriggers"] = a["relhastriggers"]
                if stage == "a006_lab_claim_lease" and a["relname"] == "lab_operations":
                    _require(b["relchecks"] == a["relchecks"] + 2)
                    b["relchecks"] = a["relchecks"]
                if key in affected_indexes:
                    _require(b["relhasindex"] is True)
                    b["relhasindex"] = a["relhasindex"]
                _require(a == b)
            else:
                _require(current == raw)
    for key in before["global"]:
        if key == "other_relations":
            old_ids = {r[0] for r in before["global"][key]}
            _require(tuple(r for r in after["global"][key] if r[0] in old_ids) == before["global"][key])
        elif key != "shared_dependencies":
            _require(after["global"][key] == before["global"][key])
    # Raw dependency continuity includes incoming RI rows. Never discard all
    # incoming constraints/triggers; only independently validated new objects.
    added = {}
    for category, rows in after.items():
        if category.startswith("pg_") and category not in ("pg_attribute", "pg_index"):
            added[category] = set(rows) - set(before[category])
    # Catalog OIDs are stable builtins; supplied by the observer, never inferred
    # from an after object's role in a difference.
    return added, new_constraints


def validate_stage(connection, before, after, stage, *, original_rows, expected_grandfathers=()):
    fks = {}
    triggerids: set[int] = set()
    addition = _COLUMN_ADDITIONS.get(stage)
    if addition is not None:
        table, column_spec = addition
        row = _columns(connection, table)[-1]
        _validate_column(connection, row, column_spec, appended=True)
    for spec in _TABLES.get(stage, ()):
        observed, triggers = _validate_table(connection, spec)
        fks.update(observed)
        triggerids.update(t["oid"] for t in triggers)
    if stage == "a009_applicant_bank_version_pin":
        specs = (_BANK_FK,)
        fks = _foreign_keys(connection, _oid(connection, "applicants"), _keys(connection, specs), "applicants", specs)
        _check_operators(connection, fks)
        triggerids.update(t["oid"] for t in _ri_triggers(connection, fks))
        # Existing indexes are conserved raw; validate exactly the appended one
        # independently rather than hiding an arbitrary index delta.
        idx = _dicts(
            connection,
            "SELECT i.*,c.relname,c.reloptions,c.reltablespace,am.amname FROM pg_catalog.pg_index i "
            "JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid JOIN pg_catalog.pg_am am ON am.oid=c.relam "
            "WHERE c.relname='ix_applicants_assessment_bank_version_id' AND c.relnamespace='public'::regnamespace",
        )
        _require(len(idx) == 1)
        i = idx[0]
        num = _columns(connection, "applicants")[-1][0]
        uuidops = connection.scalar(
            sa.text(
                "SELECT oid FROM pg_catalog.pg_opclass WHERE opcname='uuid_ops' AND "
                "opcnamespace='pg_catalog'::regnamespace AND opcmethod=(SELECT oid FROM "
                "pg_catalog.pg_am WHERE amname='btree')"
            )
        )
        _require(
            tuple(
                i[k]
                for k in (
                    "indrelid",
                    "indisunique",
                    "indisprimary",
                    "indisvalid",
                    "indisready",
                    "indislive",
                    "indnkeyatts",
                    "indnatts",
                )
            )
            == (_oid(connection, "applicants"), False, False, True, True, True, 1, 1)
        )
        _require(
            tuple(str(i[k]) for k in ("indkey", "indclass", "indcollation", "indoption"))
            == (str(num), str(uuidops), "0", "0")
        )
        _require(
            tuple(i[k] for k in ("indexprs", "indpred", "reloptions", "reltablespace", "amname"))
            == (None, None, None, 0, "btree")
        )
    if fks:
        key_constraints = {}
        for fk in fks.values():
            key = _keys(
                connection,
                (
                    (
                        fk["name"],
                        fk["columns"],
                        fk["parent_namespace"],
                        fk["parent"],
                        fk["parent_columns"],
                        fk["delete_action"],
                    ),
                ),
            )
            for relation, numbers, constraint_oid, index_oid in key.values():
                key_constraints[constraint_oid] = (relation, numbers, index_oid)
        all_triggers = _ri_triggers(connection, fks)
        checkpoint._check_dependencies(connection, fks, all_triggers, key_constraints)
    _function(connection, stage)
    _validate_rows(connection, stage, expected_grandfathers)
    appended = _validate_new_raw(before, after, stage, fks, triggerids)
    _raw_attribute_contract(connection, before, after)
    added, _ = conserve(before, after, stage=stage, appended=appended)
    _shared_dependencies(connection, before, after, added, appended)
    classids = {
        name: connection.scalar(sa.text("SELECT CAST(:name AS regclass)::oid"), {"name": "pg_catalog." + name})
        for name in added
    }
    added_pairs = {(classids[cat], oid) for cat, oids in added.items() for oid in oids}
    new_deps = Counter(after["dependencies"]) - Counter(before["dependencies"])
    _require(Counter(before["dependencies"]) <= Counter(after["dependencies"]))
    for dep in new_deps:
        cls, oid, sub, refcls, ref, refsub, kind = dep
        _require((cls, oid) in added_pairs or (cls == classids["pg_class"] and (oid, sub) in appended))
        # Only ordinary automatic/internal/normal dependencies declared by DDL;
        # extension membership or pinned/partition relationships cannot appear.
        _require(kind in ("a", "i", "n"))
    # Source predicates already validate each expression's builtin identities;
    # preserve all old row digests with only the explicit appended key removed.
    omissions = () if addition is None else ((addition[0], (addition[1][0],)),)
    _require(row_evidence(connection, before, omissions=omissions) == original_rows)


def _raw_attribute_contract(connection, before, after):
    """Validate storage/identity/inheritance fields beyond formatted SQL types."""
    for key, raw in after["pg_attribute"].items():
        if key in before["pg_attribute"]:
            continue
        a = json.loads(raw)
        _require(a["attrelid"] == key[0] and a["attnum"] == key[1])
        _require(a["attidentity"] == a["attgenerated"] == a["attcompression"] == "")
        _require(a["attoptions"] is None and a["attfdwoptions"] is None)
        _require(a["attinhcount"] == 0 and a["attislocal"] is True and a["attndims"] == 0 and not a["attisdropped"])
        _require(a["attstattarget"] in (-1, 0) and a["attcacheoff"] == -1)
        types = _rows(
            connection,
            "SELECT n.nspname,t.typname,t.typlen,t.typbyval,t.typalign,t.typstorage FROM pg_catalog.pg_type t "
            "JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE t.oid=:oid",
            oid=a["atttypid"],
        )
        _require(len(types) == 1 and types[0][0] == "pg_catalog")
        namespace, name, length, byval, align, storage = types[0]
        relation = json.loads(after["pg_class"][key[0]])
        expected_storage = "p" if relation["relkind"] in ("i", "t") else storage
        _require(
            (a["attlen"], a["attbyval"], a["attalign"], a["attstorage"]) == (length, byval, align, expected_storage)
        )
        if key[1] < 0:
            expected = {
                -1: ("ctid", "tid"),
                -2: ("xmin", "xid"),
                -3: ("cmin", "cid"),
                -4: ("xmax", "xid"),
                -5: ("cmax", "cid"),
                -6: ("tableoid", "oid"),
            }
            _require((a["attname"], name) == expected.get(key[1]))
        else:
            _require(
                name
                in (
                    "uuid",
                    "varchar",
                    "timestamptz",
                    "jsonb",
                    "float8",
                    "int4",
                    "int8",
                    "text",
                    "bool",
                    "date",
                    "oid",
                    "bytea",
                )
            )


def _shared_dependencies(connection, before, after, added, appended):
    classids = {
        name: connection.scalar(sa.text("SELECT CAST(:name AS regclass)::oid"), {"name": "pg_catalog." + name})
        for name in added
    }
    roleclass = connection.scalar(sa.text("SELECT 'pg_catalog.pg_authid'::regclass::oid"))
    roles = {r[1]: r[0] for r in _rows(connection, "SELECT oid,rolname FROM pg_catalog.pg_roles")}
    allowed_roles = {roles[r] for r in ("app_admin", "app_user", "platform_api", "academy_lab_worker")}
    old = Counter(before["global"]["shared_dependencies"])
    new = Counter(after["global"]["shared_dependencies"])
    _require(old <= new)
    for dep, count in (new - old).items():
        cls, oid, sub, refcls, role, kind = dep
        _require(count == 1 and refcls == roleclass and role in allowed_roles)
        _require(
            (cls in classids.values() and oid in next(ids for name, ids in added.items() if classids[name] == cls))
            or (cls == classids["pg_class"] and (oid, sub) in appended)
        )
        _require(kind in ("o", "a") and (kind != "o" or role == roles["app_admin"]))


def _check_non_ri_structure(packet):
    packet = {**packet, "constraints": tuple((row for row in packet["constraints"] if row[2] != "f"))}
    schema._check_rendering_context(packet)
    _require(tuple((r[0] for r in packet["relations"])) == schema._NAMES)
    for row in packet["relations"]:
        _require(row[2:4] == ("r", "app_admin"))
        tenant = row[0] != "platform_settings"
        _require(row[4:6] == (tenant, tenant))
        _require(row[6:] == ("p", False, False, None, "d", 0))
    expected_columns = tuple(((t, i, *c) for t, columns in schema._COLUMNS for i, c in enumerate(columns, 1)))
    _require(tuple((row[:6] for row in packet["columns"])) == expected_columns)
    _require(all((row[6:9] == (False, "", "") and row[11:] == (0, True) for row in packet["columns"])))
    expected_column_collations = tuple(
        (schema._column_collation(c[1]) for _, columns in schema._COLUMNS for c in columns)
    )
    _require(tuple((row[9:11] for row in packet["columns"])) == expected_column_collations)
    expected_constraints: list[tuple[str, str, str, tuple[str, ...]]] = []
    for table, primary_unique_keys in schema._KEYS:
        expected_constraints.extend(((table, name, kind, columns) for name, kind, columns in primary_unique_keys))
    checks = {(t, n): expression for t, n, expression in schema._CHECK_RENDERINGS}
    actual_constraints: list[tuple[str, str, str, tuple[str, ...]]] = []
    fk_map = {(t, f[0]): f for t, foreign_keys in schema._FOREIGN_KEYS for f in foreign_keys}
    for row in packet["constraints"]:
        table, name, kind, columns = row[:4]
        _require(kind in ("p", "u", "f", "c"))
        _require(row[10:14] == (True, False, False, kind != "c"))
        if kind == "c":
            _require((table, name) in checks and row[14] == checks[table, name])
        else:
            actual_constraints.append((table, name, kind, columns))
            _require(row[14] is None)
        if kind == "f":
            foreign_key_spec = fk_map.get((table, name))
            if foreign_key_spec is None:
                raise schema.RetainedSchemaRefused("Historical retained schema refused; root rollback required")
            _require(
                row[4:10]
                == (
                    "public",
                    foreign_key_spec[2],
                    foreign_key_spec[3],
                    "c" if foreign_key_spec[4] == "CASCADE" else "a",
                    "a",
                    "s",
                )
            )
    _require(tuple(sorted(actual_constraints)) == tuple(sorted(expected_constraints)))
    _require({(r[0], r[1]) for r in packet["constraints"] if r[2] == "c"} == set(checks))
    expected_indexes = {(t, s[0]): s for t, indexes in schema._INDEXES for s in indexes}
    partial_predicates = {(t, n): expression for t, n, expression in schema._PARTIAL_PREDICATE_RENDERINGS}
    _require({(r[0], r[1]) for r in packet["indexes"]} == set(expected_indexes))
    for row in packet["indexes"]:
        index_spec = expected_indexes[row[0], row[1]]
        _require(row[2:7] == (index_spec[2], index_spec[3], True, True, True))
        _require(row[7:11] == (index_spec[1], len(index_spec[1]), len(index_spec[1]), None))
        _require(row[12] == " ".join(("0" for _ in index_spec[1])))
        _require(row[15:] == ("btree", None, 0, "app_admin", False, True))
        expected_opclasses, expected_collations = schema._expected_index_semantics(row[0], index_spec[1])
        _require(row[13:15] == (expected_opclasses, expected_collations))
        _require(row[11] == partial_predicates.get((row[0], row[1])))
    expected_policies = tuple(
        (
            (
                t,
                t + "_tenant_isolation",
                "*",
                True,
                (0,),
                "(tenant_id = app_current_tenant_id())",
                "(tenant_id = app_current_tenant_id())",
            )
            for t in schema._NAMES
            if t != "platform_settings"
        )
    )
    _require(packet["policies"] == expected_policies)
    _require(not packet["unexpected_rules_triggers"])
    schema._check_policy_dependencies(packet)


def _fresh_parent_keys(connection):
    return {
        (ns, table): retained._key(connection, ns, table, columns, name, kind)
        for ns, table, columns, name, kind in retained._parent_specs(final=True)
    }


def _fresh_lease_checks(connection):
    oid = _oid(connection, "lab_operations")
    columns = _columns(connection, "lab_operations")
    _require(len(columns) == 21 and columns[-1][0] == 21)
    _validate_column(connection, columns[-1], ("claim_lease_seconds", "integer", True, None), appended=True)
    rows = _rows(
        connection,
        "SELECT "
        "oid,conname,contype,conkey,convalidated,condeferrable,condeferred,connoinherit,c"
        "onislocal,coninhcount,conparentid,"
        "pg_catalog.pg_get_expr(conbin,conrelid,false),conbin::text FROM pg_catalog.pg_constraint "
        "WHERE conrelid=:oid AND conname=ANY(:names) ORDER BY conname",
        oid=oid,
        names=list(lab_claim._CHECKS),
    )
    _require(len(rows) == 2 and {r[1] for r in rows} == set(lab_claim._CHECKS))
    state = next(r[0] for r in columns if r[1] == "state")
    expected = {lab_claim._POSITIVE: {21}, lab_claim._REQUIRED: {state, 21}}
    for row in rows:
        _require(row[2] == "c" and set(row[3]) == expected[row[1]])
        _require(row[4:11] == (True, False, False, False, True, 0, 0))
        _require(row[11] == lab_claim._RENDERINGS[row[1]])
        _expression(connection, row[11], row[12])


def validate_fresh_stage(
    connection, before, after, stage, *, original_rows, parent_keys, checkpoint_keys, public_schema
):
    """Independent source contracts after real command/version callbacks."""
    from app.maintenance import fresh_product as fresh

    _require(stage in fresh._STAGES)
    fresh._authority(connection)
    packet = schema._observe_historical_catalog(connection)
    cluster = schema._observe_cluster_authority(connection)
    if stage == "a006_lab_claim_lease":
        _fresh_lease_checks(connection)
        packet = retained._normalize_lab_claim_packet(packet)
        cluster = retained._normalize_lab_claim_cluster(cluster)
    _check_non_ri_structure(packet)
    schema._check_security(packet)
    retained._verify_successor_cluster(connection, public_schema, cluster=cluster)
    keys = _fresh_parent_keys(connection)
    _require(all(keys[key] == value for key, value in parent_keys.items()))
    fks, triggers = retained._check_ri(connection, packet, final=True, keys=keys)
    by_oid = {fk["oid"]: fk for fk in fks}
    trigger_ids = {t["oid"] for t in triggers}
    if stage != "a004_retained_learning_refs":
        _require(checkpoint._parent_keys(connection) == checkpoint_keys)
        _fresh_checkpoint_schema(connection, checkpoint_keys)
        if stage == "a005_erp_completion_checkpoint":
            by_oid = checkpoint._foreign_keys(connection, _oid(connection, checkpoint._TABLE), checkpoint_keys)
            trigger_ids = {t["oid"] for t in checkpoint._ri_triggers(connection, by_oid)}
        else:
            by_oid = {}
            trigger_ids = set()
    appended = _validate_new_raw(before, after, stage, by_oid, trigger_ids)
    _raw_attribute_contract(connection, before, after)
    added, _ = conserve(before, after, stage=stage, appended=appended)
    _shared_dependencies(connection, before, after, added, appended)
    _dependency_conservation(connection, before, after, added, appended)
    addition = _COLUMN_ADDITIONS.get(stage)
    omissions = () if addition is None else ((addition[0], (addition[1][0],)),)
    _require(row_evidence(connection, before, omissions=omissions) == original_rows)
    # Empty-store proof covers ALL owners and every newly created product store.
    products = (*fresh._EARLY_PRODUCT, *schema._NAMES)
    if stage != "a004_retained_learning_refs":
        products = (*products, checkpoint._TABLE)
    for namespace, table in (
        *(("public", t) for t in (*fresh._KERNEL_TABLES, *products)),
        *(("mod_learning", t) for t in fresh._LEARNING_TABLES),
    ):
        _require(connection.scalar(sa.text(f'SELECT NOT EXISTS (SELECT 1 FROM "{namespace}"."{table}")')) is True)  # noqa: S608
    return keys


def _dependency_conservation(connection, before, after, added, appended):
    classids = {
        name: connection.scalar(sa.text("SELECT CAST(:name AS regclass)::oid"), {"name": "pg_catalog." + name})
        for name in added
    }
    pairs = {(classids[cat], oid) for cat, oids in added.items() for oid in oids}
    old = Counter(before["dependencies"])
    new = Counter(after["dependencies"])
    _require(old <= new)
    for cls, oid, sub, _refcls, _ref, _refsub, kind in new - old:
        _require((cls, oid) in pairs or (cls == classids["pg_class"] and (oid, sub) in appended))
        _require(kind in ("a", "i", "n"))


def _fresh_checkpoint_schema(connection, parent_keys):
    child_oid = history._oid(connection, checkpoint._TABLE)
    _require(type(child_oid) is int and child_oid > 0)
    keys = checkpoint._parent_keys(connection)
    _require(keys == parent_keys)
    primary = retained._key(connection, "public", checkpoint._TABLE, checkpoint._COLUMNS, checkpoint._PK, "p")
    _require(primary[0] == child_oid)
    catalog = history._catalog(connection, child_oid)
    _require(catalog.relation == (child_oid, "r", "app_admin", True, True, False, False, "p", None, "d", 0))
    _require(
        tuple((row[:4] for row in catalog.columns))
        == (
            (1, "tenant_id", "uuid", True),
            (2, "completion_id", "uuid", True),
            (3, "erp_synced_at", "timestamp with time zone", False),
        )
    )
    _require(all((row[4] is False and row[5] is None and (row[6:8] == ("", "")) for row in catalog.columns)))
    _require(
        tuple(((row[0], row[1], row[2]) for row in catalog.constraints))
        == (
            (checkpoint._PK, "p", primary[1]),
            (checkpoint._TENANT_FK, "f", (1,)),
            (checkpoint._COMPLETION_FK, "f", (1, 2)),
        )
    )
    _require(catalog.incoming == ())
    _require(len(catalog.indexes) == 1 and catalog.indexes[0][:2] == (primary[3], checkpoint._PK))
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
            "SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_depend d ON "
            "d.objid=c.oid WHERE c.relkind='S' AND d.refobjid=:oid",
            oid=child_oid,
        )
    )
    by_oid = checkpoint._foreign_keys(connection, child_oid, keys)
    checkpoint._check_operators(connection, by_oid)
    triggers = checkpoint._ri_triggers(connection, by_oid)
    _require({row[0] for row in catalog.triggers} == {t["oid"] for t in triggers if t["relation_oid"] == child_oid})
    key_constraints = {constraint: (relation, numbers, index) for relation, numbers, constraint, index in keys.values()}
    key_constraints[primary[2]] = (child_oid, primary[1], primary[3])
    checkpoint._check_dependencies(connection, by_oid, triggers, key_constraints)
    checkpoint._check_policy(connection, child_oid, catalog)
    checkpoint._check_acl(connection, child_oid, catalog)
    return (catalog, frozenset(by_oid), frozenset((t["oid"] for t in triggers)))

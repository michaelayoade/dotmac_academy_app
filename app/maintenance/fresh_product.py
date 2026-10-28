"""Bounded empty-only product entry; no commit or populated-adoption authority.

Discovery is deliberately unqualified and cannot commit. A reviewed historical
versus fresh hosted convergence digest must be pinned before ordinary receipts
can be issued. Public receipt fields never establish continuation authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

import sqlalchemy as sa

from alembic import command
from alembic.script import ScriptDirectory
from app.maintenance import account_token_identity as tokens
from app.maintenance import identity_history as identity
from app.maintenance import product_adoption as product
from app.maintenance import retained_schema as schema
from app.maintenance import retained_transition as retained
from app.migration_graph import ordinary_migration_config

# Not TOFU: populated only by a separately reviewed hosted H == F proof.
FRESH_CANONICAL_SHA256: str | None = None
_A002 = "a002_credential_reset_state"
_A003 = "a003_account_token_identity"
_STAGES = ("a004_retained_learning_refs", "a005_erp_completion_checkpoint", "a006_lab_claim_lease")
_STATE_KEY = object()
_KERNEL_TABLES = (
    "audit_events",
    "auth_sessions",
    "communication_deliveries",
    "communication_suppressions",
    "domain_setting_history",
    "domain_settings",
    "external_identity_bindings",
    "feature_flag_overrides",
    "idempotency_records",
    "machine_credentials",
    "outbox_events",
    "parties",
    "party_organizations",
    "party_persons",
    "party_role_grants",
    "platform_admins",
    "platform_audit_events",
    "platform_idempotency_records",
    "platform_outbox_events",
    "platform_sessions",
    "roles",
    "tenant_domains",
    "tenant_entitlement_grants",
    "tenants",
    "user_credentials",
)
_LEARNING_TABLES = (
    "courses",
    "activities",
    "submissions",
    "scores",
    "course_completions",
    "certificates",
    "learning_events",
    "chapters",
    "question_banks",
    "question_bank_versions",
    "questions",
    "chapter_reads",
    "subtopic_reads",
    "chapter_bookmarks",
    "chapter_notes",
    "cohorts",
    "enrollments",
    "tracks",
    "track_courses",
    "cohort_tracks",
    "course_offerings",
    "course_prerequisites",
    "activity_attempts",
    "attempt_grants",
    "offering_activities",
    "class_sessions",
    "announcements",
    "success_queue_entries",
)
_PRODUCT_TABLES = (
    "academy_account_profiles",
    "academy_credential_policies",
    "academy_erp_completion_checkpoints",
    "account_tokens",
    "applicants",
    "email_outbox",
    "facilitator_nominations",
    "facilitator_requirements",
    "lab_console_activity",
    "lab_instances",
    "lab_operations",
    "lab_templates",
    "notifications",
    "onboarding_tasks",
    "platform_settings",
    "reminder_log",
    "reminder_preferences",
    "tenant_entrance_defaults",
)
_EARLY_PRODUCT = ("academy_account_profiles", "academy_credential_policies", "account_tokens")
_KERNEL_FUNCTIONS = (
    "app_current_tenant_id",
    "claim_outbox_batch",
    "settle_outbox_event",
    "claim_platform_outbox_batch",
    "settle_platform_outbox_event",
)
_ROLES = (
    "app_admin",
    "app_user",
    "platform_api",
    "academy_lab_worker",
    "outbox_dispatcher",
    "platform_outbox_dispatcher",
)


class FreshProductRefused(RuntimeError):
    """Empty-entry continuity lost; discard or roll back the entire root."""


class FreshProductUnqualified(FreshProductRefused):
    """A reviewed canonical convergence pin has not yet qualified this path."""


def _require(condition):
    if not condition:
        raise FreshProductRefused("Academy fresh product entry refused; root rollback required")


@dataclass(frozen=True, slots=True)
class FreshProductReceipt:
    revisions: tuple[str, ...]
    catalog_sha256: str


@dataclass(frozen=True, slots=True)
class FreshProductDiscovery:
    """Noncommitting evidence only; never a bootstrap/admission receipt."""

    revisions: tuple[str, ...]
    catalog_sha256: str


@dataclass(slots=True, repr=False)
class _Entry:
    connection: object
    root: object
    physical: tuple
    token_receipt: object = None
    token_catalog: object = None
    graph: tuple = ()
    next_stage: int = 0
    prepared: bool = False
    poisoned: bool = False
    completed: bool = False
    commit_guard: object = field(default=None, repr=False)
    drift_guards: tuple = field(default=(), repr=False)


def _issued(connection):
    return connection.info.get(_STATE_KEY)


def _graph():
    # Source custody is still independently enforced by the historical owner.
    product._provenance()
    scripts = ScriptDirectory.from_config(ordinary_migration_config())
    return tuple(sorted((r.revision, r.down_revision, r.dependencies) for r in scripts.walk_revisions()))


def _terminal_versions(graph):
    nodes = {row[0] for row in graph}
    parents = {p for _, down, depends in graph for edges in (down, depends) for p in retained._edges((edges,))}
    _require(parents <= nodes)
    return tuple(sorted(nodes - parents))


def _versions(connection):
    return tuple(row[0] for row in retained._version_rows(connection))


def _cut(graph, stage, *, final):
    return tuple(row[0] for row in retained._stage_versions(graph, stage, final=final))


def _identifier(name):
    _require(type(name) is str and re.fullmatch(r"[a-z_][a-z0-9_]*", name) is not None)
    return '"' + name + '"'


def _qualified(namespace, name):
    return _identifier(namespace) + "." + _identifier(name)


def _columns(names):
    return ", ".join(map(_identifier, names))


def _owner_contracts():
    from dotmac_learning.manifest import module

    from app.canonical_models import kernel_owned_tables, physical_key, product_owned_tables

    _require({physical_key(t) for t in kernel_owned_tables()} == {("public", t) for t in _KERNEL_TABLES})
    _require({physical_key(t) for t in product_owned_tables()} == {("public", t) for t in _PRODUCT_TABLES})
    _require(module.db_schema == "mod_learning" and set(module.tables) == set(_LEARNING_TABLES))


def _census(connection, *, final):
    _owner_contracts()
    names = _PRODUCT_TABLES if final else _EARLY_PRODUCT
    expected = {("public", t, "r") for t in (*_KERNEL_TABLES, *names, "alembic_version")}
    expected.update(("mod_learning", t, "r") for t in _LEARNING_TABLES)
    actual = tokens._tuples(
        connection,
        "SELECT n.nspname,c.relname,c.relkind FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
        "AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp_%' "
        "AND c.relkind IN ('r','p','v','m','f','S','c') ORDER BY 1,2,3",
    )
    _require(set(actual) == expected and len(actual) == len(expected))
    _function_census(connection, final=final)
    _no_custom_types(connection)
    _require(connection.scalar(sa.text("SELECT pg_catalog.to_regnamespace('academy_identity_compat') IS NULL")) is True)
    # Even an empty legacy/unknown schema is outside the reviewed owner census.
    _require(
        not tokens._tuples(
            connection,
            "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname NOT IN "
            "('public','mod_learning','pg_catalog','information_schema') "
            "AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp_%'",
        )
    )


def _function_census(connection, *, final):
    names = set(_KERNEL_FUNCTIONS)
    if final:
        names.update(("lab_console_activity_stamp", "activate_eligible_facilitator_nominations"))
    functions = tokens._tuples(
        connection,
        "SELECT n.nspname,p.proname FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname IN ('public','mod_learning') ORDER BY 1,2",
    )
    _require(len(functions) == len(names) and set(functions) == {("public", name) for name in names})


def _no_custom_types(connection):
    _require(
        not tokens._tuples(
            connection,
            "SELECT n.nspname,t.typname FROM pg_catalog.pg_type t "
            "JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace "
            "WHERE n.nspname IN ('public','mod_learning') AND t.typrelid=0 AND t.typelem=0",
        )
    )


def _authority(connection):
    identity._connection_preflight(connection)
    rows = tokens._tuples(
        connection,
        "SELECT rolname,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication,rolinherit "
        "FROM pg_catalog.pg_roles WHERE rolname=ANY(:roles) ORDER BY rolname",
        roles=list(_ROLES),
    )
    _require({r[0] for r in rows} == set(_ROLES))
    for name, superuser, bypass, createdb, createrole, replication, inherit in rows:
        _require(not superuser and not createdb and not createrole and not replication)
        _require(bypass is (name in ("app_admin", "academy_lab_worker")))
        if name == "academy_lab_worker":
            _require(inherit is False)
    _require(
        not tokens._tuples(
            connection,
            "SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles a ON a.oid=m.member "
            "JOIN pg_catalog.pg_roles b ON b.oid=m.roleid WHERE a.rolname=ANY(:roles) OR b.rolname=ANY(:roles)",
            roles=list(_ROLES),
        )
    )


def _empty(connection, *, final):
    # app_admin must really BYPASSRLS; FORCE RLS must not hide populated rows.
    _authority(connection)
    names = _PRODUCT_TABLES if final else _EARLY_PRODUCT
    for namespace, table in (
        *(("public", t) for t in (*_KERNEL_TABLES, *names)),
        *(("mod_learning", t) for t in _LEARNING_TABLES),
    ):
        _require(
            connection.scalar(sa.text(f"SELECT NOT EXISTS (SELECT 1 FROM {_qualified(namespace, table)})")) is True  # noqa: S608
        )


def _check(connection, entry):
    _require(type(entry) is _Entry and _issued(connection) is entry)
    _require(not entry.poisoned and not entry.completed and entry.connection is connection)
    _require(identity._connection_preflight(connection) is entry.root)
    _require(tokens._physical_context(connection) == entry.physical)
    _require(connection.info.get(product._STATE_KEY) is None and tokens._issued(connection) is None)
    if entry.token_catalog is not None:
        _require(tokens._catalog(connection) == entry.token_catalog)


def _start(connection):
    root = identity._connection_preflight(connection)
    previous = _issued(connection)
    if type(previous) is _Entry:
        previous.poisoned = True
    _require(_issued(connection) is None and connection.info.get(product._STATE_KEY) is None)
    _require(tokens._issued(connection) is None)
    _initial_empty(connection)
    entry = _Entry(connection, root, tokens._physical_context(connection))
    connection.info[_STATE_KEY] = entry

    def forbid_commit(conn):
        entry.poisoned = True
        raise FreshProductRefused("Academy fresh product root is not qualified to commit")

    entry.commit_guard = forbid_commit
    sa.event.listen(connection, "commit", forbid_commit)

    def drift(*args):
        if not entry.completed:
            entry.poisoned = True

    entry.drift_guards = ("begin", "rollback", "savepoint", "rollback_savepoint", "release_savepoint")
    for name in entry.drift_guards:
        sa.event.listen(connection, name, drift)
    entry.drift_guards = tuple((name, drift) for name in entry.drift_guards)
    return entry


def _initial_empty(connection):
    """No existing owner/legacy catalog may reach even the first migration."""
    _require(
        not tokens._tuples(
            connection,
            "SELECT n.nspname,c.relname FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
            "AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp_%'",
        )
    )
    _require(
        not tokens._tuples(
            connection,
            "SELECT n.nspname,p.proname FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
            "AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp_%'",
        )
    )
    _require(
        not tokens._tuples(
            connection,
            "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname NOT IN "
            "('public','pg_catalog','information_schema') "
            "AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp_%'",
        )
    )
    _no_custom_types(connection)


def prepare_fresh_product(connection, *, decision_ref, token_receipt):
    """Consume ONLY the private wrapper's genuine immediate a003 continuation."""
    entry = _issued(connection)
    try:
        _check(connection, entry)
        _require(type(decision_ref) is str and bool(decision_ref.strip()))
        _require(not entry.prepared and entry.next_stage == 0)
        _require(token_receipt is entry.token_receipt and type(token_receipt) is tokens.AccountTokenIdentityReceipt)
        _require(token_receipt.identity_import_receipt is None and token_receipt.token_count == 0)
        _require(token_receipt.applied_revision == _A003)
        _require(_versions(connection) == _cut(entry.graph, _STAGES[0], final=False))
        _census(connection, final=False)
        _empty(connection, final=False)
        entry.prepared = True
        entry.token_receipt = None  # one-use continuation, not a transferable receipt
        return entry
    except BaseException:
        if type(entry) is _Entry:
            entry.poisoned = True
        raise


def _retained_ddl():
    statements = []
    for table, column_specs in schema._COLUMNS:
        parts = [
            f"{_identifier(name)} {sql_type}"
            + ("" if nullable else " NOT NULL")
            + (" DEFAULT " + default if default is not None else "")
            for name, sql_type, nullable, default in column_specs
        ]
        for name, kind, keys in dict(schema._KEYS)[table]:
            parts.append(
                f'CONSTRAINT {_identifier(name)} {"PRIMARY KEY" if kind == "p" else "UNIQUE"} ({_columns(keys)})'
            )
        parts.extend(
            f"CONSTRAINT {_identifier(name)} CHECK ({expression})"
            for t, name, expression in schema._CHECKS
            if t == table
        )
        statements.append(f'CREATE TABLE {_qualified("public", table)} (' + ", ".join(parts) + ")")
    for table, name, columns, namespace, parent, target, action in retained._specs(final=True):
        statements.append(
            f'ALTER TABLE {_qualified("public", table)} ADD CONSTRAINT {_identifier(name)} '
            f'FOREIGN KEY ({_columns(columns)}) REFERENCES {_qualified(namespace, parent)} ({_columns(target)}) '
            f'MATCH SIMPLE ON DELETE {action} ON UPDATE NO ACTION NOT DEFERRABLE INITIALLY IMMEDIATE'
        )
    for table, indexes in schema._INDEXES:
        constraints = {row[0] for row in dict(schema._KEYS)[table]}
        for name, columns, unique, _, predicate in indexes:
            if name not in constraints:
                statements.append(
                    f'CREATE {"UNIQUE " if unique else ""}INDEX {_identifier(name)} '
                    f'ON {_qualified("public", table)} ({_columns(columns)})'
                    + (" WHERE " + predicate if predicate else "")
                )
    for table in schema._NAMES:
        qualified = _qualified("public", table)
        if table != "platform_settings":
            statements.extend(
                (
                    f"ALTER TABLE {qualified} ENABLE ROW LEVEL SECURITY",
                    f"ALTER TABLE {qualified} FORCE ROW LEVEL SECURITY",
                    f'CREATE POLICY {_identifier(table + "_tenant_isolation")} ON {qualified} '
                    'AS PERMISSIVE FOR ALL TO PUBLIC USING (tenant_id = public.app_current_tenant_id()) '
                    'WITH CHECK (tenant_id = public.app_current_tenant_id())',
                )
            )
        for role in ("PUBLIC", *_ROLES):
            grantee = "PUBLIC" if role == "PUBLIC" else _identifier(role)
            statements.append(f"REVOKE ALL ON TABLE {qualified} FROM {grantee}")
            privileges = schema._table_privileges(table, role) if role in schema._ROLES else ()
            if privileges:
                statements.append(f'GRANT {", ".join(privileges)} ON TABLE {qualified} TO {grantee}')
        if table in dict(schema._REQUEST_COLUMNS):
            statements.append(
                f'GRANT INSERT ({_columns(dict(schema._REQUEST_COLUMNS)[table])}) ON TABLE {qualified} TO "app_user"'
            )
    return tuple(statements)


def _checkpoint_ddl():
    # Exact historical a005 fixed DDL, without the historical raw-ACK copy.
    return (
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
    )


def _lease_ddl():
    return (
        'ALTER TABLE "public"."lab_operations" ADD COLUMN "claim_lease_seconds" integer NULL',
        'ALTER TABLE "public"."lab_operations" ADD CONSTRAINT "ck_lab_operations_claim_lease_positive" '
        "CHECK (claim_lease_seconds IS NULL OR claim_lease_seconds > 0)",
        'ALTER TABLE "public"."lab_operations" ADD CONSTRAINT "ck_lab_operations_claim_lease_required" '
        "CHECK (state <> 'claimed' OR claim_lease_seconds IS NOT NULL)",
    )


def _apply(connection, revision):
    entry = _issued(connection)
    try:
        _check(connection, entry)
        _require(entry.prepared and entry.next_stage < len(_STAGES) and revision == _STAGES[entry.next_stage])
        _require(_versions(connection) == _cut(entry.graph, revision, final=False))
        statements = (_retained_ddl, _checkpoint_ddl, _lease_ddl)[entry.next_stage]()
        entry.next_stage += 1  # A partial failure cannot be retried on this root.
        for statement in statements:
            connection.execute(sa.text(statement))
        _check(connection, entry)
    except BaseException:
        if type(entry) is _Entry:
            entry.poisoned = True
        raise


_FUNCTIONS = (
    ("app_current_tenant_id", ""),
    ("lab_console_activity_stamp", ""),
    ("activate_eligible_facilitator_nominations", "uuid, uuid, uuid, uuid, integer, uuid"),
)


def _retained_security(connection):
    # Capture EVERY direct grantee, not a runtime-role filter which hides grants.
    actual = tokens._tuples(
        connection,
        "SELECT c.relname,pg_catalog.pg_get_userbyid(a.grantor),"
        "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,"
        "a.privilege_type,a.is_grantable FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a "
        "WHERE n.nspname='public' AND c.relname=ANY(:names) ORDER BY 1,2,3,4,5",
        names=list(_PRODUCT_TABLES),
    )
    expected = tuple(
        sorted(
            (table, "app_admin", role, privilege, False)
            for table in _PRODUCT_TABLES
            for role in schema._ROLES
            for privilege in _product_privileges(table, role)
        )
    )
    _require(actual == expected)
    column_acl = tokens._tuples(
        connection,
        "SELECT c.relname,col.attname,pg_catalog.pg_get_userbyid(a.grantor),"
        "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,"
        "a.privilege_type,a.is_grantable FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_catalog.pg_attribute col ON col.attrelid=c.oid AND col.attnum>0 AND NOT col.attisdropped "
        "CROSS JOIN LATERAL pg_catalog.aclexplode(col.attacl) a "
        "WHERE n.nspname='public' AND c.relname=ANY(:names) ORDER BY 1,2,3,4,5,6",
        names=list(_PRODUCT_TABLES),
    )
    _require(
        column_acl
        == tuple(
            sorted(
                (
                    *(
                        (table, column, "app_admin", "app_user", "INSERT", False)
                        for table, columns in (
                            *schema._REQUEST_COLUMNS,
                            ("lab_console_activity", ("instance_id", "tenant_id", "last_seen_at")),
                        )
                        for column in columns
                    ),
                    ("lab_console_activity", "last_seen_at", "app_admin", "app_user", "UPDATE", False),
                )
            )
        )
    )
    # ACL equality alone misses implicit privilege through predefined roles.
    _authority(connection)
    _function_security(connection)


def _product_privileges(table, role):
    if role not in schema._ROLES:
        return ()
    if table in schema._NAMES:
        return schema._table_privileges(table, role)
    if role == "app_admin":
        return schema._PRIVILEGES
    if table == "lab_console_activity":
        return ("SELECT",) if role == "app_user" else ()
    if table == "academy_erp_completion_checkpoints" or role == "academy_lab_worker":
        return ()
    return ("SELECT", "INSERT", "UPDATE", "DELETE")


def _function_security(connection):
    for name, args in _FUNCTIONS:
        signature = f"public.{name}({args})"
        activation = name == "activate_eligible_facilitator_nominations"
        expected_roles = (
            ("app_admin", "app_user", "platform_api", "academy_lab_worker")
            if activation
            else (
                "PUBLIC",
                "app_admin",
            )
        )
        if name == "app_current_tenant_id":
            # Kernel 0001 _grant_roles adds these explicit ACL entries even
            # though the function also retains PostgreSQL's PUBLIC default.
            expected_roles = ("PUBLIC", "app_admin", "app_user", "platform_api")
        rows = tokens._tuples(
            connection,
            "SELECT pg_catalog.pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' "
            "ELSE pg_catalog.pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable "
            "FROM pg_catalog.pg_proc p CROSS JOIN LATERAL "
            "pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a "
            "WHERE p.oid=pg_catalog.to_regprocedure(:signature) ORDER BY 1,2,3,4",
            signature=signature,
        )
        _require(rows == tuple(sorted(("app_admin", role, "EXECUTE", False) for role in expected_roles)))
        attrs = tokens._tuples(
            connection,
            "SELECT pg_catalog.pg_get_userbyid(p.proowner),p.prosecdef,p.proconfig "
            "FROM pg_catalog.pg_proc p WHERE p.oid=pg_catalog.to_regprocedure(:signature)",
            signature=signature,
        )
        config = None if name == "app_current_tenant_id" else ("search_path=pg_catalog",)
        _require(attrs == (("app_admin", activation, config),))


def _catalog_packet(connection):
    """Read-only, names-based catalog digest; never fetch application row data.

    Dropped attribute slots and internal RI trigger OID-derived names are omitted
    only here. Structural RI enforcement is included; historical admission still
    uses its unchanged strict attnum and RI-trigger checks. The caller must run
    historical/fresh comparison in the same declared PostgreSQL rendering context.
    """
    identity._connection_preflight(connection)
    _owner_contracts()
    _function_census(connection, final=True)
    params = {"names": list(_PRODUCT_TABLES), "roles": list(_ROLES)}
    base = " FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
    scope = " WHERE n.nspname='public' AND c.relname=ANY(:names) "
    queries = {
        "relations": "SELECT n.nspname,c.relname,c.relkind,pg_catalog.pg_get_userbyid(c.relowner),"
        "c.relrowsecurity,c.relforcerowsecurity,c.relpersistence,c.relispartition,c.reloptions"
        + base
        + scope
        + "ORDER BY 1,2",
        "columns": "SELECT c.relname,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,"
        "pg_catalog.pg_get_expr(d.adbin,d.adrelid),cn.nspname,co.collname,a.attidentity,a.attgenerated"
        + base
        + "JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped "
        "LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum "
        "LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation "
        "LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace" + scope + "ORDER BY 1,2",
        "constraints": "SELECT c.relname,k.conname,k.contype,pg_catalog.pg_get_constraintdef(k.oid,false),"
        "k.convalidated,k.condeferrable,k.condeferred,k.connoinherit,pn.nspname,p.relname"
        + base
        + "JOIN pg_catalog.pg_constraint k ON k.conrelid=c.oid "
        "LEFT JOIN pg_catalog.pg_class p ON p.oid=k.confrelid "
        "LEFT JOIN pg_catalog.pg_namespace pn ON pn.oid=p.relnamespace" + scope + "ORDER BY 1,2",
        "indexes": "SELECT c.relname,ic.relname,pg_catalog.pg_get_indexdef(i.indexrelid),i.indisunique,"
        "i.indisprimary,i.indisvalid,i.indisready,i.indislive,i.indnullsnotdistinct,ic.reloptions"
        + base
        + "JOIN pg_catalog.pg_index i ON i.indrelid=c.oid JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid"
        + scope
        + "ORDER BY 1,2",
        "policies": "SELECT c.relname,p.polname,p.polcmd,p.polpermissive,"
        "ARRAY(SELECT CASE WHEN x=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(x) END "
        "FROM unnest(p.polroles) x ORDER BY 1),pg_catalog.pg_get_expr(p.polqual,p.polrelid),"
        "pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid)"
        + base
        + "JOIN pg_catalog.pg_policy p ON p.polrelid=c.oid"
        + scope
        + "ORDER BY 1,2",
        "triggers": "SELECT c.relname,t.tgname,pg_catalog.pg_get_triggerdef(t.oid,false),t.tgenabled,"
        "fn.nspname,f.proname,pg_catalog.pg_get_function_identity_arguments(f.oid)"
        + base
        + "JOIN pg_catalog.pg_trigger t ON t.tgrelid=c.oid AND NOT t.tgisinternal "
        "JOIN pg_catalog.pg_proc f ON f.oid=t.tgfoid JOIN pg_catalog.pg_namespace fn ON fn.oid=f.pronamespace"
        + scope
        + "ORDER BY 1,2",
        "ri_triggers": "SELECT tn.nspname,tr.relname,kn.nspname,k.conname,"
        "cn.nspname,ch.relname,pn.nspname,pa.relname,"
        "t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,t.tgisinternal,"
        "fn.nspname,f.proname,pg_catalog.pg_get_function_identity_arguments(f.oid),"
        "t.tgnargs,pg_catalog.encode(t.tgargs,'hex'),pg_catalog.pg_get_expr(t.tgqual,t.tgrelid),"
        "t.tgoldtable,t.tgnewtable FROM pg_catalog.pg_trigger t "
        "JOIN pg_catalog.pg_constraint k ON k.oid=t.tgconstraint AND k.contype='f' "
        "JOIN pg_catalog.pg_namespace kn ON kn.oid=k.connamespace "
        "JOIN pg_catalog.pg_class tr ON tr.oid=t.tgrelid "
        "JOIN pg_catalog.pg_namespace tn ON tn.oid=tr.relnamespace "
        "JOIN pg_catalog.pg_class ch ON ch.oid=k.conrelid "
        "JOIN pg_catalog.pg_namespace cn ON cn.oid=ch.relnamespace "
        "JOIN pg_catalog.pg_class pa ON pa.oid=k.confrelid "
        "JOIN pg_catalog.pg_namespace pn ON pn.oid=pa.relnamespace "
        "JOIN pg_catalog.pg_proc f ON f.oid=t.tgfoid "
        "JOIN pg_catalog.pg_namespace fn ON fn.oid=f.pronamespace "
        "WHERE (cn.nspname='public' AND ch.relname=ANY(:names)) "
        "OR (pn.nspname='public' AND pa.relname=ANY(:names)) "
        "ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21",
        "rules": "SELECT c.relname,r.rulename,pg_catalog.pg_get_ruledef(r.oid,false),r.ev_enabled"
        + base
        + "JOIN pg_catalog.pg_rewrite r ON r.ev_class=c.oid"
        + scope
        + "ORDER BY 1,2",
        "table_acl": "SELECT c.relname,pg_catalog.pg_get_userbyid(a.grantor),"
        "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,"
        "a.privilege_type,a.is_grantable"
        + base
        + "CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a"
        + scope
        + "ORDER BY 1,2,3,4,5",
        "column_acl": "SELECT c.relname,col.attname,pg_catalog.pg_get_userbyid(a.grantor),"
        "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,"
        "a.privilege_type,a.is_grantable"
        + base
        + "JOIN pg_catalog.pg_attribute col ON col.attrelid=c.oid AND col.attnum>0 AND NOT col.attisdropped "
        "CROSS JOIN LATERAL pg_catalog.aclexplode(col.attacl) a" + scope + "ORDER BY 1,2,3,4,5,6",
        "effective_tables": "SELECT c.relname,r,p,pg_catalog.has_table_privilege(r,c.oid,p)"
        + base
        + "CROSS JOIN unnest(CAST(:roles AS text[])) r CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE',"
        "'DELETE','TRUNCATE','REFERENCES','TRIGGER']) p" + scope + "ORDER BY 1,2,3",
        "effective_columns": "SELECT c.relname,a.attname,r,p,pg_catalog.has_column_privilege(r,c.oid,a.attnum,p)"
        + base
        + "JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped "
        "CROSS JOIN unnest(CAST(:roles AS text[])) r "
        "CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) p" + scope + "ORDER BY 1,2,3,4",
        "schemas": "SELECT n.nspname,pg_catalog.pg_get_userbyid(n.nspowner),pg_catalog.pg_get_userbyid(a.grantor),"
        "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,"
        "a.privilege_type,a.is_grantable "
        "FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL "
        "pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a "
        "WHERE n.nspname IN ('public','mod_learning') ORDER BY 1,2,3,4,5,6",
        "roles": "SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls "
        "FROM pg_catalog.pg_roles WHERE rolname=ANY(:roles) ORDER BY 1",
        "memberships": "SELECT a.rolname,b.rolname,m.admin_option,m.inherit_option,m.set_option "
        "FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles a ON a.oid=m.member "
        "JOIN pg_catalog.pg_roles b ON b.oid=m.roleid "
        "WHERE a.rolname=ANY(:roles) OR b.rolname=ANY(:roles) ORDER BY 1,2",
        "default_acl": "SELECT pg_catalog.pg_get_userbyid(d.defaclrole),n.nspname,d.defaclobjtype,"
        "pg_catalog.pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' "
        "ELSE pg_catalog.pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable "
        "FROM pg_catalog.pg_default_acl d LEFT JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace "
        "CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a "
        "WHERE d.defaclnamespace=0 OR n.nspname IN ('public','mod_learning') ORDER BY 1,2,3,4,5,6,7",
    }
    packet = {key: tokens._tuples(connection, sql, **params) for key, sql in queries.items()}
    _require({r[1] for r in packet["relations"]} == set(_PRODUCT_TABLES))
    functions = []
    for name, args in _FUNCTIONS:
        rows = tokens._tuples(
            connection,
            "SELECT p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid),"
            "pg_catalog.pg_get_function_result(p.oid),p.prosecdef,p.proconfig,pg_catalog.pg_get_userbyid(p.proowner),"
            "p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,l.lanname,"
            "pg_catalog.pg_get_expr(p.proargdefaults,0),p.proargnames,p.proargmodes,p.prosrc "
            "FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_language l ON l.oid=p.prolang "
            "WHERE n.nspname='public' AND p.oid=pg_catalog.to_regprocedure(:signature)",
            signature=f"public.{name}({args})",
        )
        _require(len(rows) == 1)
        functions.append((*rows[0][:-1], hashlib.sha256(rows[0][-1].encode()).hexdigest()))
        packet["function_acl:" + name] = tokens._tuples(
            connection,
            "SELECT pg_catalog.pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' "
            "ELSE pg_catalog.pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable "
            "FROM pg_catalog.pg_proc p CROSS JOIN LATERAL "
            "pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a "
            "WHERE p.oid=pg_catalog.to_regprocedure(:signature) ORDER BY 1,2,3,4",
            signature=f"public.{name}({args})",
        )
    packet["functions"] = tuple(functions)
    return packet


def catalog_fingerprint(connection):
    """Read-only canonical product catalog digest, without application rows."""
    packet = _catalog_packet(connection)
    return hashlib.sha256(json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def catalog_object_digests(connection):
    """Names and hashes only for hosted convergence diagnostics."""
    packet = _catalog_packet(connection)
    objects: dict[str, list] = {}
    for category, rows in packet.items():
        if not rows:
            objects[category] = []
        for row in rows:
            name = row[1] if category == "relations" else row[0]
            objects.setdefault(category + ":" + str(name), []).append(row)
    return {
        name: hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()
        for name, rows in objects.items()
    }


def _qualified_pin():
    if type(FRESH_CANONICAL_SHA256) is not str or re.fullmatch(r"[0-9a-f]{64}", FRESH_CANONICAL_SHA256) is None:
        raise FreshProductUnqualified(
            "Academy fresh product convergence pin unavailable; hosted qualification required"
        )
    return FRESH_CANONICAL_SHA256


def _final_evidence(connection, graph):
    _require(_versions(connection) == _terminal_versions(graph))
    _census(connection, final=True)
    _empty(connection, final=True)
    _retained_security(connection)
    return FreshProductDiscovery(_versions(connection), catalog_fingerprint(connection))


def fresh_product_receipt(connection, entry):
    """Strict final verification; release the commit fence only after pin match."""
    try:
        _check(connection, entry)
        _require(entry.prepared and entry.next_stage == len(_STAGES))
        pin = _qualified_pin()
        evidence = _final_evidence(connection, entry.graph)
        _require(evidence.catalog_sha256 == pin)
        _check(connection, entry)
        entry.completed = True
        sa.event.remove(connection, "commit", entry.commit_guard)
        for name, guard in entry.drift_guards:
            sa.event.remove(connection, name, guard)
        return FreshProductReceipt(evidence.revisions, evidence.catalog_sha256)
    except BaseException:
        if type(entry) is _Entry:
            entry.poisoned = True
        raise


def verify_fresh_composed_db(connection):
    """Read-only strict verification of the committed disposable empty database."""
    pin = _qualified_pin()
    root = identity._connection_preflight(connection)
    _require(_issued(connection) is None and connection.info.get(product._STATE_KEY) is None)
    _require(tokens._issued(connection) is None)
    evidence = _final_evidence(connection, _graph())
    _require(evidence.catalog_sha256 == pin and identity._connection_preflight(connection) is root)
    return FreshProductReceipt(evidence.revisions, evidence.catalog_sha256)


def _run(connection, *, decision_ref, discovery):
    if not discovery:
        _qualified_pin()  # Refuse before any DDL when independently unqualified.
    entry = _start(connection)
    try:
        _require(type(decision_ref) is str and bool(decision_ref.strip()))
        entry.graph = _graph()
        cfg = ordinary_migration_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, _A002)
        token_entry = tokens.prepare_fresh_account_token_identity(connection, decision_ref=decision_ref)
        command.upgrade(cfg, _A003)
        # The real owner is invoked here; no caller-supplied receipt can bind.
        receipt = tokens.account_token_identity_receipt(connection, token_entry)
        _require(token_entry.connection is connection and token_entry.root is entry.root and not token_entry.historical)
        entry.token_receipt = receipt
        entry.token_catalog = tokens._catalog(connection)
        _check(connection, entry)
        command.upgrade(cfg, "learning@head")
        prepare_fresh_product(connection, decision_ref=decision_ref, token_receipt=receipt)
        command.upgrade(cfg, "heads")
        _check(connection, entry)
        if discovery:
            _require(entry.prepared and entry.next_stage == len(_STAGES))
            evidence = _final_evidence(connection, entry.graph)
            _check(connection, entry)
            entry.completed = True
            # Keep the commit fence: discovery must finish with root rollback.
            return evidence
        return fresh_product_receipt(connection, entry)
    except BaseException:
        entry.poisoned = True
        raise


def run_fresh_composed_entry(connection, *, decision_ref):
    """Build only the independently pinned empty composed schema on one root."""
    return _run(connection, decision_ref=decision_ref, discovery=False)


def rehearse_fresh_composed_entry(connection, *, decision_ref):
    """Unqualified H/F discovery only; caller must roll back and discard target."""
    return _run(connection, decision_ref=decision_ref, discovery=True)

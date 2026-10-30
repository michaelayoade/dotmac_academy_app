"""Source-only, single-root authority for the recorded a003 token migration.

Call capture BEFORE the unchanged eight-relation relocation. The existing
Academy importer records its exact issued receipt here only after all copies.
Only server-produced full-row conservation fingerprints leave PostgreSQL;
no raw stored token hash or serialized row is fetched, logged, or copied. A writer
fence remains the caller's operational responsibility; locks last to root end.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import sqlalchemy as sa
from dotmac_kernel.migrations.identity_history import (
    IdentityHistoryImportReceiptV1,
    IdentityHistoryImportRefused,
    IdentityHistoryManifestV1,
)
from sqlalchemy.engine import Connection

_FAMILIES = (
    "tenants",
    "tenant_domains",
    "people",
    "user_credentials",
    "auth_sessions",
    "roles",
    "person_roles",
    "audit_events",
)
# Connection-owned state avoids keeping completed connections alive globally.
# The key is a private exact object, never a caller string capability.
_STATE_KEY = object()


def _issued(connection: Connection):
    return connection.info.get(_STATE_KEY)


def _admit_new_entry(connection: Connection, root: object) -> None:
    previous = _issued(connection)
    if previous is not None and previous.entry.root is not root and not previous.entry.root.is_active:
        del connection.info[_STATE_KEY]
    _require(_issued(connection) is None)


def _attribute_numbers(connection: Connection, oid: int, names: tuple[str, ...]) -> tuple:
    return tuple(
        connection.scalar(
            sa.text("SELECT attnum FROM pg_attribute WHERE attrelid=:oid AND attname=:name AND NOT attisdropped"),
            {"oid": oid, "name": name},
        )
        for name in names
    )


def _require(condition: bool) -> None:
    if not condition:
        raise IdentityHistoryImportRefused("Academy account token adoption refused; root rollback required")


def _root(connection: Connection) -> object:
    # Reuse the established privileged connection/privacy/root contract.
    from app.maintenance.identity_history import _connection_preflight

    return _connection_preflight(connection)


def _oid(connection: Connection, relation: str) -> int | None:
    return connection.scalar(sa.text("SELECT to_regclass(:relation)::oid"), {"relation": relation})


def _tuples(connection: Connection, sql: str, **params: object) -> tuple:
    def freeze(value):
        return tuple(freeze(v) for v in value) if isinstance(value, (list, tuple)) else value

    return tuple(freeze(tuple(r)) for r in connection.execute(sa.text(sql), params))


def _physical_context(connection: Connection) -> tuple:
    """Same physical transaction and server serialization implementation."""
    context = _tuples(
        connection,
        "SELECT pg_catalog.txid_current()::text,pg_catalog.pg_backend_pid(),"
        "pg_catalog.current_database(),pg_catalog.current_setting('server_version_num'),"
        "pg_catalog.current_setting('server_encoding'),pg_catalog.current_setting('client_encoding'),"
        "pg_catalog.current_setting('DateStyle'),pg_catalog.current_setting('TimeZone'),"
        "pg_catalog.current_setting('extra_float_digits'),"
        "pg_catalog.pg_typeof(EXTRACT(epoch FROM CURRENT_TIMESTAMP))='pg_catalog.numeric'::regtype",
    )[0]
    # EXTRACT must be numeric (PG14+), never the lossy date_part/float API.
    # UTF8 is an explicit serialization admission contract, not a token default.
    _require(context[4] == "UTF8" and context[-1] is True)
    return context


def _row_fingerprints(connection: Connection) -> tuple:
    """Private conservation only, NEVER authentication/identity authority.

    The closed 0014 shape has nine columns. JSON arrays preserve positions,
    text escaping and SQL NULL; exact numeric epoch TEXT preserves each UTC
    timestamp microsecond, NULL and +/-Infinity without DateStyle/TimeZone.
    No timestamp/UUID is round-tripped through Python. SHA256 and convert_to
    are pg_catalog built-ins, with no pgcrypto or extension dependency.
    Only the row ID and final digest cross the DB boundary; no raw hash/row.
    """
    return _tuples(
        connection,
        "SELECT id,pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.jsonb_build_array("
        "id::text,tenant_id::text,person_id::text,kind::text,token_hash::text,"
        "EXTRACT(epoch FROM expires_at)::text,EXTRACT(epoch FROM used_at)::text,"
        "EXTRACT(epoch FROM created_at)::text,EXTRACT(epoch FROM updated_at)::text"
        ")::text,'UTF8')) FROM public.account_tokens ORDER BY id",
    )


def _conservation(connection: Connection, issued: _Issued, *, after_creation: bool = False) -> None:
    """Reprove actual privately captured state at each owner boundary."""
    try:
        _require(not issued.refused)
        _require(issued.entry.connection is connection and issued.entry.root is _root(connection))
        _require(_physical_context(connection) == issued.physical_context)
        if issued.entry.historical or after_creation:
            _require(_row_fingerprints(connection) == issued.row_fingerprints)
    except Exception:
        # Observed drift cannot be repaired/retried into authority on this root.
        issued.refused = True
        raise IdentityHistoryImportRefused("Academy token conservation refused; root rollback required") from None


@dataclass(frozen=True, slots=True, repr=False)
class _TokenCatalog:
    relation: tuple = field(repr=False)
    columns: tuple = field(repr=False)
    keys: tuple = field(repr=False)
    foreign_keys: tuple = field(repr=False)
    indexes: tuple = field(repr=False)
    policies: tuple = field(repr=False)
    policy_dependencies: tuple = field(repr=False)
    acl: tuple = field(repr=False)
    column_acl: tuple = field(repr=False)
    rules: tuple = field(repr=False)
    triggers: tuple = field(repr=False)
    ids: tuple = field(repr=False)


def _catalog(connection: Connection) -> _TokenCatalog:
    """Catalog and complete ID cohort only; NEVER fetch stored token values."""
    params = {"oid": _oid(connection, "public.account_tokens")}
    _require(params["oid"] is not None)
    q = lambda sql: _tuples(connection, sql, **params)  # noqa: E731
    return _TokenCatalog(
        relation=q(
            "SELECT oid,relkind,pg_get_userbyid(relowner),relrowsecurity,relforcerowsecurity,"
            "relhassubclass,relispartition,relpersistence,reloptions,relreplident,reltablespace "
            "FROM pg_class WHERE oid=:oid"
        )[0],
        columns=q(
            "SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,"
            "pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated,a.attcollation FROM pg_attribute a "
            "LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum "
            "WHERE a.attrelid=:oid AND a.attnum>0 ORDER BY a.attnum"
        ),
        keys=q(
            "SELECT conname,contype,conkey,convalidated,condeferrable,condeferred "
            "FROM pg_constraint WHERE conrelid=:oid AND contype<>'f' ORDER BY conname"
        ),
        foreign_keys=q(
            "SELECT conname,conkey,confrelid,confkey,confdeltype,confupdtype,confmatchtype,"
            "convalidated,condeferrable,condeferred FROM pg_constraint "
            "WHERE conrelid=:oid AND contype='f' ORDER BY conname"
        ),
        indexes=q(
            "SELECT c.oid,c.relname,i.indisunique,i.indisprimary,i.indisvalid,i.indisready,"
            "i.indislive,i.indkey::text,pg_get_expr(i.indpred,i.indrelid),"
            "pg_get_expr(i.indexprs,i.indrelid),pg_get_indexdef(c.oid),i.indnkeyatts,i.indnatts,"
            "i.indisclustered,i.indisreplident,c.reloptions,c.reltablespace,pg_get_userbyid(c.relowner),"
            "c.relacl::text FROM pg_index i "
            "JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=:oid ORDER BY c.relname"
        ),
        policies=q(
            "SELECT p.oid,p.polname,p.polcmd,p.polpermissive,p.polroles,"
            "pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid) "
            "FROM pg_policy p WHERE p.polrelid=:oid ORDER BY p.polname"
        ),
        policy_dependencies=q(
            "SELECT d.classid::regclass::text,d.refclassid::regclass::text,"
            "d.refobjid,d.refobjsubid,d.deptype FROM pg_depend d JOIN pg_policy p "
            "ON d.classid='pg_policy'::regclass AND d.objid=p.oid "
            "WHERE p.polrelid=:oid ORDER BY 1,2,3,4,5"
        ),
        acl=q(
            "SELECT pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable "
            "FROM pg_class c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a "
            "WHERE c.oid=:oid ORDER BY 1,2,3,4"
        ),
        column_acl=q(
            "SELECT attname,attacl::text FROM pg_attribute WHERE attrelid=:oid AND attacl IS NOT NULL ORDER BY attnum"
        ),
        rules=q("SELECT oid FROM pg_rewrite WHERE ev_class=:oid"),
        triggers=q("SELECT oid FROM pg_trigger WHERE tgrelid=:oid AND NOT tgisinternal"),
        ids=_tuples(connection, "SELECT id,tenant_id,person_id FROM public.account_tokens ORDER BY id"),
    )


def _legacy_shape(connection: Connection, catalog: _TokenCatalog, relations: tuple) -> None:
    """Capture-time closed 0014 contract, duplicated/frozen by recorded a003."""
    _require(catalog.relation[1:] == ("r", "app_admin", True, True, False, False, "p", None, "d", 0))
    types = (
        "uuid",
        "uuid",
        "uuid",
        "character varying(20)",
        "character varying(64)",
        "timestamp with time zone",
        "timestamp with time zone",
        "timestamp with time zone",
        "timestamp with time zone",
    )
    names = ("id", "tenant_id", "person_id", "kind", "token_hash", "expires_at", "used_at", "created_at", "updated_at")
    default_collation = connection.scalar(sa.text("SELECT 'pg_catalog.default'::regcollation::oid"))
    _require(
        catalog.columns
        == tuple(
            (
                n,
                t,
                n != "used_at",
                "now()" if n in {"created_at", "updated_at"} else None,
                "",
                "",
                default_collation if n in {"kind", "token_hash"} else 0,
            )
            for n, t in zip(names, types, strict=True)
        )
    )
    _require(
        catalog.keys
        == (
            ("account_tokens_pkey", "p", (1,), True, False, False),
            ("uq_account_tokens_tenant_id_id", "u", (2, 1), True, False, False),
            ("uq_account_tokens_tenant_token_hash", "u", (2, 5), True, False, False),
        )
    )
    targets = dict(relations)
    _require(
        catalog.foreign_keys
        == (
            (
                "account_tokens_tenant_id_fkey",
                (2,),
                targets["tenants"],
                _attribute_numbers(connection, targets["tenants"], ("id",)),
                "c",
                "a",
                "s",
                True,
                False,
                False,
            ),
            (
                "fk_account_tokens_tenant_person",
                (2, 3),
                targets["people"],
                _attribute_numbers(connection, targets["people"], ("tenant_id", "id")),
                "c",
                "a",
                "s",
                True,
                False,
                False,
            ),
        )
    )
    _require(not catalog.column_acl and not catalog.rules and not catalog.triggers)
    _require(
        connection.scalar(
            sa.text(
                "SELECT count(*)=:count AND bool_and(t.tgenabled='O' AND c.contype='f' "
                "AND c.conrelid=t.tgrelid) FROM pg_trigger t LEFT JOIN pg_constraint c ON c.oid=t.tgconstraint "
                "WHERE t.tgrelid=:oid AND t.tgisinternal"
            ),
            {"oid": catalog.relation[0], "count": 4},
        )
        is True
    )

    indexes = {
        "account_tokens_pkey": (True, True, "1"),
        "uq_account_tokens_tenant_id_id": (True, False, "2 1"),
        "uq_account_tokens_tenant_token_hash": (True, False, "2 5"),
        "ix_account_tokens_tenant_id": (False, False, "2"),
        "ix_account_tokens_person_id": (False, False, "3"),
        "ix_account_tokens_token_hash": (False, False, "5"),
    }
    _require(len(catalog.indexes) == len(indexes))
    for index in catalog.indexes:
        (
            _,
            name,
            unique,
            primary,
            valid,
            ready,
            live,
            keys,
            pred,
            expr,
            definition,
            nkeys,
            natts,
            clustered,
            replica,
            options,
            tablespace,
            owner,
            acl,
        ) = index
        _require(nkeys == natts == len(keys.split()) and not clustered and not replica)
        _require(options is None and tablespace == 0 and owner == "app_admin" and acl is None)
        _require(name in indexes and (unique, primary, keys) == indexes[name])
        columns = {
            "1": "id",
            "2": "tenant_id",
            "3": "person_id",
            "5": "token_hash",
            "2 1": "tenant_id, id",
            "2 5": "tenant_id, token_hash",
        }[keys]
        _require(
            definition == f"CREATE {'UNIQUE ' if unique else ''}INDEX {name} "
            f"ON public.account_tokens USING btree ({columns})"
        )
        _require(valid and ready and live and pred is None and expr is None)
    _require(
        _tuples(
            connection,
            "SELECT rolname,rolsuper,rolbypassrls FROM pg_roles "
            "WHERE rolname IN ('app_user','platform_api') ORDER BY rolname",
        )
        == (("app_user", False, False), ("platform_api", False, False))
    )
    privileges = {
        row[0]
        for row in _tuples(
            connection,
            "SELECT privilege_type FROM aclexplode(acldefault('r', "
            "(SELECT oid FROM pg_roles WHERE rolname='app_admin'))) ",
        )
    }
    standard = {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
    # PostgreSQL 17+ adds owner MAINTAIN; online roles still receive CRUD only.
    _require(standard <= privileges <= standard | {"MAINTAIN"})
    expected_acl = {("app_admin", "app_admin", p, False) for p in privileges}
    expected_acl |= {
        ("app_admin", r, p, False)
        for r in ("app_user", "platform_api")
        for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
    }
    _require(set(catalog.acl) == expected_acl)
    for role in ("app_user", "platform_api"):
        for privilege in privileges:
            allowed = connection.scalar(
                sa.text("SELECT has_table_privilege(:role,'public.account_tokens',:p)"), {"role": role, "p": privilege}
            )
            _require(allowed is (privilege in {"SELECT", "INSERT", "UPDATE", "DELETE"}))
            if privilege in {"REFERENCES", "SELECT", "INSERT", "UPDATE"}:
                # Detect inherited column-only privilege escalation as well.
                _require(
                    connection.scalar(
                        sa.text("SELECT has_any_column_privilege(:role,'public.account_tokens',:p)"),
                        {"role": role, "p": privilege},
                    )
                    is (privilege != "REFERENCES")
                )
    _require(len(catalog.policies) == 1)
    _, name, command, permissive, roles, using, check = catalog.policies[0]
    _require((name, command, permissive, roles) == ("account_tokens_tenant_isolation", "*", True, (0,)))
    _require(
        using == check
        and using in {"(tenant_id = app_current_tenant_id())", "(tenant_id = public.app_current_tenant_id())"}
    )
    function_oid = connection.scalar(sa.text("SELECT 'public.app_current_tenant_id()'::regprocedure::oid"))
    _require(
        set(catalog.policy_dependencies)
        == {
            ("pg_policy", "pg_class", catalog.relation[0], 0, "a"),
            ("pg_policy", "pg_class", catalog.relation[0], 2, "n"),
            ("pg_policy", "pg_proc", function_oid, 0, "n"),
        }
    )


@dataclass(frozen=True, slots=True, repr=False)
class _TokenEntry:
    connection: Connection = field(repr=False)
    root: object = field(repr=False)
    historical: bool
    catalog: _TokenCatalog | None = field(repr=False)
    relations: tuple = field(repr=False)


@dataclass(slots=True, repr=False)
class _Issued:
    entry: _TokenEntry
    physical_context: tuple = field(repr=False)
    row_fingerprints: tuple = field(repr=False)
    imported: tuple | None = None
    ready: bool = False
    consumed: bool = False
    refused: bool = False
    final: _TokenCatalog | None = None


def capture_historical_account_tokens(connection: Connection) -> _TokenEntry:
    """Lock/capture complete 0014 public relation BEFORE any relocation."""
    try:
        root = _root(connection)
        _admit_new_entry(connection, root)
        _require(_oid(connection, "public.account_tokens") is not None)
        connection.execute(sa.text("LOCK TABLE public.account_tokens IN ACCESS EXCLUSIVE MODE"))
        relations = tuple((name, _oid(connection, "public." + name)) for name in _FAMILIES)
        _require(all(oid is not None for _, oid in relations))
        _require(all(_oid(connection, "academy_identity_compat." + n) is None for n in _FAMILIES))
        catalog = _catalog(connection)
        _legacy_shape(connection, catalog, relations)
        entry = _TokenEntry(connection, root, True, catalog, relations)
        connection.info[_STATE_KEY] = _Issued(entry, _physical_context(connection), _row_fingerprints(connection))
        return entry
    except Exception:
        raise IdentityHistoryImportRefused("Academy token capture refused; root rollback required") from None


def _record_identity_import(
    connection: Connection, expected: IdentityHistoryManifestV1, receipt: IdentityHistoryImportReceiptV1
) -> None:
    """Called ONLY by the existing importer after its successful full copy."""
    issued = _issued(connection)
    if issued is None:
        return  # Existing importer remains usable without token adoption.
    _require(issued.entry.historical and issued.entry.root is _root(connection))
    _require(issued.imported is None and not issued.consumed)
    _require(type(receipt) is IdentityHistoryImportReceiptV1)
    _require(tuple((n, getattr(expected.relations, n)) for n in _FAMILIES) == issued.entry.relations)
    _require(all(_oid(connection, "academy_identity_compat." + n) == oid for n, oid in issued.entry.relations))
    _require(all(t in expected.cohort.tenants and p in expected.cohort.people for _, t, p in issued.entry.catalog.ids))
    _conservation(connection, issued)
    issued.imported = (expected, receipt)


def authorize_historical_account_token_adoption(
    connection: Connection, entry: _TokenEntry, receipt: IdentityHistoryImportReceiptV1
) -> None:
    """Bind the EXACT capture and actual import receipt, never caller claims."""
    issued = _issued(connection)
    _require(issued is not None and issued.entry is entry and entry.connection is connection)
    _require(entry.root is _root(connection) and not issued.ready and not issued.consumed)
    _require(issued.imported is not None and issued.imported[1] is receipt)
    _conservation(connection, issued)
    issued.ready = True


def prepare_fresh_account_token_identity(connection: Connection, *, decision_ref: str) -> _TokenEntry:
    """Explicit reviewed FRESH entry only; absence is checked again by a003.

    A review reference is traceability, not historical import authority. Fresh
    admission requires live absence of tokens AND all compatibility relations.
    """
    root = _root(connection)
    _require(type(decision_ref) is str and bool(decision_ref.strip()))
    _admit_new_entry(connection, root)
    _require(_oid(connection, "public.account_tokens") is None)
    _require(all(_oid(connection, "academy_identity_compat." + n) is None for n in _FAMILIES))
    entry = _TokenEntry(connection, root, False, None, ())
    connection.info[_STATE_KEY] = _Issued(entry, _physical_context(connection), (), ready=True)
    return entry


def _consume_migration_entry(connection: Connection) -> _TokenEntry:
    issued = _issued(connection)
    _require(issued is not None and issued.ready and not issued.consumed)
    _require(issued.entry.connection is connection and issued.entry.root is _root(connection))
    issued.consumed = True  # Any failed application requires complete root rollback.
    _conservation(connection, issued)
    return issued.entry


def _record_migration_catalog(connection: Connection, entry: _TokenEntry, catalog: _TokenCatalog) -> None:
    issued = _issued(connection)
    _require(issued is not None and issued.entry is entry and issued.consumed and issued.final is None)
    _require(entry.root is _root(connection))
    _conservation(connection, issued, after_creation=True)
    issued.final = catalog


@dataclass(frozen=True, slots=True)
class AccountTokenIdentityReceipt:
    identity_import_receipt: IdentityHistoryImportReceiptV1 | None
    token_relation_oid: int
    token_count: int
    applied_revision: str
    validated_canonical_foreign_keys: int


def account_token_identity_receipt(connection: Connection, entry: _TokenEntry) -> AccountTokenIdentityReceipt:
    """Post-Alembic, pre-commit material-free facts on the still-active root."""
    issued = _issued(connection)
    _require(issued is not None and issued.entry is entry and entry.root is _root(connection))
    _require(issued.consumed and issued.final is not None)
    _require(
        connection.scalar(
            sa.text(
                "SELECT EXISTS(SELECT 1 FROM public.alembic_version WHERE version_num='a003_account_token_identity')"
            )
        )
        is True
    )
    _conservation(connection, issued, after_creation=True)
    _require(_catalog(connection) == issued.final)
    result = AccountTokenIdentityReceipt(
        None if issued.imported is None else issued.imported[1],
        issued.final.relation[0],
        len(issued.final.ids),
        "a003_account_token_identity",
        len(issued.final.foreign_keys),
    )
    del connection.info[_STATE_KEY]
    return result

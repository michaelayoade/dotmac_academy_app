"""Trusted fixed Academy decoder and caller-root atomic extension copy.

Source only: the public importer, lossless JSONB type, composed-head handling
and Kernel's genuine new credential-key revision must travel together. Caller
rolls back on every exception, including after a successful canonical import.
Locks are not a lasting writer fence.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict, cast
from uuid import UUID

import sqlalchemy as sa
from dotmac_kernel.migrations.identity_history import (
    HistoricalAuditEventV1,
    HistoricalCredentialV1,
    HistoricalJsonbV1,
    HistoricalPersonRoleV1,
    HistoricalPersonV1,
    HistoricalRoleV1,
    HistoricalSessionV1,
    HistoricalTenantDomainV1,
    HistoricalTenantV1,
    IdentityHistoryImportOperationV1,
    IdentityHistoryImportReceiptV1,
    IdentityHistoryImportRefused,
    IdentityHistoryManifestV1,
    IdentityHistoryRowsV1,
    import_identity_history,
    verify_identity_history,
)
from dotmac_kernel.modules import ModuleRegistry
from dotmac_kernel.prerequisites import PrerequisiteBinding
from psycopg import Connection as PsycopgConnection
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Connection, RootTransaction
from sqlalchemy.sql.elements import quoted_name

from app.models.identity_extensions import (
    AcademyAccountProfile,
    AcademyCredentialPolicy,
)

_FAMILIES = (
    ("tenants", HistoricalTenantV1),
    ("tenant_domains", HistoricalTenantDomainV1),
    ("people", HistoricalPersonV1),
    ("user_credentials", HistoricalCredentialV1),
    ("auth_sessions", HistoricalSessionV1),
    ("roles", HistoricalRoleV1),
    ("person_roles", HistoricalPersonRoleV1),
    ("audit_events", HistoricalAuditEventV1),
)
_ACCOUNT = cast(sa.Table, AcademyAccountProfile.__table__)
_POLICY = cast(sa.Table, AcademyCredentialPolicy.__table__)
_TARGETS = (_ACCOUNT, _POLICY)
_ASSEMBLY_VERSIONS = Path(__file__).resolve().parents[2] / "alembic/identity_assembly_versions"


if TYPE_CHECKING:
    _HistoricalRow = (
        HistoricalTenantV1
        | HistoricalTenantDomainV1
        | HistoricalPersonV1
        | HistoricalCredentialV1
        | HistoricalSessionV1
        | HistoricalRoleV1
        | HistoricalPersonRoleV1
        | HistoricalAuditEventV1
    )

    class _DecodedIdentityRows(TypedDict):
        tenants: tuple[HistoricalTenantV1, ...]
        tenant_domains: tuple[HistoricalTenantDomainV1, ...]
        people: tuple[HistoricalPersonV1, ...]
        user_credentials: tuple[HistoricalCredentialV1, ...]
        auth_sessions: tuple[HistoricalSessionV1, ...]
        roles: tuple[HistoricalRoleV1, ...]
        person_roles: tuple[HistoricalPersonRoleV1, ...]
        audit_events: tuple[HistoricalAuditEventV1, ...]


def _require(condition: object) -> None:
    if not condition:
        raise IdentityHistoryImportRefused("Academy identity extension preflight refused")


def _time(value: object) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


@dataclass(frozen=True, slots=True, repr=False)
class _AcademyJsonbText:
    """Private lossless PostgreSQL JSONB text, never Python numeric decoding."""

    raw_json: str = field(repr=False)


def _projection_preflight(connection: Connection, table: sa.Table, values: dict[str, object]) -> None:
    _require(set(values) == set(table.c.keys()))
    for column in table.c:
        value = values[column.name]
        if isinstance(column.type, sa.JSON):
            _require(type(value) is _AcademyJsonbText and type(cast(_AcademyJsonbText, value).raw_json) is str)
            # PostgreSQL validates its own complete numeric domain; parsing via
            # Python float would round decimals or reject valid huge numerics.
            _require(
                connection.scalar(
                    sa.text("SELECT jsonb_typeof(CAST(:raw AS JSONB))"),
                    {"raw": cast(_AcademyJsonbText, value).raw_json},
                )
                is not None
            )
            continue
        _require(value is not None or column.nullable)
        if value is None:
            continue
        if isinstance(column.type, sa.String):
            _require(type(value) is str and len(value) <= cast(int, column.type.length))
        elif isinstance(column.type, sa.Uuid):
            _require(type(value) is UUID)
        elif isinstance(column.type, sa.Boolean):
            _require(type(value) is bool)
        elif isinstance(column.type, sa.BigInteger):
            _require(type(value) is int and 0 <= value < 2**63)
        elif isinstance(column.type, sa.Integer):
            _require(type(value) is int and -(2**31) <= value < 2**31)
        elif isinstance(column.type, sa.DateTime):
            _require(_time(value))


@dataclass(frozen=True, slots=True, repr=False)
class _IdentitySnapshot:
    rows: IdentityHistoryRowsV1 = field(repr=False)
    accounts: tuple = field(repr=False)
    policies: tuple = field(repr=False)
    target_oids: tuple = field(repr=False)


# Fixed canonical owner names; values are checked by the actual Kernel owner.
_CANONICAL_TARGETS = (
    "tenants",
    "tenant_domains",
    "parties",
    "party_persons",
    "user_credentials",
    "auth_sessions",
    "roles",
    "party_role_grants",
    "audit_events",
    "academy_account_profiles",
    "academy_credential_policies",
)


def _target_oids(connection):
    result = tuple(
        (name, connection.scalar(sa.text("SELECT to_regclass(:name)::oid"), {"name": "public." + name}))
        for name in _CANONICAL_TARGETS
    )
    _require(all(type(oid) is int and oid > 0 for _, oid in result))
    return result


@dataclass(slots=True, repr=False)
class AcademyIdentityHistoryDecoder:
    """Private extension projections are captured during the importer's locks.

    No caller-supplied schema, table names, SQL or decoder callbacks. Each
    decoder is single-use and bound to the supplied Connection/root identity.
    """

    _accounts: tuple[dict[str, object], ...] = field(default=(), init=False, repr=False)
    _policies: tuple[dict[str, object], ...] = field(default=(), init=False, repr=False)
    _connection: Connection | None = field(default=None, init=False, repr=False)
    _root: object = field(default=None, init=False, repr=False)
    _snapshot: _IdentitySnapshot | None = field(default=None, init=False, repr=False)

    def decode(self, connection: Connection) -> IdentityHistoryRowsV1:
        _require(self._connection is None)
        self._connection = connection
        self._root = connection.get_transaction()
        decoded: dict[str, tuple[_HistoricalRow, ...]] = {}
        accounts: list[dict[str, object]] = []
        policies: list[dict[str, object]] = []
        rows: list[_HistoricalRow] | IdentityHistoryRowsV1
        for family, row_type in _FAMILIES:
            names = tuple(item.name for item in fields(row_type))
            extra = (
                ("status", "avatar_path", "prefs")
                if family == "people"
                else ("email", "failed_login_attempts", "locked_until")
                if family == "user_credentials"
                else ()
            )
            # Both identifiers and column names derive only from reviewed fixed
            # constants/dataclass fields; no schema or SQL callback is accepted.
            source = sa.table(
                quoted_name(family, True),
                *(sa.column(quoted_name(name, True)) for name in (*names, *extra)),
                schema=quoted_name("academy_identity_compat", True),
            )
            statement = (
                sa.select(
                    *(
                        sa.cast(source.c[name], sa.Text).label(quoted_name(name, True))
                        if (family, name) in {("people", "prefs"), ("audit_events", "details")}
                        else source.c[name]
                        for name in (*names, *extra)
                    )
                )
                .select_from(source)
                .order_by(source.c.id)
            )
            rows = []
            for raw in connection.execute(statement).mappings():
                values = {name: raw[name] for name in names}
                if family == "audit_events":
                    # Source details is NOT NULL JSONB. Literal JSON null is the
                    # text "null"; no SQL NULL or Python numeric decoding enters
                    # the public canonical JSONB representation.
                    _require(type(raw["details"]) is str)
                    values["details"] = HistoricalJsonbV1(raw_json=raw["details"])
                rows.append(row_type(**values))
                if family in {"people", "user_credentials"}:
                    projection = {name: raw[name] for name in (*extra, "tenant_id", "created_at", "updated_at")}
                    projection["party_id" if family == "people" else "credential_id"] = raw["id"]
                    target = _ACCOUNT if family == "people" else _POLICY
                    if family == "people":
                        projection["prefs"] = _AcademyJsonbText(raw["prefs"])
                    else:
                        # Explicit CURRENT adoption generation, never decoded
                        # from legacy state or a historical password-change count.
                        projection["lifecycle_version"] = 0
                        # Legacy login has no lifecycle recovery restriction.
                        # This CURRENT state is not historical recovery proof.
                        projection["reset_required"] = False
                    _projection_preflight(connection, target, projection)
                    (accounts if family == "people" else policies).append(projection)
            decoded[family] = tuple(rows)
        # Original case-sensitive alias uniqueness; no normalization/collapse.
        _require(len({(r["tenant_id"], r["email"]) for r in policies}) == len(policies))
        self._accounts = tuple(accounts)
        self._policies = tuple(policies)
        rows = IdentityHistoryRowsV1(**cast("_DecodedIdentityRows", decoded))
        self._snapshot = _IdentitySnapshot(
            rows,
            tuple(tuple(values.items()) for values in accounts),
            tuple(tuple(values.items()) for values in policies),
            _target_oids(connection),
        )
        # The genuine importer registered this decoder before calling Kernel.
        # A new reader used for preservation never replaces that association.
        from app.maintenance import product_adoption as product

        product._capture_identity_decoder(connection, self)
        return rows


def _connection_preflight(connection: Connection) -> RootTransaction:
    root = connection.get_transaction()
    _require(not connection.closed and not connection.invalidated)
    _require(root is not None and root.is_active and not connection.in_nested_transaction())
    _require(connection.dialect.name == "postgresql" and connection.dialect.driver == "psycopg")
    _require(cast(PsycopgConnection, connection.connection.driver_connection).autocommit is False)
    _require(connection.engine.hide_parameters is True and connection.engine.echo is False)
    _require(not connection.engine.logger.isEnabledFor(logging.DEBUG))
    _require(connection.get_execution_options().get("isolation_level") != "AUTOCOMMIT")
    _require(connection.scalar(sa.text("SELECT current_user")) == "app_admin")
    return cast(RootTransaction, root)


def _extension_catalog_preflight(connection: Connection) -> None:
    inspector = sa.inspect(connection)
    for table in _TARGETS:
        _require(
            connection.scalar(
                sa.text(
                    "SELECT NOT EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class=to_regclass(:table) AND ev_enabled<>'D')"
                ),
                {"table": "public." + table.name},
            )
            is True
        )
        _require(
            connection.scalar(
                sa.text(
                    "SELECT NOT EXISTS(SELECT 1 FROM pg_trigger "
                    "WHERE tgrelid=to_regclass(:table) AND NOT tgisinternal AND tgenabled<>'D')"
                ),
                {"table": "public." + table.name},
            )
            is True
        )
        columns = inspector.get_columns(table.name, schema="public")
        _require({c["name"] for c in columns} == set(table.c.keys()))
        for actual in columns:
            expected = table.c[actual["name"]]
            _require(actual["nullable"] == expected.nullable and actual.get("default") is None)
            if table is _POLICY and actual["name"] in {"lifecycle_version", "reset_required"}:
                _require(actual.get("identity") is None and actual.get("computed") is None)
            _require(
                str(actual["type"].compile(dialect=connection.dialect))
                == str(expected.type.compile(dialect=connection.dialect))
            )
        _require(
            inspector.get_pk_constraint(table.name, schema="public")["constrained_columns"]
            == [next(c.name for c in table.c if c.primary_key)]
        )
        expected_fks = {
            (
                tuple(f.column_keys),
                "public",
                f.elements[0].column.table.name,
                tuple(e.column.name for e in f.elements),
                "CASCADE",
            )
            for f in table.foreign_key_constraints
        }
        actual_fks = {
            (
                tuple(f["constrained_columns"]),
                f["referred_schema"],
                f["referred_table"],
                tuple(f["referred_columns"]),
                f["options"].get("ondelete"),
            )
            for f in inspector.get_foreign_keys(table.name, schema="public", postgresql_ignore_search_path=True)
        }
        _require(actual_fks == expected_fks)
        checks = inspector.get_check_constraints(table.name, schema="public")
        if table is _POLICY:
            _require(len(checks) == 1)
            check = checks[0]
            _require(check["name"] == "ck_academy_policy_lifecycle_version")
            normalized_check = re.sub(r'[\s()"]', "", check["sqltext"]).lower()
            _require(normalized_check in {"lifecycle_version>=0", "lifecycle_version>=0::bigint"})
            _require(
                connection.scalar(
                    sa.text(
                        "SELECT convalidated FROM pg_constraint WHERE conrelid=to_regclass(:table) "
                        "AND contype='c' AND conname='ck_academy_policy_lifecycle_version'"
                    ),
                    {"table": "public." + table.name},
                )
                is True
            )
        else:
            _require(not checks)
        _require(
            connection.scalar(
                sa.text(
                    "SELECT bool_and(convalidated AND NOT condeferrable) "
                    "FROM pg_constraint WHERE conrelid=to_regclass(:table) AND contype='f'"
                ),
                {"table": "public." + table.name},
            )
            is True
        )
        uniques = {tuple(u["column_names"]) for u in inspector.get_unique_constraints(table.name, schema="public")}
        _require(uniques == ({("tenant_id", "email")} if table is _POLICY else set()))
        # Extra unique indexes can reject admitted aliases despite unchanged
        # constraint names; partial uniqueness cannot replace a real key.
        full_unique = set(
            connection.scalars(
                sa.text(
                    "SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid "
                    "WHERE i.indrelid=to_regclass(:table) AND i.indisunique AND i.indisvalid "
                    "AND i.indisready AND i.indislive AND i.indpred IS NULL AND i.indexprs IS NULL"
                ),
                {"table": "public." + table.name},
            )
        )
        actual_indexes = inspector.get_indexes(table.name, schema="public")
        indexed_unique = set()
        for index in actual_indexes:
            if index.get("unique"):
                _require(index["name"] in full_unique)
                indexed_unique.add(tuple(index["column_names"]))
        _require(indexed_unique == uniques)
        posture = connection.execute(
            sa.text(
                "SELECT pg_get_userbyid(relowner), relrowsecurity, relforcerowsecurity "
                "FROM pg_class WHERE oid=to_regclass(:table)"
            ),
            {"table": "public." + table.name},
        ).one()
        _require(tuple(posture) == ("app_admin", True, True))
        _require(
            connection.scalar(
                sa.text(
                    "SELECT NOT EXISTS(SELECT 1 FROM pg_class c, "
                    "LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a "
                    "WHERE c.oid=to_regclass(:table) AND a.grantee=0)"
                ),
                {"table": "public." + table.name},
            )
            is True
        )
        policies = connection.execute(
            sa.text(
                "SELECT cmd,roles,permissive,qual,with_check FROM pg_policies "
                "WHERE schemaname='public' AND tablename=:table"
            ),
            {"table": table.name},
        ).all()
        _require(len(policies) == 1)
        cmd, roles, permissive, using, check = policies[0]
        _require(cmd == "ALL" and list(roles) == ["public"] and permissive == "PERMISSIVE")
        for expression in (using, check):
            normalized = re.sub(r'[\s()"]', "", expression or "").replace("public.", "").lower()
            _require(normalized == "tenant_id=app_current_tenant_id")
        for role in ("app_user", "platform_api"):
            for privilege in (
                "SELECT",
                "INSERT",
                "UPDATE",
                "DELETE",
                "TRUNCATE",
                "REFERENCES",
                "TRIGGER",
            ):
                params = {
                    "role": role,
                    "table": "public." + table.name,
                    "privilege": privilege,
                }
                allowed = privilege in {"SELECT", "INSERT", "UPDATE", "DELETE"}
                _require(
                    connection.scalar(
                        sa.text(
                            "SELECT has_table_privilege(CAST(:role AS name),CAST(:table AS text),CAST(:privilege "
                            "AS text))"
                        ),
                        params,
                    )
                    is allowed
                )
                if privilege == "REFERENCES":
                    _require(
                        connection.scalar(
                            sa.text(
                                "SELECT has_any_column_privilege(CAST(:role AS name),CAST(:table AS "
                                "text),CAST(:privilege AS text))"
                            ),
                            params,
                        )
                        is False
                    )


def _extension_targets_preflight(connection: Connection) -> None:
    _extension_catalog_preflight(connection)
    for table in _TARGETS:
        _require(connection.scalar(sa.select(sa.func.count()).select_from(table)) == 0)


def _verify_identity_import_data(
    connection,
    decoder,
    expected,
    operation,
    receipt,
    *,
    module_registry=None,
    module_versions=None,
    prerequisite_bindings=(),
):
    """Compare ORIGINAL decoder expectations; never issue product authority."""
    _require(type(decoder) is AcademyIdentityHistoryDecoder)
    root = _connection_preflight(connection)
    _require(decoder._connection is connection and decoder._root is root)
    captured = decoder._snapshot
    _require(type(captured) is _IdentitySnapshot and captured.target_oids == _target_oids(connection))
    reread = AcademyIdentityHistoryDecoder()
    reread.decode(connection)
    _require(reread._snapshot == captured)
    verify_identity_history(
        connection,
        captured.rows,
        expected,
        operation,
        receipt,
        assembly_versions=_ASSEMBLY_VERSIONS,
        module_registry=module_registry,
        module_versions=module_versions,
        prerequisite_bindings=prerequisite_bindings,
    )
    _extension_catalog_preflight(connection)
    for table, records in ((_ACCOUNT, captured.accounts), (_POLICY, captured.policies)):
        key = next(iter(table.primary_key.columns))
        expected_ids = set()
        for record in records:
            values = dict(record)
            _projection_preflight(connection, table, values)
            _require(values[key.name] not in expected_ids)
            expected_ids.add(values[key.name])
            predicates = []
            for column in table.c:
                value = values[column.name]
                if isinstance(column.type, sa.JSON):
                    expected_json = sa.cast(
                        sa.bindparam(None, cast(_AcademyJsonbText, value).raw_json, type_=sa.Text), JSONB
                    )
                    predicate = sa.cast(column, sa.Text).is_not_distinct_from(sa.cast(expected_json, sa.Text))
                else:
                    predicate = column.is_not_distinct_from(sa.bindparam(None, value, type_=column.type))
                predicates.append(predicate)
            _require(connection.scalar(sa.select(sa.func.count()).select_from(table).where(*predicates)) == 1)
        actual_ids = tuple(connection.scalars(sa.select(key)))
        _require(len(actual_ids) == len(expected_ids) and set(actual_ids) == expected_ids)
    _require(captured.target_oids == _target_oids(connection))
    _require(_connection_preflight(connection) is root)


def import_academy_identity_history(
    connection: Connection,
    expected: IdentityHistoryManifestV1,
    operation: IdentityHistoryImportOperationV1,
    *,
    module_registry: ModuleRegistry | None = None,
    module_versions: Mapping[str, Path] | None = None,
    prerequisite_bindings: tuple[PrerequisiteBinding, ...] = (),
) -> IdentityHistoryImportReceiptV1:
    """Copy canonical identity ONCE, then all Academy policy on the SAME root.

    No transaction, savepoint, engine, Session, commit or rollback is created.
    Errors suppress driver diagnostics; caller MUST roll back the entire root.
    These optional source inputs must come from the SAME reviewed composition
    as env.py. Genuine installed Learning/audit-prerequisite caller wiring is
    pending adoption work; this function neither invents nor installs it.
    """
    try:
        root = _connection_preflight(connection)
        _require(expected.relations.schema == "academy_identity_compat")
        connection.execute(
            sa.text(
                "LOCK TABLE public.academy_account_profiles, public.academy_credential_policies IN "
                "ACCESS EXCLUSIVE MODE"
            )
        )
        _extension_targets_preflight(connection)
        decoder = AcademyIdentityHistoryDecoder()
        from app.maintenance import product_adoption as product

        product._register_identity_import(
            connection,
            decoder,
            expected,
            operation,
            module_registry=module_registry,
            module_versions=module_versions,
            prerequisite_bindings=prerequisite_bindings,
        )
        receipt = import_identity_history(
            connection,
            decoder,
            expected,
            operation,
            assembly_versions=_ASSEMBLY_VERSIONS,
            module_registry=module_registry,
            module_versions=module_versions,
            prerequisite_bindings=prerequisite_bindings,
        )
        _require(decoder._connection is connection and decoder._root is root)
        _require(connection.get_transaction() is root and root.is_active)
        _require({r["party_id"] for r in decoder._accounts} == expected.cohort.people)
        _require({r["credential_id"] for r in decoder._policies} == expected.cohort.user_credentials)
        for table, rows in (
            (_ACCOUNT, decoder._accounts),
            (_POLICY, decoder._policies),
        ):
            for values in rows:
                if table is _ACCOUNT:
                    # Only our private decoder projection can reach this fixed
                    # bound TEXT->JSONB expression; no supplied SQL is executed.
                    prefs = values["prefs"]
                    _require(type(prefs) is _AcademyJsonbText)
                    insert_values = {
                        **values,
                        "prefs": sa.cast(sa.bindparam("_academy_prefs_raw", type_=sa.Text), JSONB),
                    }
                    connection.execute(
                        sa.insert(table).values(**insert_values),
                        {"_academy_prefs_raw": cast(_AcademyJsonbText, prefs).raw_json},
                    )
                else:
                    connection.execute(sa.insert(table).values(**values))
        _require(connection.get_transaction() is root and root.is_active)
        from app.maintenance.account_token_identity import _record_identity_import

        _verify_identity_import_data(
            connection,
            decoder,
            expected,
            operation,
            receipt,
            module_registry=module_registry,
            module_versions=module_versions,
            prerequisite_bindings=prerequisite_bindings,
        )
        product._complete_identity_import(connection, decoder, receipt)
        _record_identity_import(connection, expected, receipt)
        return receipt
    except BaseException as error:
        from app.maintenance import product_adoption as product

        product._poison(connection, None)
        if not isinstance(error, Exception):
            raise
        location = product._maintenance_refusal_locations(error)
        raise IdentityHistoryImportRefused(
            f"Academy identity history import refused; caller rollback required [maintenance {location}]"
        ) from None

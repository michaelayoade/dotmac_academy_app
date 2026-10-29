"""Private retained-row observations; no admission, registry, DDL or writer.

Frozen62 schema/security and hosted environment qualification must succeed
before capture with a genuine live hosted resource context.
Only product_adoption may retain the exact fragment under its private State.
"""

from __future__ import annotations

from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy.engine import Connection, RootTransaction
from sqlalchemy.exc import SQLAlchemyError

from app.maintenance import retained_environment as environment
from app.maintenance import retained_schema as retained


class RetainedHistoryRefused(retained.RetainedSchemaRefused):
    """Conservation observation contradicted; sole owner must roll back root."""


def _require(condition: bool) -> None:
    if not condition:
        raise RetainedHistoryRefused("Historical retained conservation refused; root rollback required")


# Literal source specification derived from reviewed frozen62 retained._COLUMNS.
# Not an observation-derived baseline or caller-selectable namespace/type map.
_ROW_SPEC = (
    (
        "applicants",
        "id",
        (
            ("id", "uuid"),
            ("tenant_id", "uuid"),
            ("email", "character varying(254)"),
            ("first_name", "character varying(80)"),
            ("last_name", "character varying(80)"),
            ("phone", "character varying(40)"),
            ("program", "character varying(120)"),
            ("status", "character varying(20)"),
            ("source", "character varying(30)"),
            ("external_ref", "character varying(64)"),
            ("notes", "character varying(1000)"),
            ("applied_on", "date"),
            ("person_id", "uuid"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
            ("cohort_id", "uuid"),
            ("assessment_score", "double precision"),
            ("assessment_level", "character varying(20)"),
            ("assessment_profile", "jsonb"),
            ("assessment_taken_at", "timestamp with time zone"),
            ("assessment_token_hash", "character varying(128)"),
            ("assessment_started_at", "timestamp with time zone"),
            ("assessment_time_exceeded", "boolean"),
            ("assessment_answers", "jsonb"),
            ("assessment_valid", "boolean"),
            ("assessment_invalid_reason", "character varying(40)"),
            ("assessment_reset_count", "integer"),
            ("date_of_birth", "date"),
            ("state", "character varying(60)"),
            ("city", "character varying(60)"),
            ("highest_qualification", "character varying(60)"),
            ("field_of_study", "character varying(120)"),
            ("years_experience", "integer"),
            ("current_role", "character varying(120)"),
            ("has_device", "boolean"),
            ("has_internet", "boolean"),
            ("can_work_at_height", "boolean"),
            ("available_from", "date"),
            ("heard_from", "character varying(60)"),
            ("cv_url", "character varying(500)"),
            ("assessment_deadline", "timestamp with time zone"),
            ("invite_sent_at", "timestamp with time zone"),
            ("assessment_elapsed_seconds", "integer"),
            ("onboarding_token_hash", "character varying(128)"),
            ("track_id", "uuid"),
            ("assessment_bank_id", "uuid"),
            ("assessment_return_url", "character varying(2048)"),
            ("assessment_erp_synced_at", "timestamp with time zone"),
            ("assessment_result_version", "integer"),
        ),
    ),
    (
        "email_outbox",
        "id",
        (
            ("id", "uuid"),
            ("tenant_id", "uuid"),
            ("idempotency_key", "character varying(200)"),
            ("kind", "character varying(60)"),
            ("recipient", "character varying(254)"),
            ("subject", "character varying(300)"),
            ("html_body", "text"),
            ("text_body", "text"),
            ("payload", "jsonb"),
            ("status", "character varying(20)"),
            ("attempts", "integer"),
            ("available_at", "timestamp with time zone"),
            ("sent_at", "timestamp with time zone"),
            ("last_error", "character varying(120)"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
        ),
    ),
    (
        "lab_instances",
        "id",
        (
            ("id", "uuid"),
            ("tenant_id", "uuid"),
            ("activity_id", "uuid"),
            ("person_id", "uuid"),
            ("instance_name", "character varying(120)"),
            ("seed", "jsonb"),
            ("status", "character varying(16)"),
            ("consoles", "jsonb"),
            ("error", "text"),
            ("started_at", "timestamp with time zone"),
            ("last_active_at", "timestamp with time zone"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
            ("runtime_presence", "character varying(16)"),
        ),
    ),
    (
        "lab_operations",
        "id",
        (
            ("id", "uuid"),
            ("tenant_id", "uuid"),
            ("instance_id", "uuid"),
            ("kind", "character varying(16)"),
            ("state", "character varying(16)"),
            ("requested_by", "uuid"),
            ("requested_at", "timestamp with time zone"),
            ("not_before", "timestamp with time zone"),
            ("claimed_by", "character varying(200)"),
            ("claimed_at", "timestamp with time zone"),
            ("heartbeat_at", "timestamp with time zone"),
            ("attempts", "integer"),
            ("finished_at", "timestamp with time zone"),
            ("last_error", "text"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
            ("claimed_host", "character varying(255)"),
            ("claimed_epoch", "character varying(64)"),
            ("origin", "character varying(32)"),
            ("runtime_precondition", "character varying(16)"),
        ),
    ),
    (
        "lab_templates",
        "id",
        (
            ("id", "uuid"),
            ("tenant_id", "uuid"),
            ("course_id", "uuid"),
            ("chapter_number", "integer"),
            ("activity_id", "uuid"),
            ("slug", "character varying(63)"),
            ("title", "character varying(200)"),
            ("topology", "text"),
            ("instructions_html", "text"),
            ("checks", "jsonb"),
            ("seed_spec", "jsonb"),
            ("limits", "jsonb"),
            ("engine", "character varying(20)"),
            ("source_hash", "character varying(64)"),
            ("version", "integer"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
            ("instructions_md", "text"),
        ),
    ),
    (
        "notifications",
        "id",
        (
            ("id", "uuid"),
            ("tenant_id", "uuid"),
            ("person_id", "uuid"),
            ("kind", "character varying(40)"),
            ("title", "character varying(200)"),
            ("body", "text"),
            ("link", "character varying(255)"),
            ("read_at", "timestamp with time zone"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
        ),
    ),
    (
        "onboarding_tasks",
        "id",
        (
            ("id", "uuid"),
            ("tenant_id", "uuid"),
            ("applicant_id", "uuid"),
            ("key", "character varying(40)"),
            ("label", "character varying(200)"),
            ("order_index", "integer"),
            ("status", "character varying(10)"),
            ("completed_at", "timestamp with time zone"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
        ),
    ),
    ("platform_settings", "key", (("key", "character varying(80)"), ("value", "text"))),
    (
        "reminder_log",
        "id",
        (
            ("id", "uuid"),
            ("tenant_id", "uuid"),
            ("person_id", "uuid"),
            ("event_kind", "character varying(30)"),
            ("occurrence_key", "character varying(160)"),
            ("title", "character varying(240)"),
            ("link", "character varying(300)"),
            ("channel", "character varying(20)"),
            ("status", "character varying(20)"),
            ("outbox_key", "character varying(200)"),
            ("sent_at", "timestamp with time zone"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
        ),
    ),
    (
        "reminder_preferences",
        "id",
        (
            ("id", "uuid"),
            ("tenant_id", "uuid"),
            ("person_id", "uuid"),
            ("frequency", "character varying(20)"),
            ("quiet_start_hour", "integer"),
            ("quiet_end_hour", "integer"),
            ("optouts", "jsonb"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
        ),
    ),
    (
        "tenant_entrance_defaults",
        "tenant_id",
        (
            ("tenant_id", "uuid"),
            ("default_bank_id", "uuid"),
            ("default_time_limit_minutes", "integer"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
        ),
    ),
)


@dataclass(frozen=True, slots=True, repr=False)
class _TableRows:
    name: str
    oid: int
    rows: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True, repr=False)
class _PublicSchemaEnvelope:
    oid: int
    owner_oid: int
    raw_acl: str | None
    acl: tuple[tuple[str, str, str, bool], ...]


def _public_schema_envelope(connection: Connection) -> _PublicSchemaEnvelope:
    rows = retained._rows(
        connection,
        "SELECT n.oid,n.nspowner,n.nspacl::text FROM pg_catalog.pg_namespace n WHERE n.nspname='public'",
    )
    _require(len(rows) == 1 and len(rows[0]) == 3)
    oid, owner_oid, raw_acl = rows[0]
    _require(type(oid) is int and oid > 0 and type(owner_oid) is int and owner_oid > 0)
    _require(raw_acl is None or type(raw_acl) is str)
    acl = retained._rows(
        connection,
        "SELECT pg_catalog.pg_get_userbyid(a.grantor),"
        "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,"
        "a.privilege_type,a.is_grantable FROM pg_catalog.pg_namespace n,"
        "LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a "
        "WHERE n.nspname='public' ORDER BY 1,2,3,4",
    )
    _require(all(len(row) == 4 and all(type(v) is str for v in row[:3]) and type(row[3]) is bool for row in acl))
    return _PublicSchemaEnvelope(oid, owner_oid, raw_acl, acl)


@dataclass(frozen=True, slots=True, repr=False)
class _RetainedFragment:
    """Private immutable observations, NEVER independently accepted authority.

    No registry or issuance claim. Future product owner must store this exact
    object beneath its actual private State; constructing an equal object does
    not create a product phase or authorize a004.
    """

    connection: Connection
    root: object
    physical_xid: str
    tables: tuple[_TableRows, ...]
    catalog: tuple[tuple[str, tuple], ...]
    public_schema: _PublicSchemaEnvelope


def _literal_bytes(value: str) -> str:
    # Values are exclusively internal domain tags, fixed names and fixed types.
    return "pg_catalog.convert_to('" + value.replace("'", "''") + "','UTF8')"


def _frame(expression: str) -> str:
    return f"(pg_catalog.int8send(pg_catalog.octet_length({expression})::bigint)||({expression}))"


def _cell(column: str, sql_type: str) -> str:
    identifier = '"' + column + '"'
    if sql_type == "uuid":
        payload = f"pg_catalog.uuid_send({identifier})"
    elif sql_type == "integer":
        payload = f"pg_catalog.int4send({identifier})"
    elif sql_type == "boolean":
        payload = f"pg_catalog.boolsend({identifier})"
    elif sql_type == "double precision":
        payload = f"pg_catalog.float8send({identifier})"
    elif sql_type == "timestamp with time zone":
        # Numeric epoch text retains every microsecond and +/-Infinity, independent
        # of TimeZone/DateStyle. No Python datetime conversion or float rounding.
        payload = f"pg_catalog.convert_to((extract(epoch FROM {identifier}))::text,'UTF8')"
    elif sql_type == "date":
        payload = (
            f"pg_catalog.convert_to((CASE WHEN {identifier}='infinity'::date THEN 'Infinity' "
            f"WHEN {identifier}='-infinity'::date THEN '-Infinity' "
            f"ELSE ({identifier}-'2000-01-01'::date)::text END),'UTF8')"
        )
    elif sql_type == "jsonb":
        payload = f"pg_catalog.convert_to({identifier}::text,'UTF8')"
    elif sql_type == "text" or sql_type.startswith("character varying("):
        payload = f"pg_catalog.convert_to({identifier},'UTF8')"
    else:
        raise RetainedHistoryRefused("Unsupported frozen retained cell type")
    domain = _frame(_literal_bytes(column)) + "||" + _frame(_literal_bytes(sql_type))
    # SQL NULL has its own marker. JSON null is a nonnull jsonb native payload.
    return (
        f"({domain}||CASE WHEN {identifier} IS NULL THEN pg_catalog.decode('00','hex') "
        f"ELSE pg_catalog.decode('01','hex')||{_frame(payload)} END)"
    )


def _row_query(table: str) -> str:
    # Private fixed-name lookup; no arbitrary identifiers/expressions/parameters.
    spec = next((spec for spec in _ROW_SPEC if spec[0] == table), None)
    if spec is None:
        raise RetainedHistoryRefused("Historical retained conservation refused; root rollback required")
    name, key, columns = spec
    cells = "||".join(_cell(column, sql_type) for column, sql_type in columns)
    domain = _frame(_literal_bytes("academy-retained-row/v1")) + "||" + _frame(_literal_bytes(name))
    return (
        f"SELECT \"{key}\"::text,pg_catalog.encode(pg_catalog.sha256({domain}||{cells}),'hex') " f'FROM public."{name}"'  # noqa: S608 -- fixed literal source spec only
    )


def _locked_context(connection: Connection) -> tuple[RootTransaction, str, tuple[tuple[str, int], ...]]:
    retained._preflight(connection)
    root = connection.get_transaction()
    if root is None:
        raise RetainedHistoryRefused("Historical retained conservation refused; root rollback required")
    xid = connection.scalar(sa.text("SELECT pg_catalog.txid_current()::text"))
    oids = []
    for name, _, _ in _ROW_SPEC:
        oid = connection.scalar(sa.text("SELECT pg_catalog.to_regclass(:name)::oid"), {"name": "public." + name})
        _require(type(oid) is int)
        _require(
            connection.scalar(
                sa.text(
                    "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks "
                    "WHERE pid=pg_catalog.pg_backend_pid() AND locktype='relation' "
                    "AND relation=:oid AND mode='AccessExclusiveLock' AND granted)"
                ),
                {"oid": oid},
            )
            is True
        )
        oids.append((name, oid))
    _require(root.is_active and connection.get_transaction() is root)
    return root, xid, tuple(oids)


def _read_fixed_rows(connection: Connection) -> tuple[_TableRows, ...]:
    """Return only fixed-table PK/digest data; never issue or accept authority.

    This primitive deliberately does not rerun Genesis catalog/security checks:
    the product owner must authenticate its reached private State and exact
    stored fragment, live hosted context, complete locks and same-OID identity
    association before and after comparing this data with fragment.tables.
    There are no caller-selected namespaces, columns or expected packets.
    """
    root, xid, oids = _locked_context(connection)
    result = []
    for name, oid in oids:
        try:
            rows = tuple(tuple(row) for row in connection.execute(sa.text(_row_query(name))).tuples())
        except SQLAlchemyError:
            # Never expose a driver error/DETAIL or sensitive row in this API.
            raise RetainedHistoryRefused("Historical retained digest read refused; root rollback required") from None
        _require(all(type(key) is str and type(digest) is str and len(digest) == 64 for key, digest in rows))
        _require(len({key for key, _ in rows}) == len(rows))
        # Sort identifiers in Python by UTF8 bytes, independent of SQL collation.
        result.append(_TableRows(name, oid, tuple(sorted(rows, key=lambda row: row[0].encode("utf-8")))))
    after_root, after_xid, after_oids = _locked_context(connection)
    _require(after_root is root and after_xid == xid and after_oids == oids)
    return tuple(result)


def _observe_rows(connection: Connection) -> tuple[_TableRows, ...]:
    """Strict historical Genesis observations; explicitly no admission.

    Full fixed source/security checks remain mandatory here. Product phases
    after genuine identity relocation must use the private data primitive only
    beneath the product owner's authenticated conservation boundary.
    """
    root, xid, oids = _locked_context(connection)
    packet = retained._observe_historical_catalog(connection)
    retained._check_structure(packet)
    retained._check_security(packet)
    result = _read_fixed_rows(connection)
    after_root, after_xid, after_oids = _locked_context(connection)
    _require(after_root is root and after_xid == xid and after_oids == oids)
    return result


def _qualify(
    connection: Connection, bindings: environment.HostedEnvironmentBindings, *, _hosted_context: object = None
) -> None:
    # These are the REAL gates, not internal check helpers. No catch-and-continue.
    _require(type(bindings) is environment.HostedEnvironmentBindings)
    retained._verify_historical_retained_schema(connection)
    environment.observe_retained_environment(connection, bindings, _hosted_context=_hosted_context)


def _capture_retained_rows(
    connection: Connection, bindings: environment.HostedEnvironmentBindings, *, _hosted_context: object = None
) -> _RetainedFragment:
    """Gated private capture; missing live hosted context still fails closed."""
    _qualify(connection, bindings, _hosted_context=_hosted_context)
    root, xid, _ = _locked_context(connection)
    tables = _observe_rows(connection)
    catalog = tuple(sorted(retained._observe_historical_catalog(connection).items()))
    public_schema = _public_schema_envelope(connection)
    _require(root.is_active and connection.get_transaction() is root)
    return _RetainedFragment(connection, root, xid, tables, catalog, public_schema)


def _recheck_retained_rows(
    connection: Connection,
    fragment: _RetainedFragment,
    bindings: environment.HostedEnvironmentBindings,
    *,
    _hosted_context: object = None,
) -> None:
    """Compare private observations only; never authenticates a product phase."""
    _qualify(connection, bindings, _hosted_context=_hosted_context)
    _require(type(fragment) is _RetainedFragment)
    root, xid, _ = _locked_context(connection)
    _require(fragment.connection is connection and fragment.root is root and fragment.physical_xid == xid)
    _require(_public_schema_envelope(connection) == fragment.public_schema)
    _require(_observe_rows(connection) == fragment.tables)
    _require(tuple(sorted(retained._observe_historical_catalog(connection).items())) == fragment.catalog)

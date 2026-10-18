"""Candidate disposable hosted Genesis environment; observation is never admission.

Bindings are expectations supplied before observation by trusted Settings/CI.
No binding, packet, or result establishes an exclusive boundary or proof.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from sqlalchemy.engine import Connection

from app.maintenance import retained_schema as retained


class RetainedEnvironmentRefused(retained.RetainedSchemaRefused):
    """Observed authority contradicts the fixed disposable Genesis profile."""


class RetainedEnvironmentUnsupported(RetainedEnvironmentRefused):
    """Missing binding or hosted qualification; no successful admission exists."""


@dataclass(frozen=True, slots=True, repr=False)
class HostedEnvironmentBindings:
    """Constructible non-secret expectations, explicitly NOT trusted evidence.

    None for provider-specific locale values must be explicitly declared.
    Service image is a required CI expectation: SQL cannot authenticate it.
    No defaults are inferred from a live catalog or application business policy.
    """

    target_database: str
    setup_session: str
    service_image: str
    server_version_num: int
    encoding: str
    locale_provider: str
    lc_collate: str
    lc_ctype: str
    icu_locale: str | None
    collation_version: str | None
    actual_collation_version: str | None
    extension_versions: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class _FixedProfile:
    name: str
    roles: tuple[tuple[str, bool, bool], ...]
    source_manifest_sha256: str
    actual_a5_ci_sha256: str
    actual_role_script_blob: str


# Internal security protocol: no caller profile, ACL, role, namespace or switch.
_PROFILE = _FixedProfile(
    name="academy-hosted-frozen62-pg16/v1",
    roles=(
        ("academy_lab_worker", False, True),
        ("app_admin", True, True),
        ("app_user", True, False),
        ("outbox_dispatcher", True, False),
        ("platform_api", True, False),
        ("platform_outbox_dispatcher", True, False),
    ),
    source_manifest_sha256="7c39bfd4193c5667664e83e09b27611c8c9f51ee63a1f77784ba9f51109f635f",
    actual_a5_ci_sha256="c786e61f4560ca874683c4fcd154ba45620b3bccef96e25a8d54960d3bd7c6e0",
    actual_role_script_blob="d5bbe2812eb419a14287cba70d72a3bc08a20799",
)
_ROLE_NAMES = tuple(row[0] for row in _PROFILE.roles)
_RUNTIME_ROLES = tuple(name for name in _ROLE_NAMES if name != "app_admin")
_BINDING_FIELDS = tuple(HostedEnvironmentBindings.__dataclass_fields__)
_BINDING_PREFIX = "academy_retained_environment_"


def _require(condition: bool) -> None:
    if not condition:
        # Never interpolate bindings, server packets, role configuration or SQL.
        raise RetainedEnvironmentRefused("Disposable hosted Genesis environment refused; root rollback required")


def bindings_from_settings(settings: object) -> HostedEnvironmentBindings:
    """Read only the named non-secret fields; does not inspect/dump Settings.

    Existing Settings/CI have no adoption wiring in this slice. Missing fields
    remain Unsupported. A mapping is useful for the next trusted CI projection;
    it is still freely constructible and grants no authority.
    """
    values = {}
    for name in _BINDING_FIELDS:
        key = _BINDING_PREFIX + name
        if isinstance(settings, Mapping):
            if key not in settings:
                raise RetainedEnvironmentUnsupported("Required hosted environment bindings absent")
            values[name] = settings[key]
        else:
            try:
                values[name] = getattr(settings, key)
            except AttributeError:
                raise RetainedEnvironmentUnsupported("Required hosted environment bindings absent") from None
    result = HostedEnvironmentBindings(**values)
    _check_bindings(result)
    return result


def _check_bindings(bindings: HostedEnvironmentBindings | None) -> None:
    if bindings is None:
        raise RetainedEnvironmentUnsupported("Required hosted environment bindings absent")
    _require(type(bindings) is HostedEnvironmentBindings)
    _require(type(bindings.target_database) is str)
    _require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", bindings.target_database) is not None)
    _require(bindings.setup_session == "postgres")
    _require(type(bindings.service_image) is str)
    _require(re.fullmatch(r"[A-Za-z0-9_./:@-]{1,240}", bindings.service_image) is not None)
    _require("://" not in bindings.service_image and bindings.service_image.count("@") <= 1)
    _require(type(bindings.server_version_num) is int and 160000 <= bindings.server_version_num < 170000)
    _require(bindings.encoding == "UTF8" and bindings.locale_provider in ("c", "i"))
    for value in (bindings.lc_collate, bindings.lc_ctype):
        _require(type(value) is str and 0 < len(value) <= 128 and value.isprintable())
    for value in (bindings.icu_locale, bindings.collation_version, bindings.actual_collation_version):
        _require(value is None or (type(value) is str and 0 < len(value) <= 128 and value.isprintable()))
    _require((bindings.icu_locale is None) is (bindings.locale_provider == "c"))
    _require(bindings.collation_version == bindings.actual_collation_version)
    _require(type(bindings.extension_versions) is tuple and len(bindings.extension_versions) == 1)
    extension = bindings.extension_versions[0]
    _require(type(extension) is tuple and len(extension) == 2 and extension[0] == "plpgsql")
    _require(type(extension[1]) is str and re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", extension[1]) is not None)


# Only SELECT metadata. No raw role/routine settings, passwords, DSNs, row reads,
# arbitrary namespaces, mutation, transaction management, locks, or fence flags.
_QUERIES = (
    (
        "context",
        """
        SELECT current_database(),session_user,current_user,
               current_setting('server_version_num')::integer,
               current_setting('session_replication_role'),current_setting('row_security'),
               current_setting('transaction_read_only'),current_setting('transaction_isolation'),
               current_setting('search_path'),pg_catalog.current_schemas(true),
               current_setting('quote_all_identifiers'),current_setting('standard_conforming_strings')
        """,
    ),
    (
        "database",
        """
        SELECT pg_catalog.pg_get_userbyid(d.datdba),pg_catalog.pg_encoding_to_char(d.encoding),
               d.datlocprovider,d.datcollate,d.datctype,d.daticulocale,d.datcollversion,
               pg_catalog.pg_database_collation_actual_version(d.oid),d.datallowconn,d.datistemplate
        FROM pg_catalog.pg_database d WHERE d.datname=current_database()
        """,
    ),
    (
        "roles",
        """
        SELECT rolname,rolcanlogin,rolinherit,rolbypassrls,rolsuper,rolcreatedb,rolcreaterole,rolreplication,
               coalesce(cardinality(rolconfig),0)>0,rolconnlimit,rolvaliduntil IS NULL
        FROM pg_catalog.pg_roles WHERE rolname=ANY(:roles) ORDER BY rolname
        """,
    ),
    (
        "memberships",
        """
        SELECT m.admin_option,m.inherit_option,m.set_option
        FROM pg_catalog.pg_auth_members m
        WHERE m.roleid IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=ANY(:roles))
           OR m.member IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=ANY(:roles))
           OR m.grantor IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=ANY(:roles))
        """,
    ),
    (
        "role_database_settings",
        """
        SELECT EXISTS (
            SELECT 1 FROM pg_catalog.pg_db_role_setting s
            WHERE s.setdatabase IN (0,(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()))
              AND s.setrole IN (SELECT oid FROM pg_catalog.pg_roles
                                WHERE rolname=ANY(:roles) OR rolname='postgres' UNION ALL SELECT 0)
        )
        """,
    ),
    (
        "default_acl_overrides",
        """SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_default_acl)""",
    ),
    (
        "parameter_acl_grants",
        """
        SELECT EXISTS (
            SELECT 1 FROM pg_catalog.pg_parameter_acl p,LATERAL pg_catalog.aclexplode(p.paracl) a
        )
        """,
    ),
    (
        "database_acl",
        """
        SELECT pg_catalog.pg_get_userbyid(a.grantor),
               CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,
               a.privilege_type,a.is_grantable
        FROM pg_catalog.pg_database d,
             LATERAL pg_catalog.aclexplode(coalesce(d.datacl,pg_catalog.acldefault('d',d.datdba))) a
        WHERE d.datname=current_database() ORDER BY 1,2,3,4
        """,
    ),
    (
        "schemas",
        """
        SELECT nspname,pg_catalog.pg_get_userbyid(nspowner)
        FROM pg_catalog.pg_namespace
        WHERE nspname<>'information_schema' AND nspname !~ '^pg_' ORDER BY nspname
        """,
    ),
    (
        "schema_acl",
        """
        SELECT pg_catalog.pg_get_userbyid(a.grantor),
               CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,
               a.privilege_type,a.is_grantable
        FROM pg_catalog.pg_namespace n,
             LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
        WHERE n.nspname='public' ORDER BY 1,2,3,4
        """,
    ),
    (
        "effective_database",
        """
        SELECT r.rolname,p.privilege,pg_catalog.has_database_privilege(r.oid,current_database(),p.privilege)
        FROM pg_catalog.pg_roles r CROSS JOIN (VALUES ('CONNECT'),('CREATE'),('TEMPORARY')) p(privilege)
        WHERE r.rolname=ANY(:roles) ORDER BY 1,2
        """,
    ),
    (
        "effective_schema",
        """
        SELECT r.rolname,p.privilege,pg_catalog.has_schema_privilege(r.oid,'public',p.privilege)
        FROM pg_catalog.pg_roles r CROSS JOIN (VALUES ('USAGE'),('CREATE')) p(privilege)
        WHERE r.rolname=ANY(:roles) ORDER BY 1,2
        """,
    ),
    (
        "runtime_ownership",
        """
        SELECT EXISTS (
            SELECT 1 FROM pg_catalog.pg_database WHERE datdba IN
                (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=ANY(:runtime_roles))
            UNION ALL SELECT 1 FROM pg_catalog.pg_namespace WHERE nspowner IN
                (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=ANY(:runtime_roles))
            UNION ALL SELECT 1 FROM pg_catalog.pg_class WHERE relowner IN
                (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=ANY(:runtime_roles))
        )
        """,
    ),
    (
        "outbox_tables",
        """
        SELECT c.relname,r.rolname,p.privilege,pg_catalog.has_table_privilege(r.oid,c.oid,p.privilege)
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN pg_catalog.pg_roles r CROSS JOIN
             (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) p(privilege)
        WHERE n.nspname='public' AND c.relname=ANY(:names) AND r.rolname=ANY(:outbox_roles) ORDER BY 1,2,3
        """,
    ),
    (
        "outbox_columns",
        """
        SELECT c.relname,a.attname,r.rolname,p.privilege,
               pg_catalog.has_column_privilege(r.oid,c.oid,a.attnum,p.privilege)
        FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace CROSS JOIN pg_catalog.pg_roles r
        CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
        WHERE n.nspname='public' AND c.relname=ANY(:names) AND a.attnum>0 AND NOT a.attisdropped
              AND r.rolname=ANY(:outbox_roles) ORDER BY 1,2,3,4
        """,
    ),
    (
        "extensions",
        """
        SELECT e.extname,e.extversion,n.nspname,pg_catalog.pg_get_userbyid(e.extowner),
               e.extrelocatable,e.extconfig IS NULL,e.extcondition IS NULL
        FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace ORDER BY e.extname
        """,
    ),
    (
        "additional_routines",
        """
        SELECT EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname<>'information_schema' AND n.nspname !~ '^pg_'
              AND NOT (n.nspname='public' AND p.proname='app_current_tenant_id' AND p.pronargs=0)
        )
        """,
    ),
)


def _observe_hosted_environment(connection: Connection) -> dict[str, tuple]:
    """Freely constructible metadata observation; no issuance or authority."""
    root = retained._preflight(connection)
    params = {
        "roles": list(_ROLE_NAMES),
        "runtime_roles": list(_RUNTIME_ROLES),
        "names": list(retained._NAMES),
        "outbox_roles": ["outbox_dispatcher", "platform_outbox_dispatcher"],
    }
    packet = {name: retained._rows(connection, sql, **params) for name, sql in _QUERIES}
    _require(connection.get_transaction() is root and root.is_active)
    return packet


def _check_fixed_environment(packet: dict[str, tuple], bindings: HostedEnvironmentBindings) -> None:
    """Source-derived fixed checks; packet equality never confers admission."""
    _check_bindings(bindings)
    _require(
        packet["context"]
        == (
            (
                bindings.target_database,
                bindings.setup_session,
                "app_admin",
                bindings.server_version_num,
                "origin",
                "on",
                "off",
                "read committed",
                '"$user", public',
                ("pg_catalog", "public"),
                "off",
                "on",
            ),
        )
    )
    _require(
        packet["database"]
        == (
            (
                "app_admin",
                bindings.encoding,
                bindings.locale_provider,
                bindings.lc_collate,
                bindings.lc_ctype,
                bindings.icu_locale,
                bindings.collation_version,
                bindings.actual_collation_version,
                True,
                False,
            ),
        )
    )
    _require(
        packet["roles"]
        == tuple(
            (name, True, inherit, bypass, False, False, False, False, False, -1, True)
            for name, inherit, bypass in _PROFILE.roles
        )
    )
    _require(not packet["memberships"])
    for key in (
        "role_database_settings",
        "default_acl_overrides",
        "parameter_acl_grants",
        "runtime_ownership",
        "additional_routines",
    ):
        _require(packet[key] == ((False,),))
    database_acl = [("app_admin", "PUBLIC", p, False) for p in ("CONNECT", "TEMPORARY")]
    database_acl.extend(("app_admin", "app_admin", p, False) for p in ("CONNECT", "CREATE", "TEMPORARY"))
    _require(packet["database_acl"] == tuple(sorted(database_acl)))
    _require(packet["schemas"] == (("public", "pg_database_owner"),))
    schema_acl = [("pg_database_owner", "PUBLIC", "USAGE", False)]
    schema_acl.extend(
        ("pg_database_owner", r, p, False) for r in ("pg_database_owner", "app_admin") for p in ("CREATE", "USAGE")
    )
    schema_acl.extend(("pg_database_owner", r, "USAGE", False) for r in ("app_user", "platform_api"))
    _require(packet["schema_acl"] == tuple(sorted(schema_acl)))
    _require(
        packet["effective_database"]
        == tuple(
            sorted(
                (r, p, r == "app_admin" or p != "CREATE")
                for r in _ROLE_NAMES
                for p in ("CONNECT", "CREATE", "TEMPORARY")
            )
        )
    )
    _require(
        packet["effective_schema"]
        == tuple(sorted((r, p, r == "app_admin" or p == "USAGE") for r in _ROLE_NAMES for p in ("CREATE", "USAGE")))
    )
    outbox = ("outbox_dispatcher", "platform_outbox_dispatcher")
    _require(
        packet["outbox_tables"]
        == tuple(sorted((t, r, p, False) for t in retained._NAMES for r in outbox for p in retained._PRIVILEGES))
    )
    _require(
        packet["outbox_columns"]
        == tuple(
            sorted(
                (t, c[0], r, p, False)
                for t, columns in retained._COLUMNS
                for c in columns
                for r in outbox
                for p in retained._COLUMN_PRIVILEGES
            )
        )
    )
    _require(
        packet["extensions"]
        == (("plpgsql", bindings.extension_versions[0][1], "pg_catalog", "postgres", False, True, True),)
    )


def observe_retained_environment(connection: Connection, bindings: HostedEnvironmentBindings | None) -> None:
    """Read fixed environment and retained checks, then ALWAYS Unsupported.

    Does not authenticate the service image or exclusive CI boundary. Does not
    issue proof, consume proof, authorize a004, acquire locks, establish a fence,
    manage the root, or approve production. Future adoption must wire trusted
    Settings/CI and qualify the genuine hosted projection separately.
    """
    if bindings is None:
        raise RetainedEnvironmentUnsupported("Required hosted environment bindings absent")
    _check_bindings(bindings)
    root = retained._preflight(connection)
    packet = _observe_hosted_environment(connection)
    _check_fixed_environment(packet, bindings)
    try:
        catalog = retained._observe_historical_catalog(connection)
        retained._check_structure(catalog)
        retained._check_security(catalog)
        retained._check_tenant_helper(catalog)
    except retained.RetainedSchemaRefused:
        raise RetainedEnvironmentRefused(
            "Frozen retained source/security contradiction; root rollback required"
        ) from None
    _require(connection.get_transaction() is root and root.is_active)
    raise RetainedEnvironmentUnsupported("Hosted bindings, service image and exclusive Genesis boundary unqualified")

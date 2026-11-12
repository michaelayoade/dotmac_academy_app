"""Hosted PostgreSQL proof of the composed Kernel a109 / Academy OIDC upgrade."""

from __future__ import annotations

import os
import re
from uuid import uuid4

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from tests.conftest import _superuser_url, _url_for

_KERNEL_TABLE = "rate_limit_buckets"
_OIDC_TABLE = "academy_oidc_login_states"
_CRUD = ("SELECT", "INSERT", "UPDATE", "DELETE")
_ALL_PRIVILEGES = (*_CRUD, "TRUNCATE", "REFERENCES", "TRIGGER")


def _versions(conn):
    return conn.scalars(text("SELECT version_num FROM public.alembic_version ORDER BY version_num")).all()


def _table_exists(conn, table):
    return conn.scalar(text("SELECT to_regclass(:table) IS NOT NULL"), {"table": f"public.{table}"})


def _posture(conn, table):
    return conn.execute(
        text(
            "SELECT pg_get_userbyid(relowner), relrowsecurity, relforcerowsecurity "
            "FROM pg_catalog.pg_class WHERE oid = to_regclass(:table)"
        ),
        {"table": f"public.{table}"},
    ).one()


def _privileges(conn, table, role, privileges, allowed):
    for privilege in privileges:
        assert (
            conn.scalar(
                text("SELECT has_table_privilege(:role, :table, :privilege)"),
                {"role": role, "table": f"public.{table}", "privilege": privilege},
            )
            is allowed
        ), (table, role, privilege)


def _public_denied(conn, table):
    # PUBLIC is ACL grantee zero, rather than a role accepted by has_table_privilege.
    assert (
        conn.scalar(
            text(
                "SELECT count(*) FROM pg_catalog.pg_class AS c, "
                "LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) AS acl "
                "WHERE c.oid = to_regclass(:table) AND acl.grantee = 0"
            ),
            {"table": f"public.{table}"},
        )
        == 0
    )


def _kernel_catalog(admin):
    with admin.connect() as conn:
        assert _posture(conn, _KERNEL_TABLE) == ("app_admin", False, False)
        for role in ("app_admin", "platform_api"):
            _privileges(conn, _KERNEL_TABLE, role, _CRUD, True)
        _privileges(conn, _KERNEL_TABLE, "app_user", _ALL_PRIVILEGES, False)
        _public_denied(conn, _KERNEL_TABLE)
        assert (
            conn.scalar(
                text("SELECT count(*) FROM pg_catalog.pg_policies WHERE schemaname = 'public' AND tablename = :table"),
                {"table": _KERNEL_TABLE},
            )
            == 0
        )

    inspector = inspect(admin)
    assert [
        (column["name"], column["type"].compile(dialect=admin.dialect), column["nullable"])
        for column in inspector.get_columns(_KERNEL_TABLE, schema="public")
    ] == [
        ("key_hash", "VARCHAR(64)", False),
        ("window_start", "TIMESTAMP WITH TIME ZONE", False),
        ("hit_count", "INTEGER", False),
        ("expires_at", "TIMESTAMP WITH TIME ZONE", False),
    ]
    primary_key = inspector.get_pk_constraint(_KERNEL_TABLE, schema="public")
    assert (primary_key["name"], primary_key["constrained_columns"]) == (
        "pk_rate_limit_buckets",
        ["key_hash", "window_start"],
    )
    checks = inspector.get_check_constraints(_KERNEL_TABLE, schema="public")
    assert len(checks) == 1
    assert checks[0]["name"] == "ck_rate_limit_buckets_hit_count"
    assert checks[0]["sqltext"] in ("hit_count >= 1", "(hit_count >= 1)")
    assert [
        (index["name"], index["column_names"], index["unique"])
        for index in inspector.get_indexes(_KERNEL_TABLE, schema="public")
    ] == [("ix_rate_limit_buckets_expires_at", ["expires_at"], False)]


def test_kernel_a109_then_oidc_upgrade_preserves_composed_versions_and_catalogs(monkeypatch):
    from app.migration_cli import main

    # Refuse any connection outside the disposable GitHub CI service, before CREATE.
    assert os.getenv("CI") == "true" and os.getenv("GITHUB_ACTIONS") == "true"
    superuser = _superuser_url()
    base = make_url(superuser)
    assert (base.drivername, base.host, base.port, base.database, base.username) == (
        "postgresql+psycopg",
        "127.0.0.1",
        5437,
        "academy_v2_ci",
        "postgres",
    )
    assert base.password is None and not base.query
    name = f"academy_v2_a109_{uuid4().hex}"
    assert re.fullmatch(r"academy_v2_a109_[0-9a-f]{32}", name)
    server = create_engine(superuser, isolation_level="AUTOCOMMIT")
    setup = admin = None
    created = False
    try:
        with server.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{name}"'))
            created = True
        setup = create_engine(_url_for(superuser, name), isolation_level="AUTOCOMMIT")
        with setup.connect() as conn:
            conn.execute(text("ALTER SCHEMA public OWNER TO app_admin"))
            conn.execute(text(f'GRANT CREATE ON DATABASE "{name}" TO app_admin'))
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{name}" TO app_user, platform_api, academy_lab_worker'))
        admin_url = _url_for(superuser, name, user="app_admin")
        admin = create_engine(admin_url)
        with monkeypatch.context() as migration_env:
            migration_env.setenv("MIGRATION_DATABASE_URL", admin_url)
            main(["upgrade", "a0010_audit_source_application"])
            with admin.connect() as conn:
                assert _versions(conn) == ["a0010_audit_source_application"]
                assert not _table_exists(conn, _KERNEL_TABLE)
                assert not _table_exists(conn, _OIDC_TABLE)

            main(["upgrade", "0031_rate_limit_buckets"])
            with admin.connect() as conn:
                assert _versions(conn) == ["0031_rate_limit_buckets", "a0010_audit_source_application"]
                assert not _table_exists(conn, _OIDC_TABLE)
            _kernel_catalog(admin)

            main(["upgrade", "a0011_oidc_login_states"])
            with admin.connect() as conn:
                # Learning lr0012 is a consumed dependency, never an extra physical row.
                assert _versions(conn) == ["0031_rate_limit_buckets", "a0011_oidc_login_states"]
                assert _table_exists(conn, _KERNEL_TABLE) and _table_exists(conn, _OIDC_TABLE)
                assert _posture(conn, _OIDC_TABLE) == ("app_admin", True, True)
                policy = conn.execute(
                    text(
                        "SELECT policyname, cmd, qual, with_check FROM pg_catalog.pg_policies "
                        "WHERE schemaname = 'public' AND tablename = :table"
                    ),
                    {"table": _OIDC_TABLE},
                ).one()
                assert policy.policyname == "academy_oidc_login_states_tenant_isolation"
                assert policy.cmd == "ALL"
                assert policy.qual == policy.with_check
                assert "tenant_id = app_current_tenant_id()" in policy.qual
                _privileges(conn, _OIDC_TABLE, "app_user", _CRUD, True)
                _public_denied(conn, _OIDC_TABLE)
            _kernel_catalog(admin)
    finally:
        try:
            for engine in (admin, setup):
                if engine is not None:
                    engine.dispose()
            if created:
                with server.connect() as conn:
                    conn.execute(
                        text(
                            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE datname = :name AND pid <> pg_backend_pid()"
                        ),
                        {"name": name},
                    )
                    conn.execute(text(f'DROP DATABASE "{name}"'))
        finally:
            server.dispose()


def _oidc_preservation_snapshot(admin):
    """Prove the pre-existing ceremony table, then retain its physical/catalog identity."""
    with admin.connect() as conn:
        posture = tuple(_posture(conn, _OIDC_TABLE))
        assert posture == ("app_admin", True, True)
        policy = conn.execute(
            text(
                "SELECT policyname, cmd, qual, with_check FROM pg_catalog.pg_policies "
                "WHERE schemaname = 'public' AND tablename = :table"
            ),
            {"table": _OIDC_TABLE},
        ).one()
        assert policy.policyname == "academy_oidc_login_states_tenant_isolation"
        assert policy.cmd == "ALL"
        assert policy.qual == policy.with_check
        assert "tenant_id = app_current_tenant_id()" in policy.qual
        _privileges(conn, _OIDC_TABLE, "app_user", _CRUD, True)
        _privileges(conn, _OIDC_TABLE, "app_user", ("TRUNCATE", "REFERENCES", "TRIGGER"), False)
        _public_denied(conn, _OIDC_TABLE)
        relation = conn.execute(
            text("SELECT oid::bigint, relacl::text FROM pg_catalog.pg_class WHERE oid = to_regclass(:table)"),
            {"table": f"public.{_OIDC_TABLE}"},
        ).one()
        constraints = conn.execute(
            text(
                "SELECT conname, contype, pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint "
                "WHERE conrelid = to_regclass(:table) ORDER BY conname"
            ),
            {"table": f"public.{_OIDC_TABLE}"},
        ).all()
        indexes = conn.execute(
            text(
                "SELECT indexname, indexdef FROM pg_catalog.pg_indexes "
                "WHERE schemaname = 'public' AND tablename = :table ORDER BY indexname"
            ),
            {"table": _OIDC_TABLE},
        ).all()
    columns = [
        (column["name"], column["type"].compile(dialect=admin.dialect), column["nullable"], column["default"])
        for column in inspect(admin).get_columns(_OIDC_TABLE, schema="public")
    ]
    assert [(name, kind, nullable) for name, kind, nullable, _default in columns] == [
        ("id", "UUID", False),
        ("tenant_id", "UUID", False),
        ("state_hash", "VARCHAR(64)", False),
        ("provider_binding", "VARCHAR(80)", False),
        ("code_verifier", "TEXT", False),
        ("nonce", "TEXT", False),
        ("redirect_uri", "TEXT", False),
        ("return_to", "TEXT", False),
        ("issued_at", "BIGINT", False),
        ("expires_at", "TIMESTAMP WITH TIME ZONE", False),
        ("created_at", "TIMESTAMP WITH TIME ZONE", False),
    ]
    return {
        "relation": tuple(relation),
        "posture": posture,
        "policy": tuple(policy),
        "columns": columns,
        "constraints": [tuple(row) for row in constraints],
        "indexes": [tuple(row) for row in indexes],
    }


def test_existing_oidc_then_kernel_a109_upgrade_preserves_composed_versions_and_catalogs(monkeypatch):
    from app.migration_cli import main

    # The same CI-only admission and disposable database custody as the other order.
    assert os.getenv("CI") == "true" and os.getenv("GITHUB_ACTIONS") == "true"
    superuser = _superuser_url()
    base = make_url(superuser)
    assert (base.drivername, base.host, base.port, base.database, base.username) == (
        "postgresql+psycopg",
        "127.0.0.1",
        5437,
        "academy_v2_ci",
        "postgres",
    )
    assert base.password is None and not base.query
    name = f"academy_v2_a109_{uuid4().hex}"
    assert re.fullmatch(r"academy_v2_a109_[0-9a-f]{32}", name)
    server = create_engine(superuser, isolation_level="AUTOCOMMIT")
    setup = admin = None
    created = False
    try:
        with server.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{name}"'))
            created = True
        setup = create_engine(_url_for(superuser, name), isolation_level="AUTOCOMMIT")
        with setup.connect() as conn:
            conn.execute(text("ALTER SCHEMA public OWNER TO app_admin"))
            conn.execute(text(f'GRANT CREATE ON DATABASE "{name}" TO app_admin'))
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{name}" TO app_user, platform_api, academy_lab_worker'))
        admin_url = _url_for(superuser, name, user="app_admin")
        admin = create_engine(admin_url)
        with monkeypatch.context() as migration_env:
            migration_env.setenv("MIGRATION_DATABASE_URL", admin_url)
            main(["upgrade", "a0010_audit_source_application"])
            with admin.connect() as conn:
                assert _versions(conn) == ["a0010_audit_source_application"]
                assert not _table_exists(conn, _KERNEL_TABLE)
                assert not _table_exists(conn, _OIDC_TABLE)

            # Reproduce the actually observed pre-existing OIDC physical vector.
            main(["upgrade", "a0011_oidc_login_states"])
            with admin.connect() as conn:
                assert _versions(conn) == ["a0011_oidc_login_states"]
                assert _table_exists(conn, _OIDC_TABLE)
                assert not _table_exists(conn, _KERNEL_TABLE)
            oidc_before = _oidc_preservation_snapshot(admin)

            # This is the sole remaining DDL target; never replay Academy0011.
            main(["upgrade", "0031_rate_limit_buckets"])
            with admin.connect() as conn:
                # Learning lr0012 remains a consumed dependency, not a physical row.
                assert _versions(conn) == ["0031_rate_limit_buckets", "a0011_oidc_login_states"]
                assert _table_exists(conn, _KERNEL_TABLE) and _table_exists(conn, _OIDC_TABLE)
            _kernel_catalog(admin)
            assert _oidc_preservation_snapshot(admin) == oidc_before
    finally:
        try:
            for engine in (admin, setup):
                if engine is not None:
                    engine.dispose()
            if created:
                with server.connect() as conn:
                    conn.execute(
                        text(
                            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE datname = :name AND pid <> pg_backend_pid()"
                        ),
                        {"name": name},
                    )
                    conn.execute(text(f'DROP DATABASE "{name}"'))
        finally:
            server.dispose()

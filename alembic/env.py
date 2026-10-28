"""Ordinary online migration environment; preserves a caller's active root.

Frozen legacy replay must complete independently before protected adoption.
This environment never replays legacy history, stamps a head or supplies import
receipts. Offline adoption and autogeneration have no supported evidence path.
"""

from __future__ import annotations

from dotmac_kernel.migrations.configuration import select_migration_database_url
from dotmac_kernel.migrations.verify import require_prerequisites
from sqlalchemy import create_engine, pool, text
from sqlalchemy.engine import Connection

from alembic import context
from app.config import settings
from app.migration_graph import ordinary_migration_config

config = ordinary_migration_config(config=context.config)
# Actual owner metadata still contains copied identity references; it cannot
# truthfully supply a canonical, duplicate-free autogenerate metadata sequence.
target_metadata = None


def validate_migration_authority(connection: Connection) -> None:
    """Prove configured server identities and actual migration-role effects."""
    login = settings.migration_login_role
    effective = settings.migration_effective_role
    if not login or login != login.strip() or not effective or effective != effective.strip():
        raise ValueError("explicit migration login and effective role policy is required")
    if connection.dialect.name != "postgresql":
        raise ValueError("migration authority requires PostgreSQL catalog evidence")
    actual = connection.execute(text("SELECT session_user, current_user")).one()
    if tuple(actual) != (login, effective):
        raise ValueError("migration server identities do not match configured policy")
    capable = connection.scalar(
        text("SELECT rolbypassrls AND NOT rolsuper FROM pg_roles WHERE rolname=current_user")
    )
    if capable is not True:
        raise ValueError("migration effective role lacks required catalog posture")
    require_prerequisites(connection, ("module_database_roles.v1",))


def run_on_connection(connection: Connection) -> None:
    """Never reconnect, close, commit or replace this actual caller root."""
    if not isinstance(connection, Connection) or connection.closed:
        raise ValueError("an actual open SQLAlchemy Connection is required")
    root = connection.get_transaction()
    if root is None or not root.is_active or connection.in_nested_transaction():
        raise ValueError("migration entry requires one active caller root transaction")
    validate_migration_authority(connection)
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        version_table_schema="public",
        transactional_ddl=True,
        on_version_apply=config.attributes.get("on_version_apply", ()),
    )
    revision_context = context.get_context().opts.get("revision_context")
    if revision_context is not None and revision_context.command_args.get("autogenerate"):
        raise ValueError("autogenerate unavailable: canonical owner metadata contains copied identity references")
    context.run_migrations()
    if connection.closed or connection.get_transaction() is not root or not root.is_active:
        raise ValueError("migration execution changed caller connection or root")


def run_migrations_online() -> None:
    supplied = config.attributes.get("connection")
    if supplied is not None:
        run_on_connection(supplied)
        return
    # Preserve explicit blank migration URL refusal; fallback is product policy.
    configured = "migration_database_url" in settings.model_fields_set
    url = select_migration_database_url(
        migration_database_url=settings.migration_database_url if configured else None,
        fallback_database_url=settings.database_url,
    )
    engine = create_engine(url, poolclass=pool.NullPool, hide_parameters=True)
    try:
        with engine.connect() as connection, connection.begin():
            run_on_connection(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise ValueError("offline adoption is unsupported: actual catalog and identity history evidence is required")
if getattr(config.cmd_opts, "autogenerate", False):
    raise ValueError("autogenerate unavailable: canonical owner metadata contains copied identity references")
run_migrations_online()

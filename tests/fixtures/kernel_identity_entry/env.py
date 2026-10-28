"""Fixture-only Alembic environment: caller supplies connection and revisions."""

from alembic import context

config = context.config
connection = config.attributes["connection"]
context.configure(
    connection=connection,
    target_metadata=None,
    version_table_schema="public",
    transactional_ddl=True,
    on_version_apply=config.attributes["on_version_apply"],
)
with context.begin_transaction():
    context.run_migrations()

"""D1 replacement for main's pre-cutover identity/autogenerate guard.

Canonical metadata and frozen history have their own retained guards; see
docs/inventories/d1_main_architecture_guard_disposition.md for the transfer.
These tests cover real ordinary Alembic entry before DB work and perturb the
actual installed owner graph, rather than preserving obsolete people mappings.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from dotmac_kernel.modules import ModuleRegistry
from dotmac_learning.manifest import module as learning_module

from alembic import command
from app.canonical_models import (
    ModelOwnershipError,
    compose_inspection_graph,
    declared_ownership,
    kernel_owned_tables,
    physical_key,
)
from app.config import settings
from app.migration_graph import ordinary_migration_config
from app.owner_composition import compose_migration_owner_declarations, inspect_owner_registry


@pytest.mark.parametrize("signal", ["cmd_opts", "revision_context"])
@pytest.mark.parametrize("supplied", [False, True], ids=["engine-path", "supplied-path"])
def test_actual_ordinary_env_refuses_autogenerate_before_any_database_entry(monkeypatch, signal, supplied):
    config = ordinary_migration_config()
    if supplied:
        # If the gate is late, this reaches the actual Connection type guard.
        config.attributes["connection"] = object()

    def forbid_database(*args, **kwargs):
        pytest.fail("autogenerate entered the database path before refusal")

    monkeypatch.setattr(sa, "create_engine", forbid_database)
    monkeypatch.setattr(sa.engine.Engine, "connect", forbid_database)
    monkeypatch.setattr(sa.engine.Connection, "execute", forbid_database)
    monkeypatch.setattr(sa.engine.Connection, "scalar", forbid_database)
    monkeypatch.setattr(
        "dotmac_kernel.migrations.configuration.select_migration_database_url", forbid_database,
    )
    with pytest.raises(ValueError, match="autogenerate unavailable: canonical owner metadata"):
        if signal == "cmd_opts":
            config.cmd_opts = SimpleNamespace(autogenerate=True)
            command.current(config)
        else:
            # This creates the real Alembic RevisionContext/EnvironmentContext,
            # with no cmd_opts signal and no substituted context implementation.
            assert config.cmd_opts is None
            command.revision(config, message="must refuse", autogenerate=True)


def test_ordinary_non_autogenerate_still_reaches_supplied_connection_validation():
    config = ordinary_migration_config()
    config.attributes["connection"] = object()
    with pytest.raises(ValueError, match="an actual open SQLAlchemy Connection is required"):
        command.current(config)


def test_ordinary_non_autogenerate_still_reaches_engine_entry(monkeypatch):
    class EngineEntryReached(Exception):
        pass

    def stop_at_engine(*args, **kwargs):
        raise EngineEntryReached

    monkeypatch.setattr(settings, "database_url", "postgresql+psycopg://inert@localhost/inert")
    monkeypatch.setattr(sa, "create_engine", stop_at_engine)
    with pytest.raises(EngineEntryReached):
        command.current(ordinary_migration_config())


def test_actual_installed_owner_graph_remains_closed_with_learning_disabled():
    declarations = tuple(
        replace(item, enabled_by_default=False) if item is learning_module else item
        for item in compose_migration_owner_declarations()
    )
    registry = ModuleRegistry(declarations)
    assert "learning" not in registry.enabled_codes()
    assert registry.get("learning").tables == learning_module.tables
    assert learning_module.migration_owner() in registry.namespaces().owners()
    owned = declared_ownership(registry, kernel_tables=kernel_owned_tables())
    graph = inspect_owner_registry(registry, declarations=declarations)
    copied = {physical_key(table): table for table in graph.metadata.tables.values()}
    assert set(copied) == {physical_key(item.table) for item in owned} == set(graph.owners)
    assert {key for key, owner in graph.owners.items() if owner == "learning"} == {
        (learning_module.db_schema, name)
        for name in (*learning_module.tables, *learning_module.platform_tables)
    }
    for item in owned:
        table = copied[physical_key(item.table)]
        assert table is not item.table
        assert graph.owners[physical_key(table)] == item.owner
        for column in item.table.columns:
            expected = {
                (physical_key(fk.column.table), fk.column.name, fk.ondelete)
                for fk in column.foreign_keys
            }
            actual = {
                (physical_key(fk.column.table), fk.column.name, fk.ondelete)
                for fk in table.c[column.name].foreign_keys
            }
            assert actual == expected
            for fk in table.c[column.name].foreign_keys:
                assert fk.column is copied[physical_key(fk.column.table)].c[fk.column.name]


def test_actual_owner_graph_refuses_missing_and_duplicate_kernel_owner():
    registry = ModuleRegistry(compose_migration_owner_declarations())
    owned = declared_ownership(registry, kernel_tables=kernel_owned_tables())
    tenant = next(item for item in owned if physical_key(item.table) == ("public", "tenants"))
    assert tenant.owner == "kernel"
    with pytest.raises(ModelOwnershipError, match="foreign key target has no declared owner"):
        compose_inspection_graph(tuple(item for item in owned if item is not tenant))
    with pytest.raises(ModelOwnershipError, match="duplicate physical table owner"):
        compose_inspection_graph((*owned, tenant))

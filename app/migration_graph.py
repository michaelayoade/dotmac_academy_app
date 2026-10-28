"""Canonical graph configuration, built before Alembic reads any revision.

Location resolvers are explicit assembly wiring: the public MigrationOwner
records identify lineages but do not publish package-location lookup methods.
The resolver set must match every actual installed owner, including disabled
modules. No naming convention guesses a distribution or a migration package.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path

from dotmac_kernel.migrations.gate import run_gate
from dotmac_kernel.modules import ModuleRegistry
from dotmac_kernel.planes import install_module_plane_selections
from dotmac_kernel.prerequisites import install_prerequisite_bindings

from alembic.config import Config
from app.migration_bindings import ASSEMBLY_PREREQUISITE_BINDINGS

BINDINGS_IMPORT = "app.migration_bindings:ASSEMBLY_PREREQUISITE_BINDINGS"
ROOT = Path(__file__).resolve().parent.parent
IDENTITY_VERSIONS = ROOT / "alembic" / "identity_assembly_versions"


def build_migration_config(
    assembly,
    *,
    owner_locations: Mapping[str, Callable[[], Path]],
    config: Config | None = None,
) -> Config:
    """Validate installed owners, then configure complete graph locations.

    Every supported command must call this before ScriptDirectory.from_config.
    The binding autoload channel also covers heads/history/show, which never
    execute env.py. This does not create an app, engine, connection or root.
    """
    registry = ModuleRegistry(assembly.modules)
    namespaces = registry.namespaces()
    owners = namespaces.owners()
    expected = {owner.owner for owner in owners}
    if set(owner_locations) != expected:
        raise ValueError("migration location resolvers must cover every installed owner exactly")
    if Path(assembly.assembly_migrations).resolve() != IDENTITY_VERSIONS.resolve():
        raise ValueError("ordinary adoption requires the complete identity assembly lineage")
    locations = tuple(
        Path(owner_locations[owner.owner]()).resolve()
        for owner in owners
    )
    if Path(owner_locations["assembly"]()).resolve() != IDENTITY_VERSIONS.resolve():
        raise ValueError("assembly locator must select complete identity lineage")
    if len(set(locations)) != len(locations) or not all(path.is_dir() for path in locations):
        raise ValueError("migration owners require distinct existing version locations")
    install_prerequisite_bindings(ASSEMBLY_PREREQUISITE_BINDINGS)
    install_module_plane_selections(assembly.module_planes)
    os.environ["DOTMAC_MIGRATION_BINDINGS"] = BINDINGS_IMPORT
    report = run_gate(
        registry.startup_order(),
        locations,
        registry=namespaces,
        bindings=ASSEMBLY_PREREQUISITE_BINDINGS,
        module_planes=assembly.module_planes,
    )
    if not report.ok:
        raise ValueError("invalid installed migration graph: " + "; ".join(report.violations))
    configured = config if config is not None else Config(str(ROOT / "alembic.ini"))
    configured.set_main_option("script_location", str(ROOT / "alembic"))
    configured.set_main_option("path_separator", "os")
    configured.set_main_option("version_path_separator", "os")
    configured.set_main_option("version_locations", os.pathsep.join(map(str, locations)))
    configured.attributes["academy_migration_registry"] = registry
    configured.attributes["module_plane_selections"] = assembly.module_planes
    configured.attributes["academy_migration_locations"] = locations
    return configured


def ordinary_migration_config(*, config: Config | None = None) -> Config:
    """Build graph-only composition from the shared genuine declarations."""
    from types import SimpleNamespace

    from dotmac_kernel.migrations import versions_dir as kernel_versions_dir
    from dotmac_learning.migrations import versions_dir as learning_versions_dir

    from app.owner_composition import compose_migration_owner_declarations

    declarations = SimpleNamespace(
        modules=compose_migration_owner_declarations(),
        assembly_migrations=IDENTITY_VERSIONS,
        module_planes=(),
    )
    return build_migration_config(
        declarations,
        owner_locations={
            "kernel": kernel_versions_dir,
            "learning": learning_versions_dir,
            "assembly": lambda: IDENTITY_VERSIONS,
        },
        config=config,
    )

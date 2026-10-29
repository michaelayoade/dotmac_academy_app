"""Pure source/propagation tests only; no catalog or import qualification."""

import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from dotmac_kernel import planes, prerequisites
from dotmac_kernel.migrations import versions_dir as kernel_versions
from dotmac_kernel.modules import ModuleRegistry
from dotmac_learning.manifest import module as learning_module
from dotmac_learning.migrations import versions_dir as learning_versions
from sqlalchemy.engine import Engine

from alembic.script import ScriptDirectory
from app import migration_graph as graph
from app.maintenance import account_token_identity as tokens
from app.maintenance import identity_history as identity
from app.maintenance import product_adoption as product
from app.owner_composition import compose_migration_owner_declarations


def _forbid(*args, **kwargs):
    pytest.fail("source composition cannot install globals, load a graph, or connect")


@pytest.fixture
def no_composition_effects(monkeypatch):
    for target, name in (
        (graph, "install_prerequisite_bindings"),
        (graph, "install_module_plane_selections"),
        (prerequisites, "install_prerequisite_bindings"),
        (planes, "install_module_plane_selections"),
        (graph, "run_gate"),
        (graph, "Config"),
        (ScriptDirectory, "from_config"),
        (sa, "create_engine"),
        (Engine, "connect"),
    ):
        monkeypatch.setattr(target, name, _forbid)


def test_fixed_source_helper_is_pure_complete_and_immutable(no_composition_effects):
    keys = ("DOTMAC_MIGRATION_BINDINGS", "DOTMAC_MODULE_PLANE_SELECTIONS")
    before = tuple(os.environ.get(key) for key in keys)
    source = graph.academy_migration_source()
    assert tuple(os.environ.get(key) for key in keys) == before
    assert source.registry.startup_order() == ModuleRegistry(compose_migration_owner_declarations()).startup_order()
    assert source.registry.get("learning") is learning_module
    assert dict(source.owner_versions) == {
        "kernel": kernel_versions().resolve(),
        "learning": learning_versions().resolve(),
        "assembly": graph.IDENTITY_VERSIONS.resolve(),
    }
    assert dict(source.module_versions) == {"learning": learning_versions().resolve()}
    assert source.assembly_versions == identity._ASSEMBLY_VERSIONS.resolve()
    assert source.bindings is graph.ASSEMBLY_PREREQUISITE_BINDINGS
    assert source.module_planes == ()
    with pytest.raises(TypeError):
        source.owner_versions["learning"] = Path("wrong")
    with pytest.raises(TypeError):
        source.module_versions["learning"] = Path("wrong")


def test_ordinary_config_consumes_same_pure_source_coordinates(monkeypatch, no_composition_effects):
    source = graph.academy_migration_source()
    result = object()
    calls = []
    monkeypatch.setattr(graph, "academy_migration_source", lambda: source)

    def build(assembly, *, owner_locations, config):
        calls.append(config)
        assert assembly.modules == source.registry.startup_order()
        assert assembly.assembly_migrations == source.assembly_versions
        assert assembly.module_planes == source.module_planes
        assert {owner: resolver() for owner, resolver in owner_locations.items()} == dict(source.owner_versions)
        return result

    monkeypatch.setattr(graph, "build_migration_config", build)
    assert graph.ordinary_migration_config() is result
    assert calls == [None]


def test_source_includes_disabled_learning(monkeypatch, no_composition_effects):
    from app.config import settings

    monkeypatch.setattr(settings, "disabled_features", "learning,academy")
    source = graph.academy_migration_source()
    assert source.registry.get("learning") is learning_module
    assert "learning" in source.module_versions


def _explicit(source):
    return {
        "module_registry": source.registry,
        "module_versions": dict(source.module_versions),
        "prerequisite_bindings": source.bindings,
    }


def test_identity_default_uses_fixed_source_not_installed_globals(monkeypatch, no_composition_effects):
    monkeypatch.setattr(prerequisites, "installed_bindings", _forbid)
    registry, versions, bindings = identity._resolve_identity_composition()
    assert registry.startup_order() == graph.academy_migration_source().registry.startup_order()
    assert dict(versions) == {"learning": learning_versions().resolve()}
    assert bindings is graph.ASSEMBLY_PREREQUISITE_BINDINGS


@pytest.mark.parametrize(
    "attack",
    [
        "none",
        "empty",
        "partial",
        "missing_learning",
        "wrong_path",
        "wrong_provider",
        "missing_binding",
        "missing_registry_owner",
        "extra_module_path",
        "untyped_binding",
        "string_path",
    ],
)
def test_explicit_incomplete_or_drifted_composition_is_not_repaired(attack, no_composition_effects):
    source = graph.academy_migration_source()
    kwargs = _explicit(source)
    if attack == "none":
        kwargs = dict.fromkeys(kwargs)
    elif attack == "empty":
        kwargs.update(module_versions={}, prerequisite_bindings=())
    elif attack == "partial":
        kwargs.pop("module_versions")
    elif attack == "missing_learning":
        kwargs["module_versions"] = {}
    elif attack == "wrong_path":
        kwargs["module_versions"] = {"learning": source.assembly_versions}
    elif attack == "wrong_provider":
        kwargs["prerequisite_bindings"] = (replace(source.bindings[0], provider_owner="assembly"), *source.bindings[1:])
    elif attack == "missing_binding":
        kwargs["prerequisite_bindings"] = source.bindings[:-1]
    elif attack == "missing_registry_owner":
        kwargs["module_registry"] = ModuleRegistry(
            tuple(module for module in source.registry.startup_order() if module is not learning_module)
        )
    elif attack == "extra_module_path":
        kwargs["module_versions"]["kernel"] = kernel_versions()
    elif attack == "untyped_binding":
        kwargs["prerequisite_bindings"] = tuple("not-a-binding" for _ in source.bindings)
    else:
        kwargs["module_versions"] = {"learning": str(learning_versions())}
    with pytest.raises(identity.IdentityHistoryImportRefused):
        identity._resolve_identity_composition(**kwargs)


def test_explicit_validation_retains_supplied_objects(no_composition_effects):
    source = graph.academy_migration_source()
    supplied = _explicit(source)
    registry, versions, bindings = identity._resolve_identity_composition(**supplied)
    assert registry is supplied["module_registry"]
    assert bindings is supplied["prerequisite_bindings"]
    assert versions is supplied["module_versions"]


def test_import_forwards_identical_resolved_objects_without_installing(monkeypatch, no_composition_effects):
    root = SimpleNamespace(is_active=True)
    connection = SimpleNamespace(info={}, get_transaction=lambda: root, execute=lambda statement: None)
    expected = SimpleNamespace(
        relations=SimpleNamespace(schema="academy_identity_compat"),
        cohort=SimpleNamespace(people=set(), user_credentials=set()),
    )
    receipt, operation = object(), object()
    calls = []
    supplied = _explicit(graph.academy_migration_source())
    monkeypatch.setattr(identity, "_connection_preflight", lambda actual: root)
    monkeypatch.setattr(identity, "_extension_targets_preflight", lambda actual: None)

    def register(actual, decoder, manifest, op, **composition):
        calls.append(("register", composition))
        assert composition["module_versions"] is not supplied["module_versions"]
        supplied["module_versions"].clear()
        with pytest.raises(TypeError):
            composition["module_versions"]["learning"] = Path("wrong")

    def import_owner(actual, decoder, manifest, op, **composition):
        decoder._connection, decoder._root = actual, root
        calls.append(("import", composition))
        return receipt

    def verify(actual, decoder, manifest, op, actual_receipt, **composition):
        assert actual_receipt is receipt
        calls.append(("verify", composition))

    monkeypatch.setattr(product, "_register_identity_import", register)
    monkeypatch.setattr(identity, "import_identity_history", import_owner)
    monkeypatch.setattr(identity, "_verify_identity_import_data", verify)
    monkeypatch.setattr(tokens, "_record_identity_import", lambda *args: None)
    assert identity.import_academy_identity_history(connection, expected, operation, **supplied) is receipt
    assert [stage for stage, _ in calls] == ["register", "import", "verify"]
    for name in ("module_registry", "module_versions", "prerequisite_bindings"):
        assert all(values[name] is calls[0][1][name] for _, values in calls)
    assert dict(calls[0][1]["module_versions"]) == {"learning": learning_versions().resolve()}
    assert calls[1][1]["assembly_versions"] == graph.IDENTITY_VERSIONS


@pytest.mark.parametrize("defaults", [False, True])
def test_direct_verifier_validates_source_and_preserves_explicit_map(monkeypatch, no_composition_effects, defaults):
    root = object()
    connection = SimpleNamespace(scalars=lambda statement: ())
    captured = identity._IdentitySnapshot(rows=object(), accounts=(), policies=(), target_oids=())
    decoder = identity.AcademyIdentityHistoryDecoder()
    decoder._connection, decoder._root, decoder._snapshot = connection, root, captured
    supplied = _explicit(graph.academy_migration_source())
    observed = []
    monkeypatch.setattr(identity, "_connection_preflight", lambda actual: root)
    monkeypatch.setattr(identity, "_target_oids", lambda actual: ())
    monkeypatch.setattr(identity, "_extension_catalog_preflight", lambda actual: None)

    def decode(reread, actual):
        reread._snapshot = captured
        return captured.rows

    def verify(*args, **composition):
        observed.append(composition)

    monkeypatch.setattr(identity.AcademyIdentityHistoryDecoder, "decode", decode)
    monkeypatch.setattr(identity, "verify_identity_history", verify)
    identity._verify_identity_import_data(
        connection, decoder, object(), object(), object(), **({} if defaults else supplied)
    )
    assert len(observed) == 1
    actual = observed[0]
    if not defaults:
        for name in supplied:
            assert actual[name] is supplied[name]
    assert actual["module_registry"].startup_order() == graph.academy_migration_source().registry.startup_order()
    assert dict(actual["module_versions"]) == {"learning": learning_versions().resolve()}
    assert actual["prerequisite_bindings"] is graph.ASSEMBLY_PREREQUISITE_BINDINGS
    if defaults:
        with pytest.raises(TypeError):
            actual["module_versions"]["learning"] = Path("wrong")


@pytest.mark.parametrize("name", ["module_registry", "module_versions", "prerequisite_bindings"])
@pytest.mark.parametrize("attack", ["none", "omitted", "only"])
def test_each_explicit_composition_argument_must_be_complete(name, attack, no_composition_effects):
    kwargs = _explicit(graph.academy_migration_source())
    if attack == "none":
        kwargs[name] = None
    elif attack == "omitted":
        kwargs.pop(name)
    else:
        kwargs = {name: kwargs[name]}
    with pytest.raises(identity.IdentityHistoryImportRefused):
        identity._resolve_identity_composition(**kwargs)


def test_direct_verifier_refuses_explicit_binding_drift_before_data_reads(monkeypatch, no_composition_effects):
    decoder = identity.AcademyIdentityHistoryDecoder()
    monkeypatch.setattr(identity, "_connection_preflight", lambda actual: object())
    monkeypatch.setattr(identity, "_target_oids", _forbid)
    monkeypatch.setattr(identity, "verify_identity_history", _forbid)
    source = graph.academy_migration_source()
    with pytest.raises(identity.IdentityHistoryImportRefused):
        identity._verify_identity_import_data(
            object(),
            decoder,
            object(),
            object(),
            object(),
            module_registry=source.registry,
            module_versions=source.module_versions,
            prerequisite_bindings=(),
        )

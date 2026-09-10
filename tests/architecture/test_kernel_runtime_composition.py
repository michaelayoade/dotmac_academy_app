"""Academy's `dimensional-composition.v2` record is validated by Academy's
own CI, against Academy's own tree — Starter's protected-main revision is
cited, never re-fetched at test time.

`composition_schema.py` in this directory is a byte-for-byte mirror of the
frozen contract at `dotmac_starter_mt`'s `tests/architecture/composition_schema.py`
on protected main `08a2dae1b1f6510e9d1076ac9dbd6eca0db06137` — see that
module's own docstring for the full v1->v2 rationale. This file never
imports `dotmac_starter_mt`; the schema is copied, not imported, because
these are two separate repositories and Academy's CI cannot open the other
one's files at test time (the same constraint the schema module's own
docstring states about its ERP/Sub controls).

`tests/architecture/fixtures/starter_catalogue_08a2dae1/packages/` is a
pinned MIRROR of every `packages/*/EXTRACTION.toml` (plus, for every
`optional-module` distribution, its `manifest.py`) in `dotmac_starter_mt` at
that same revision — the product-independent catalogue universe Ruling 2
requires every product's record to be checked against. It is data, not
code: nothing here re-derives Starter's own classification decisions, it
only reads what Starter's dossiers already say, offline, at the pinned
commit.

This module's job is exactly the readiness test's job for a different
record: read `docs/kernel-runtime-composition.json`, independently
re-measure every dimension directly from Academy's own `pyproject.toml`,
`poetry.lock`, `app/assembly.py`, and `alembic/versions/*.py`, and assert
the two agree — field by field, never as one aggregate pass/fail.
"""

from __future__ import annotations

import ast
import copy
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import composition_schema as cs  # noqa: E402

RECORD_PATH = ROOT / "docs" / "kernel-runtime-composition.json"
PACKAGES_ROOT = Path(__file__).resolve().parent / "fixtures" / "starter_catalogue_08a2dae1" / "packages"
STARTER_REVISION = "08a2dae1b1f6510e9d1076ac9dbd6eca0db06137"
EXPECTED_PRODUCT = "dotmac_academy_app"
EXPECTED_TOP_LEVEL_KEYS = {
    "schema_version",
    "product",
    "starter_protected_main_revision",
    "catalogue_size",
    "records",
}
RECORD_REQUIRED_KEYS = {
    "schema_version",
    "product",
    "distribution",
    "classification",
    "installation",
    "module_registration",
    "migration_lineage",
    "runtime_consumption",
    "evidence",
}


def _load_record() -> dict[str, Any]:
    return json.loads(RECORD_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Ground-truth measurement of Academy's own tree — independent of, and never
# imported from, the record under test.
# ---------------------------------------------------------------------------


def _measure_installed_dotmac_distributions(root: Path = ROOT) -> set[str]:
    """[tool.poetry.dependencies] (a table) and poetry.lock must agree on
    which `dotmac-*` distributions are resolved; [project].dependencies,
    when it is a non-empty list, must be PEP 508 strings and must not name a
    `dotmac-*` distribution the poetry table disagrees about. Disagreement
    refuses (raises), it is never silently reconciled."""
    pyproject = tomllib.loads((root / "pyproject.toml").read_text())
    poetry_section = pyproject.get("tool", {}).get("poetry", {})
    poetry_deps = poetry_section.get("dependencies")
    if not isinstance(poetry_deps, dict):
        raise ValueError("[tool.poetry.dependencies] is not a table")

    project_deps = pyproject.get("project", {}).get("dependencies")
    project_dotmac: set[str] = set()
    if isinstance(project_deps, list):
        for entry in project_deps:
            if not isinstance(entry, str):
                raise ValueError(f"[project].dependencies entry {entry!r} is not a PEP 508 string")
            name = entry.split(";")[0].strip()
            for sep in ("==", ">=", "<=", "^", "~", ">", "<", "[", " "):
                name = name.split(sep)[0]
            name = name.strip()
            if name.startswith("dotmac-"):
                project_dotmac.add(name)
    elif project_deps is not None:
        raise ValueError("[project].dependencies is declared but is not a list")

    poetry_dotmac = {name for name in poetry_deps if name.startswith("dotmac-")}
    if project_dotmac and project_dotmac != poetry_dotmac:
        raise ValueError(
            f"[project].dependencies names {sorted(project_dotmac)} but "
            f"[tool.poetry.dependencies] names {sorted(poetry_dotmac)} — disagreement refused"
        )

    lock = tomllib.loads((root / "poetry.lock").read_text())
    locked_dotmac = {pkg["name"] for pkg in lock.get("package", []) if pkg["name"].startswith("dotmac-")}
    if locked_dotmac != poetry_dotmac:
        raise ValueError(
            f"pyproject.toml declares {sorted(poetry_dotmac)} but poetry.lock resolves "
            f"{sorted(locked_dotmac)} — poetry.lock must prove resolution of exactly the declared set"
        )
    return poetry_dotmac


def _find_single_call(tree: ast.Module, name: str) -> ast.Call:
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name
    ]
    if len(calls) != 1:
        raise ValueError(f"expected exactly one {name}(...) call, found {len(calls)}")
    return calls[0]


def _measure_registered_module_names(assembly_source: str) -> set[str]:
    """The `Name` references bound into `ProductAssemblySpec(modules=(...))`
    — read by AST, never text search. A distribution imported anywhere in
    `assembly_source` but never placed in this tuple is NOT registered; only
    membership in the tuple itself counts."""
    tree = ast.parse(assembly_source)
    call = _find_single_call(tree, "ProductAssemblySpec")
    modules_kw = next((kw for kw in call.keywords if kw.arg == "modules"), None)
    if modules_kw is None or not isinstance(modules_kw.value, ast.Tuple):
        raise ValueError("ProductAssemblySpec(...) has no literal modules=(...) tuple")
    names: set[str] = set()
    for elt in modules_kw.value.elts:
        if isinstance(elt, ast.Name):
            names.add(elt.id)
        else:
            raise ValueError(f"modules= tuple element {ast.dump(elt)!r} is not a plain Name reference")
    return names


def _measure_alembic_combined_text(root: Path = ROOT) -> str:
    versions_dir = root / "alembic" / "versions"
    return "\n".join(p.read_text() for p in sorted(versions_dir.glob("*.py")))


def _lineage_schema_token_present(alembic_text: str, migration_prefix: str) -> bool:
    """The ONLY signal treated as lineage-present: the immutable `mod_<short_code>`
    schema-qualifying token (Starter rule 14). A bare `migration_prefix`/
    `short_code` string is deliberately never matched on its own — several
    real prefixes/short_codes (e.g. `people`) are ordinary English words that
    also occur throughout Academy's own unrelated product vocabulary, and a
    substring match on those would manufacture a false lineage-present
    finding."""
    return f"mod_{migration_prefix}" in alembic_text


def _measure_imported_top_level_packages(root: Path = ROOT) -> set[str]:
    """Every top-level package name imported anywhere under `app/`, by AST —
    never a grep — across every `app/**/*.py` file."""
    names: set[str] = set()
    for py_file in (root / "app").rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    names.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names.add(node.module.split(".")[0])
    return names


def _expected_dimensions_for(
    dossier: cs.PackageDossier,
    *,
    installed: set[str],
    registered_module_names: set[str],
    alembic_text: str,
    imported_packages: set[str],
) -> dict[str, str]:
    """Rebuild what every dimension SHOULD be for one dossier, from Academy's
    own measured tree — the ground truth the committed record is checked
    against. Mirrors `composition_record_from_payload`'s own applicability
    rules exactly (it is the authority on what NOT_APPLICABLE means), but
    computes Academy-specific installation/registration/lineage/runtime
    facts independently."""
    dist = dossier.distribution
    import_pkg = dist.replace("-", "_")
    classification = dossier.classification

    is_installed = dist in installed
    installation = cs.DimensionValue.TRUE if is_installed else cs.DimensionValue.FALSE

    if classification.module_registration_applies:
        # Academy's own manifest names are never one of the catalogue's own
        # distributions; only genuine tuple membership would flip this.
        module_registration = (
            cs.DimensionValue.TRUE if import_pkg in registered_module_names else cs.DimensionValue.FALSE
        )
    else:
        module_registration = cs.DimensionValue.NOT_APPLICABLE

    manifest_applies = False
    if classification is cs.PackageClassification.OPTIONAL_MODULE:
        manifest_applies = cs.derive_migration_lineage_applicability_from_manifest(PACKAGES_ROOT, dist)
    lineage_applies = classification.migration_lineage_applies(manifest_applies)

    if lineage_applies:
        manifest_path = cs._manifest_source_path(PACKAGES_ROOT, dist)
        manifest_tree = ast.parse(manifest_path.read_text())
        call = cs._find_module_manifest_call(manifest_tree)
        prefix_val = next(
            (
                kw.value.value
                for kw in call.keywords
                if kw.arg == "migration_prefix" and isinstance(kw.value, ast.Constant)
            ),
            None,
        )
        present = (
            isinstance(prefix_val, str) and bool(prefix_val) and _lineage_schema_token_present(alembic_text, prefix_val)
        )
        migration_lineage = cs.DimensionValue.TRUE if present else cs.DimensionValue.FALSE
    else:
        migration_lineage = cs.DimensionValue.NOT_APPLICABLE

    runtime_present = import_pkg in imported_packages
    runtime_consumption = cs.DimensionValue.TRUE if runtime_present else cs.DimensionValue.FALSE

    return {
        "installation": installation.value,
        "module_registration": module_registration.value,
        "migration_lineage": migration_lineage.value,
        "runtime_consumption": runtime_consumption.value,
    }


# ---------------------------------------------------------------------------
# Record-level validation
# ---------------------------------------------------------------------------


def _validate_record(record: dict[str, Any]) -> None:
    assert set(record.keys()) == EXPECTED_TOP_LEVEL_KEYS, (
        f"unexpected top-level keys: {set(record.keys()) - EXPECTED_TOP_LEVEL_KEYS} "
        f"(missing: {EXPECTED_TOP_LEVEL_KEYS - set(record.keys())})"
    )
    assert record["schema_version"] == cs.CURRENT_SCHEMA_VERSION
    assert record["product"] == EXPECTED_PRODUCT
    assert record["starter_protected_main_revision"] == STARTER_REVISION

    universe = cs.derive_distribution_universe(PACKAGES_ROOT)
    universe_by_name = {d.distribution: d for d in universe}
    assert record["catalogue_size"] == len(universe)

    records = record["records"]
    seen: set[str] = set()
    for raw in records:
        assert set(raw.keys()) == RECORD_REQUIRED_KEYS, (
            f"{raw.get('distribution')!r}: unexpected record keys "
            f"{set(raw.keys()) - RECORD_REQUIRED_KEYS} (missing: {RECORD_REQUIRED_KEYS - set(raw.keys())})"
        )
        dist = raw["distribution"]
        assert dist not in seen, f"duplicate record for {dist!r}"
        seen.add(dist)
        assert dist in universe_by_name, f"{dist!r} is not in the pinned catalogue universe"

        # Must be independently constructible by the frozen contract itself —
        # this is what proves the payload is coherent under v2, not just
        # shaped like JSON.
        built = cs.composition_record_from_payload(raw, PACKAGES_ROOT)
        cs.derive_composition_state(built)  # must not raise

    assert seen == set(universe_by_name), (
        f"record is missing distributions {set(universe_by_name) - seen} "
        f"or carries unknown ones {seen - set(universe_by_name)}"
    )

    installed = _measure_installed_dotmac_distributions()
    registered = _measure_registered_module_names((ROOT / "app" / "assembly.py").read_text())
    alembic_text = _measure_alembic_combined_text()
    imported = _measure_imported_top_level_packages()

    for raw in records:
        dossier = universe_by_name[raw["distribution"]]
        expected = _expected_dimensions_for(
            dossier,
            installed=installed,
            registered_module_names=registered,
            alembic_text=alembic_text,
            imported_packages=imported,
        )
        for dimension, expected_value in expected.items():
            actual_value = raw[dimension]
            assert actual_value == expected_value, (
                f"{raw['distribution']}/{dimension}: record claims {actual_value!r} but this tree "
                f"measures {expected_value!r}"
            )


def test_kernel_runtime_composition_record_is_truthful() -> None:
    """Near-miss control: the actual, unmodified record passes every check —
    proof that truthful `false` dimensions across nearly the whole catalogue
    are accepted, not rejected by construction."""
    _validate_record(_load_record())


@pytest.mark.parametrize(
    "distribution,dimension",
    [
        ("dotmac-billing", "installation"),
        ("dotmac-billing", "module_registration"),
        ("dotmac-billing", "migration_lineage"),
        ("dotmac-deployment-foundation", "installation"),
        ("dotmac-document-rendering", "module_registration"),
    ],
)
def test_flipping_a_measured_false_dimension_to_true_is_caught(distribution: str, dimension: str) -> None:
    """Plant: a genuinely false dimension flipped to true fails the build,
    naming the offending distribution.

    Two distinct, both-acceptable failure shapes: for an installed
    distribution, only the ground-truth comparison below can catch the lie
    (`AssertionError`). For a NOT-installed distribution, flipping
    `module_registration`/`migration_lineage` to `true` alongside
    `installation=false` is also a cross-dimensional contradiction the
    frozen contract itself refuses first, at construction
    (`DimensionalIncoherence`, step 3 of `derive_composition_state`'s
    pipeline) — that is an earlier, stricter catch of the same lie, not a
    gap in this validator."""
    record = copy.deepcopy(_load_record())
    (row,) = [r for r in record["records"] if r["distribution"] == distribution]
    assert row[dimension] == "false", f"fixture assumption broken: {distribution}/{dimension} is not recorded false"
    row[dimension] = "true"
    with pytest.raises((AssertionError, cs.DimensionalIncoherence), match=distribution):
        _validate_record(record)


def test_every_catalogue_distribution_has_exactly_one_record() -> None:
    record = _load_record()
    universe = cs.derive_distribution_universe(PACKAGES_ROOT)
    recorded = {r["distribution"] for r in record["records"]}
    assert recorded == {d.distribution for d in universe}


# ---------------------------------------------------------------------------
# Control: an optional-module distribution reporting NOT_APPLICABLE for a
# dimension that genuinely applies is refused; a genuinely stateless one for
# lineage is accepted.
# ---------------------------------------------------------------------------


def _base_optional_module_payload(distribution: str) -> dict[str, Any]:
    (row,) = [r for r in _load_record()["records"] if r["distribution"] == distribution]
    payload = {k: v for k, v in row.items() if k != "evidence"}
    return payload


def test_optional_module_cannot_record_registration_not_applicable() -> None:
    payload = _base_optional_module_payload("dotmac-billing")
    payload["module_registration"] = "not_applicable"
    with pytest.raises(ValueError, match="module_registration"):
        cs.composition_record_from_payload(payload, PACKAGES_ROOT)


def test_optional_module_with_applicable_lineage_cannot_record_lineage_not_applicable() -> None:
    payload = _base_optional_module_payload("dotmac-billing")
    payload["migration_lineage"] = "not_applicable"
    with pytest.raises(ValueError, match="migration_lineage"):
        cs.composition_record_from_payload(payload, PACKAGES_ROOT)


def test_genuinely_stateless_optional_module_accepts_lineage_not_applicable() -> None:
    """dotmac-document-rendering's own manifest declares neither short_code
    nor migration_prefix, and no tables/platform_tables/migration_branch —
    Ruling 1 outcome 2. Its migration_lineage=not_applicable payload is
    accepted, proving the refusal above is about genuine applicability, not
    a blanket rejection of not_applicable."""
    payload = _base_optional_module_payload("dotmac-document-rendering")
    assert payload["migration_lineage"] == "not_applicable"
    built = cs.composition_record_from_payload(payload, PACKAGES_ROOT)
    assert built.migration_lineage is cs.DimensionValue.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# Control: a distribution imported somewhere but never registered through
# the consumed assembly measures module_registration=false — paired with a
# genuine positive where tuple membership does flip it true.
# ---------------------------------------------------------------------------


def test_import_without_tuple_membership_is_not_registration() -> None:
    source = (
        "from dotmac_billing import billing_feature\n"
        "assembly = ProductAssemblySpec(\n"
        "    name='x',\n"
        "    modules=(),\n"
        ")\n"
    )
    registered = _measure_registered_module_names(source)
    assert "billing_feature" not in registered
    assert registered == set()


def test_tuple_membership_is_registration() -> None:
    source = (
        "from dotmac_billing import billing_feature\n"
        "assembly = ProductAssemblySpec(\n"
        "    name='x',\n"
        "    modules=(billing_feature,),\n"
        ")\n"
    )
    registered = _measure_registered_module_names(source)
    assert registered == {"billing_feature"}


# ---------------------------------------------------------------------------
# Control: a planted lineage token adds lineage for a distribution that
# lacked it.
# ---------------------------------------------------------------------------


def test_planted_schema_token_flips_lineage_present() -> None:
    alembic_text = _measure_alembic_combined_text()
    assert not _lineage_schema_token_present(
        alembic_text, "bi"
    ), "fixture assumption broken: mod_bi already present in Academy's alembic tree"
    planted = alembic_text + "\nSCHEMA = 'mod_bi'\n"
    assert _lineage_schema_token_present(planted, "bi")


def test_ordinary_english_short_code_does_not_manufacture_lineage() -> None:
    """`people` is both a real distribution's `short_code` and an ordinary
    word Academy's own domain vocabulary uses; a naive substring match on
    the bare short_code (rather than the `mod_<prefix>` schema token) would
    wrongly report lineage as present. Confirm the schema-token check is not
    fooled by that coincidence."""
    text_with_the_word_people_but_no_module_schema = "class PersonProfile:\n    '''people table'''\n"
    assert not _lineage_schema_token_present(text_with_the_word_people_but_no_module_schema, "pe")


# ---------------------------------------------------------------------------
# Control: missing input refuses rather than yielding an empty set.
# ---------------------------------------------------------------------------


def test_missing_packages_root_refuses(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    with pytest.raises(cs.CatalogueDerivationError):
        cs.derive_distribution_universe(missing)


def test_missing_pyproject_refuses(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        _measure_installed_dotmac_distributions(tmp_path)


# ---------------------------------------------------------------------------
# Control: the catalogue derivation is non-vacuous — a synthetic dossier
# enters the universe, and a packages/<x>/ with no dossier refuses rather
# than being skipped.
# ---------------------------------------------------------------------------


def test_synthetic_dossier_enters_the_universe(tmp_path: Path) -> None:
    pkg_dir = tmp_path / "dotmac-synthetic-contract-catalogue"
    pkg_dir.mkdir()
    (pkg_dir / "EXTRACTION.toml").write_text(
        'package = "dotmac-synthetic-contract-catalogue"\n' 'classification = "stateless-contract-catalogue"\n'
    )
    universe = cs.derive_distribution_universe(tmp_path)
    assert {d.distribution for d in universe} == {"dotmac-synthetic-contract-catalogue"}
    assert universe[0].classification is cs.PackageClassification.STATELESS_CONTRACT_CATALOGUE


def test_package_directory_with_no_dossier_refuses_not_skips(tmp_path: Path) -> None:
    pkg_dir = tmp_path / "dotmac-no-dossier"
    pkg_dir.mkdir()
    with pytest.raises(cs.CatalogueDerivationError, match="no EXTRACTION.toml"):
        cs.derive_distribution_universe(tmp_path)


# ---------------------------------------------------------------------------
# Control: dependency authority. [project].dependencies is a list of PEP 508
# strings, [tool.poetry.dependencies] a table; disagreement refuses;
# poetry.lock proves resolution.
# ---------------------------------------------------------------------------


def test_dependency_authority_agrees_on_the_real_tree() -> None:
    installed = _measure_installed_dotmac_distributions()
    assert installed == {"dotmac-kernel", "dotmac-ui"}


def test_project_dependencies_table_instead_of_list_refuses(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n" 'dependencies = { not = "a list" }\n' "[tool.poetry.dependencies]\n" 'python = ">=3.12"\n'
    )
    (tmp_path / "poetry.lock").write_text("")
    with pytest.raises(ValueError, match="not a list"):
        _measure_installed_dotmac_distributions(tmp_path)


def test_project_and_poetry_dependency_disagreement_refuses(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'dependencies = ["dotmac-billing>=1.0"]\n'
        "[tool.poetry.dependencies]\n"
        'python = ">=3.12"\n'
        'dotmac-kernel = "0.1.0a38"\n'
    )
    (tmp_path / "poetry.lock").write_text("[[package]]\n" 'name = "dotmac-kernel"\n' 'version = "0.1.0a38"\n')
    with pytest.raises(ValueError, match="disagreement refused"):
        _measure_installed_dotmac_distributions(tmp_path)


def test_poetry_lock_disagreeing_with_declared_dependencies_refuses(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'dynamic = ["dependencies"]\n'
        "[tool.poetry.dependencies]\n"
        'python = ">=3.12"\n'
        'dotmac-kernel = "0.1.0a38"\n'
    )
    (tmp_path / "poetry.lock").write_text("")  # resolves nothing
    with pytest.raises(ValueError, match="poetry.lock"):
        _measure_installed_dotmac_distributions(tmp_path)

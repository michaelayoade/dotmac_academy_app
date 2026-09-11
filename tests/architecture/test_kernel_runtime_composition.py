"""Academy's `dimensional-composition.v2` record is validated by Academy's
own CI, against Academy's own tree — Starter's protected-main revision is
cited, never re-fetched at test time.

`composition_schema.py` in this directory is a byte-for-byte mirror of the
frozen contract at `dotmac_starter_mt`'s `tests/architecture/composition_schema.py`
on protected main `a9dc45ecd00d5a0163b6544278888220082e2e75` — see that
module's own docstring for the full v1->v2 rationale, and in particular
"What `installation` means" for the production-profile ruling this file's
own installation derivation follows. This file never imports
`dotmac_starter_mt`; the schema is copied, not imported, because these are
two separate repositories and Academy's CI cannot open the other one's files
at test time (the same constraint the schema module's own docstring states
about its ERP/Sub controls).

`tests/architecture/fixtures/starter_catalogue_a9dc45ec/packages/` is a
pinned MIRROR of every `packages/*/EXTRACTION.toml` (plus, for every
`optional-module` distribution, its `manifest.py`) in `dotmac_starter_mt` at
that same revision — the product-independent catalogue universe Ruling 2
requires every product's record to be checked against. It is data, not
code: nothing here re-derives Starter's own classification decisions, it
only reads what Starter's dossiers already say, offline, at the pinned
commit. `packages/` itself is byte-identical between `08a2dae1` (this
mirror's previous pin) and `a9dc45ec` (confirmed: `git diff --stat
08a2dae1...a9dc45ec -- packages/` is empty upstream), so only the mirror's
directory name and the schema module changed for this revision bump.

This module's job is exactly the readiness test's job for a different
record: read `docs/kernel-runtime-composition.json`, independently
re-measure every dimension directly from Academy's own `pyproject.toml`,
`poetry.lock`, `app/assembly.py`, `alembic/versions/*.py`, and an AST import
graph rooted at Academy's own declared production entry points, and assert
the two agree — field by field, never as one aggregate pass/fail.

The `installation` dimension: no authoritative recipe, so `unknown`
------------------------------------------------------------------------
Ruled by Michael: `installation` is derived against Academy's own checked-in
PRODUCTION installation path; absent one, every distribution's `installation`
is `unknown` — never `false`, and never a fallback to `poetry.lock`
membership (exactly the reading the frozen contract's own docstring calls
out and forbids).

`_locate_production_install_recipes` is the one search this module performs,
and it is exercised by both a positive control (a synthetic `Dockerfile`
with a real `RUN poetry install` line IS found) and against Academy's own
real tree (nothing is found) — see the two tests bracketing it below. What
was checked, concretely, against this real repository:

* No `Dockerfile*` exists anywhere under this repository (searched
  recursively, excluding `.git`, `node_modules`, and the pinned Starter
  fixture mirror).
* `docker-compose.prod.yml` declares exactly one service (`db`), uses
  `image: postgres:16`, and carries no `build:` key — confirmed
  structurally, via `yaml.safe_load` against the real `services` mapping,
  by `test_docker_compose_prod_has_exactly_one_service_with_no_build_
  stanza` below (a bare `"build:" not in text` substring check would miss a
  second service pulling a prebuilt image; this reads the parsed document).
* Exactly TWO workflow files exist under `.github/workflows/`:
  `ci.yml` and `engineering-standards.yml` — confirmed by
  `test_workflow_files_are_exactly_ci_and_engineering_standards` below, not
  asserted narratively. `ci.yml` declares one job (`test`) whose
  `poetry install --no-interaction --no-root` step installs the CI runner's
  test environment, not a deployed production artifact.
  `engineering-standards.yml` declares two jobs (`pin-preflight`,
  `standards`) and installs nothing at all — its own checked-in comment
  says so ("Standard library only: no install step can be trusted to run
  before the gate that decides whether this adoption is armed at all").
  `_enumerate_workflow_install_steps` reads every workflow file's `jobs`
  mapping structurally (via `yaml.safe_load`, never a text scan across the
  whole file) and confirms the only `poetry install`/`poetry sync` step
  anywhere under `.github/workflows/` belongs to `ci.yml`'s `test` job —
  see `test_only_the_ci_test_job_installs_dependencies_across_every_
  workflow` and `test_engineering_standards_workflow_installs_nothing`.
* `deploy/*.service` (the real systemd units Academy ships) each `ExecStart`
  a pre-built `/home/dotmac/projects/dotmac_academy_app/.venv/bin/python`
  directly — none of them contains an install command; whatever provisions
  that `.venv` is not a checked-in recipe this repository carries.
* `README.md`'s only `poetry install` line sits under the `## Local
  development` heading (confirmed by `test_readme_poetry_install_is_scoped_
  to_local_development` below) — explicitly not a production artifact.

Named, dismissed counter-evidence (Michael's item 5)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Two checked-in statements assert that Poetry DOES run on Academy's
production host — the record must not read as though the tree is silent
about production installation, when it is specific but incomplete.
`_locate_counter_evidence_for_production_installation` finds both by
content (never a hardcoded line number) and `test_counter_evidence_
statements_are_found_and_named` proves both are real, present statements
today, not a claim this module merely asserts:

* `README.md`: "Poetry's version is pinned — in CI and on the production
  host alike" (under the "Local development" heading, immediately before
  the pin rationale).
* `.github/workflows/ci.yml`: a comment on the pinned-Poetry-install step,
  "it must stay in step with the academy production host, which runs the
  same version from `/usr/local/bin`".

Both are DISMISSED as recipes, explicitly, not silently: neither supplies
an install command, a dependency-group selection, or a target artifact —
they assert Poetry EXISTS on the production host, never what it is told to
install there or from what checked-in source. The distance between
`installation: unknown x95` and what a bare `poetry install` against
Academy's real lock would actually resolve (`true` for `dotmac-kernel`,
`false` for the rest, per `test_derive_installation_dimension_would_say_
true_with_a_real_recipe` below) rests entirely on this dismissal — on the
ruling that a statement naming a host and a toolchain, with no command, is
not a recipe. Both statements are recorded in every row's
`evidence.installation` string precisely so a future reader does not
mistake "no recipe" for "no evidence found."

Because no recipe is authoritative, `derive_installation_dimension` is
called with `recipes=_locate_production_install_recipes(ROOT)` for every
distribution — that tuple is empty today, but the call always flows
through the search function itself rather than a hard-coded `recipes=()`;
if a recipe ever appears on disk, this derivation changes by itself,
without this file's own code changing. The frozen contract is what then
returns `DimensionValue.UNKNOWN` uniformly (see that function's own
docstring: an empty `recipes` tuple makes `derive_installation_group_
universe` refuse, which `derive_installation_dimension` turns into
`UNKNOWN` regardless of what `poetry.lock` resolves). Under the derivation
pipeline this yields `EVIDENCE_INCOMPLETE` for every applicable row rather
than `NOT_COMPOSED` — expected, not a defect to engineer around.

The search perimeter, stated honestly (ADR-0018)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
`_locate_production_install_recipes` globs `Dockerfile*` only; that is a
real mechanism, not a hand-written claim, but it does not by itself cover
every shape a production install recipe could take.
`_search_additional_deploy_recipe_families` closes most of that gap as
CODE rather than leaving it as a one-time manual claim: it structurally
checks for `Makefile`, `Procfile`, `fly.toml`, `render.yaml`, `app.yaml`,
`.ebextensions/`, `ansible/`, `helm/`, `charts/`, `k8s/`, `terraform/`,
`infra/`, every `*.sh` file, and every `ExecStartPre`/`ExecStartPost` hook
in `deploy/*.service` — the exact family list an independent review
searched by hand and confirmed absent (see
`test_no_additional_deploy_recipe_family_exists`). What remains
UNMONITORED by this module's own code, named explicitly rather than
silently treated as exempt (rule 23 / ADR-0018): a recipe embedded in a
CI vendor config this repository does not use (no `.gitlab-ci.yml`, no
`.circleci/`, checked structurally above only for `.github/workflows/*`),
or a recipe living in a file whose name matches none of the families
above at all. That residual is real and is not claimed to be covered.

The provenance plant this file would normally carry — copy the real
production recipe to a temp path, rewrite its install line to select a
different profile, leave the record unchanged, and prove the validator
reports the mismatch — is NOT CONSTRUCTIBLE here: there is no real recipe
file to copy and mutate. What this file proves instead is the search
itself: `test_locate_production_install_recipes_finds_a_real_dockerfile`
(positive control — the search mechanism can say yes) paired with
`test_locate_production_install_recipes_finds_none_in_this_tree` (the real,
un-mutated claim about Academy's own tree — the near-miss control, proving
the search is not vacuously empty by construction).

The `runtime_consumption` dimension: an AST import graph from real entry points
---------------------------------------------------------------------------------
Academy's declared production entry points are exactly two, both confirmed
by reading real files rather than assumed: `app.main` (the ASGI app
`README.md`'s `uvicorn app.main:app` command runs) and `app.cli` (every
`deploy/*.service` unit's `ExecStart` invokes `python -m app.cli <command>`;
confirmed there is no third entry point anywhere in `deploy/*.service` or
`README.md`). `_build_app_import_graph` reads every `app/**/*.py` file's real
`ast.Import`/`ast.ImportFrom` nodes — never a substring or an intermediary
needle — into an internal (`app.*` -> `app.*`) edge set and an external
(top-level `dotmac_*`) import set per module;
`_measure_reachable_dotmac_imports` walks the internal edges breadth-first
from the two entry points and returns the union of external imports reached
along the way. A distribution's `runtime_consumption` is `true` only if a
real import of it is reachable from a real entry point through real internal
edges — see `test_deleting_the_real_import_breaks_reachability` and
`test_a_comment_mentioning_an_import_is_not_reachability` below for the
sensitivity proof this dimension carries (an ERP review previously found a
needle-based version of this exact check pass with the real import deleted;
this dimension is built to not repeat that shape).

`test_academy_entry_points_are_exactly_main_and_cli` refuses, rather than
silently skips, an `ExecStart` line it cannot parse as a `-m <module>`
target — an earlier version only collected lines containing `-m `, so an
`ExecStart=.../uvicorn app.main:app` or a direct script path would have
been skipped rather than refused, and a third entry point could have hidden
behind that gap undetected. `test_every_dotmac_import_anywhere_under_app_
is_exactly_kernel_and_ui` is the independent backstop that makes the
`runtime_consumption` conclusion robust rather than lucky: it asserts the
set of top-level `dotmac_*` imports across EVERY module under `app/` (not
only the ones reachable from the two declared entry points) is exactly
`{dotmac_kernel, dotmac_ui}` — so even a missed entry point could not
currently hide a reachable-but-unlisted distribution.

The `module_registration` dimension: origin-resolved, not name-compared
---------------------------------------------------------------------------
`_measure_registered_module_names` returns the bare local `Name` ids bound
into `ProductAssemblySpec(modules=(...))` — e.g. `billing_feature`, never
`dotmac_billing`. An earlier version of this validator compared a
distribution's own import-package name (`dotmac_billing`) directly against
those bare local ids, which is not a measurement that can ever succeed for
any real registration shape: a real registration reads
`from dotmac_billing import billing_feature` and puts the LOCAL name
`billing_feature` in the tuple, never the distribution's import-package
name itself. That comparison was structurally pinned to `false` for every
one of the 93 `optional-module` rows regardless of what was actually
registered — so the flip-to-`true` plant test for `module_registration`
was passing for the wrong reason (the expected value was necessarily
`false`, not measured `false`).

`_resolve_registered_distribution_origins` fixes this: it traces each bound
local `Name` back to a real `from <package> import <name> [as <alias>]`
statement in the same file and returns the set of top-level packages those
names actually came from. `module_registration` now compares a
distribution's import package against that resolved origin set, which CAN
answer `true` — see `test_import_origin_resolves_registration_to_the_true_
source_package` — and correctly cannot for a name that is locally defined
rather than imported (Academy's own real shape:
`academy_feature = FeatureManifest(...)`, never imported from anywhere —
see `test_locally_defined_manifest_name_never_resolves_to_an_origin`) or
bound via a plain `import` statement rather than `from ... import ...`
(`test_import_via_plain_import_statement_never_resolves_to_an_origin`).
Academy's real `module_registration` value is unchanged by this fix (still
`false` for every optional-module row — `academy_feature` resolves to no
origin either way) — only the MECHANISM changed, from a comparison that
could never measure `true` to one that genuinely can.
"""

from __future__ import annotations

import ast
import copy
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import composition_schema as cs  # noqa: E402

RECORD_PATH = ROOT / "docs" / "kernel-runtime-composition.json"
PACKAGES_ROOT = Path(__file__).resolve().parent / "fixtures" / "starter_catalogue_a9dc45ec" / "packages"
STARTER_REVISION = "a9dc45ecd00d5a0163b6544278888220082e2e75"
EXPECTED_PRODUCT = "dotmac_academy_app"

#: The pinned Starter fixture mirror's own directory name, DERIVED from
#: `PACKAGES_ROOT` rather than repeated as a second hand-typed literal — a
#: prior version duplicated `"starter_catalogue_a9dc45ec"` at two call
#: sites, so a re-pin required editing both by hand and finding the second
#: one only by luck.
_FIXTURE_MIRROR_DIR_NAME = PACKAGES_ROOT.parent.name
_SEARCH_EXCLUDED_DIR_NAMES = {".git", "node_modules", _FIXTURE_MIRROR_DIR_NAME}

#: Academy's own row shape: every field the frozen contract's closed
#: `_KNOWN_PAYLOAD_FIELDS` accepts, plus `evidence` — Academy's own
#: value-add annotation, which is NOT part of the shared contract's closed
#: record shape (`evidence` is absent from `cs.REQUIRED_PAYLOAD_FIELDS`).
#: This is why `_validate_record` strips `evidence` per row before routing
#: through `cs.composition_records_from_envelope` — feeding the contract
#: reader a row carrying `evidence` verbatim would be refused outright as
#: an unrecognized field, exactly the closed-shape refusal the contract
#: documents for an `api_key`-shaped extra key.
ACADEMY_ROW_KEYS = cs._KNOWN_PAYLOAD_FIELDS | {"evidence"}

ENTRY_POINTS: tuple[str, ...] = ("app.main", "app.cli")


def _load_record() -> dict[str, Any]:
    return json.loads(RECORD_PATH.read_text(encoding="utf-8"))


def _strip_evidence(row: dict[str, Any]) -> dict[str, Any]:
    """The one place a row's `evidence` annotation is stripped — used by
    both `_contract_envelope` (whole-document validation) and
    `_base_optional_module_payload` (single-row payload tests). A prior
    version implemented this same strip at both call sites independently,
    so a second non-contract annotation added later would only be caught at
    one of them."""
    return {k: v for k, v in row.items() if k != "evidence"}


def _contract_envelope(record: dict[str, Any]) -> dict[str, Any]:
    """Academy's own document, with each row's `evidence` annotation
    stripped, so what remains is exactly the shape
    `cs.composition_records_from_envelope` accepts. `evidence` is real
    documentation Academy chooses to keep alongside the contract fields; it
    is not part of the shared contract and must never be fed to it."""
    stripped = copy.deepcopy(record)
    if isinstance(stripped.get("records"), list):
        stripped["records"] = [_strip_evidence(row) for row in stripped["records"] if isinstance(row, dict)]
    return stripped


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


def _resolve_registered_distribution_origins(assembly_source: str) -> set[str]:
    """The set of top-level distribution import packages (e.g.
    `dotmac_billing`) that `ProductAssemblySpec(modules=(...))` ACTUALLY
    registers a manifest from — resolved by tracing each bound local `Name`
    (from `_measure_registered_module_names`) back to a real
    `from <package> import <name> [as <alias>]` statement in the same file.

    This is what makes `module_registration` a genuine measurement rather
    than a comparison that can only ever answer `false`: an earlier version
    compared a distribution's own import-package name directly against the
    bare local `Name` ids (`dotmac_billing` against `billing_feature`),
    which are never the same string for any real registration shape — a
    real registration binds the manifest object's LOCAL name into the
    tuple, never the distribution's import-package name itself. That
    comparison was structurally pinned to `false` regardless of what was
    actually registered.

    A `Name` that is locally DEFINED rather than imported (Academy's own
    real shape: `academy_feature = FeatureManifest(...)`, never imported
    from anywhere) resolves to no origin, and never counts — a variable
    name coincidentally matching a distribution's import package is not a
    registration. A `Name` bound via a plain `import` statement (rather
    than `from ... import ...`) likewise resolves to no origin here: real
    registration in this fleet always binds a manifest object pulled out of
    its owning package by name, never a whole imported module."""
    names = _measure_registered_module_names(assembly_source)
    tree = ast.parse(assembly_source)
    origin_by_local_name: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            for alias in node.names:
                bound = alias.asname or alias.name
                origin_by_local_name[bound] = top
    return {origin_by_local_name[name] for name in names if name in origin_by_local_name}


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


# ---------------------------------------------------------------------------
# runtime_consumption: an AST import graph from real production entry
# points, never "imported anywhere under app/" and never a text search.
# ---------------------------------------------------------------------------


def _module_name_for(path: Path, root: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _build_app_import_graph(root: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Per `app/**/*.py` module: the set of internal `app.*` modules it
    imports (by real `ast.Import`/`ast.ImportFrom` node, resolving relative
    imports against the importing module's own package), and the set of
    top-level `dotmac_*` packages it imports directly. Never a substring
    search — a comment or a string literal mentioning an import is not a
    node this function ever inspects."""
    internal_edges: dict[str, set[str]] = {}
    external_imports: dict[str, set[str]] = {}
    for py in (root / "app").rglob("*.py"):
        mod = _module_name_for(py, root)
        try:
            tree = ast.parse(py.read_text())
        except SyntaxError:
            internal_edges[mod] = set()
            external_imports[mod] = set()
            continue
        internal: set[str] = set()
        external: set[str] = set()
        pkg_parts = mod.split(".")
        is_init = py.name == "__init__.py"
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top == "app":
                        internal.add(alias.name)
                    elif top.startswith("dotmac_"):
                        external.add(top)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    base = pkg_parts if is_init else pkg_parts[:-1]
                    if node.level > 1:
                        base = base[: len(base) - (node.level - 1)]
                    full = ".".join([*base, *node.module.split(".")]) if node.module else ".".join(base)
                    internal.add(full)
                elif node.module:
                    top = node.module.split(".")[0]
                    if top == "app":
                        internal.add(node.module)
                    elif top.startswith("dotmac_"):
                        external.add(top)
        internal_edges[mod] = internal
        external_imports[mod] = external
    return internal_edges, external_imports


def _measure_reachable_dotmac_imports(root: Path, entry_points: tuple[str, ...]) -> set[str]:
    """Breadth-first walk of the internal import graph from `entry_points`,
    returning the union of top-level `dotmac_*` imports reached along any
    real internal edge. A module never imported (directly or transitively)
    from an entry point contributes nothing, no matter what it imports."""
    internal_edges, external_imports = _build_app_import_graph(root)
    visited: set[str] = set()
    queue: list[str] = list(entry_points)
    reached: set[str] = set()
    while queue:
        current = queue.pop()
        if current in visited:
            continue
        visited.add(current)
        reached.update(external_imports.get(current, set()))
        for target in internal_edges.get(current, set()):
            if target in internal_edges:
                queue.append(target)
            else:
                # `target` may name a package (e.g. `app.services`) rather
                # than the exact submodule an ImportFrom pulled a name out
                # of; widen to every real submodule beneath it.
                for candidate in internal_edges:
                    if candidate == target or candidate.startswith(target + "."):
                        queue.append(candidate)
    return reached


# ---------------------------------------------------------------------------
# installation: no authoritative checked-in production install recipe —
# see the module docstring's "no authoritative recipe" section. This search
# is real and exercised in both directions below (positive control on a
# synthetic Dockerfile; the actual, un-mutated Academy tree finds none).
# ---------------------------------------------------------------------------

_RUN_LINE_PATTERN = re.compile(r"^\s*RUN\b(.*)$")


def _extract_dockerfile_run_instructions(dockerfile_text: str) -> tuple[str, ...]:
    """Every `RUN` instruction in a Dockerfile, as its complete (backslash-
    continuation-joined) text — the shape `cs.parse_install_command` takes.
    A line not starting with `RUN` (after stripping leading whitespace) is
    never treated as one; a `RUN` line's continuation is any subsequent
    line while the previous line ends in a trailing `\\`."""
    instructions: list[str] = []
    lines = dockerfile_text.splitlines()
    i = 0
    while i < len(lines):
        match = _RUN_LINE_PATTERN.match(lines[i])
        if not match:
            i += 1
            continue
        collected = [lines[i]]
        while collected[-1].rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            collected.append(lines[i])
        instructions.append("\n".join(collected))
        i += 1
    return tuple(instructions)


def _locate_production_install_recipes(root: Path) -> tuple[cs.InstallRecipe, ...]:
    """Search `root` for every checked-in `Dockerfile*` (recursively,
    excluding `.git`, `node_modules`, and the pinned Starter fixture
    mirror), extract each one's `RUN` instructions, and parse every one
    that tokenizes as a `poetry install`/`poetry sync` recipe via
    `cs.parse_install_command`. A `RUN` instruction that is not a Poetry
    install/sync command (e.g. `RUN apt-get update`) is silently skipped —
    it is not evidence about installation either way, and only a real
    Poetry-shaped instruction is returned. Returns an empty tuple, never a
    guess, when no `Dockerfile*` exists in `root` at all — the real Academy
    case; see `test_locate_production_install_recipes_finds_none_in_this_
    tree`."""
    recipes: list[cs.InstallRecipe] = []
    for dockerfile in sorted(root.rglob("Dockerfile*")):
        if not dockerfile.is_file():
            continue
        if _SEARCH_EXCLUDED_DIR_NAMES & set(dockerfile.parts):
            continue
        text = dockerfile.read_text()
        for instruction in _extract_dockerfile_run_instructions(text):
            try:
                recipe = cs.parse_install_command(instruction, source=str(dockerfile.relative_to(root)))
            except cs.InstallRecipeParseError:
                continue
            if recipe.tool == "poetry" and recipe.subcommand in ("install", "sync"):
                recipes.append(recipe)
    return tuple(recipes)


def test_locate_production_install_recipes_finds_a_real_dockerfile(tmp_path: Path) -> None:
    """Positive control: the search mechanism can say yes. A synthetic
    Dockerfile with a real, multi-line `RUN poetry install` instruction is
    found and parses."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n" "RUN poetry install \\\n" "    --only main \\\n" "    --no-root --no-ansi\n"
    )
    recipes = _locate_production_install_recipes(tmp_path)
    assert len(recipes) == 1
    assert recipes[0].tool == "poetry"
    assert recipes[0].subcommand == "install"
    assert ("--only", "main") in recipes[0].flags


def test_locate_production_install_recipes_finds_none_in_this_tree() -> None:
    """The real, un-mutated claim about Academy's own tree: no
    Dockerfile-shaped production install recipe exists anywhere in it. This
    is the near-miss control paired with the positive control above — the
    search mechanism is proven capable of finding a real recipe, and then,
    separately, proven to find nothing here, not because it cannot find
    anything at all."""
    assert _locate_production_install_recipes(ROOT) == ()


def test_no_dockerfile_exists_anywhere_in_this_repository() -> None:
    found = [p for p in ROOT.rglob("Dockerfile*") if p.is_file() and not (_SEARCH_EXCLUDED_DIR_NAMES & set(p.parts))]
    assert found == []


def test_docker_compose_prod_has_exactly_one_service_with_no_build_stanza() -> None:
    """Structural, via `yaml.safe_load` against the parsed `services`
    mapping — not a substring check. A bare `"build:" not in text` (the
    prior version of this test) would pass even if a SECOND service pulling
    a prebuilt `image:` existed alongside `db`; this additionally asserts
    the service key SET is exactly `{"db"}`, which the docstring and every
    row's evidence string both claim."""
    document = yaml.safe_load((ROOT / "docker-compose.prod.yml").read_text())
    services = document.get("services", {})
    assert set(services) == {"db"}
    assert "build" not in services["db"]
    assert services["db"].get("image") == "postgres:16"


def _enumerate_workflow_files(root: Path) -> tuple[Path, ...]:
    workflows_dir = root / ".github" / "workflows"
    return tuple(sorted({*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")}))


def _enumerate_workflow_install_steps(root: Path) -> tuple[tuple[str, str], ...]:
    """For every REAL workflow file under `.github/workflows/` (enumerated
    by `_enumerate_workflow_files`, never a single hard-coded filename),
    every job carrying a step whose `run:` text contains `poetry install` or
    `poetry sync` — read structurally via `yaml.safe_load`'s `jobs`/`steps`
    mapping, never a text scan across the whole file. A prior version of
    this module claimed this glob was searched while no code actually
    enumerated it; this function is what makes that claim true."""
    found: list[tuple[str, str]] = []
    for workflow_file in _enumerate_workflow_files(root):
        document = yaml.safe_load(workflow_file.read_text())
        jobs = document.get("jobs", {}) if isinstance(document, dict) else {}
        for job_name, job in jobs.items():
            steps = job.get("steps", []) if isinstance(job, dict) else []
            for step in steps:
                run_text = step.get("run") if isinstance(step, dict) else None
                if isinstance(run_text, str) and ("poetry install" in run_text or "poetry sync" in run_text):
                    found.append((workflow_file.name, job_name))
    return tuple(found)


def test_workflow_files_are_exactly_ci_and_engineering_standards() -> None:
    names = {p.name for p in _enumerate_workflow_files(ROOT)}
    assert names == {"ci.yml", "engineering-standards.yml"}


def test_ci_workflow_declares_only_a_test_job() -> None:
    """Read the workflow's `jobs` mapping STRUCTURALLY.

    The first version of this test matched `^  (\\w[\\w-]*):\\s*$` over the raw
    text, which collects every two-space-indented key in the file -- so it
    returned `['push', 'pull_request', 'test']`, the `on:` triggers alongside
    the one real job, and failed CI. A regex over indentation cannot tell a
    job name from a trigger name; only the parsed document can. This is the
    same substring-for-structure mistake the composition contract itself
    exists to refuse, so it does not get to live in the validator that
    enforces it. Scoped deliberately to `ci.yml` alone — the broader claim
    across every workflow file is `test_only_the_ci_test_job_installs_
    dependencies_across_every_workflow` below.
    """
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    assert list(workflow["jobs"]) == ["test"]


def test_only_the_ci_test_job_installs_dependencies_across_every_workflow() -> None:
    """Widens the claim above to every workflow file that actually exists
    (`_enumerate_workflow_files`, not a hard-coded pair) — the only
    `poetry install`/`poetry sync` step anywhere under
    `.github/workflows/` belongs to `ci.yml`'s `test` job."""
    assert _enumerate_workflow_install_steps(ROOT) == (("ci.yml", "test"),)


def test_engineering_standards_workflow_installs_nothing() -> None:
    """`engineering-standards.yml` — confirmed to exist by
    `test_workflow_files_are_exactly_ci_and_engineering_standards` above —
    declares two jobs (`pin-preflight`, `standards`) and neither installs
    anything; its own checked-in comment says so ("Standard library only:
    no install step can be trusted to run before the gate that decides
    whether this adoption is armed at all")."""
    document = yaml.safe_load((ROOT / ".github" / "workflows" / "engineering-standards.yml").read_text())
    assert set(document["jobs"]) == {"pin-preflight", "standards"}
    installs = [
        (job_name, step.get("run"))
        for job_name, job in document["jobs"].items()
        for step in job.get("steps", [])
        if isinstance(step, dict)
        and isinstance(step.get("run"), str)
        and ("poetry install" in step["run"] or "poetry sync" in step["run"])
    ]
    assert installs == []


def test_deploy_service_units_carry_no_install_command() -> None:
    deploy_dir = ROOT / "deploy"
    service_files = sorted(deploy_dir.glob("*.service"))
    assert service_files, "fixture assumption broken: no deploy/*.service files found"
    for service_file in service_files:
        text = service_file.read_text()
        assert "poetry install" not in text and "poetry sync" not in text
        assert ".venv/bin/python" in text


def test_readme_poetry_install_is_scoped_to_local_development() -> None:
    text = (ROOT / "README.md").read_text()
    lines = text.splitlines()
    install_lines = [i for i, line in enumerate(lines) if line.strip() == "poetry install"]
    assert install_lines, "fixture assumption broken: README.md no longer says 'poetry install'"
    heading = None
    for line in lines[: install_lines[0]]:
        if line.startswith("## "):
            heading = line
    assert heading == "## Local development"


# ---------------------------------------------------------------------------
# Named, dismissed counter-evidence (Michael's item 5): checked-in
# statements asserting Poetry DOES run on the production host, found by
# content, dismissed because neither supplies a command, a group selection,
# or an artifact.
# ---------------------------------------------------------------------------


def _locate_counter_evidence_for_production_installation(root: Path) -> tuple[str, ...]:
    found: list[str] = []
    readme_text = (root / "README.md").read_text()
    if "production host alike" in readme_text:
        found.append(
            "README.md: \"Poetry's version is pinned — in CI and on the production host "
            'alike" — names a production host running Poetry; supplies no install command'
        )
    ci_text = (root / ".github" / "workflows" / "ci.yml").read_text()
    if "academy production host" in ci_text:
        found.append(
            '.github/workflows/ci.yml: "must stay in step with the academy production '
            'host, which runs the same version from /usr/local/bin" — names a production '
            "host running Poetry; supplies no install command"
        )
    return tuple(found)


def test_counter_evidence_statements_are_found_and_named() -> None:
    """Non-vacuity: both named counter-evidence statements are real and
    locatable by content in this tree today, not merely asserted."""
    assert len(_locate_counter_evidence_for_production_installation(ROOT)) == 2


# ---------------------------------------------------------------------------
# The search perimeter, stated honestly (Michael's item 7 / ADR-0018):
# every additional deploy/install-recipe family an independent review
# manually checked, reproduced here as code rather than left as a one-time
# claim.
# ---------------------------------------------------------------------------

_DEPLOY_RECIPE_FILE_FAMILIES: tuple[str, ...] = (
    "Makefile",
    "Procfile",
    "fly.toml",
    "render.yaml",
    "app.yaml",
)
_DEPLOY_RECIPE_DIR_FAMILIES: tuple[str, ...] = (
    ".ebextensions",
    "ansible",
    "helm",
    "charts",
    "k8s",
    "terraform",
    "infra",
)


def _search_additional_deploy_recipe_families(root: Path) -> dict[str, list[str]]:
    """Structural existence checks for every deploy/install-recipe family an
    independent review manually searched Academy's tree for (Makefiles,
    shell scripts, Procfile, fly.toml, render.yaml, app.yaml,
    `.ebextensions/`, `ansible/`, `helm/`, `charts/`, `k8s/`, `terraform/`,
    `infra/`, and `ExecStartPre`/`ExecStartPost` hooks) — reproducing that
    manual finding as code instead of leaving it as a dated, unverifiable
    claim. Returns, per family, the real paths found; an empty list means
    confirmed absent."""
    findings: dict[str, list[str]] = {}
    for name in _DEPLOY_RECIPE_FILE_FAMILIES:
        path = root / name
        findings[name] = [str(path.relative_to(root))] if path.is_file() else []
    for name in _DEPLOY_RECIPE_DIR_FAMILIES:
        path = root / name
        findings[name] = [str(path.relative_to(root))] if path.is_dir() else []
    findings["*.sh"] = [
        str(p.relative_to(root))
        for p in sorted(root.rglob("*.sh"))
        if p.is_file() and not (_SEARCH_EXCLUDED_DIR_NAMES & set(p.parts))
    ]
    hooks: list[str] = []
    for service_file in sorted((root / "deploy").glob("*.service")):
        for line in service_file.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("ExecStartPre") or stripped.startswith("ExecStartPost"):
                hooks.append(f"{service_file.name}: {stripped}")
    findings["ExecStartPre/ExecStartPost"] = hooks
    return findings


def test_no_additional_deploy_recipe_family_exists() -> None:
    findings = _search_additional_deploy_recipe_families(ROOT)
    nonempty = {family: paths for family, paths in findings.items() if paths}
    assert nonempty == {}, f"unexpected deploy-recipe-shaped paths found: {nonempty}"


def test_additional_deploy_recipe_search_can_find_a_planted_makefile(tmp_path: Path) -> None:
    """Positive control for the perimeter search: a synthetic `Makefile`
    with a real install target IS found, proving the empty result above is
    not vacuous."""
    (tmp_path / "Makefile").write_text("install:\n\tpoetry install --only main\n")
    (tmp_path / "deploy").mkdir()
    findings = _search_additional_deploy_recipe_families(tmp_path)
    assert findings["Makefile"] == ["Makefile"]


# ---------------------------------------------------------------------------
# Sensitivity proof for runtime_consumption: a real deleted import is
# caught; a comment/string mentioning an import is never mistaken for one.
# ---------------------------------------------------------------------------


def test_deleting_the_real_import_breaks_reachability(tmp_path: Path) -> None:
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "__init__.py").write_text("")
    (app_dir / "main.py").write_text("from app.kernel_runtime import create_app\napp = create_app()\n")
    (app_dir / "cli.py").write_text("import app.main\n")
    (app_dir / "kernel_runtime.py").write_text("import dotmac_kernel\n\n\ndef create_app():\n    return object()\n")

    reached = _measure_reachable_dotmac_imports(tmp_path, ("app.main", "app.cli"))
    assert "dotmac_kernel" in reached

    # Plant: delete the real import.
    (app_dir / "kernel_runtime.py").write_text(
        "# dotmac_kernel used to be imported here\n\n\ndef create_app():\n    return object()\n"
    )
    reached_after_deletion = _measure_reachable_dotmac_imports(tmp_path, ("app.main", "app.cli"))
    assert "dotmac_kernel" not in reached_after_deletion


def test_a_comment_mentioning_an_import_is_not_reachability(tmp_path: Path) -> None:
    """Near-miss: a comment naming an import site is never treated as one —
    this is what a needle/substring check would get wrong (the exact defect
    an independent review found in ERP's earlier version, where the real
    import was deleted and a needle-based check still passed)."""
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "__init__.py").write_text("")
    (app_dir / "main.py").write_text(
        "# import dotmac_kernel  -- this is a comment, not a real import\n" "app = object()\n"
    )
    (app_dir / "cli.py").write_text('CLI_HELP = "run: import dotmac_kernel"\n')

    reached = _measure_reachable_dotmac_imports(tmp_path, ("app.main", "app.cli"))
    assert "dotmac_kernel" not in reached


_EXEC_START_MODULE_PATTERN = re.compile(r"-m\s+(\S+)")


def _measure_exec_start_targets(service_files: tuple[Path, ...]) -> set[str]:
    """Every `-m <module>` target across every `ExecStart` line in
    `service_files`. Refuses — raises `AssertionError` naming the offending
    line — rather than silently skipping any `ExecStart` line it cannot
    parse this way (e.g. `ExecStart=.../uvicorn app.main:app`, or a direct
    script path with no `-m` at all). A prior version of this function only
    collected lines containing `-m `, so a third entry point declared in
    one of the shapes above would have been silently skipped rather than
    refused — see `test_an_unparseable_execstart_target_is_refused_not_
    skipped` for the plant proving this now fails loudly instead."""
    targets: set[str] = set()
    for service_file in service_files:
        for line in service_file.read_text().splitlines():
            stripped = line.strip()
            if not stripped.startswith("ExecStart"):
                continue
            match = _EXEC_START_MODULE_PATTERN.search(stripped)
            if match is None:
                raise AssertionError(
                    f"{service_file.name}: ExecStart line {stripped!r} does not declare a "
                    "`-m <module>` target -- refused rather than silently skipped, since a "
                    "third entry point could otherwise hide behind an unparsed shape"
                )
            targets.add(match.group(1))
    return targets


def test_an_unparseable_execstart_target_is_refused_not_skipped(tmp_path: Path) -> None:
    """Plant: an `ExecStart` line with no `-m <module>` target (e.g. a direct
    uvicorn invocation) is refused, not silently skipped — the defect this
    function's prior version carried."""
    service = tmp_path / "fake.service"
    service.write_text("[Service]\nExecStart=/home/dotmac/.venv/bin/uvicorn app.main:app\n")
    with pytest.raises(AssertionError, match="does not declare"):
        _measure_exec_start_targets((service,))


def test_academy_entry_points_are_exactly_main_and_cli() -> None:
    """The declared production entry points, confirmed by reading real
    files: README's uvicorn command targets `app.main:app`, and every
    `deploy/*.service` unit's `ExecStart` targets `app.cli`. No third entry
    point exists in either location."""
    readme = (ROOT / "README.md").read_text()
    assert "uvicorn app.main:app" in readme

    service_files = tuple(sorted((ROOT / "deploy").glob("*.service")))
    assert service_files
    for service_file in service_files:
        assert "app.cli" in service_file.read_text()

    exec_start_targets = _measure_exec_start_targets(service_files)
    assert exec_start_targets == {"app.cli"}


def test_every_dotmac_import_anywhere_under_app_is_exactly_kernel_and_ui() -> None:
    """The robustness backstop (Michael's item 4): even if the entry-point
    BFS above somehow missed a real production entry point, this
    independently confirms the identical conclusion across EVERY module
    under `app/` — not only the ones reachable from `app.main`/`app.cli` —
    so no false `false` `runtime_consumption` is reachable today even
    through a missed entry point. This is what an independent review
    verified by hand; nothing in this validator asserted it until now."""
    _, external_imports = _build_app_import_graph(ROOT)
    all_dotmac_imports: set[str] = set()
    for imports in external_imports.values():
        all_dotmac_imports.update(imports)
    assert all_dotmac_imports == {"dotmac_kernel", "dotmac_ui"}


# ---------------------------------------------------------------------------
# Rebuilding the expected dimensions from Academy's own measured tree.
# ---------------------------------------------------------------------------


def _expected_dimensions_for(
    dossier: cs.PackageDossier,
    *,
    lock_membership: cs.LockGroupMembership | None,
    group_optionality: dict[str, bool] | None,
    production_recipes: tuple[cs.InstallRecipe, ...],
    registered_distribution_origins: set[str],
    alembic_text: str,
    reachable_imports: set[str],
) -> dict[str, str]:
    """Rebuild what every dimension SHOULD be for one dossier, from
    Academy's own measured tree — the ground truth the committed record is
    checked against. Mirrors `composition_record_from_payload`'s own
    applicability rules exactly (it is the authority on what NOT_APPLICABLE
    means), but computes Academy-specific installation/registration/
    lineage/runtime facts independently."""
    dist = dossier.distribution
    import_pkg = dist.replace("-", "_")
    classification = dossier.classification

    # installation: routed through the shared contract function itself,
    # with recipes=_locate_production_install_recipes(ROOT) — the search's
    # own real result, never a hard-coded recipes=(). Today that tuple is
    # empty (no authoritative checked-in production install recipe exists
    # in this tree — see module docstring), so this derives UNKNOWN via
    # cs.derive_installation_dimension's own documented behaviour for an
    # empty recipes tuple; if a recipe ever appears on disk, THIS call is
    # what changes the derived value, without any code here changing.
    installation = cs.derive_installation_dimension(
        distribution=dist,
        lock_membership=lock_membership,
        recipes=production_recipes,
        group_optionality=group_optionality,
    )

    if classification.module_registration_applies:
        module_registration = (
            cs.DimensionValue.TRUE if import_pkg in registered_distribution_origins else cs.DimensionValue.FALSE
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

    runtime_present = import_pkg in reachable_imports
    runtime_consumption = cs.DimensionValue.TRUE if runtime_present else cs.DimensionValue.FALSE

    return {
        "installation": installation.value,
        "module_registration": module_registration.value,
        "migration_lineage": migration_lineage.value,
        "runtime_consumption": runtime_consumption.value,
    }


# ---------------------------------------------------------------------------
# Record-level validation — routed through the shared contract reader.
# ---------------------------------------------------------------------------


def _validate_record(record: dict[str, Any]) -> None:
    assert record.get("product"), "product is mandatory and must not be empty"
    assert record["product"] == EXPECTED_PRODUCT
    assert (
        isinstance(record.get("starter_catalogue_revision"), str) and len(record["starter_catalogue_revision"]) == 40
    ), (
        "starter_catalogue_revision must be the full 40-character commit SHA, "
        f"not {record.get('starter_catalogue_revision')!r}"
    )
    assert record["starter_catalogue_revision"] == STARTER_REVISION

    raw_records = record.get("records")
    assert isinstance(raw_records, list) and raw_records, "records must be a non-empty list"
    for raw in raw_records:
        assert set(raw.keys()) == ACADEMY_ROW_KEYS, (
            f"{raw.get('distribution')!r}: unexpected record keys "
            f"{set(raw.keys()) - ACADEMY_ROW_KEYS} (missing: {ACADEMY_ROW_KEYS - set(raw.keys())})"
        )

    # The one shared contract reader — closed envelope shape, closed record
    # shape, catches duplicate distributions and product disagreement, and
    # routes every row through composition_record_from_payload itself. No
    # local envelope handling remains in this module.
    built_records = cs.composition_records_from_envelope(_contract_envelope(record), PACKAGES_ROOT)
    for built in built_records:
        cs.derive_composition_state(built)  # must not raise

    universe = cs.derive_distribution_universe(PACKAGES_ROOT)
    universe_by_name = {d.distribution: d for d in universe}
    seen = {r.distribution for r in built_records}
    assert seen == set(universe_by_name), (
        f"record is missing distributions {set(universe_by_name) - seen} "
        f"or carries unknown ones {seen - set(universe_by_name)}"
    )

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock_document = tomllib.loads((ROOT / "poetry.lock").read_text())
    lock_membership = cs.derive_lock_group_membership(lock_document)
    group_optionality = cs.derive_group_optionality(pyproject)

    production_recipes = _locate_production_install_recipes(ROOT)
    registered_origins = _resolve_registered_distribution_origins((ROOT / "app" / "assembly.py").read_text())
    alembic_text = _measure_alembic_combined_text()
    reachable_imports = _measure_reachable_dotmac_imports(ROOT, ENTRY_POINTS)

    for raw in raw_records:
        dossier = universe_by_name[raw["distribution"]]
        expected = _expected_dimensions_for(
            dossier,
            lock_membership=lock_membership,
            group_optionality=group_optionality,
            production_recipes=production_recipes,
            registered_distribution_origins=registered_origins,
            alembic_text=alembic_text,
            reachable_imports=reachable_imports,
        )
        for dimension, expected_value in expected.items():
            actual_value = raw[dimension]
            assert actual_value == expected_value, (
                f"{raw['distribution']}/{dimension}: record claims {actual_value!r} but this tree "
                f"measures {expected_value!r}"
            )


def test_kernel_runtime_composition_record_is_truthful() -> None:
    """Near-miss control: the actual, unmodified record passes every check —
    proof that a truthful `unknown` installation dimension across the whole
    catalogue, and truthful `false` dimensions elsewhere, are accepted, not
    rejected by construction."""
    _validate_record(_load_record())


@pytest.mark.parametrize(
    "distribution,dimension",
    [
        ("dotmac-billing", "module_registration"),
        ("dotmac-billing", "migration_lineage"),
        ("dotmac-document-rendering", "module_registration"),
    ],
)
def test_flipping_a_measured_false_dimension_to_true_is_caught(distribution: str, dimension: str) -> None:
    """Plant: a genuinely false dimension flipped to true fails the build,
    naming the offending distribution. `installation` is `unknown` (not
    `false`) for every row now — see the module docstring — so it is
    exercised separately below
    (`test_flipping_installation_unknown_to_true_is_caught`)."""
    record = copy.deepcopy(_load_record())
    (row,) = [r for r in record["records"] if r["distribution"] == distribution]
    assert row[dimension] == "false", f"fixture assumption broken: {distribution}/{dimension} is not recorded false"
    row[dimension] = "true"
    with pytest.raises(AssertionError, match=distribution):
        _validate_record(record)


@pytest.mark.parametrize("distribution", ["dotmac-billing", "dotmac-deployment-foundation"])
def test_flipping_installation_unknown_to_true_is_caught(distribution: str) -> None:
    """Every row's `installation` is `unknown` today (no authoritative
    recipe). Flipping one row's `installation` to `true` — with no
    corresponding recipe evidence anywhere in this tree — is caught by the
    ground-truth comparison. This never raises `DimensionalIncoherence`:
    the frozen contract's contradiction check (step 3 of
    `derive_composition_state`'s pipeline) only fires when `installation`
    is confirmed `FALSE`, not `UNKNOWN`, so this plant is caught solely by
    this validator's own ground-truth check — worth stating explicitly
    since it is a different failure shape than the false-dimension plants
    above."""
    record = copy.deepcopy(_load_record())
    (row,) = [r for r in record["records"] if r["distribution"] == distribution]
    assert (
        row["installation"] == "unknown"
    ), f"fixture assumption broken: {distribution}/installation is not recorded unknown"
    row["installation"] = "true"
    with pytest.raises(AssertionError, match=distribution):
        _validate_record(record)


def test_every_catalogue_distribution_has_exactly_one_record() -> None:
    record = _load_record()
    universe = cs.derive_distribution_universe(PACKAGES_ROOT)
    recorded = {r["distribution"] for r in record["records"]}
    assert recorded == {d.distribution for d in universe}


# ---------------------------------------------------------------------------
# Control: the shared cross-product envelope, exercised through
# cs.composition_records_from_envelope itself — no local envelope handling.
# ---------------------------------------------------------------------------


def test_stored_catalogue_size_is_rejected() -> None:
    record = copy.deepcopy(_load_record())
    record["catalogue_size"] = len(record["records"])
    with pytest.raises(cs.IncompatibleSchemaVersion, match="catalogue_size"):
        _validate_record(record)


def test_empty_product_is_rejected() -> None:
    record = copy.deepcopy(_load_record())
    record["product"] = ""
    with pytest.raises(AssertionError, match="mandatory"):
        _validate_record(record)


def test_truncated_revision_is_rejected() -> None:
    record = copy.deepcopy(_load_record())
    record["starter_catalogue_revision"] = record["starter_catalogue_revision"][:7]
    with pytest.raises(AssertionError, match="40-character"):
        _validate_record(record)


def test_an_evidence_field_reaching_the_contract_reader_is_refused() -> None:
    """`evidence` is Academy's own annotation, outside the frozen contract's
    closed record shape. Confirms `_contract_envelope`'s stripping is load-
    bearing: feeding a row's `evidence` straight through
    `composition_records_from_envelope` (bypassing the strip) is refused."""
    record = _load_record()
    (row,) = [r for r in record["records"] if r["distribution"] == "dotmac-kernel"]
    assert "evidence" in row
    unstripped_envelope = {**record, "records": [row]}
    with pytest.raises(cs.IncompatibleSchemaVersion, match="evidence"):
        cs.composition_records_from_envelope(unstripped_envelope, PACKAGES_ROOT)


# ---------------------------------------------------------------------------
# Control: an optional-module distribution reporting NOT_APPLICABLE for a
# dimension that genuinely applies is refused; a genuinely stateless one for
# lineage is accepted.
# ---------------------------------------------------------------------------


def _base_optional_module_payload(distribution: str) -> dict[str, Any]:
    (row,) = [r for r in _load_record()["records"] if r["distribution"] == distribution]
    return _strip_evidence(row)


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
#
# `_measure_registered_module_names` alone (the bare local `Name` ids) is
# not the measurement `module_registration` is built on — see
# `_resolve_registered_distribution_origins` below and the module
# docstring's "origin-resolved, not name-compared" section.
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
    assert _resolve_registered_distribution_origins(source) == set()


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


def test_import_origin_resolves_registration_to_the_true_source_package() -> None:
    """The genuine positive: a real `from dotmac_billing import
    billing_feature` binding, placed in `modules=(...)`, resolves origin
    `dotmac_billing` — proving `module_registration` CAN measure `true`,
    unlike the bare-name comparison it replaces."""
    source = (
        "from dotmac_billing import billing_feature\n"
        "assembly = ProductAssemblySpec(\n"
        "    name='x',\n"
        "    modules=(billing_feature,),\n"
        ")\n"
    )
    assert _resolve_registered_distribution_origins(source) == {"dotmac_billing"}


def test_locally_defined_manifest_name_never_resolves_to_an_origin() -> None:
    """Academy's own real shape: `academy_feature = FeatureManifest(...)` is
    a local assignment, never an import. It can never register any
    catalogue distribution, no matter what it happens to be named — the
    exact case that keeps `module_registration` measuring `false` for
    Academy's real assembly.py today, under the fixed mechanism, unchanged
    from before the fix."""
    source = (
        "academy_feature = FeatureManifest(name='dotmac_billing')\n"
        "assembly = ProductAssemblySpec(\n"
        "    name='x',\n"
        "    modules=(academy_feature,),\n"
        ")\n"
    )
    assert _resolve_registered_distribution_origins(source) == set()


def test_import_via_plain_import_statement_never_resolves_to_an_origin() -> None:
    """A plain `import dotmac_billing` (rather than `from dotmac_billing
    import billing_feature`) is never traced to an origin — real
    registration in this fleet always binds a manifest object pulled out of
    its owning package by name, never a whole imported module."""
    source = (
        "import dotmac_billing\n"
        "assembly = ProductAssemblySpec(\n"
        "    name='x',\n"
        "    modules=(dotmac_billing,),\n"
        ")\n"
    )
    assert _resolve_registered_distribution_origins(source) == set()


def test_academy_real_assembly_module_registration_origin_is_empty() -> None:
    """Confirms the fix changes only the MECHANISM, not Academy's real
    measured value: `academy_feature` resolves to no origin against
    Academy's actual `app/assembly.py`, exactly as the bare-name comparison
    also (structurally, not by genuine measurement) produced before."""
    origins = _resolve_registered_distribution_origins((ROOT / "app" / "assembly.py").read_text())
    assert origins == set()


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


# ---------------------------------------------------------------------------
# Control: derive_installation_dimension itself, against Academy's real
# lock/pyproject data, with no recipes — proves the UNKNOWN result is the
# contract's own derivation, not a hand-written stand-in.
# ---------------------------------------------------------------------------


def test_derive_installation_dimension_is_unknown_for_every_distribution_with_no_recipe() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock_document = tomllib.loads((ROOT / "poetry.lock").read_text())
    lock_membership = cs.derive_lock_group_membership(lock_document)
    group_optionality = cs.derive_group_optionality(pyproject)
    assert lock_membership is not None  # Academy's real lock does carry `groups`

    for distribution in ("dotmac-kernel", "dotmac-ui", "dotmac-billing"):
        result = cs.derive_installation_dimension(
            distribution=distribution,
            lock_membership=lock_membership,
            recipes=(),
            group_optionality=group_optionality,
        )
        assert result is cs.DimensionValue.UNKNOWN


def test_derive_installation_dimension_would_say_true_with_a_real_recipe() -> None:
    """Sensitivity proof for the installation derivation itself (not just
    the search): supplying a real, matching recipe flips a genuinely
    installed distribution's `installation` to `true` — proving `UNKNOWN`
    above is because no recipe exists, not because the derivation can never
    say `true`."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock_document = tomllib.loads((ROOT / "poetry.lock").read_text())
    lock_membership = cs.derive_lock_group_membership(lock_document)
    group_optionality = cs.derive_group_optionality(pyproject)
    recipe = cs.parse_install_command("poetry install --no-root --no-ansi", source="synthetic")
    result = cs.derive_installation_dimension(
        distribution="dotmac-kernel",
        lock_membership=lock_membership,
        recipes=(recipe,),
        group_optionality=group_optionality,
    )
    assert result is cs.DimensionValue.TRUE

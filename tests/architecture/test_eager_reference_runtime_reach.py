"""Per-entry-point-family reach of the eager `dotmac_kernel.db` reference
runtime — a ratchet, not a gate, companion to the runtime-readiness inventory
in `docs/2026-09-09-eager-reference-runtime-readiness-inventory.md`.

Academy is slated as the first pilot for a Kernel product-bound database
runtime seam (`ProductAssemblySpec.database_runtime` /
`require_database_runtime`, landing on a sibling Kernel branch as of this
writing). That pilot needs an exact, current map of what still reaches the
eager reference runtime (`dotmac_kernel.db`'s two module-scope
`create_engine(...)` calls) — and it needs to be told the instant that map
changes, in either direction.

## Why two-directional, not a one-way "must not increase" gate

A count reaching zero for every family does NOT mean the eager reference
runtime stopped executing. It could mean:

* a genuine retirement (the pilot happened, the seam is in use) — good, but
  this file must be edited to say so in the same change, or
* the reach moved somewhere these five families don't cover (a new script,
  a new router file this test's file lists don't enumerate) — bad, and
  exactly the kind of "the grep found nothing" false confidence the
  `docs/kernel-alignment-gap-analysis.md` incident already cost this repo
  once (`app/db.py` silently drifting from `dotmac_kernel/db.py`).

So this ratchet fails on growth (a family newly reaching the eager runtime)
AND on shrink (a family that stops reaching it, without the baseline file
being lowered on purpose) — same shape as
`test_kernel_duplication.py`'s baseline, applied to `dotmac_kernel.db` reach
instead of model-name duplication.

## What "reach" means here, precisely

* **Direct** — an AST-detected `from dotmac_kernel.db import ...` /
  `from dotmac_kernel import db` / `import dotmac_kernel.db` at the top of a
  file in the family's own file list. Cheap, static, no execution.
* **Transitive** — whether importing the family's one representative entry
  module, in a FRESH subprocess, leaves `dotmac_kernel.db` in
  `sys.modules` afterward. This is the half a grep misses: Academy's own
  `app.main`/`app.kernel_runtime` never mention `dotmac_kernel.db` by name,
  yet importing either eagerly builds the reference engine, because
  resolving `dotmac_kernel.create_app` pulls in the kernel's own
  `app_factory` → `middleware.tenant` → `dotmac_kernel.db` chain — none of
  it Academy code. See the inventory doc's "one sentence that matters most"
  for the full chain with file:line citations.

A subprocess is required, not a `sys.modules` check in-process: other
architecture tests (`test_kernel_assembly.py`) already import `app.main` at
module scope, so by the time this file's tests run, `dotmac_kernel.db` is
already loaded in the pytest process for unrelated reasons. Only a clean
child process can tell you whether a GIVEN entry point, on its own, reaches
it.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE = Path(__file__).with_name("eager_reference_runtime_reach_baseline.txt")


def _imports_dotmac_kernel_db(tree: ast.AST) -> bool:
    """True iff `tree` contains a real import of `dotmac_kernel.db` — the two
    shapes Academy's code actually uses (`from dotmac_kernel.db import ...`
    and `from dotmac_kernel import db`) plus the bare `import
    dotmac_kernel.db` form. AST-only: a string or comment merely naming
    `dotmac_kernel.db` is not an `Import`/`ImportFrom` node and must not
    trip this (see the near-miss test below).
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "dotmac_kernel.db":
                return True
            if node.module == "dotmac_kernel" and any(alias.name == "db" for alias in node.names):
                return True
        elif isinstance(node, ast.Import):
            if any(alias.name == "dotmac_kernel.db" for alias in node.names):
                return True
    return False


def _direct_import_count(paths: list[Path]) -> int:
    count = 0
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _imports_dotmac_kernel_db(tree):
            count += 1
    return count


# The exact files this task's runtime-readiness inventory examined for each
# entry-point family. Adding a new file to a family (a new router, a new
# script) belongs here in the same change that adds it — an unlisted file is
# an unmonitored region, not a family with a zero count.
FAMILY_FILES: dict[str, list[Path]] = {
    "boot": [
        REPO_ROOT / "app" / "kernel_runtime.py",
        REPO_ROOT / "app" / "main.py",
    ],
    "api_deps": [
        REPO_ROOT / "app" / "api" / "deps.py",
        REPO_ROOT / "app" / "api" / "auth.py",
        REPO_ROOT / "app" / "api" / "persons.py",
        REPO_ROOT / "app" / "api" / "erp_applicant_assessments.py",
        REPO_ROOT / "app" / "api" / "rbac.py",
        REPO_ROOT / "app" / "api" / "admissions.py",
    ],
    "cli": [
        REPO_ROOT / "app" / "cli.py",
    ],
    "web": [
        REPO_ROOT / "app" / "web" / "context.py",
        REPO_ROOT / "app" / "web" / "labs.py",
    ],
    "scripts_tasks": [
        REPO_ROOT / "app" / "services" / "lab_jobs.py",
        REPO_ROOT / "scripts" / "seed_academy_demo.py",
    ],
}

# One importable module per family, used ONLY to probe transitive reach in a
# subprocess. Chosen as the family's actual boot/entry surface, not an
# arbitrary file: `app.main` for boot (the real ASGI entrypoint),
# `app.api.deps` for the request path, `app.cli` for the CLI, `app.web.context`
# for web (runs on every rendered page), `app.services.lab_jobs` for
# scripts/tasks/workers.
FAMILY_ENTRY_MODULE: dict[str, str] = {
    "boot": "app.main",
    "api_deps": "app.api.deps",
    "cli": "app.cli",
    "web": "app.web.context",
    "scripts_tasks": "app.services.lab_jobs",
}


@dataclass(frozen=True)
class FamilyReach:
    direct: int
    transitive: bool


def _measure_transitive_reach(module: str) -> bool:
    probe = (
        "import sys\n"
        f"import {module}\n"
        "print('REACHED' if 'dotmac_kernel.db' in sys.modules else 'NOT_REACHED')\n"
    )
    result = subprocess.run(  # noqa: S603 — sys.executable + a fixed probe string, no shell
        [sys.executable, "-c", probe],
        cwd=REPO_ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"probe import of {module!r} failed (exit {result.returncode}):\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return "REACHED" in result.stdout


def _measure_family(name: str) -> FamilyReach:
    return FamilyReach(
        direct=_direct_import_count(FAMILY_FILES[name]),
        transitive=_measure_transitive_reach(FAMILY_ENTRY_MODULE[name]),
    )


def _read_baseline() -> dict[str, FamilyReach]:
    baseline: dict[str, FamilyReach] = {}
    for raw_line in BASELINE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        family, rest = line.split(":direct=", 1)
        direct_str, transitive_str = rest.split(":transitive=", 1)
        baseline[family] = FamilyReach(direct=int(direct_str), transitive=transitive_str == "yes")
    return baseline


def test_baseline_names_exactly_the_declared_families() -> None:
    """Guard the guard: a family missing from the baseline passes vacuously."""
    baseline = _read_baseline()
    assert baseline, "baseline is empty — every other assertion here would pass vacuously"
    assert set(baseline) == set(FAMILY_FILES) == set(FAMILY_ENTRY_MODULE), (
        "the baseline file, FAMILY_FILES, and FAMILY_ENTRY_MODULE must all name "
        "exactly the same entry-point families"
    )


def test_no_family_reach_moves_without_the_baseline_being_edited() -> None:
    """Fails on GROWTH (a family newly reaches the eager runtime) and on
    SHRINK (a family stops reaching it without this file being lowered on
    purpose) — see module docstring for why the shrink direction matters
    just as much here."""
    baseline = _read_baseline()
    drift: list[str] = []
    for family in sorted(baseline):
        pinned = baseline[family]
        measured = _measure_family(family)
        if measured != pinned:
            drift.append(
                f"{family}: baseline direct={pinned.direct} "
                f"transitive={'yes' if pinned.transitive else 'no'}; "
                f"measured direct={measured.direct} "
                f"transitive={'yes' if measured.transitive else 'no'}"
            )
    assert not drift, (
        "dotmac_kernel.db reach changed for these families. If this is a "
        "deliberate retirement (or a deliberate new reach), update "
        "eager_reference_runtime_reach_baseline.txt AND the runtime-readiness "
        "inventory doc in the same change — do not let the number drift "
        "silently in either direction:\n  " + "\n  ".join(drift)
    )


def test_the_ast_detector_bites_a_planted_direct_import() -> None:
    """Sensitivity proof (1/2): every real import shape is named."""
    assert _imports_dotmac_kernel_db(ast.parse("from dotmac_kernel.db import get_db\n")) is True
    assert _imports_dotmac_kernel_db(ast.parse("from dotmac_kernel import db\n")) is True
    assert _imports_dotmac_kernel_db(ast.parse("import dotmac_kernel.db\n")) is True


def test_the_ast_detector_does_not_flag_a_comment_or_docstring_near_miss() -> None:
    """Sensitivity proof (2/2): several real files in this repo (and in the
    pinned kernel itself, e.g. `dotmac_kernel/errors.py`'s comments
    explaining why the db import is deferred) deliberately NAME
    `dotmac_kernel.db` in prose without importing it. A detector that fired
    on those would be untrustworthy noise, not a ratchet."""
    near_miss = ast.parse(
        '"""This module deliberately avoids dotmac_kernel.db at import time."""\n'
        "# see dotmac_kernel.db for the session helpers\n"
        "x = 'dotmac_kernel.db'\n"
    )
    assert _imports_dotmac_kernel_db(near_miss) is False

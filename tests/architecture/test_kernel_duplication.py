"""What this app reimplements from the kernel, as a number that can only go down.

This repo still defines its own `Base`, `Tenant`, `Role`, `UserCredential`, and
`AuthSession`, each of which the kernel also provides by the same name. The five
duplicate middleware modules were retired when Academy adopted the kernel app
factory; the remaining model entries are intentionally deferred because their
lineage and identity cutover is a separate migration.

The fork is not free, and 2026-08-10 priced it three times in one afternoon:

* `app/db.py` was a copy of `dotmac_kernel/db.py` that stopped tracking it. It
  never gained a non-request session boundary, so every CLI command ran with no
  RLS scope. RLS fails closed, so `audit-banks` printed `TOTAL 0 0` against a
  database holding 333 question banks, and `load-banks` had deployed nothing for
  37 commits. Neither ever raised.
* Adopting a kernel package moved this repo's dependencies for the first time,
  and the deploy recipe had no `poetry install` step. 502.
* The single-tenant lockdown was once adopted as a *setting*
  (`TENANCY=single`) but not as *behaviour*. Academy now runs the kernel
  lifespan and tests the binding through its real app.

## Why a ratchet and not a gate

Every entry below is a real duplicate today. Failing the build on all of them
would be red from the first run, and a permanently red check is one nobody
reads. `kernel_duplication_baseline.txt` records today's list; this fails only
on movement:

  * a duplicate that is **not** in the baseline — a new fork of something the
    kernel already provides;
  * a baseline entry that is **no longer** a duplicate — the list must shrink
    or it outlives the problem;
  * a baseline entry whose file is **gone**.

The middle rule is the point. It turns "academy is a fork" from an assertion
into a number, and makes convergence measurable whichever way ADR-0015 goes.

## What counts

Compared against the **installed kernel**, not a hardcoded list, so this stays
true as the kernel's surface moves: `dotmac_kernel.models.__all__` for models,
and the module names under `dotmac_kernel/middleware/` for middleware.

Name collision is the test, deliberately — not behavioural equivalence. Two
classes called `Role` mapping the same table are a duplication problem whether
or not their columns agree today. `Person` and `PersonRole` are NOT listed:
the kernel exports `Party`/`PartyRole`, so those are a divergence to decide
about, not a duplicate to delete.
"""

from __future__ import annotations

import ast
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BASELINE = pathlib.Path(__file__).with_name("kernel_duplication_baseline.txt")


def _kernel_model_names() -> set[str]:
    import dotmac_kernel.models as kernel_models

    return set(kernel_models.__all__)


def _kernel_middleware_modules() -> set[str]:
    import dotmac_kernel.middleware as kernel_middleware

    directory = pathlib.Path(kernel_middleware.__file__).parent
    return {p.stem for p in directory.glob("*.py") if p.stem != "__init__"}


def find_duplications() -> list[str]:
    """Everything this repo defines that the kernel already provides.

    Models are reported as `path:ClassName`, middleware as a bare path, so a
    reader can tell at a glance which kind an entry is.
    """
    found: list[str] = []

    kernel_models = _kernel_model_names()
    for path in sorted((REPO_ROOT / "app" / "models").glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in kernel_models:
                found.append(f"app/models/{path.name}:{node.name}")

    kernel_middleware = _kernel_middleware_modules()
    for path in sorted((REPO_ROOT / "app" / "middleware").glob("*.py")):
        if path.stem != "__init__" and path.stem in kernel_middleware:
            found.append(f"app/middleware/{path.name}")

    return sorted(found)


def _read_baseline() -> set[str]:
    return {
        line.strip()
        for line in BASELINE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def _entry_path(entry: str) -> pathlib.Path:
    return REPO_ROOT / entry.split(":", 1)[0]


def test_no_new_kernel_duplication() -> None:
    """Do not fork something the kernel already provides."""
    new = sorted(set(find_duplications()) - _read_baseline())
    assert not new, (
        "These duplicate a name the installed kernel already provides:\n  "
        + "\n  ".join(new)
        + "\n\nImport it from `dotmac_kernel` instead. If the kernel's version is "
        "genuinely missing something, add it there — every academy-private "
        "capability examined so far turned out to be a missing kernel capability "
        "(tenant_session_by_slug, resolver_session, TENANCY=single)."
    )


def test_baseline_shrinks_when_a_duplicate_is_retired() -> None:
    """A retired duplicate must leave the list, or the list outlives the problem."""
    baseline = _read_baseline()
    still_missing = {e for e in baseline if not _entry_path(e).is_file()}
    retired = sorted(baseline - set(find_duplications()) - still_missing)
    assert not retired, (
        "These are no longer duplicates and must be removed from "
        "kernel_duplication_baseline.txt:\n  " + "\n  ".join(retired)
    )


def test_baseline_entries_still_exist() -> None:
    """A renamed file leaves a hole for its replacement to fall into."""
    gone = sorted(e for e in _read_baseline() if not _entry_path(e).is_file())
    assert not gone, "These baseline entries no longer exist and must be removed:\n  " + "\n  ".join(gone)


def test_the_comparison_tracks_the_installed_kernel() -> None:
    """Guard the guard: a hardcoded list would rot as the kernel's surface moved.

    If this ever reads empty, every other assertion here passes vacuously.
    """
    assert _kernel_model_names(), "kernel exports no models — comparison is vacuous"
    assert _kernel_middleware_modules(), "kernel has no middleware — comparison is vacuous"

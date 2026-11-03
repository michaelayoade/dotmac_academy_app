"""Deterministic test shards for the hosted CI matrix.

The unit of placement is a test file, except for the few files listed under
``split`` in ``scripts/ci_test_weights.json``: those are slower than a shard can
afford, so each of their module-level test functions is its own unit, written as
``path::function`` (every parametrized case of that function runs with it).
Every test therefore belongs to exactly one shard.

Units are weighted by measured seconds from the committed table
(``scripts/ci_test_weights.json``, from CI run 41471936765); a file that is not in
the table is weighted ``size_bytes x seconds_per_byte``. They are ordered by weight
then name and placed greedily on the currently lightest shard (ties go to the
lowest shard index). Adding, removing or renaming a test file re-balances
deterministically; ``tests/test_ci_test_shards.py`` proves full, disjoint coverage,
that the table matches the tree, the predicted maximum shard time, and that the
workflow matrix agrees with this script.

Usage: ``python -m scripts.ci_test_shards --shard I --count N`` prints shard I
(1-based) of N, one pytest argument per line.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = "tests"
# pytest's default ``norecursedirs`` plus bytecode caches.
_PRUNED = (".*", "*.egg", "_darcs", "build", "CVS", "dist", "node_modules", "venv", "{arch}", "__pycache__")
_PATTERNS = ("test_*.py", "*_test.py")
WEIGHTS = "scripts/ci_test_weights.json"
#: Files that commit tenants through the platform runtime. They run once, in
#: their own pytest process against the dedicated ``academy_bootstrap_identity``
#: database (see the workflow), so the shared database never holds their rows.
ISOLATED = (
    "tests/services/test_bootstrap_identity.py",
    "tests/services/test_bootstrap.py",
)


def discover(root: Path = ROOT) -> list[str]:
    """Sorted, repository-relative POSIX paths of every collectable test file."""
    found: list[str] = []
    base = root / TESTS
    for directory, subdirs, names in os.walk(base):
        subdirs[:] = sorted(d for d in subdirs if not any(fnmatch.fnmatch(d, p) for p in _PRUNED))
        for name in names:
            if any(fnmatch.fnmatch(name, pattern) for pattern in _PATTERNS):
                found.append((Path(directory) / name).relative_to(root).as_posix())
    return sorted(found)


def assign(files: list[str], weights: dict[str, int], count: int) -> list[list[str]]:
    """Greedy longest-first placement; deterministic for a given input."""
    if count < 1:
        raise ValueError("shard count must be at least 1")
    shards: list[list[str]] = [[] for _ in range(count)]
    totals = [0] * count
    for path in sorted(files, key=lambda item: (-weights[item], item)):
        target = min(range(count), key=lambda index: (totals[index], index))
        shards[target].append(path)
        totals[target] += weights[path]
    return [sorted(shard) for shard in shards]


def load_weights(root: Path = ROOT) -> dict:
    return json.loads((root / WEIGHTS).read_text(encoding="utf-8"))


def test_functions(path: str, root: Path = ROOT) -> list[str]:
    """Module-level test functions of a split file, in source order.

    A split file must not define test classes: their methods could not be addressed
    as ``path::function`` units and would silently drop out of every shard.
    """
    tree = ast.parse((root / path).read_text(encoding="utf-8"))
    if any(isinstance(node, ast.ClassDef) and node.name.startswith("Test") for node in tree.body):
        raise ValueError(f"{path} defines a test class and cannot be split by function")
    functions = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test"):
                functions.append(node.name)
            continue
        if isinstance(node, ast.ClassDef):
            continue
        # Any other binding of a test* name (import, assignment, conditional or
        # try-guarded definition) would be collected by pytest but is not addressable here.
        for inner in ast.walk(node):
            names: list[str] = []
            if isinstance(inner, (ast.Import, ast.ImportFrom)):
                names = [(alias.asname or alias.name).split(".")[0] for alias in inner.names]
            elif isinstance(inner, ast.Name) and isinstance(inner.ctx, (ast.Store, ast.Del)):
                names = [inner.id]
            elif isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names = [inner.name]
            for name in names:
                if name.startswith("test"):
                    raise ValueError(f"{path} binds {name!r} other than by a plain module-level def; cannot split")
    return functions


def units(root: Path = ROOT) -> dict[str, int]:
    """Every placement unit (``path`` or ``path::function``) with its weight in seconds."""
    table = load_weights(root)
    split = table["split"]
    per_byte = table["seconds_per_byte"]
    result: dict[str, int] = {}
    for path in discover(root):
        if path in ISOLATED:
            continue
        if path in split:
            for name in test_functions(path, root):
                result[f"{path}::{name}"] = max(1, int(split[path][name]))
        elif path in table["files"]:
            result[path] = max(1, int(table["files"][path]))
        else:
            result[path] = max(1, round((root / path).stat().st_size * per_byte))
    return result


def shards(count: int, root: Path = ROOT) -> list[list[str]]:
    weights = units(root)
    return assign(list(weights), weights, count)


def shard_files(index: int, count: int, root: Path = ROOT) -> list[str]:
    """Units (paths or ``path::function``) of shard ``index`` (1-based) out of ``count``."""
    if not 1 <= index <= count:
        raise ValueError("shard index must satisfy 1 <= index <= count")
    return shards(count, root)[index - 1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, required=True, help="1-based shard index")
    parser.add_argument("--count", type=int, required=True, help="total number of shards")
    args = parser.parse_args(argv)
    try:
        files = shard_files(args.shard, args.count)
    except ValueError as exc:
        print(f"ci_test_shards: {exc}", file=sys.stderr)
        return 2
    if not files:
        print("ci_test_shards: refusing an empty shard", file=sys.stderr)
        return 2
    print("\n".join(files))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

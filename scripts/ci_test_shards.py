"""Deterministic test-file shards for the hosted CI matrix.

Every pytest-collectable test file under ``tests/`` belongs to exactly one shard.
The split is a pure function of the committed tree: files are discovered with
pytest's own default patterns (``test_*.py`` / ``*_test.py``), ordered by size
(a coarse proxy for run time) then path, and placed greedily on the currently
lightest shard (ties go to the lowest shard index). Adding, removing or
renaming a test file therefore re-balances deterministically with no manifest to
forget; ``tests/test_ci_test_shards.py`` proves full, disjoint coverage and that
the workflow matrix agrees with this script.

Usage: ``python -m scripts.ci_test_shards --shard I --count N`` prints shard I
(1-based) of N, one repository-relative POSIX path per line.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = "tests"
# pytest's default ``norecursedirs`` plus bytecode caches.
_PRUNED = (".*", "*.egg", "_darcs", "build", "CVS", "dist", "node_modules", "venv", "{arch}", "__pycache__")
_PATTERNS = ("test_*.py", "*_test.py")


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


def shards(count: int, root: Path = ROOT) -> list[list[str]]:
    files = discover(root)
    weights = {path: max(1, (root / path).stat().st_size) for path in files}
    return assign(files, weights, count)


def shard_files(index: int, count: int, root: Path = ROOT) -> list[str]:
    """Files of shard ``index`` (1-based) out of ``count``."""
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

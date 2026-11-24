"""Require a substantive README update alongside runtime-surface changes."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import PurePosixPath

RUNTIME_ROOTS = frozenset({"app", "templates", "static", "content", "alembic", "deploy", "scripts"})
RUNTIME_FILES = frozenset({"pyproject.toml", "poetry.lock", "alembic.ini"})


def requires_readme(paths: tuple[str, ...]) -> bool:
    return any(PurePosixPath(path).parts[0] in RUNTIME_ROOTS or path in RUNTIME_FILES for path in paths)


def validate_update(*, paths: tuple[str, ...], before: str, after: str) -> bool:
    """Whitespace-only edits and README deletion do not satisfy the rule."""
    if not requires_readme(paths):
        return True
    return "README.md" in paths and bool(after.strip()) and before.split() != after.split()


def git_output(*args: str) -> bytes:
    return subprocess.check_output(["git", *args])  # noqa: S603,S607 - fixed Git binary, validated commit arguments


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    for ref in (args.base, args.head):
        if re.fullmatch(r"[0-9a-f]{40}", ref) is None:
            parser.error("base and head must be full lowercase Git commit SHAs")
    # Compare only changes introduced by the PR, even when main advanced.
    ancestor = git_output("merge-base", args.base, args.head).decode().strip()
    paths = tuple(
        path.decode("utf-8")
        for path in git_output("diff", "--name-only", "--no-renames", "-z", ancestor, args.head).split(b"\0")
        if path
    )
    if not requires_readme(paths):
        print("README policy passed: no runtime-surface changes.")
        return 0
    before = git_output("show", f"{ancestor}:README.md").decode("utf-8")
    try:
        after = git_output("show", f"{args.head}:README.md").decode("utf-8")
    except subprocess.CalledProcessError:
        after = ""
    if not validate_update(paths=paths, before=before, after=after):
        print("README policy failed: describe the feature/behaviour change in README.md in this PR.")
        print("Link detailed documentation and distinguish source capability from deployed availability.")
        return 1
    print("README policy passed: runtime changes include a README update; reviewers must check its accuracy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

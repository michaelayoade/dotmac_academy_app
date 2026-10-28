"""The migration graph has exactly one head, and every parent exists.

A forked graph is caught today only by a full database run, and it does not
report itself: alembic refuses to upgrade with "Multiple head revisions are
present for given argument 'head'", no tables are created, and every DB-backed
test then fails with ``relation "tenants" does not exist``. That symptom names
neither the fork nor the file that caused it, so the failure reads as a broken
database rather than a bad ``down_revision``.

Two properties of this repo make picking the wrong parent easy:

- **Revision numbers are duplicated.** ``0036_tracks`` and a newly written
  ``0036_attempt_grants`` both existed at once.
- **Two filename conventions sort against each other.** ``0050_*.py`` sorts
  before ``20260711_0035_*.py``, so the newest-looking file in a directory
  listing is not the head.

These checks need no database, so they fail in the lint-fast part of the run
with a message that names the offending revisions.
"""

from __future__ import annotations

import ast
import pathlib

VERSIONS = pathlib.Path(__file__).resolve().parent.parent / "alembic" / "versions"


def _graph() -> tuple[dict[str, str], dict[str, object]]:
    """Map revision -> filename and revision -> parent(s).

    Parsed with ``ast`` rather than a regex because ``down_revision`` is a tuple
    at merge revisions, and several files declare it on the same line as
    ``revision`` — a ``^down_revision`` regex both misses those parents and
    invents extra heads as a result.
    """
    revisions: dict[str, str] = {}
    parents: dict[str, object] = {}
    for path in sorted(VERSIONS.glob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text())
        rev: str | None = None
        down: object = None
        seen_down = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                try:
                    value = ast.literal_eval(node.value)
                except (ValueError, SyntaxError):
                    continue
                if target.id == "revision" and isinstance(value, str):
                    rev = value
                elif target.id == "down_revision":
                    down, seen_down = value, True
        if rev is not None:
            assert rev not in revisions, (
                f"duplicate revision id {rev!r} in {path.name} and {revisions[rev]}"
            )
            revisions[rev] = path.name
            if seen_down:
                parents[rev] = down
    return revisions, parents


def _parent_set(parents: dict[str, object]) -> set[str]:
    out: set[str] = set()
    for value in parents.values():
        if isinstance(value, str):
            out.add(value)
        elif isinstance(value, (list, tuple)):
            out.update(v for v in value if isinstance(v, str))
    return out


def test_there_is_exactly_one_head():
    revisions, parents = _graph()
    heads = sorted(r for r in revisions if r not in _parent_set(parents))
    assert len(heads) == 1, (
        "the migration graph has forked, so alembic cannot upgrade and every "
        "DB-backed test will fail on a missing table. Heads: "
        + ", ".join(f"{h} ({revisions[h]})" for h in heads)
        + ". Chain the new migration onto the real head, or add a merge revision."
    )


def test_every_parent_exists():
    """A typo in down_revision detaches a subtree as silently as a fork does."""
    revisions, parents = _graph()
    for rev, parent in parents.items():
        for name in [parent] if isinstance(parent, str) else list(parent or []):
            assert name in revisions, (
                f"{rev} ({revisions[rev]}) names a down_revision {name!r} "
                "that no migration defines"
            )


def test_only_the_base_has_no_parent():
    """Two parentless migrations are two separate chains, not one history."""
    revisions, parents = _graph()
    roots = sorted(r for r in revisions if not parents.get(r))
    assert len(roots) == 1, (
        "expected a single base revision, found: "
        + ", ".join(f"{r} ({revisions[r]})" for r in roots)
    )


# One duplicate predates this check and CANNOT be fixed: a revision id is
# recorded in production's alembic_version table, so renaming either of these
# would strand every deployed database on an id no migration defines. It is
# grandfathered rather than repaired, and the guard below still catches new ones.
KNOWN_DUPLICATE_NUMBERS = {"0020"}  # 0020_activity_attempts, 0020_notifications


def test_revision_numbers_are_unique():
    """``0036_tracks`` and a new ``0036_attempt_grants`` coexisted once, and a
    duplicate number is how the *next* migration gets chained to the wrong
    parent — the author reads the number, not the graph."""
    revisions, _ = _graph()
    by_number: dict[str, list[str]] = {}
    for rev in revisions:
        number = rev.split("_", 1)[0]
        if number.isdigit():
            by_number.setdefault(number, []).append(rev)
    clashes = {
        n: sorted(v)
        for n, v in by_number.items()
        if len(v) > 1 and n not in KNOWN_DUPLICATE_NUMBERS
    }
    assert not clashes, (
        f"revision numbers reused: {clashes}. Renumber the new migration — "
        "the existing one's id may already be recorded in a deployed database."
    )

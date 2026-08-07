"""The curriculum manifest must describe courses that exist and a graph that terminates.

``load-curriculum`` refuses to write on an unknown slug or a cycle, but that
refusal happens against a live database at deploy time. These checks run against
the file alone, so a bad edit fails in CI rather than during an import.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
MANIFEST = ROOT / "content" / "management" / "CURRICULUM.yaml"


@pytest.fixture(scope="module")
def curriculum() -> dict:
    return yaml.safe_load(MANIFEST.read_text())["curriculum"]


@pytest.fixture(scope="module")
def course_slugs() -> set[str]:
    slugs = {p.name for p in (ROOT / "content" / "management").glob("mgmt-*") if p.is_dir()}
    assert slugs, "no course directories found — the glob or the layout changed"
    return slugs


def test_every_declared_slug_exists(curriculum, course_slugs):
    """A typo'd slug would otherwise look exactly like a run that enforced nothing."""
    declared: set[str] = set()
    for members in curriculum["groups"].values():
        declared |= set(members)
    for edge in curriculum["prerequisites"]:
        declared.add(edge["course"])
        declared |= set(edge["requires"])
    assert declared <= course_slugs, f"declared but absent: {sorted(declared - course_slugs)}"


def test_every_course_is_grouped(curriculum, course_slugs):
    """A course in neither group is a course nobody decided where to put."""
    grouped: set[str] = set()
    for members in curriculum["groups"].values():
        grouped |= set(members)
    assert course_slugs <= grouped, f"ungrouped: {sorted(course_slugs - grouped)}"


def test_no_course_is_in_two_groups(curriculum):
    seen: set[str] = set()
    for members in curriculum["groups"].values():
        clash = seen & set(members)
        assert not clash, f"in two groups: {sorted(clash)}"
        seen |= set(members)


def test_the_graph_has_no_cycle(curriculum):
    """A cycle locks every course in it permanently unreachable."""
    edges: dict[str, set[str]] = {}
    for entry in curriculum["prerequisites"]:
        edges.setdefault(entry["course"], set()).update(entry["requires"])

    state: dict[str, int] = {}

    def walk(node: str, path: list[str]) -> None:
        state[node] = 1
        for nxt in edges.get(node, ()):
            assert state.get(nxt) != 1, f"cycle: {' -> '.join([*path, node, nxt])}"
            if not state.get(nxt):
                walk(nxt, [*path, node])
        state[node] = 2

    for node in list(edges):
        if not state.get(node):
            walk(node, [])


def test_no_course_requires_itself(curriculum):
    for entry in curriculum["prerequisites"]:
        assert entry["course"] not in entry["requires"], entry["course"]


def test_chains_stay_one_deep(curriculum):
    """A learner who must finish three courses before the one they were sent to
    do will do none of them. The manifest says one edge; this holds it there."""
    requires: dict[str, set[str]] = {}
    for entry in curriculum["prerequisites"]:
        requires.setdefault(entry["course"], set()).update(entry["requires"])
    for course, reqs in requires.items():
        for req in reqs:
            assert req not in requires, (
                f"{course} requires {req}, which itself has prerequisites — "
                "that is a two-deep chain"
            )

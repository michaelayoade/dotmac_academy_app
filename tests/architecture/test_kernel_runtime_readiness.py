"""Academy's Kernel runtime-readiness record is validated by Academy's own CI.

The successor's compatibility gate (`dotmac_starter_mt`) previously took a
product's Kernel-compatibility facts as booleans that Starter itself authored
— a producing repository asserting a property it cannot verify about a
consuming repository. That was ruled out. The boolean now lives at
`docs/kernel-runtime-readiness.json`, written and owned by Academy, and this
module is the only thing that checks it against Academy's actual tree.
Starter's gate reads the record from a Git blob and parses it; it authors
nothing and re-derives nothing here.

This is deliberately NOT an import-the-app test. `app/api/deps.py`,
`app/cli.py`, `app/web/context.py`, and `app/web/labs.py` all import
`dotmac_kernel.db` at module scope, and importing that module eagerly
constructs the reference assembly's SQLAlchemy engines from `DATABASE_URL`
(see that module's docstring). Whether that import is safe to trigger during
collection is exactly the fact under test, so the checks below work by
reading source text and running `ast` over it — never by importing `app.*`
or `dotmac_kernel.db` — so the record itself, not incidental CI database
availability, decides whether this test can even run.
"""

from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
RECORD_PATH = ROOT / "docs" / "kernel-runtime-readiness.json"

EXPECTED_SCHEMA = "kernel-runtime-readiness.v1"
EXPECTED_PRODUCT = "dotmac_academy_app"
#: Canonical, owned by Starter's `PRODUCT_SPECS` -- NOT a phrase this record
#: coins. The richer semantics belong in `requirements[]`; encoding them into
#: the subject makes one identifier answer two questions and lets three
#: repositories drift into three different answers.
EXPECTED_SUBJECT = "academy-kernel-successor-readiness"
EXPECTED_TOP_LEVEL_KEYS = {
    "schema",
    "product",
    "subject",
    "requirements",
    "composition",
    "source_references",
}


def _load_record() -> dict[str, Any]:
    return json.loads(RECORD_PATH.read_text(encoding="utf-8"))


def _resolve_source_reference(source_reference: str) -> tuple[Path, int | None]:
    """Split a "path" or "path:line" reference and confirm the path exists.

    A Windows-style drive-letter colon never appears here (this tree runs on
    POSIX CI), so the first ":" from the right is always the line separator
    when present.
    """
    if ":" in source_reference:
        path_part, _, line_part = source_reference.rpartition(":")
        line_no = int(line_part)
    else:
        path_part, line_no = source_reference, None
    path = ROOT / path_part
    assert path.is_file(), f"source_reference path does not exist in this tree: {source_reference}"
    if line_no is not None:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert 1 <= line_no <= line_count, (
            f"source_reference line does not resolve: {source_reference} (file has {line_count} lines)"
        )
    return path, line_no


def _module_scope_import_present(path: Path, module_name: str) -> tuple[bool, int | None]:
    """True + the 1-indexed line number if `module_name` is imported at module scope.

    Only the file's top-level statements are inspected (`tree.body`, not
    `ast.walk`) — an import nested inside a function or an `if TYPE_CHECKING:`
    block does not eagerly construct anything at import time, and is not the
    property this record is about.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == module_name:
            return True, node.lineno
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == module_name:
                    return True, node.lineno
    return False, None


def _bind_database_runtime_called_anywhere_under_app() -> bool:
    """True if any file under app/ calls `bind_database_runtime` at all.

    A textual grep is deliberately sufficient here: the requirement is a
    negative claim (this call does not exist anywhere on Academy's import
    path today), and a name occurring anywhere in `app/` is the most
    generous possible reading in Academy's favour — if even that is absent,
    a narrower "called before the eager imports" check would also fail.
    """
    for py_file in (ROOT / "app").rglob("*.py"):
        if "bind_database_runtime" in py_file.read_text(encoding="utf-8"):
            return True
    return False


# One ground-truth check per requirement id. Each returns the fact as it
# actually is in this tree today — independent of what the record claims.
REQUIREMENT_GROUND_TRUTH = {
    "no-module-scope-kernel-db-import-in-api-deps": lambda: not _module_scope_import_present(
        ROOT / "app" / "api" / "deps.py", "dotmac_kernel.db"
    )[0],
    "no-module-scope-kernel-db-import-in-cli": lambda: not _module_scope_import_present(
        ROOT / "app" / "cli.py", "dotmac_kernel.db"
    )[0],
    "no-module-scope-kernel-db-import-in-web-context": lambda: not _module_scope_import_present(
        ROOT / "app" / "web" / "context.py", "dotmac_kernel.db"
    )[0],
    "no-module-scope-kernel-db-import-in-web-labs": lambda: not _module_scope_import_present(
        ROOT / "app" / "web" / "labs.py", "dotmac_kernel.db"
    )[0],
    "product-owned-runtime-bound-before-any-kernel-db-import": (
        lambda: _bind_database_runtime_called_anywhere_under_app()
    ),
}

# Requirement id -> (file, module) whose module-scope import line, if any,
# must match the record's declared source_reference line.
REQUIREMENT_IMPORT_SITE = {
    "no-module-scope-kernel-db-import-in-api-deps": (ROOT / "app" / "api" / "deps.py", "dotmac_kernel.db"),
    "no-module-scope-kernel-db-import-in-cli": (ROOT / "app" / "cli.py", "dotmac_kernel.db"),
    "no-module-scope-kernel-db-import-in-web-context": (ROOT / "app" / "web" / "context.py", "dotmac_kernel.db"),
    "no-module-scope-kernel-db-import-in-web-labs": (ROOT / "app" / "web" / "labs.py", "dotmac_kernel.db"),
}


def _validate_record(record: dict[str, Any]) -> None:
    """Raise AssertionError naming the exact failure if `record` is not truthful.

    Every top-level field, every requirement's `satisfied` value, and every
    composition declaration is checked against this tree — this is the
    function the plant test below flips a single bit against.
    """
    assert set(record.keys()) == EXPECTED_TOP_LEVEL_KEYS, (
        f"unexpected top-level keys: {set(record.keys()) - EXPECTED_TOP_LEVEL_KEYS} "
        f"(missing: {EXPECTED_TOP_LEVEL_KEYS - set(record.keys())})"
    )
    assert record["schema"] == EXPECTED_SCHEMA
    assert record["product"] == EXPECTED_PRODUCT
    assert record["subject"] == EXPECTED_SUBJECT

    requirements = record["requirements"]
    assert requirements, "requirements must not be empty"
    seen_ids: set[str] = set()
    for requirement in requirements:
        req_id = requirement["id"]
        assert req_id not in seen_ids, f"duplicate requirement id: {req_id}"
        seen_ids.add(req_id)

        _resolve_source_reference(requirement["source_reference"])

        assert req_id in REQUIREMENT_GROUND_TRUTH, (
            f"requirement {req_id!r} has no ground-truth check registered — "
            "add one to REQUIREMENT_GROUND_TRUTH before trusting its satisfied value"
        )
        actual = REQUIREMENT_GROUND_TRUTH[req_id]()
        claimed = requirement["satisfied"]
        assert claimed == actual, (
            f"requirement {req_id!r} claims satisfied={claimed!r} but this tree shows {actual!r}: "
            f"{requirement['statement']}"
        )

        if req_id in REQUIREMENT_IMPORT_SITE:
            path, module_name = REQUIREMENT_IMPORT_SITE[req_id]
            present, lineno = _module_scope_import_present(path, module_name)
            if present:
                _, declared_line = _resolve_source_reference(requirement["source_reference"])
                assert declared_line == lineno, (
                    f"requirement {req_id!r} source_reference line {declared_line} does not match "
                    f"the actual module-scope import at {path.relative_to(ROOT)}:{lineno}"
                )

    composition = record["composition"]
    assert composition, "composition must not be empty"
    for entry in composition:
        _resolve_source_reference(entry["source_reference"])

    # Composition-specific checks: the systemd application shape.
    service_files = sorted((ROOT / "deploy").glob("*.service"))
    timer_files = sorted((ROOT / "deploy").glob("*.timer"))
    assert len(service_files) == 9, f"expected 9 systemd .service units, found {len(service_files)}"
    assert len(timer_files) == 8, f"expected 8 systemd .timer units, found {len(timer_files)}"
    for service_file in service_files:
        text = service_file.read_text(encoding="utf-8")
        assert ".venv/bin/python -m app.cli" in text, (
            f"{service_file.relative_to(ROOT)} does not ExecStart .venv/bin/python -m app.cli"
        )
    assert not list(ROOT.rglob("Dockerfile*")), "a Dockerfile exists — the systemd-only composition claim is stale"

    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    compose_services = yaml_top_level_service_names(compose)
    assert compose_services == {"db"}, (
        f"docker-compose.yml declares services {compose_services}, not just {{'db'}} — "
        "the record's claim that no application container exists needs updating"
    )

    for path_str in record["source_references"]:
        assert (ROOT / path_str).exists(), f"source_references entry does not exist: {path_str}"


def yaml_top_level_service_names(compose_text: str) -> set[str]:
    """Minimal, dependency-free extraction of `services:` child keys.

    Avoids adding a YAML parser dependency to an architecture test for one
    two-line file; this is intentionally narrow (top-level keys directly
    under `services:`, unindented further) rather than a general YAML parser.
    """
    lines = compose_text.splitlines()
    names: set[str] = set()
    in_services = False
    for line in lines:
        if line.rstrip() == "services:":
            in_services = True
            continue
        if not in_services:
            continue
        if line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":"):
            names.add(line.strip().rstrip(":"))
        elif line and not line.startswith(" "):
            break
    return names


def test_kernel_runtime_readiness_record_is_truthful() -> None:
    """Near-miss control: the actual, unmodified record passes every check.

    This is the proof that a truthful record — including its honest `false`
    claims — is accepted rather than the validator rejecting everything by
    construction.
    """
    _validate_record(_load_record())


@pytest.mark.parametrize(
    "requirement_id",
    [
        "no-module-scope-kernel-db-import-in-api-deps",
        "no-module-scope-kernel-db-import-in-cli",
        "no-module-scope-kernel-db-import-in-web-context",
        "no-module-scope-kernel-db-import-in-web-labs",
        "product-owned-runtime-bound-before-any-kernel-db-import",
    ],
)
def test_flipping_a_false_requirement_to_true_is_caught(requirement_id: str) -> None:
    """Plant: lying about one requirement's satisfied value fails the build.

    Every requirement in the committed record is honestly `false` today —
    that is the whole point of this record. Flip exactly one to `true`
    (a claim the tree does not support) and confirm `_validate_record`
    names that exact requirement, not just "something is wrong".
    """
    record = copy.deepcopy(_load_record())
    (requirement,) = [r for r in record["requirements"] if r["id"] == requirement_id]
    assert requirement["satisfied"] is False, (
        f"fixture assumption broken: {requirement_id} is no longer recorded as false — "
        "update this plant once the underlying import is actually fixed"
    )
    requirement["satisfied"] = True

    with pytest.raises(AssertionError, match=requirement_id):
        _validate_record(record)


def test_every_requirement_ground_truth_check_is_registered() -> None:
    """A requirement id with no registered check would silently trust its claim."""
    record = _load_record()
    ids = {r["id"] for r in record["requirements"]}
    assert ids <= set(REQUIREMENT_GROUND_TRUTH), (
        f"requirement ids missing a ground-truth check: {ids - set(REQUIREMENT_GROUND_TRUTH)}"
    )


def test_record_declares_no_extra_top_level_field() -> None:
    """The envelope is owned by Starter; a product may not add a field to it."""
    record = _load_record()
    assert set(record.keys()) == EXPECTED_TOP_LEVEL_KEYS


def test_record_does_not_mention_foundation_deployment_adoption() -> None:
    """Foundation-deployment non-adoption is a Governance/deployment fact, not
    Kernel-compatibility evidence, and must never appear in this file under
    any field name — see this record's owning task for the ruling."""
    raw = RECORD_PATH.read_text(encoding="utf-8")
    for forbidden in ("foundation", "adopt", "adoption", "deployment-foundation"):
        assert forbidden not in raw.lower(), f"forbidden Foundation-deployment term {forbidden!r} found in record"

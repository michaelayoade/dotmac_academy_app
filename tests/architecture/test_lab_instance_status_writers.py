"""Pin which modules may write ``LabInstance.status`` (app/models/lab.py).

``status`` is derived lifecycle state, not a value any caller should assign
on a whim: today only the worker's operation-settlement code
(``app/services/lab_operations.py``) and its provision/destroy/reap
lifecycle code (``app/services/lab_lifecycle.py``) write it. Everything else
in the app — web routes, admin handlers, metrics, jobs — must only READ it
(``LabInstance.status.in_(...)``, ``LabInstance.status == "active"``, ...).

This is a two-directional RATCHET over
``lab_instance_status_writer_baseline.txt``, same shape as
``test_kernel_duplication.py``: it fails on a NEW writer file, on any
existing file's count RISING, and on a stale/lowered count left unrecorded
in the baseline (so the baseline can only shrink, never silently drift in
either direction).

## What counts as a write

Resolved pragmatically by AST shape, not by real type inference (this repo
has no type checker running over every file at collection time):

* ``<name>.status = ...`` / ``<name>.status += ...`` /
  ``<name>.status: T = ...`` (assignment forms only — an annotation with no
  value assigns nothing) in a file that imports or otherwise references the
  name ``LabInstance`` anywhere;
* ``setattr(<name>, "status", ...)`` in such a file;
* ``update(LabInstance)....values(status=...)`` (the SQLAlchemy Core bulk
  form), matched directly by finding the ``update(LabInstance)`` call inside
  the object the ``.values(...)`` call chains off of.

## Documented blind spots (deliberately not fixed)

* **False negative** — a status write that goes through a dict or
  ``**kwargs`` (e.g. ``setattr(instance, key, value)`` where ``key`` is a
  variable, or ``instance.__dict__.update(payload)``) is invisible to this
  scan. It only recognises the literal string ``"status"``.
* **False positive** — a DIFFERENT model's ``.status = ...`` assignment in a
  file that merely happens to also reference ``LabInstance`` (e.g. import it
  for an unrelated query) is counted as if it were a ``LabInstance`` write.
  The gate is "does this file reference the name ``LabInstance`` anywhere",
  not "is this specific attribute target proven to be a ``LabInstance``" —
  real type inference is out of scope for a static AST scan. In today's app
  this only affects ``app/services/lab_operations.py`` and
  ``app/services/lab_lifecycle.py`` themselves, since no other file that
  references ``LabInstance`` also assigns a differently-named model's
  ``.status`` — but a future file could trip this false positive, and that is
  an acceptable, documented cost of the ratchet, not a bug to silently work
  around.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = Path(__file__).with_name("lab_instance_status_writer_baseline.txt")


def _references_lab_instance(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "LabInstance":
            return True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or alias.name
                if name.split(".")[-1] == "LabInstance":
                    return True
    return False


def _count_attribute_status_writes(tree: ast.AST) -> int:
    count = 0
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Attribute) and target.attr == "status":
                count += 1
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "setattr" and len(node.args) >= 2:
                second = node.args[1]
                if isinstance(second, ast.Constant) and second.value == "status":
                    count += 1
    return count


def _contains_update_lab_instance_call(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            name: str | None = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name == "update":
                for arg in sub.args:
                    if isinstance(arg, ast.Name) and arg.id == "LabInstance":
                        return True
    return False


def _count_update_values_status(tree: ast.AST) -> int:
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "values":
                has_status_kw = any(kw.arg == "status" for kw in node.keywords)
                if has_status_kw and _contains_update_lab_instance_call(func.value):
                    count += 1
    return count


def _count_file(path: Path) -> int:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return 0
    if not _references_lab_instance(tree):
        return 0
    return _count_attribute_status_writes(tree) + _count_update_values_status(tree)


def scan_lab_instance_status_writers(root: Path) -> dict[str, int]:
    """Per-file ``LabInstance.status`` write counts under ``<root>/app``."""
    counts: dict[str, int] = {}
    for path in sorted((root / "app").rglob("*.py")):
        count = _count_file(path)
        if count:
            counts[str(path.relative_to(root))] = count
    return counts


def _read_baseline() -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("TOTAL "):
            continue
        count_str, _, path = stripped.partition(" ")
        counts[path] = int(count_str)
    return counts


def _baseline_total() -> int:
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("TOTAL "):
            return int(stripped.partition(" ")[2])
    raise AssertionError("baseline has no TOTAL line")


def test_no_new_lab_instance_status_writer_file() -> None:
    """A file not already in the baseline must not write LabInstance.status."""
    current = scan_lab_instance_status_writers(ROOT)
    baseline = _read_baseline()
    new_files = sorted(set(current) - set(baseline))
    assert not new_files, (
        "These files write LabInstance.status but are not in "
        "lab_instance_status_writer_baseline.txt — route the write through "
        "app/services/lab_operations.py or app/services/lab_lifecycle.py "
        "instead:\n  " + "\n  ".join(new_files)
    )


def test_no_file_count_rises_above_its_baseline() -> None:
    """An owning file's write count may not grow without updating the baseline."""
    current = scan_lab_instance_status_writers(ROOT)
    baseline = _read_baseline()
    risen = sorted(
        f"{path}: baseline {baseline[path]} -> now {current.get(path, 0)}"
        for path in baseline
        if current.get(path, 0) > baseline[path]
    )
    assert not risen, (
        "These files' LabInstance.status write counts rose above the " "recorded baseline:\n  " + "\n  ".join(risen)
    )


def test_stale_or_lowered_counts_are_recorded() -> None:
    """A retired or reduced writer must leave (or shrink in) the baseline file.

    This is the other direction of the ratchet: a baseline entry that no
    longer matches reality — because the file was deleted, stopped
    referencing LabInstance, or now writes status fewer times — must be
    updated. The baseline is a live record, not a historical artifact that
    only ever grows stale.
    """
    current = scan_lab_instance_status_writers(ROOT)
    baseline = _read_baseline()
    drifted = sorted(
        f"{path}: baseline {baseline[path]} but actual is {current.get(path, 0)}"
        for path in baseline
        if current.get(path, 0) < baseline[path]
    )
    assert not drifted, (
        "These baseline entries no longer match the real (lower) write "
        "count and must be updated in "
        "lab_instance_status_writer_baseline.txt:\n  " + "\n  ".join(drifted)
    )


def test_baseline_total_matches_the_sum_of_its_entries() -> None:
    baseline = _read_baseline()
    assert _baseline_total() == sum(baseline.values())


def test_scan_matches_the_baseline_exactly() -> None:
    """The real app/ tree, scanned today, equals the recorded baseline exactly."""
    assert scan_lab_instance_status_writers(ROOT) == _read_baseline()
    assert sum(scan_lab_instance_status_writers(ROOT).values()) == _baseline_total()


def test_sensitivity_a_planted_writer_is_detected(tmp_path: Path) -> None:
    planted = tmp_path / "planted_writer.py"
    planted.write_text(
        "from app.models.lab import LabInstance\n"
        "\n"
        "\n"
        "def settle(instance: LabInstance) -> None:\n"
        "    instance.status = 'active'\n"
    )
    assert _count_file(planted) == 1


def test_sensitivity_a_read_is_not_a_write(tmp_path: Path) -> None:
    planted = tmp_path / "planted_reader.py"
    planted.write_text(
        "from app.models.lab import LabInstance\n"
        "\n"
        "\n"
        "def is_active(instance: LabInstance) -> bool:\n"
        "    return instance.status == 'active'\n"
    )
    assert _count_file(planted) == 0


def test_sensitivity_a_comparison_is_not_a_write(tmp_path: Path) -> None:
    planted = tmp_path / "planted_compare.py"
    planted.write_text(
        "from app.models.lab import LabInstance\n"
        "\n"
        "\n"
        "def build_query():\n"
        "    return LabInstance.status.in_(('active', 'queued'))\n"
    )
    assert _count_file(planted) == 0


def test_sensitivity_status_on_an_unrelated_model_in_an_unrelated_file_is_not_counted(
    tmp_path: Path,
) -> None:
    """A near-miss: `.status = ...` on a model, in a file with no LabInstance.

    The file never references LabInstance at all, so the gate excludes it —
    unlike the documented false-positive blind spot, which only fires when
    the file DOES reference LabInstance for some other reason.
    """
    planted = tmp_path / "planted_unrelated.py"
    planted.write_text(
        "class Enrollment:\n"
        "    pass\n"
        "\n"
        "\n"
        "def activate(enrollment: Enrollment) -> None:\n"
        "    enrollment.status = 'active'\n"
    )
    assert _count_file(planted) == 0


def test_sensitivity_a_status_reason_attribute_is_not_a_status_write(
    tmp_path: Path,
) -> None:
    """A near-miss: a similarly-named attribute (`status_reason`) is not `status`."""
    planted = tmp_path / "planted_status_reason.py"
    planted.write_text(
        "from app.models.lab import LabInstance\n"
        "\n"
        "\n"
        "def annotate(instance: LabInstance) -> None:\n"
        "    instance.status_reason = 'manual override'\n"
    )
    assert _count_file(planted) == 0

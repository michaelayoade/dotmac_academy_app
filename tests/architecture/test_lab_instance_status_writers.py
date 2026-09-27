"""Pin which files may write a `.status` attribute anywhere under `app/`.

`LabInstance.status` (app/models/lab.py) is derived lifecycle state, owned
today by exactly two files: the worker's operation-settlement code
(`app/services/lab_operations.py`) and its provision/destroy/reap lifecycle
code (`app/services/lab_lifecycle.py`). Everything else must only READ it.

The scan itself, however, is NOT scoped to files that reference the name
`LabInstance` — an earlier version of this guard gated the attribute-write
count on that reference and was found to have a real hole: a new file
somewhere under `app/web/` could assign `some_lab.status = "active"` without
importing `LabInstance` by that name at all (a bare parameter, a dict lookup,
a differently-imported alias — anything that skips a literal `LabInstance`
token), and the old gate would silently count it as zero. There is no static,
import-free way to prove a bare attribute target is NOT some other model's
`.status`, so this scan makes the opposite, honest trade: it counts EVERY
`.status` attribute write anywhere under `app/`, for any object, and the
baseline lists every file that has one — not just LabInstance's owners. A
new file writing ANY `.status` attribute, on any model, fails the build and
forces a human to look at it and confirm it is not a new LabInstance writer
in disguise.

The SQLAlchemy Core bulk-write forms (`update(LabInstance).values(...)`,
`insert(LabInstance).values(...)`, `.update({...})`, `LabInstance(status=...)`
constructor calls, `bulk_update_mappings(LabInstance, ...)`,
`execute(update(LabInstance), [...])`, and a narrow raw-SQL shape) are the
one place this scan CAN name the target model explicitly, because the model
is a literal argument in the code (`update(LabInstance)`, `LabInstance(...)`)
— so those shapes stay LabInstance-specific, on top of the file-wide
plain-attribute count.

This is a two-directional RATCHET over
`lab_instance_status_writer_baseline.txt`, same shape as
`test_kernel_duplication.py`: it fails on a NEW writer file, on any existing
file's count RISING, and on a stale/lowered count left unrecorded in the
baseline.

## What counts as a write

* `<any-expr>.status = ...` / `+= ...` / `: T = ...` (assignment forms only
  — a bare annotation with no value assigns nothing) — ANYWHERE under
  `app/`, for any target, not just `LabInstance`.
* `setattr(<any-expr>, "status", ...)` — same, file-wide.
* `update(LabInstance).values(status=...)` / `insert(LabInstance).values(status=...)`
  — keyword form, either statement.
* `update(LabInstance).values({"status": ...})` / `insert(LabInstance).values({"status": ...})`
  — dict-literal form, either statement.
* `query(LabInstance)....update({"status": ...})` — dict-literal form.
  These require the `LabInstance` reference to appear as an argument to the
  `update(...)`/`insert(...)`/`query(...)` call somewhere in the chain the
  `.values(...)`/`.update(...)` call is made on — resolved as either a bare
  `Name` (`LabInstance`) or an `Attribute` (`lab_models.LabInstance`), so a
  module-qualified import alias is still recognised.
* `LabInstance(status=...)` — a `status=` keyword argument passed directly to
  the constructor, including through a module alias (`lab_models.LabInstance(status=...)`).
* `bulk_update_mappings(LabInstance, ...)` — counted unconditionally once the
  first positional argument resolves to `LabInstance`; unlike the other
  bulk forms this one is not gated on finding the literal string `"status"`
  anywhere, since the mapping list is usually a runtime value.
* `execute(update(LabInstance), [{...}, ...])` — a bulk-parameter `execute`
  call whose first argument is an `update(LabInstance)` (or
  `insert(LabInstance)`/`query(LabInstance)`) chain and whose second argument
  is a literal list containing at least one dict literal with a `"status"` key.
* `text("...UPDATE lab_instances... status ...")` — a raw-SQL string literal
  passed to `text(...)`, counted only when the literal contains BOTH the
  substrings `"UPDATE lab_instances"` and `"status"`. Any other raw-SQL shape
  is a documented blind spot below, not something this scan attempts.

## Documented blind spots (deliberately not fixed)

* **False negative** — a status write that goes through a dict/`**kwargs`
  with a non-literal key (`setattr(instance, key, value)` where `key` is a
  variable, or `instance.__dict__.update(payload)`) is invisible. Only the
  literal string `"status"` is recognised.
* **False negative** — the bulk-write shapes above require the model to
  appear as a literal `LabInstance`/`<alias>.LabInstance` token in the same
  statement's call chain; a bulk update built through an intermediate
  variable (`stmt = update(LabInstance); ...; stmt.values(status=...)`
  across two statements) is not connected by this scan.
* **False negative** — raw SQL is recognised in exactly one shape: a
  string-literal argument to `text(...)` containing both `"UPDATE
  lab_instances"` and `"status"` verbatim. A dynamically built string
  (f-string, `.format()`, concatenation), a different table alias/casing, a
  multi-statement script, or SQL passed some other way than `text(...)`'s
  first positional argument is invisible to this scan. Raw SQL against
  `lab_instances` is inherently the hardest case for a static AST scan to
  cover honestly, and this narrow, literal-substring match is the entire
  extent of the attempt — it is not a general SQL parser.
* Every non-bulk `.status` write on any OTHER model still counts toward that
  file's total (that is the point — see above), so the baseline is honestly
  a list of "all `.status` writers today", not "all LabInstance writers
  today". `LabInstance`'s only real owners are `lab_operations.py` and
  `lab_lifecycle.py`; every other baseline entry writes some other model's
  `.status` (`Enrollment`, `EmailOutbox`, `SuccessQueueEntry`, ...).
* A file that fails to parse (a syntax error) is a bug in the scan's own
  assumptions about the tree and is allowed to raise — it is not silently
  treated as "zero writes here."
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = Path(__file__).with_name("lab_instance_status_writer_baseline.txt")


def _is_lab_instance_reference(node: ast.AST) -> bool:
    """True for a bare `LabInstance` name or a `<alias>.LabInstance` attribute."""
    return (isinstance(node, ast.Name) and node.id == "LabInstance") or (
        isinstance(node, ast.Attribute) and node.attr == "LabInstance"
    )


def _call_names_lab_instance(call: ast.Call) -> bool:
    return any(_is_lab_instance_reference(arg) for arg in call.args)


_LAB_INSTANCE_TARGETING_CALL_NAMES = ("update", "insert", "query")


def _callee_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _chain_targets_lab_instance(node: ast.AST) -> bool:
    """True if an `update(LabInstance)`/`insert(LabInstance)`/`query(LabInstance)` call is anywhere in this chain."""
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Call)
            and _callee_name(sub) in _LAB_INSTANCE_TARGETING_CALL_NAMES
            and _call_names_lab_instance(sub)
        ):
            return True
    return False


def _dict_has_status_key(node: ast.AST) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    return any(isinstance(key, ast.Constant) and key.value == "status" for key in node.keys)


def _iter_status_attribute_targets(target: ast.expr) -> Iterator[ast.Attribute]:
    """Yield every `.status` attribute nested inside an assignment target.

    An assignment target is not always a bare `Attribute` — it can be a
    `Tuple`/`List` unpacking pattern (`lab.status, other = ...`,
    `(a.status, b) = ...`) or wrap a `Starred` element
    (`x, *lab.status = ...`). Recurse through both so a `.status` write
    hidden inside an unpacking target is not missed.
    """
    if isinstance(target, ast.Attribute) and target.attr == "status":
        yield target
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _iter_status_attribute_targets(elt)
    elif isinstance(target, ast.Starred):
        yield from _iter_status_attribute_targets(target.value)


def _count_attribute_status_writes(tree: ast.AST) -> int:
    """Every `.status` attribute write anywhere in the file, for any target.

    Every element of a chained assignment (`a = lab.status = ...`) is its
    own entry in `Assign.targets` and is checked independently. `for
    lab.status in ...:` and `with ... as lab.status:` targets are ordinary
    assignment targets in the AST sense and are included on the same basis.
    """
    count = 0
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            targets = [node.target]
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            targets = [node.optional_vars]
        for target in targets:
            count += sum(1 for _ in _iter_status_attribute_targets(target))
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "setattr" and len(node.args) >= 2:
                second = node.args[1]
                if isinstance(second, ast.Constant) and second.value == "status":
                    count += 1
    return count


def _count_lab_instance_bulk_status_writes(tree: ast.AST) -> int:
    """`update(LabInstance).values(status=...)`/`insert(...)` and their dict-literal siblings."""
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in ("values", "update")):
            continue
        has_status_kw = func.attr == "values" and any(kw.arg == "status" for kw in node.keywords)
        has_status_dict = any(_dict_has_status_key(arg) for arg in node.args)
        if (has_status_kw or has_status_dict) and _chain_targets_lab_instance(func.value):
            count += 1
    return count


def _count_lab_instance_constructor_status_writes(tree: ast.AST) -> int:
    """`LabInstance(status=...)`, including `lab_models.LabInstance(status=...)`."""
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_lab_instance_reference(node.func):
            if any(kw.arg == "status" for kw in node.keywords):
                count += 1
    return count


def _count_lab_instance_bulk_update_mappings(tree: ast.AST) -> int:
    """`bulk_update_mappings(LabInstance, ...)` — counted unconditionally, see docstring."""
    count = 0
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and _callee_name(node) == "bulk_update_mappings"
            and node.args
            and _is_lab_instance_reference(node.args[0])
        ):
            count += 1
    return count


def _list_literal_has_a_status_dict(node: ast.AST) -> bool:
    return isinstance(node, ast.List) and any(_dict_has_status_key(elt) for elt in node.elts)


def _count_lab_instance_execute_update_list_writes(tree: ast.AST) -> int:
    """`execute(update(LabInstance), [{..., "status": ...}])`."""
    count = 0
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and _callee_name(node) == "execute"
            and len(node.args) >= 2
            and _chain_targets_lab_instance(node.args[0])
            and _list_literal_has_a_status_dict(node.args[1])
        ):
            count += 1
    return count


def _count_raw_sql_lab_instance_status_writes(tree: ast.AST) -> int:
    """`text("...UPDATE lab_instances... status ...")` — see the narrow blind-spot note above."""
    count = 0
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and _callee_name(node) == "text"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            sql = node.args[0].value
            if "UPDATE lab_instances" in sql and "status" in sql:
                count += 1
    return count


def _count_file(path: Path) -> int:
    """Raises on a syntax error — a file that fails to parse is not "zero writes"."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return (
        _count_attribute_status_writes(tree)
        + _count_lab_instance_bulk_status_writes(tree)
        + _count_lab_instance_constructor_status_writes(tree)
        + _count_lab_instance_bulk_update_mappings(tree)
        + _count_lab_instance_execute_update_list_writes(tree)
        + _count_raw_sql_lab_instance_status_writes(tree)
    )


def scan_status_writers(root: Path) -> dict[str, int]:
    """Per-file `.status` write counts under `<root>/app` (file-wide, any model)."""
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


def test_no_new_status_writer_file() -> None:
    """A file not already in the baseline must not write any `.status` attribute."""
    current = scan_status_writers(ROOT)
    baseline = _read_baseline()
    new_files = sorted(set(current) - set(baseline))
    assert not new_files, (
        "These files write a `.status` attribute but are not in "
        "lab_instance_status_writer_baseline.txt — if this is LabInstance.status, "
        "route it through app/services/lab_operations.py or "
        "app/services/lab_lifecycle.py; if it is a different model, add it to the "
        "baseline deliberately:\n  " + "\n  ".join(new_files)
    )


def test_no_file_count_rises_above_its_baseline() -> None:
    current = scan_status_writers(ROOT)
    baseline = _read_baseline()
    risen = sorted(
        f"{path}: baseline {baseline[path]} -> now {current.get(path, 0)}"
        for path in baseline
        if current.get(path, 0) > baseline[path]
    )
    assert not risen, "These files' `.status` write counts rose above the recorded baseline:\n  " + "\n  ".join(risen)


def test_stale_or_lowered_counts_are_recorded() -> None:
    """A retired or reduced writer must leave (or shrink in) the baseline file."""
    current = scan_status_writers(ROOT)
    baseline = _read_baseline()
    drifted = sorted(
        f"{path}: baseline {baseline[path]} but actual is {current.get(path, 0)}"
        for path in baseline
        if current.get(path, 0) < baseline[path]
    )
    assert not drifted, (
        "These baseline entries no longer match the real (lower) write count and "
        "must be updated in lab_instance_status_writer_baseline.txt:\n  " + "\n  ".join(drifted)
    )


def test_baseline_total_matches_the_sum_of_its_entries() -> None:
    baseline = _read_baseline()
    assert _baseline_total() == sum(baseline.values())


def test_scan_matches_the_baseline_exactly() -> None:
    """The real app/ tree, scanned today, equals the recorded baseline exactly."""
    current = scan_status_writers(ROOT)
    assert current == _read_baseline()
    assert sum(current.values()) == _baseline_total()


def test_sensitivity_exact_set_over_a_planted_tree(tmp_path: Path) -> None:
    """One positive per counter, plus every documented near-miss, as one exact-set assertion."""
    app_dir = tmp_path / "app"
    app_dir.mkdir()

    # One positive for each of the four plain-attribute counters. None of
    # these reference LabInstance at all -- the whole point of the file-wide
    # rule is that they still count.
    (app_dir / "positives.py").write_text(
        "def assign(x):\n"
        "    x.status = 'active'\n"
        "\n"
        "\n"
        "def augmented(x):\n"
        "    x.status += '!'\n"
        "\n"
        "\n"
        "def annotated(x):\n"
        "    x.status: str = 'active'\n"
        "\n"
        "\n"
        "def via_setattr(x):\n"
        "    setattr(x, 'status', 'active')\n"
    )

    # One positive for each LabInstance-specific bulk/constructor/raw-SQL form:
    # update().values() kw + dict, query().update() dict, insert().values()
    # kw + dict, the constructor kwarg (through a module alias),
    # bulk_update_mappings, execute(update(...), [...]), and the narrow raw
    # text() SQL shape. That is 9 positives in this one file.
    (app_dir / "lab_bulk.py").write_text(
        "from app.models import lab as lab_models\n"
        "from sqlalchemy import bulk_update_mappings, execute, insert, text, update\n"
        "\n"
        "\n"
        "def update_kw_form():\n"
        "    return update(lab_models.LabInstance).values(status='active')\n"
        "\n"
        "\n"
        "def update_dict_form():\n"
        "    return update(lab_models.LabInstance).values({'status': 'active'})\n"
        "\n"
        "\n"
        "def query_update_dict_form(session):\n"
        "    return session.query(lab_models.LabInstance).filter_by(id=1).update({'status': 'active'})\n"
        "\n"
        "\n"
        "def insert_kw_form():\n"
        "    return insert(lab_models.LabInstance).values(status='active')\n"
        "\n"
        "\n"
        "def insert_dict_form():\n"
        "    return insert(lab_models.LabInstance).values({'status': 'active'})\n"
        "\n"
        "\n"
        "def constructor_form():\n"
        "    return lab_models.LabInstance(status='queued')\n"
        "\n"
        "\n"
        "def bulk_update_mappings_form(session):\n"
        "    return bulk_update_mappings(lab_models.LabInstance, [{'id': 1}])\n"
        "\n"
        "\n"
        "def execute_update_list_form(conn):\n"
        "    return conn.execute(update(lab_models.LabInstance), [{'id': 1, 'status': 'active'}])\n"
        "\n"
        "\n"
        "def raw_sql_form(conn):\n"
        "    return conn.execute(text('UPDATE lab_instances SET status = :status'))\n"
    )

    # One positive for each unpacking-target/chained/for/with shape: a bare
    # tuple target, a parenthesized tuple target, a starred target, a
    # chained assignment (only the attribute half of which should count),
    # a `for` loop target, and a `with ... as` target.
    (app_dir / "unpacking_targets.py").write_text(
        "def tuple_target(lab, other):\n"
        "    lab.status, other = 1, 2\n"
        "\n"
        "\n"
        "def parenthesized_tuple_target(a, b):\n"
        "    (a.status, b) = (1, 2)\n"
        "\n"
        "\n"
        "def starred_target(lab):\n"
        "    x, *lab.status = [1, 2, 3]\n"
        "\n"
        "\n"
        "def chained_assignment(a, lab):\n"
        "    a = lab.status = 1\n"
        "\n"
        "\n"
        "def for_loop_target(lab, seq):\n"
        "    for lab.status in seq:\n"
        "        pass\n"
        "\n"
        "\n"
        "def with_as_target(lab, ctx):\n"
        "    with ctx() as lab.status:\n"
        "        pass\n"
    )

    # Every documented near-miss: a read, a comparison, a same-named-but-
    # different attribute, a bulk update targeting a DIFFERENT model, and a
    # raw-SQL text() literal that mentions the table but never "status".
    (app_dir / "near_misses.py").write_text(
        "from sqlalchemy import text, update\n"
        "from app.models.enrollment import Enrollment\n"
        "\n"
        "\n"
        "def is_active(x):\n"
        "    return x.status == 'active'\n"
        "\n"
        "\n"
        "def annotate(x):\n"
        "    x.status_reason = 'manual override'\n"
        "\n"
        "\n"
        "def other_model_bulk_update():\n"
        "    return update(Enrollment).values(status='active')\n"
        "\n"
        "\n"
        "def raw_sql_without_status(conn):\n"
        "    return conn.execute(text('UPDATE lab_instances SET runtime_presence = :p'))\n"
    )

    assert scan_status_writers(tmp_path) == {
        "app/positives.py": 4,
        "app/lab_bulk.py": 9,
        "app/unpacking_targets.py": 6,
    }

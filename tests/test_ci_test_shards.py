"""The sharded hosted CI runs every test exactly once and keeps every gate."""

import ast
from pathlib import Path

import pytest
import yaml

from scripts import ci_test_shards as sharding

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


@pytest.fixture(scope="module")
def workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def count(workflow):
    shard_axis = workflow["jobs"]["test"]["strategy"]["matrix"]["shard"]
    assert shard_axis == list(range(1, len(shard_axis) + 1)), "matrix shards must be exactly 1..N"
    assert len(shard_axis) > 1
    return len(shard_axis)


def _independent_discovery() -> set[str]:
    return {
        path.relative_to(ROOT).as_posix()
        for pattern in ("test_*.py", "*_test.py")
        for path in (ROOT / "tests").rglob(pattern)
        if "__pycache__" not in path.parts
    }


def _module_test_functions(path: str) -> list[str]:
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    return [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test")
    ]


def test_every_test_is_in_exactly_one_shard(count):
    """Each unsplit file, or each module-level test function of a split file, lands in one shard.

    This is finer than file-level coverage: a split file's path never appears whole,
    and a function of a split file is placed exactly once.
    """
    everything = _independent_discovery()
    assert everything and set(sharding.discover(ROOT)) == everything
    split = sharding.load_weights(ROOT)["split"]
    expected = set()
    for path in everything:
        if path in split:
            expected |= {f"{path}::{name}" for name in _module_test_functions(path)}
        else:
            expected.add(path)
    placed = [unit for shard in sharding.shards(count, ROOT) for unit in shard]
    assert len(placed) == len(set(placed)), "a test unit appears in more than one shard"
    assert set(placed) == expected, "a test unit is missing from every shard or unknown"
    assert not set(split) & set(placed), "a split file's path must never appear whole"


def test_weight_table_matches_the_tree():
    table = sharding.load_weights(ROOT)
    discovered = set(sharding.discover(ROOT))
    assert set(table["files"]) <= discovered
    assert set(table["split"]) <= discovered
    assert not set(table["files"]) & set(table["split"])
    for path, by_function in table["split"].items():
        # No stale and no missing function; split files have no test classes.
        assert set(by_function) == set(_module_test_functions(path)), path
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        assert not [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name.startswith("Test")], path
        assert all(type(v) is int and v > 0 for v in by_function.values())
    assert all(type(v) is int and v > 0 for v in table["files"].values())
    assert table["seconds_per_byte"] > 0
    assert set(table["estimated"]) <= set(table["split"])


# The job allows 25 minutes (1500 s) and spends about 3.6 minutes before pytest starts.
MAX_PREDICTED_SHARD_SECONDS = 1080


def test_predicted_slowest_shard_fits_the_budget(count):
    weights = sharding.units(ROOT)
    assert max(weights.values()) <= MAX_PREDICTED_SHARD_SECONDS, "a single unit exceeds the shard budget"
    totals = [sum(weights[unit] for unit in shard) for shard in sharding.shards(count, ROOT)]
    assert max(totals) <= MAX_PREDICTED_SHARD_SECONDS, totals


def test_no_shard_is_empty_and_the_split_is_deterministic(count):
    first = sharding.shards(count, ROOT)
    assert first == sharding.shards(count, ROOT)
    assert all(first), "an empty shard would fall through to no tests"
    for index in range(1, count + 1):
        assert sharding.shard_files(index, count, ROOT) == first[index - 1]


def test_shard_selection_refuses_out_of_range_requests():
    for index, total in ((0, 3), (4, 3), (1, 0)):
        with pytest.raises(ValueError):
            sharding.shard_files(index, total, ROOT)
    assert sharding.main(["--shard", "9", "--count", "3"]) == 2


def test_workflow_runs_each_shard_with_every_gate_and_its_own_evidence(workflow):
    job = workflow["jobs"]["test"]
    assert job["timeout-minutes"] == 25
    assert job["strategy"]["fail-fast"] is False
    steps = {step.get("name"): step for step in job["steps"]}
    tests = steps["Tests"]
    assert tests["env"] == {"SHARD_INDEX": "${{ matrix.shard }}", "SHARD_COUNT": "${{ strategy.job-total }}"}
    script = tests["run"]
    assert "-m scripts.ci_test_shards --shard \"$SHARD_INDEX\" --count \"$SHARD_COUNT\"" in script
    assert "pytest -x " in script and "--junitxml=artifacts/pytest.xml" in script
    assert '"${shard_files[@]}"' in script and "-eq 0" in script
    # The skip-evidence gate reads this same shard's JUnit report.
    skips = steps["Refuse unreviewed test skips"]
    assert "artifacts/pytest.xml tests/ci_skip_allowlist.txt" in skips["run"]
    for name in (
        "Materialize the declared Genesis-only PostgreSQL image",
        "Discover historical and fresh schema convergence without commit",
        "Bootstrap qualified empty composed application database",
        "Verify ordinary migration CLI is a no-op and verify committed schema",
        "Lint (ruff)",
        "Type check (mypy)",
    ):
        assert name in steps, name
    upload = steps["Retain hosted rehearsal execution evidence"]
    assert upload["with"]["name"].endswith("-shard-${{ matrix.shard }}")
    assert "artifacts/shard-files.txt" in upload["with"]["path"]


def test_aggregate_check_requires_every_shard(workflow):
    aggregate = workflow["jobs"]["test-complete"]
    assert aggregate["name"] == "test"
    assert aggregate["needs"] == "test" and aggregate["if"] == "always()"
    (step,) = aggregate["steps"]
    assert step["env"] == {"SHARDS_RESULT": "${{ needs.test.result }}"}
    assert '"$SHARDS_RESULT" != "success"' in step["run"]

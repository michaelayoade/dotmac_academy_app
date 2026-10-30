"""A cast's type argument is evaluated even with postponed annotations."""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _violations(source):
    tree = ast.parse(source)
    unavailable = set()
    for node in tree.body:
        if not isinstance(node, ast.If) or node.orelse:
            continue
        condition = node.test
        checking = isinstance(condition, ast.Name) and condition.id == "TYPE_CHECKING"
        checking |= isinstance(condition, ast.Attribute) and condition.attr == "TYPE_CHECKING"
        if not checking:
            continue
        for item in node.body:
            if isinstance(item, ast.Assign):
                unavailable.update(t.id for t in item.targets if isinstance(t, ast.Name))
            elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                unavailable.add(item.target.id)
            elif isinstance(item, ast.ImportFrom):
                unavailable.update(n.asname or n.name for n in item.names)
            elif isinstance(item, ast.Import):
                unavailable.update(n.asname or n.name.split(".")[0] for n in item.names)
    return [
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Call) and node.args
        and (isinstance(node.func, ast.Name) and node.func.id == "cast"
             or isinstance(node.func, ast.Attribute) and node.func.attr == "cast")
        and any(isinstance(name, ast.Name) and name.id in unavailable for name in ast.walk(node.args[0]))
    ]


def test_product_casts_never_evaluate_type_checking_only_names():
    failures = {str(p.relative_to(ROOT)): lines for p in (ROOT / "app").rglob("*.py")
                if (lines := _violations(p.read_text()))}
    assert failures == {}


@pytest.mark.parametrize(("expression", "invalid"), [
    ("_PrivateRecord", True), ("tuple[_PrivateRecord, ...]", True),
    ('"_PrivateRecord"', False), ('"tuple[_PrivateRecord, ...]"', False),
])
def test_guard_detects_direct_and_compound_runtime_name_errors(expression, invalid):
    source = f"if TYPE_CHECKING:\n    _PrivateRecord = tuple[int, str]\nvalue = cast({expression}, data)\n"
    assert bool(_violations(source)) is invalid

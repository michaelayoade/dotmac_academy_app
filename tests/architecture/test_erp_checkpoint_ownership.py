"""Import-free guard for ERP transport's learning-state boundary.

Covers literal attributes, constructor/bulk keyword/dict keys, setattr and SQL.
Dynamic keys/SQL cannot be proven by AST and still require code review.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_transport_does_not_write_completion_delivery_snapshot():
    source = (ROOT / "app/services/erp_sync.py").read_text()
    tree = ast.parse(source)
    writes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store) and node.attr == "erp_synced_at":
            writes.append(ast.unparse(node.value))
        if isinstance(node, ast.Call):
            assert not any(k.arg == "erp_synced_at" for k in node.keywords)
            if isinstance(node.func, ast.Name) and node.func.id == "setattr":
                assert not any(isinstance(a, ast.Constant) and a.value == "erp_synced_at" for a in node.args)
        if isinstance(node, ast.Dict):
            assert not any(isinstance(k, ast.Constant) and k.value == "erp_synced_at" for k in node.keys)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            sql = node.value.lower()
            assert not ("course_completions" in sql and any(w in sql for w in ("update ", "insert ")))
    assert writes == ["checkpoint"]
    assert "ERPCompletionCheckpoint" in source
    assert "with_for_update" in source and "populate_existing=True" in source


def test_learning_services_do_not_own_checkpoints():
    for path in (ROOT / "app/services").rglob("*.py"):
        if path.name == "erp_sync.py":
            continue
        source = path.read_text()
        assert "ERPCompletionCheckpoint" not in source, path
        assert "academy_erp_completion_checkpoints" not in source, path

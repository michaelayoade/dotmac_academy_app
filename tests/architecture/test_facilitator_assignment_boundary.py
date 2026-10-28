"""Prevent the retired enrollment-as-facilitator writer from returning."""

import ast
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[2] / "app"


def _is_instructor_literal(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value == "instructor"


def test_application_never_writes_instructor_as_an_enrollment_role() -> None:
    violations: list[str] = []
    for path in APP_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "assign_facilitator":
                violations.append(f"{path}:{node.lineno}: retired assign_facilitator writer")
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "role_in_cohort" and _is_instructor_literal(keyword.value):
                        violations.append(f"{path}:{node.lineno}: instructor Enrollment constructor")
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if _is_instructor_literal(value) and any(
                    isinstance(target, ast.Attribute) and target.attr == "role_in_cohort" for target in targets
                ):
                    violations.append(f"{path}:{node.lineno}: instructor Enrollment mutation")

    assert violations == [], "\n".join(violations)

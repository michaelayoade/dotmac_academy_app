# ruff: noqa: S101 -- assertions qualify the public source boundary.
"""Prevent operational data or vendor fixtures entering this code package."""

import hashlib
import importlib.util
import sys
from pathlib import Path


def test_package_contains_only_source_and_generic_contracts():
    root = Path(__file__).parents[1]
    allowed_names = {"README.md", "pytest.ini", "requirements-ci.txt", "SOURCE_FILES.sha256"}
    forbidden_parts = {"fixtures", "history", ".cutover-private", "acceptance-binding"}
    for path in root.rglob("*"):
        if not path.is_file() or {"__pycache__", ".pytest_cache"}.intersection(path.parts):
            continue
        relative = path.relative_to(root)
        assert not forbidden_parts.intersection(relative.parts)
        assert path.suffix == ".py" or path.name.endswith(".schema.json") or path.name in allowed_names


def test_byte_inventory_covers_every_published_package_file():
    root = Path(__file__).parents[1]
    listed = {}
    for line in (root / "SOURCE_FILES.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        relative = Path(name)
        assert not relative.is_absolute() and ".." not in relative.parts
        assert name not in listed
        listed[name] = digest
    actual = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
        and path.name != "SOURCE_FILES.sha256"
        and not {"__pycache__", ".pytest_cache"}.intersection(path.parts)
    }
    assert set(listed) == actual
    for name, digest in listed.items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest


def test_all_helpers_import_without_application_or_external_operations(monkeypatch):
    root = Path(__file__).parents[1]
    for path in sorted(root.glob("candidate_*.py")):
        name = "synthetic_cutover_import_" + path.stem
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        spec.loader.exec_module(module)
        assert module.__file__ == str(path)

"""Frozen custody and assembly successors cannot be substituted or expanded."""

import shutil
from pathlib import Path

import pytest

from app.maintenance import product_adoption as product

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def isolated_sources(tmp_path, monkeypatch):
    for directory in ("versions", "identity_assembly_versions"):
        shutil.copytree(ROOT / "alembic" / directory, tmp_path / "alembic" / directory)
    monkeypatch.setattr(product, "__file__", str(tmp_path / "app" / "maintenance" / "product_adoption.py"))
    return tmp_path


def test_exact_frozen62_and_assembly10_sources_are_accepted(isolated_sources):
    frozen, assembly, _, _, graph = product._provenance()
    assert len(frozen) == 62 and len(assembly) == 10
    assert "a010_facilitator_nominations" in graph[1]


@pytest.mark.parametrize("drift", ["legacy_successor", "unknown_assembly", "missing_assembly", "tampered_assembly"])
def test_source_drift_is_refused_before_any_database_entry(isolated_sources, drift):
    legacy = isolated_sources / "alembic" / "versions"
    assembly = isolated_sources / "alembic" / "identity_assembly_versions"
    if drift == "legacy_successor":
        shutil.copyfile(ROOT / "tests/fixtures/legacy_successors/0062_lab_template_access.py", legacy / "0062_lab_template_access.py")
    elif drift == "unknown_assembly":
        (assembly / "a011_unknown.py").write_text('revision="a011_unknown"\ndown_revision="a010_facilitator_nominations"\n')
    elif drift == "missing_assembly":
        (assembly / "a010_facilitator_nominations.py").unlink()
    else:
        path = assembly / "a007_lab_template_access.py"
        path.write_bytes(path.read_bytes() + b"\n# unreviewed source drift\n")
    with pytest.raises(product.ProductAdoptionRefused):
        product._provenance()

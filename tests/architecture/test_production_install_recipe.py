from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECIPE = ROOT / "deploy" / "install.sh"
EXPECTED_SYNC_ARGUMENTS = (
    "sync",
    "--only",
    "main",
    "--no-root",
    "--no-interaction",
    "--no-ansi",
)
EXPECTED_ENVIRONMENT = (
    "VIRTUAL_ENV=<unset>",
    "POETRY_VIRTUALENVS_IN_PROJECT=true",
)


def _fake_poetry(tmp_path: Path, version: str) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "poetry-calls"
    executable = bin_dir / "poetry"
    executable.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'if [[ "${1:-}" == "--version" ]]; then\n'
        f"  printf '%s\\n' {version!r}\n"
        "  exit 0\n"
        "fi\n"
        "{\n"
        "  printf 'VIRTUAL_ENV=%s\\n' \"${VIRTUAL_ENV-<unset>}\"\n"
        "  printf 'POETRY_VIRTUALENVS_IN_PROJECT=%s\\n' "
        '"${POETRY_VIRTUALENVS_IN_PROJECT-<unset>}"\n'
        "  printf 'ARG=%s\\n' \"$@\"\n"
        '} > "${ACADEMY_POETRY_CALLS:?}"\n'
    )
    executable.chmod(0o755)
    return bin_dir, calls


def _run_recipe(tmp_path: Path, version: str) -> tuple[subprocess.CompletedProcess[str], Path]:
    bin_dir, calls = _fake_poetry(tmp_path, version)
    environment = os.environ.copy()
    environment["PATH"] = f"{bin_dir}{os.pathsep}{environment['PATH']}"
    environment["ACADEMY_POETRY_CALLS"] = str(calls)
    environment["VIRTUAL_ENV"] = "/tmp/unrelated-active-environment"
    result = subprocess.run(  # noqa: S603 - fixed repository-owned script
        [str(RECIPE)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    return result, calls


def test_production_recipe_is_valid_bash() -> None:
    result = subprocess.run(  # noqa: S603 - fixed interpreter and path
        ["/bin/bash", "-n", str(RECIPE)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_production_recipe_uses_path_poetry_and_the_closed_main_profile(tmp_path: Path) -> None:
    result, calls = _run_recipe(tmp_path, "Poetry (version 2.4.1)")

    assert result.returncode == 0, result.stderr
    lines = tuple(calls.read_text().splitlines())
    assert lines[:2] == EXPECTED_ENVIRONMENT
    assert tuple(line.removeprefix("ARG=") for line in lines[2:]) == EXPECTED_SYNC_ARGUMENTS


def test_production_recipe_refuses_a_different_poetry_version(tmp_path: Path) -> None:
    result, calls = _run_recipe(tmp_path, "Poetry (version 2.4.0)")

    assert result.returncode != 0
    assert "Refusing rather than proceeding" in result.stderr
    assert not calls.exists(), "the rejected Poetry executable reached sync"


def test_production_recipe_refuses_version_output_with_extra_text(tmp_path: Path) -> None:
    result, calls = _run_recipe(tmp_path, "Poetry (version 2.4.1) unexpected")

    assert result.returncode != 0
    assert not calls.exists(), "a non-exact version report reached sync"

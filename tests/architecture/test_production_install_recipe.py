from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

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
    "POETRY_VIRTUALENVS_CREATE=true",
    "POETRY_VIRTUALENVS_IN_PROJECT=true",
)
# Marks the start of a single fake-poetry invocation's recorded block, so
# invocations with different argument counts can still be split apart
# reliably (see _invocations below).
_INVOCATION_MARKER = "===ACADEMY-POETRY-INVOCATION==="
# Every recorded block starts with one PWD= line, then the EXPECTED_ENVIRONMENT
# lines, then one ARG= line per argument — derive the slice boundaries from
# EXPECTED_ENVIRONMENT's length so adding/removing a tracked variable can't
# silently desync the slicing from what the fake actually records.
_ENV_START = 1
_ARGS_START = _ENV_START + len(EXPECTED_ENVIRONMENT)


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
        f"  printf '{_INVOCATION_MARKER}\\n'\n"
        "  printf 'PWD=%s\\n' \"${PWD}\"\n"
        "  printf 'VIRTUAL_ENV=%s\\n' \"${VIRTUAL_ENV-<unset>}\"\n"
        "  printf 'POETRY_VIRTUALENVS_CREATE=%s\\n' "
        '"${POETRY_VIRTUALENVS_CREATE-<unset>}"\n'
        "  printf 'POETRY_VIRTUALENVS_IN_PROJECT=%s\\n' "
        '"${POETRY_VIRTUALENVS_IN_PROJECT-<unset>}"\n'
        "  printf 'ARG=%s\\n' \"$@\"\n"
        # Append, not truncate: a poetry call made before `sync` (e.g.
        # `poetry config ...`, `poetry run alembic upgrade head`) must stay
        # visible in the recorded call log instead of being silently
        # overwritten by whatever poetry invocation runs last.
        '} >> "${ACADEMY_POETRY_CALLS:?}"\n'
    )
    executable.chmod(0o755)
    return bin_dir, calls


def _run_recipe(
    tmp_path: Path, version: str, *, cwd: Path | None = None
) -> tuple[subprocess.CompletedProcess[str], Path]:
    bin_dir, calls = _fake_poetry(tmp_path, version)
    environment = os.environ.copy()
    environment["PATH"] = f"{bin_dir}{os.pathsep}{environment['PATH']}"
    environment["ACADEMY_POETRY_CALLS"] = str(calls)
    environment["VIRTUAL_ENV"] = "/tmp/unrelated-active-environment"
    result = subprocess.run(  # noqa: S603 - fixed repository-owned script
        [str(RECIPE)],
        cwd=cwd if cwd is not None else ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    return result, calls


def _invocations(calls: Path) -> tuple[tuple[str, ...], ...]:
    """Split the (possibly multi-invocation) call log into per-call blocks,
    each block's lines starting with PWD=, then the environment lines, then
    one ARG= line per argument that invocation received."""
    text = calls.read_text()
    blocks = [block for block in text.split(_INVOCATION_MARKER + "\n") if block]
    return tuple(tuple(block.splitlines()) for block in blocks)


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
    # Assert on the COMPLETE set of recorded poetry invocations, not just
    # that the expected sync call appears somewhere in the log — a poetry
    # invocation added before sync (`poetry config ...`, `poetry run alembic
    # upgrade head`, ...) must be refused here, not merely tolerated.
    invocations = _invocations(calls)
    assert (
        len(invocations) == 1
    ), f"expected exactly one poetry invocation (the sync), got {len(invocations)}: {invocations!r}"
    (only_invocation,) = invocations
    assert only_invocation[_ENV_START:_ARGS_START] == EXPECTED_ENVIRONMENT
    assert tuple(line.removeprefix("ARG=") for line in only_invocation[_ARGS_START:]) == EXPECTED_SYNC_ARGUMENTS


def test_production_recipe_refuses_a_different_poetry_version(tmp_path: Path) -> None:
    result, calls = _run_recipe(tmp_path, "Poetry (version 2.4.0)")

    assert result.returncode != 0
    assert "Refusing rather than proceeding" in result.stderr
    assert not calls.exists(), "the rejected Poetry executable reached sync"


def test_production_recipe_refuses_version_output_with_extra_text(tmp_path: Path) -> None:
    result, calls = _run_recipe(tmp_path, "Poetry (version 2.4.1) unexpected")

    assert result.returncode != 0
    assert not calls.exists(), "a non-exact version report reached sync"


def test_production_recipe_targets_academy_regardless_of_invoking_cwd(tmp_path: Path) -> None:
    """Poetry resolves its project by walking up from cwd, not from the
    script's own location. A recipe that does not `cd` to its own checkout
    root before invoking poetry silently targets whatever project happens
    to sit above the invoking cwd instead — exits 0, and the operator
    believes Academy was installed. Prove the `cd` actually happened by
    checking poetry's own $PWD, not merely that the fake poetry ran (the
    fake doesn't consult pyproject.toml, so an assertion that stops at
    "sync ran with the right arguments" would pass even without repair 2 —
    see _run_recipe's previous hardcoded cwd=ROOT, which is exactly why this
    was invisible before)."""
    other_cwd = tmp_path / "elsewhere"
    other_cwd.mkdir()

    result, calls = _run_recipe(tmp_path, "Poetry (version 2.4.1)", cwd=other_cwd)

    assert result.returncode == 0, result.stderr
    (only_invocation,) = _invocations(calls)
    recorded_pwd = only_invocation[0]
    assert recorded_pwd == f"PWD={ROOT}", (
        f"recipe invoked poetry from {recorded_pwd!r}, not the checkout root "
        f"{ROOT!r} — it did not cd there before running poetry"
    )
    assert tuple(line.removeprefix("ARG=") for line in only_invocation[_ARGS_START:]) == EXPECTED_SYNC_ARGUMENTS


def _required_poetry_version_from_recipe() -> str:
    text = RECIPE.read_text()
    match = re.search(r'REQUIRED_POETRY_VERSION="([^"]+)"', text)
    assert match, "could not find REQUIRED_POETRY_VERSION in deploy/install.sh"
    return match.group(1)


@pytest.mark.skipif(
    shutil.which("poetry") is None,
    reason="no 'poetry' on PATH (expected on a developer workstation; CI installs it)",
)
def test_required_poetry_version_matches_the_real_poetry_it_will_accept() -> None:
    """REQUIRED_POETRY_VERSION is only meaningful if it is the exact string
    a correctly-installed Poetry 2.4.1 reports. Every existing test feeds
    that same constant back in through the fake poetry, so none of them can
    catch the constant itself being wrong (spacing, parenthesisation, a
    trailing field) — which would make the recipe refuse the correct Poetry
    on the production host. This compares against the REAL `poetry` CI
    installs, not another restated literal."""
    expected = _required_poetry_version_from_recipe()

    result = subprocess.run(  # noqa: S603 - fixed interpreter, real poetry on PATH
        ["poetry", "--version", "--no-ansi"],  # noqa: S607 - deliberately PATH-resolved, same as the recipe under test
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected

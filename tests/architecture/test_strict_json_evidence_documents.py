"""Academy's strict-JSON evidence documents must stay strict JSON.

Ruled by Michael (fleet-wide, from an ERP-lane finding): strict-JSON evidence
files must be outside Ruff's formatting ownership, and their validator must
run AFTER formatting and fail on invalid JSON. Confirmed by direct execution
against this tree: `ruff format` (0.6.9) rewrites both
`docs/kernel-runtime-composition.json` and `docs/kernel-runtime-readiness.json`
into trailing-comma PSEUDO-JSON (a real, valid `ruff format` output for a
`.json` file — Ruff formats JSON, and Ruff's JSON style permits a trailing
comma that strict `json.load` refuses). `pyproject.toml`'s
`[tool.ruff]` now carries `force-exclude = true` plus an `extend-exclude` for
exactly these two paths — a plain `exclude`/`extend-exclude` entry alone does
NOT stop a hook that passes one of these paths explicitly on the command
line (confirmed: without `force-exclude`, `ruff format <path>` still
reformats an explicitly-named excluded file); `force-exclude = true` is what
makes the exclusion hold in that case too (confirmed the other way: with it
set, `ruff format docs/kernel-runtime-composition.json` — path passed
explicitly, exactly the hook shape — is now a no-op).

That configuration removes the hazard at its source. This module is the
independent check that does not trust the configuration to have worked: it
runs `json.load` directly against the actual committed bytes of every
strict-JSON evidence document and fails, naming the path, on any parse
error.

Two places run this same underlying check, deliberately, and neither is a
redundant copy of the other:

* `.github/workflows/ci.yml`'s `test` job carries a "Strict-JSON evidence
  documents parse" STEP, in the same job and runner as `ruff check .`,
  positioned where a `ruff format`/`ruff format --check` step would sit if
  this job ran one. It catches a formatter that mangled a document DURING
  THAT RUN, before any later step (including this file's own `pytest` run)
  could mask it — the ordering the ERP/Sub finding requires. Academy's `test`
  job does not run `ruff format` today (only `ruff check .`,
  `.github/workflows/ci.yml:83`), so that ordering guarantee is currently
  VACUOUS — there is no format step for this step to follow, only a
  correctly-chosen place for the day one is added. Say this plainly rather
  than implying a guarantee the workflow does not yet provide.
* This architecture test (run by `pytest`, the last step in that same job)
  catches a document that arrived already broken by ANY OTHER ROUTE — a hand
  edit, an editor's own auto-format, a bad merge, or the CI step above having
  been skipped, changed, or removed. It is the one of the two that still
  fires even if the CI step is deleted by someone who does not realize it is
  load-bearing.

Academy's own `ci.yml` invokes no `ruff format` step at all today, and this
repository carries no `.pre-commit-config.yaml` (confirmed: `git ls-files`
and a recursive search for the filename both return nothing). That means
today's green Academy CI reflects the gate never walking a formatter over
these files, NOT the gate walking formatting and the JSON surviving it —
the fix above is still required so the next person who adds a format gate
or a pre-commit hook (exactly what happened in the ERP lane) does not
reintroduce this defect silently.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: Every strict-JSON evidence document in this repository. Add a new one
#: here — never leave it to be discovered by a formatter mangling it first.
STRICT_JSON_EVIDENCE_DOCUMENTS: tuple[Path, ...] = (
    ROOT / "docs" / "kernel-runtime-composition.json",
    ROOT / "docs" / "kernel-runtime-readiness.json",
)


@pytest.mark.parametrize("path", STRICT_JSON_EVIDENCE_DOCUMENTS, ids=lambda p: str(p.relative_to(ROOT)))
def test_strict_json_evidence_document_parses_as_strict_json(path: Path) -> None:
    """Near-miss control: the actual, committed document parses cleanly —
    proof this check accepts a genuinely valid document, not just rejects."""
    assert path.is_file(), f"{path.relative_to(ROOT)} does not exist"
    raw = path.read_text(encoding="utf-8")
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        pytest.fail(f"{path.relative_to(ROOT)} is not valid strict JSON: {exc}")


def test_ruff_format_ownership_is_excluded_for_every_evidence_document() -> None:
    """The configuration half of the repair: every document above must be
    named, verbatim, in `pyproject.toml`'s `[tool.ruff] extend-exclude`, and
    `force-exclude` must be `true` so an explicitly-passed path (the hook
    shape) is still excluded."""
    pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "force-exclude = true" in pyproject_text, (
        "[tool.ruff] force-exclude must be true, or a hook passing one of "
        "the strict-JSON evidence paths explicitly bypasses extend-exclude"
    )
    for path in STRICT_JSON_EVIDENCE_DOCUMENTS:
        relative = str(path.relative_to(ROOT))
        assert relative in pyproject_text, (
            f"{relative} is not named in pyproject.toml's Ruff exclusion — "
            "it is still inside Ruff's formatting ownership"
        )


def test_trailing_comma_document_is_rejected() -> None:
    """Plant: the exact defect `ruff format` produced against this tree —
    a trailing comma before a closing brace/bracket — must fail this check.
    Without this, the check above could pass for the wrong reason (e.g. by
    accident never actually calling `json.loads`)."""
    trailing_comma_pseudo_json = """{
        "schema_version": "dimensional-composition.v2",
        "product": "dotmac_academy_app",
        "records": [
            {
                "distribution": "dotmac-billing",
            },
        ],
    }"""
    with pytest.raises(json.JSONDecodeError):
        json.loads(trailing_comma_pseudo_json)


def test_ruff_format_reproduction_is_caught_by_this_checks_own_logic(tmp_path: Path) -> None:
    """The plant above uses a hand-written trailing comma; this control
    additionally proves the SPECIFIC bytes `ruff format` actually produces
    against one of these real documents fail the same way, closing the gap
    between "a trailing comma" in the abstract and the real defect."""
    import shutil
    import subprocess

    # Prefer Academy's own pinned .venv when present (a local dev checkout);
    # fall back to whatever `ruff` a CI runner's PATH resolves (its own
    # `poetry install` puts one there). Either is "Academy's pinned ruff" —
    # the version is pinned by pyproject.toml/poetry.lock, not by this path.
    in_project = ROOT / ".venv" / "bin" / "ruff"
    ruff_executable = str(in_project) if in_project.is_file() else shutil.which("ruff")
    if ruff_executable is None:
        pytest.skip("no ruff executable available in this environment (neither .venv nor PATH)")

    scratch = tmp_path / "kernel-runtime-composition.json"
    scratch.write_text((ROOT / "docs" / "kernel-runtime-composition.json").read_text(encoding="utf-8"))

    result = subprocess.run(  # noqa: S603
        [ruff_executable, "format", "--isolated", str(scratch)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"ruff format failed outright: {result.stderr}"

    reformatted = scratch.read_text(encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        json.loads(reformatted)

    # Sanity: prove this scratch reproduction is actually exercising Ruff's
    # JSON formatter, not silently a no-op that left the file untouched.
    original = (ROOT / "docs" / "kernel-runtime-composition.json").read_text(encoding="utf-8")
    assert reformatted != original, "ruff format --isolated made no change — reproduction did not exercise the defect"

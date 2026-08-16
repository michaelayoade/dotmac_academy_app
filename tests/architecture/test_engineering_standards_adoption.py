"""Academy's side of the Governance engineering-standards adoption.

Two things are being kept honest here, and neither of them is a connector
detector. dotmac_governance ADR 0011 owns the detector and says so explicitly
("A copied detector is not a substitute"), because six repositories with six
local copies is the drift the central engine exists to prevent. What Academy
owns, and what this module enforces, is:

1. **The pin.** The Governance revision is written in three places that must
   never disagree — `governance_model.revision` in the profile, `GOVERNANCE_REF`
   in the workflow, and the workflow's `uses:` ref (GitHub forbids an expression
   there, so the value has to be repeated literally).
   `scripts/check_governance_pin.py` is the one implementation of that rule; the
   workflow's preflight job and this module are both thin adapters over it.

2. **The declared surface.** The profile must stay a schema-version-9 profile
   that declares a baseline for all six categories and a baseline may not move
   without the measured evidence in
   `docs/external-connector-surface.md` moving with it.

Point 2 is a REVIEW-SURFACE ratchet, not a measurement: it cannot notice a new
connector landing. Only the pinned Governance engine can. The workflow runs it
against the accepted canonical-main revision; these tests guard the immutable
pin and declared review record without copying its classifier.

Every assertion below is paired with a proof that it bites — an assertion that
only ever passes is not evidence (ADR 0018).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import types

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PROFILE_PATH = REPO_ROOT / ".dotmac" / "standards-profile.json"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "engineering-standards.yml"
EVIDENCE_PATH = REPO_ROOT / "docs" / "external-connector-surface.md"

#: Closed at six by ADR 0011, so a category cannot be dropped from the profile to
#: make its count disappear. Spelled out here rather than imported: Academy does
#: not depend on the Governance package, and this list is the thing under test.
CONNECTOR_CATEGORIES = (
    "outbound_transport",
    "webhook_surface",
    "provider_credential",
    "connector_task",
    "sync_checkpoint",
    "delivery_retry",
)

ARMED_SHA = "0" * 39 + "a"
OTHER_SHA = "1" * 39 + "b"
ACCEPTED_GOVERNANCE_SHA = "4f6fbf98c25f7cfbb3dacc4f3d2f5fd7e473f193"

_EVIDENCE_ROW = re.compile(r"^\|\s*`(\w+)`\s*\|\s*(\d+)\s*\|", re.MULTILINE)


def _pin_checker() -> types.ModuleType:
    """Load the checked-in pin rule by path; `scripts/` is not an importable package."""
    path = REPO_ROOT / "scripts" / "check_governance_pin.py"
    spec = importlib.util.spec_from_file_location("check_governance_pin", path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _profile() -> dict:
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


# --- the declared surface ---------------------------------------------------


def test_the_profile_is_a_schema_version_nine_profile() -> None:
    """Version 9 is the accepted external-connector profile shape."""
    profile = _profile()
    assert profile["schema_version"] == 9, "the accepted connector surface is schema version 9"
    assert profile["enforcement_mode"] == "required", "an adopted profile is not advisory"


def test_every_connector_category_declares_a_baseline() -> None:
    """All six, or a category could be dropped to make its count disappear."""
    baselines = _profile()["external_connector_surface"]["baselines"]
    assert set(baselines) == set(CONNECTOR_CATEGORIES), (
        f"the category list is closed at six (dotmac_governance ADR 0011); profile declares {sorted(baselines)}"
    )
    assert all(isinstance(v, int) and v >= 0 for v in baselines.values()), baselines


def test_the_profile_cannot_declare_its_measurement_scope() -> None:
    """Schema 9 derives scope from Git; adopter-owned scope keys are refused."""
    surface = _profile()["external_connector_surface"]
    assert set(surface) == {"baselines", "conserved_exclusions"}, surface


def test_a_baseline_cannot_move_without_the_measured_evidence_moving_with_it() -> None:
    """The profile's numbers and the reviewed record must agree.

    Not a measurement — it cannot see a new connector. It makes raising a
    baseline cost an edit to the file that says which files are behind it, so
    the raise arrives with its justification rather than as a lone integer.
    """
    baselines = _profile()["external_connector_surface"]["baselines"]
    recorded = {name: int(count) for name, count in _EVIDENCE_ROW.findall(EVIDENCE_PATH.read_text(encoding="utf-8"))}
    documented = {k: v for k, v in recorded.items() if k in set(CONNECTOR_CATEGORIES)}
    assert documented == baselines, (
        f"{EVIDENCE_PATH.name} records {documented} but the profile declares {baselines}; "
        "re-measure and update both in the same change"
    )


def test_the_evidence_record_is_actually_being_read() -> None:
    """Guard the guard: an unparsed table would make the check above vacuous."""
    recorded = _EVIDENCE_ROW.findall(EVIDENCE_PATH.read_text(encoding="utf-8"))
    assert len(recorded) >= len(CONNECTOR_CATEGORIES), (
        f"only parsed {len(recorded)} baseline rows out of {EVIDENCE_PATH.name}; "
        "the comparison would pass on an empty set"
    )


# --- the pin ----------------------------------------------------------------


def test_the_governance_pin_is_coherent_across_all_three_places() -> None:
    checker = _pin_checker()
    revision, env_ref, uses_ref = checker.read_pins(REPO_ROOT)
    assert revision == env_ref == uses_ref, (
        f"profile revision={revision!r}, workflow GOVERNANCE_REF={env_ref!r}, uses: ref={uses_ref!r}"
    )


def test_the_pin_check_is_reading_the_real_files() -> None:
    """Guard the guard: three empty strings are 'coherent' and prove nothing."""
    checker = _pin_checker()
    revision, env_ref, uses_ref = checker.read_pins(REPO_ROOT)
    assert revision and env_ref and uses_ref, (
        "one of the three pins could not be read — the coherence check above would pass vacuously"
    )


def test_the_pin_is_the_accepted_canonical_governance_commit() -> None:
    checker = _pin_checker()
    pin = checker.read_pins(REPO_ROOT)[0]
    assert pin == ACCEPTED_GOVERNANCE_SHA, pin
    assert checker.SHA.fullmatch(pin), pin


def test_the_adopted_files_contain_no_placeholder_pin() -> None:
    assert "PENDING-APPROVAL" not in PROFILE_PATH.read_text(encoding="utf-8")
    assert "@PENDING-APPROVAL" not in WORKFLOW_PATH.read_text(encoding="utf-8")


def test_the_profile_names_the_accepted_governance_model() -> None:
    model = _profile()["governance_model"]
    assert model["kind"] == "pinned", "only the Governance control plane may use a local governance source"
    assert model["status"] == "accepted", "declaring a lower status would let an unapproved record satisfy this profile"
    assert model["source"].endswith("0006-cross-repository-engineering-conformance.md"), model["source"]
    assert model["revision"] == ACCEPTED_GOVERNANCE_SHA, model["revision"]


# --- sensitivity proofs for the pin rule, in both directions ----------------


def test_the_pin_check_accepts_an_armed_pin() -> None:
    """The upward direction: a real, agreed SHA is the one thing that passes."""
    checker = _pin_checker()
    assert checker.problems(ARMED_SHA, ARMED_SHA, ARMED_SHA) == []


def test_the_pin_check_reports_the_placeholder_as_blocked() -> None:
    checker = _pin_checker()
    found = checker.problems(checker.PLACEHOLDER, checker.PLACEHOLDER, checker.PLACEHOLDER)
    assert len(found) == 1 and "placeholder" in found[0], found
    assert "ACCEPTED" in found[0], "the failure must name what approval unblocks it"


def test_the_pin_check_refuses_a_moving_or_ambiguous_ref() -> None:
    """The specific bad fix this exists to stop: making the red job green with `@main`."""
    checker = _pin_checker()
    for bad in ("main", "v1", "HEAD", ARMED_SHA[:7], ARMED_SHA.upper(), ARMED_SHA + "a"):
        found = checker.problems(bad, bad, bad)
        assert found, f"{bad!r} was accepted as a Governance pin"
        assert "40-character" in found[0], found


def test_the_pin_check_refuses_a_disagreement_in_any_of_the_three_places() -> None:
    """Drift in one file only. Each place is proved separately, not as a set."""
    checker = _pin_checker()
    for triple in (
        (OTHER_SHA, ARMED_SHA, ARMED_SHA),
        (ARMED_SHA, OTHER_SHA, ARMED_SHA),
        (ARMED_SHA, ARMED_SHA, OTHER_SHA),
        (ARMED_SHA, ARMED_SHA, ""),
    ):
        found = checker.problems(*triple)
        assert found and "disagree" in found[0], (triple, found)


def test_the_replacement_note_detector_bites() -> None:
    """Guard the guard: prove the note check can fail, not just pass."""
    checker = _pin_checker()
    assert checker.missing_replacement_note(REPO_ROOT / "docs"), (
        "missing_replacement_note() returned False for a directory with no workflow at all"
    )

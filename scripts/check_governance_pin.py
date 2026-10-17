"""The one owner of Academy's Governance pin rule.

Academy's engineering-standards job runs the Governance-owned conformance
engine (dotmac_governance ADR 0006), and schema version 9 of the profile carries
the accepted external-connector-surface ratchet (ADR 0011). Both are pinned to
an exact Governance commit, in two files that must never drift apart:

* ``.dotmac/standards-profile.json`` -> ``governance_model.revision``
* ``.github/workflows/engineering-standards.yml`` -> the ``GOVERNANCE_REF`` env
  value AND the ``uses:`` ref, because GitHub forbids an expression in ``uses:``
  and the pin therefore has to be written out literally.

Three places, one value. This module is the single implementation of that rule;
the workflow and ``tests/architecture/test_engineering_standards_adoption.py``
are thin adapters over it.

## Why a placeholder fails

Accepted ADR 0011 is carried by a canonical Governance commit, so Academy's pin
must be that immutable commit. ``PENDING-APPROVAL`` remains a refused sentinel,
not a state this adopted workflow may run with: a workflow that went green
against a placeholder would claim enforcement that is not running.

Two further barriers sit behind this one, and neither is this file's job:

* GitHub cannot resolve ``@PENDING-APPROVAL`` to a ref, so the standards job
  could not download the action even if this check were removed;
* the profile declares an accepted Governance source, so the engine verifies
  that status in the pinned checkout.

## What "armed" means

Exactly one thing: all three places hold the SAME lower-case 40-character Git
SHA. A branch (``main``), a tag (``v1``), a short SHA and an upper-case SHA are
all refused — a moving ref is not a pin, and "fix the red job by pinning
``@main``" is the specific failure this refusal exists to stop.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = REPO_ROOT / ".dotmac" / "standards-profile.json"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "engineering-standards.yml"

#: A refused sentinel meaning no accepted Governance revision was pinned.
PLACEHOLDER = "PENDING-APPROVAL"

#: An armed pin. Lower-case only: Git resolves either case, but two spellings of
#: one commit would let the three files disagree while looking equal to a human.
SHA = re.compile(r"^[0-9a-f]{40}$")

_ENV_REF = re.compile(r"^\s*GOVERNANCE_REF:\s*[\"']?([^\"'\s#]+)[\"']?\s*$", re.MULTILINE)
_USES_REF = re.compile(
    r"^\s*uses:\s*michaelayoade/dotmac_governance/\.github/actions/standards-check@([^\s#]+)\s*$",
    re.MULTILINE,
)

#: What must be true in the workflow before the placeholder is allowed to sit
#: there at all: a reader has to be told what replaces it.
REPLACEMENT_NOTE = "replace PENDING-APPROVAL"

_BLOCKED = (
    f"the Governance pin is still the placeholder {PLACEHOLDER!r}. Replace it, in all three "
    "places at once, with the merged Governance commit that carries an ACCEPTED "
    "docs/adr/0011-external-connector-surface-ratchet.md. Until then this job is "
    "correctly red: nothing is enforcing Academy's external-connector baselines."
)


def problems(profile_revision: str, env_ref: str, uses_ref: str) -> list[str]:
    """Everything wrong with this pin, most structural first.

    Coherence is checked before validity on purpose: three disagreeing values
    have no single "the pin" to judge, and reporting both would only bury the
    disagreement under a second message.
    """
    found: list[str] = []
    seen = {
        "profile governance_model.revision": profile_revision,
        "workflow GOVERNANCE_REF": env_ref,
        "workflow uses: ref": uses_ref,
    }
    if len(set(seen.values())) != 1:
        rendered = ", ".join(f"{where}={value!r}" for where, value in seen.items())
        return [f"the Governance pin is written in three places and they disagree: {rendered}"]

    pin = profile_revision
    if pin == PLACEHOLDER:
        found.append(_BLOCKED)
    elif not SHA.match(pin):
        found.append(
            f"{pin!r} is not a Governance pin. A pin is a lower-case 40-character Git SHA; "
            f"a branch, a tag, a short SHA and an upper-case SHA are all moving or ambiguous "
            f"targets. Use {PLACEHOLDER!r} while no approved revision exists."
        )
    return found


def read_pins(root: pathlib.Path = REPO_ROOT) -> tuple[str, str, str]:
    """Read the three written pins. A missing one reads as an empty string.

    Empty rather than raising, so a deleted workflow or a renamed key surfaces
    as a disagreement the caller reports, not as a traceback.
    """
    profile_path = root / ".dotmac" / "standards-profile.json"
    workflow_path = root / ".github" / "workflows" / "engineering-standards.yml"
    revision = ""
    if profile_path.is_file():
        model = json.loads(profile_path.read_text(encoding="utf-8")).get("governance_model", {})
        revision = str(model.get("revision", ""))
    text = workflow_path.read_text(encoding="utf-8") if workflow_path.is_file() else ""
    env_match = _ENV_REF.search(text)
    uses_match = _USES_REF.search(text)
    return revision, (env_match.group(1) if env_match else ""), (uses_match.group(1) if uses_match else "")


def missing_replacement_note(root: pathlib.Path = REPO_ROOT) -> bool:
    """Is the placeholder sitting in the workflow with nothing telling a reader what replaces it?"""
    workflow_path = root / ".github" / "workflows" / "engineering-standards.yml"
    text = workflow_path.read_text(encoding="utf-8") if workflow_path.is_file() else ""
    return REPLACEMENT_NOTE not in text


def main() -> int:
    found = problems(*read_pins())
    if not found:
        print(f"governance pin OK: {read_pins()[0]}")
        return 0
    print("Governance pin preflight FAILED:", file=sys.stderr)
    for item in found:
        print(f"  - {item}", file=sys.stderr)
    print(f"\n  profile:  {PROFILE.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(f"  workflow: {WORKFLOW.relative_to(REPO_ROOT)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

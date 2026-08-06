"""Every question bank committed to this repository must pass lint_bank.

Without this, the rules are enforced only when someone runs `load-banks` — so a
bank can be committed broken, sit in git indefinitely, and only fail at the
moment of an import that someone is probably doing under time pressure. The
linter already exists; this points it at the content on every push.

The live estate is a separate question, answered by `python -m app.cli
audit-banks`, which runs the same linter over the database.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.bank_loader import lint_bank, parse_bank

CONTENT = Path(__file__).resolve().parents[2] / "content"
BANKS = sorted(CONTENT.glob("**/banks/*.yaml"))


def test_content_directory_has_banks_to_check():
    """A glob that silently matches nothing would make every test below vacuous."""
    assert BANKS, f"no bank files found under {CONTENT}"


@pytest.mark.parametrize("path", BANKS, ids=lambda p: f"{p.parent.parent.name}/{p.stem}")
def test_bank_passes_lint(path: Path):
    violations = lint_bank(parse_bank(path))
    assert not violations, "\n".join([f"{path.relative_to(CONTENT)}:", *violations])

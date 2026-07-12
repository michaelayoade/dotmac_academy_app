"""The seed script must never fall back to a hardcoded admin password.

A committed default (`ADMIN_PASSWORD = "…"`) in scripts/seed_academy_demo.py was
leaked in public git history and found live on prod. These tests lock in that the
password comes only from SEED_ADMIN_PASSWORD and that weak/absent values refuse to
seed, and scan the scripts/ tree so a new hardcoded credential default can't creep
back in.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from scripts.seed_academy_demo import _MIN_PASSWORD_LEN, resolve_admin_password


def test_missing_password_refuses(monkeypatch):
    monkeypatch.delenv("SEED_ADMIN_PASSWORD", raising=False)
    with pytest.raises(SystemExit):
        resolve_admin_password()


@pytest.mark.parametrize("weak", ["", "changeme-dev-only", "changeme", "password", "admin", "short"])
def test_weak_password_refuses(monkeypatch, weak):
    monkeypatch.setenv("SEED_ADMIN_PASSWORD", weak)
    with pytest.raises(SystemExit):
        resolve_admin_password()


def test_strong_password_accepted(monkeypatch):
    strong = "x" * _MIN_PASSWORD_LEN + "!"
    monkeypatch.setenv("SEED_ADMIN_PASSWORD", strong)
    assert resolve_admin_password() == strong


def test_no_hardcoded_password_default_in_scripts():
    # os.environ.get("...PASSWORD...", "<default>") — a non-empty default is the smell.
    pat = re.compile(r"""environ\.get\(\s*["'][A-Z_]*PASSWORD[A-Z_]*["']\s*,\s*["']([^"']+)["']""")
    offenders = []
    for p in pathlib.Path("scripts").rglob("*.py"):
        for m in pat.finditer(p.read_text()):
            offenders.append(f"{p}: default {m.group(1)!r}")
    assert offenders == [], f"hardcoded password default(s) in scripts/: {offenders}"

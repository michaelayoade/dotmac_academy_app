from __future__ import annotations

import shutil

import pytest

from app import cli
from app.config import settings


def test_lab_worker_exits_nonzero_on_web_host(monkeypatch):
    monkeypatch.setattr(settings, "lab_host_role", "web")
    with pytest.raises(SystemExit, match="LAB_HOST_ROLE=lab"):
        cli._lab_worker(None)


def test_lab_worker_exits_nonzero_when_containerlab_is_missing(monkeypatch):
    monkeypatch.setattr(settings, "lab_host_role", "lab")
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(SystemExit, match="requires containerlab"):
        cli._lab_worker(None)


def test_lab_reconcile_exits_nonzero_when_containerlab_is_missing(monkeypatch):
    monkeypatch.setattr(settings, "lab_host_role", "lab")
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(SystemExit, match="requires containerlab"):
        cli._lab_reconcile(None)

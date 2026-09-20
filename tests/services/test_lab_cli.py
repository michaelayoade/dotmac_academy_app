from __future__ import annotations

import argparse
import shutil
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from app import cli
from app.config import settings
from app.services import host_lock as host_lock_module
from app.services import lab_jobs, lab_operations
from app.services.host_lock import HostLockUnavailable
from app.services.labengine import containerlab as containerlab_module


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


class _FakeEngine:
    """Stands in for ContainerlabEngine so these tests never touch containerlab."""

    def __init__(self, *args, **kwargs):
        pass


def _prepare_worker_environment(monkeypatch, tmp_path):
    """Common setup so ``_lab_worker`` reaches its polling loop in a test."""
    monkeypatch.setattr(settings, "lab_host_role", "lab")
    monkeypatch.setattr(settings, "lab_workdir", str(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/containerlab")
    monkeypatch.setattr("app.config.validate_settings", lambda s: [])
    monkeypatch.setattr(containerlab_module, "ContainerlabEngine", _FakeEngine)


def test_lab_worker_holds_the_singleton_lock_once_across_iterations(monkeypatch, tmp_path):
    """The lock is acquired ONCE at startup and held across every polling
    iteration — not re-acquired per iteration.
    """
    _prepare_worker_environment(monkeypatch, tmp_path)

    fake_db = MagicMock()

    @contextmanager
    def fake_session():
        yield fake_db

    monkeypatch.setattr(lab_jobs, "lab_worker_session", fake_session)
    monkeypatch.setattr(lab_operations, "reconcile_stuck", lambda db: 0)
    monkeypatch.setattr("app.cli.time.sleep", lambda seconds: None)

    class _StopLoop(Exception):
        pass

    drain_calls = {"n": 0}

    def fake_drain(db, engine):
        drain_calls["n"] += 1
        if drain_calls["n"] >= 3:
            raise _StopLoop
        return 0

    monkeypatch.setattr(lab_jobs, "drain_once", fake_drain)

    enter_count = {"n": 0}
    real_lock = host_lock_module.worker_singleton_lock

    @contextmanager
    def counting_lock(*args, **kwargs):
        enter_count["n"] += 1
        with real_lock(*args, **kwargs):
            yield

    monkeypatch.setattr(host_lock_module, "worker_singleton_lock", counting_lock)

    with pytest.raises(_StopLoop):
        cli._lab_worker(argparse.Namespace())

    assert enter_count["n"] == 1, "worker_singleton_lock must be entered exactly once"
    assert drain_calls["n"] == 3


def test_lab_worker_lock_contention_prevents_any_db_session_or_drain_work(
    monkeypatch, tmp_path
):
    """Losing the startup lock race must exit before any database session,
    reclaim, or drain call — never partially starting worker duties.
    """
    _prepare_worker_environment(monkeypatch, tmp_path)

    @contextmanager
    def failing_lock(*args, **kwargs):
        raise HostLockUnavailable("worker singleton lock is already held")
        yield  # pragma: no cover - unreachable, satisfies generator shape

    monkeypatch.setattr(host_lock_module, "worker_singleton_lock", failing_lock)

    session_spy = MagicMock()
    reconcile_spy = MagicMock()
    drain_spy = MagicMock()
    monkeypatch.setattr(lab_jobs, "lab_worker_session", session_spy)
    monkeypatch.setattr(lab_operations, "reconcile_stuck", reconcile_spy)
    monkeypatch.setattr(lab_jobs, "drain_once", drain_spy)

    with pytest.raises(SystemExit, match="already held"):
        cli._lab_worker(argparse.Namespace())

    session_spy.assert_not_called()
    reconcile_spy.assert_not_called()
    drain_spy.assert_not_called()


def test_lab_worker_exits_cleanly_and_releases_the_lock_on_shutdown_request(
    monkeypatch, tmp_path
):
    """Simulates "a SIGTERM arrived mid-operation" by having ``drain_once``
    raise ``_WorkerShutdownRequested`` directly — exactly what the real
    SIGTERM handler installed by ``_sigterm_raises_shutdown_requested``
    would raise — without needing a real OS signal for this narrower
    unit-level test.

    ``_lab_worker`` must exit cleanly: no unhandled exception propagates out
    of the function, and the singleton lock is actually released afterward,
    proven by a subsequent acquisition on the same directory succeeding.
    """
    _prepare_worker_environment(monkeypatch, tmp_path)

    fake_db = MagicMock()

    @contextmanager
    def fake_session():
        yield fake_db

    monkeypatch.setattr(lab_jobs, "lab_worker_session", fake_session)
    monkeypatch.setattr(lab_operations, "reconcile_stuck", lambda db: 0)

    def fake_drain(db, engine):
        raise cli._WorkerShutdownRequested()

    monkeypatch.setattr(lab_jobs, "drain_once", fake_drain)

    cli._lab_worker(argparse.Namespace())  # must return normally, not raise

    # The lock was released on shutdown: a fresh acquisition on the same
    # directory (settings.lab_workdir, patched to tmp_path above) succeeds.
    with host_lock_module.worker_singleton_lock():
        pass

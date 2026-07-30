"""GlitchTip error tracking — inert by default, opt-in, and never raising."""

from __future__ import annotations

from app.config import settings
from app.error_tracking import init_error_tracking, tag_request


def test_disabled_without_dsn(monkeypatch):
    monkeypatch.setattr(settings, "glitchtip_enabled", True)
    monkeypatch.setattr(settings, "glitchtip_dsn", "")
    assert init_error_tracking() is False


def test_disabled_when_flag_off(monkeypatch):
    monkeypatch.setattr(settings, "glitchtip_enabled", False)
    monkeypatch.setattr(settings, "glitchtip_dsn", "https://key@glitchtip.example/1")
    assert init_error_tracking() is False


def test_enabled_with_dsn_and_flag(monkeypatch):
    monkeypatch.setattr(settings, "glitchtip_enabled", True)
    monkeypatch.setattr(settings, "glitchtip_dsn", "https://key@127.0.0.1/1")
    assert init_error_tracking() is True


def test_init_never_raises_on_bad_dsn(monkeypatch):
    """A malformed DSN must not take the app down at startup."""
    monkeypatch.setattr(settings, "glitchtip_enabled", True)
    monkeypatch.setattr(settings, "glitchtip_dsn", "not-a-dsn")
    assert init_error_tracking() is False


def test_tag_request_is_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "glitchtip_enabled", False)
    monkeypatch.setattr(settings, "glitchtip_dsn", "")
    tag_request("abc-123")  # must not raise

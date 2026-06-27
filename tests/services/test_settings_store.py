"""Tests for the platform settings store: effective() merge + type coercion."""

from __future__ import annotations

from app.config import settings
from app.models.platform_settings import PlatformSetting
from app.services import settings_store
from app.services.settings_store import effective, get_all, set_many


def _clear(db):
    db.query(PlatformSetting).delete()
    db.flush()


def test_effective_falls_back_to_env_defaults(admin_session, monkeypatch):
    """With no stored rows, effective() returns the env/config defaults."""
    _clear(admin_session)
    monkeypatch.setattr(settings, "smtp_host", "env-host.example", raising=False)
    monkeypatch.setattr(settings, "max_concurrent_labs", 7, raising=False)

    cfg = effective(admin_session)
    assert cfg.smtp_host == "env-host.example"
    assert cfg.max_concurrent_labs == 7
    # Literal defaults for keys with no env source.
    assert cfg.branding_name == "Dotmac Academy"
    assert cfg.email_auto_on_pass is True
    assert cfg.email_digest_enabled is True
    admin_session.rollback()


def test_effective_db_overrides_with_type_coercion(admin_session):
    """set_many then effective() reflects overrides, coerced to native types."""
    _clear(admin_session)
    set_many(
        admin_session,
        {
            "smtp_host": "smtp.store.example",
            "smtp_port": "2525",
            "smtp_starttls": "false",
            "email_auto_on_pass": "false",
            "branding_name": "Acme Academy",
            "max_concurrent_labs": "3",
            "lab_idle_minutes": "15",
        },
    )

    cfg = effective(admin_session)
    assert cfg.smtp_host == "smtp.store.example"
    assert cfg.smtp_port == 2525 and isinstance(cfg.smtp_port, int)
    assert cfg.smtp_starttls is False
    assert cfg.email_auto_on_pass is False
    assert cfg.branding_name == "Acme Academy"
    assert cfg.max_concurrent_labs == 3
    assert cfg.lab_idle_minutes == 15

    # get_all returns the raw stored strings.
    raw = get_all(admin_session)
    assert raw["smtp_port"] == "2525"
    admin_session.rollback()


def test_effective_safe_when_db_none():
    """effective(None) never touches the DB and returns env defaults."""
    cfg = effective(None)
    assert cfg.smtp_port == settings.smtp_port
    assert cfg.branding_name == "Dotmac Academy"


def test_set_many_upserts(admin_session):
    """set_many updates an existing key instead of duplicating it."""
    _clear(admin_session)
    set_many(admin_session, {"branding_name": "First"})
    set_many(admin_session, {"branding_name": "Second"})
    assert get_all(admin_session)["branding_name"] == "Second"
    assert effective(admin_session).branding_name == "Second"
    admin_session.rollback()


def test_effective_falls_back_when_table_query_fails(admin_session, monkeypatch):
    """A failing get_all is swallowed; env defaults are returned."""
    def boom(_db):
        raise RuntimeError("table gone")

    monkeypatch.setattr(settings_store, "get_all", boom)
    cfg = effective(admin_session)
    assert cfg.branding_name == "Dotmac Academy"
    admin_session.rollback()

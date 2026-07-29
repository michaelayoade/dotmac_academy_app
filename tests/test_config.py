"""Production configuration fail-closed contracts."""

from app.config import Settings, validate_settings


def _production_settings(**overrides):
    values = {
        "environment": "production",
        "database_url": "postgresql+psycopg://app_user@db/academy",
        "platform_database_url": "postgresql+psycopg://settings_writer@db/academy",
        "platform_root_domain": "academy.example.com",
        "academy_tenant_slug": "academy",
        "trusted_hosts": "academy.example.com,*.academy.example.com",
        "jwt_secret": "production-jwt-secret",
        "session_hash_secret": "production-session-secret",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_production_requires_single_academy_slug():
    errors = validate_settings(_production_settings(academy_tenant_slug=""))
    assert "ACADEMY_TENANT_SLUG is required in production" in errors


def test_production_rejects_disabled_browser_guards():
    errors = validate_settings(
        _production_settings(
            csrf_enabled=False,
            rate_limit_enabled=False,
        )
    )
    assert "CSRF_ENABLED must be true in production" in errors
    assert "RATE_LIMIT_ENABLED must be true in production" in errors

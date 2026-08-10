"""Production configuration fail-closed contracts."""

from app.config import Settings, validate_settings


def _production_settings(**overrides):
    values = {
        "environment": "production",
        "database_url": "postgresql+psycopg://app_user@db/academy",
        "platform_database_url": "postgresql+psycopg://settings_writer@db/academy",
        "platform_root_domain": "academy.example.com",
        "trusted_hosts": "academy.example.com,*.academy.example.com",
        "jwt_secret": "production-jwt-secret",
        "session_hash_secret": "production-session-secret",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_production_requires_single_tenancy(monkeypatch):
    """The posture is still required in production; the mechanism moved.

    It used to be ACADEMY_TENANT_SLUG naming the tenant. It is now the kernel's
    TENANCY=single, which asserts at startup that exactly one tenant row exists
    — the identity comes from the database rather than from configuration.
    """
    from dotmac_kernel.config import settings as kernel_settings

    monkeypatch.setattr(kernel_settings, "tenancy", "multi", raising=False)
    errors = validate_settings(_production_settings())
    assert any("TENANCY must be 'single' in production" in e for e in errors)

    monkeypatch.setattr(kernel_settings, "tenancy", "single", raising=False)
    assert not any("TENANCY" in e for e in validate_settings(_production_settings()))


def test_production_rejects_disabled_browser_guards():
    errors = validate_settings(
        _production_settings(
            csrf_enabled=False,
            rate_limit_enabled=False,
        )
    )
    assert "CSRF_ENABLED must be true in production" in errors
    assert "RATE_LIMIT_ENABLED must be true in production" in errors

def test_erp_integration_requires_companion_settings_and_distinct_secrets():
    errors = validate_settings(
        _production_settings(
            erp_inbound_hmac_secret="same-secret",
            erp_webhook_secret="same-secret",
            erp_assessment_token_secret="",
            erp_allowed_return_origins="",
            academy_public_base_url="",
        )
    )
    assert "ERP_ASSESSMENT_TOKEN_SECRET is required when ERP inbound integration is enabled" in errors
    assert "ERP_ALLOWED_RETURN_ORIGINS is required when ERP inbound integration is enabled" in errors
    assert "ACADEMY_PUBLIC_BASE_URL is required when ERP inbound integration is enabled" in errors
    assert "ERP inbound and outbound HMAC secrets must be distinct" in errors


def test_erp_public_base_url_requires_https_in_production():
    errors = validate_settings(
        _production_settings(academy_public_base_url="http://academy.example.com")
    )
    assert "ACADEMY_PUBLIC_BASE_URL must use HTTPS in production" in errors

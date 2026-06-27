"""Application configuration.

Read from environment. Fail-closed in production for required values.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "dev"
    database_url: str = ""
    platform_database_url: str = ""
    migration_database_url: str = ""
    platform_root_domain: str = "localhost"
    trusted_hosts: str = ""
    jwt_secret: str = "dev-insecure-change-me"  # noqa: S105 - rejected in production.
    session_hash_secret: str = "dev-insecure-change-me"  # noqa: S105 - rejected in prod.
    jwt_ttl_seconds: int = 3600
    csrf_enabled: bool = True
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    trust_inbound_request_id: bool = False

    # Lab orchestration (Increment 2).
    max_concurrent_labs: int = 20
    lab_workdir: str = "/home/dotmac/labs"
    lab_idle_minutes: int = 60

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()


def validate_settings(s: Settings) -> list[str]:
    """Return list of fatal errors (empty if OK). Caller raises if non-empty in prod."""
    errors: list[str] = []
    if not s.database_url:
        errors.append("DATABASE_URL is required")
    if s.is_production and not s.platform_database_url:
        errors.append("PLATFORM_DATABASE_URL is required in production")
    if s.is_production and not s.trusted_hosts:
        errors.append("TRUSTED_HOSTS is required in production")
    if s.is_production and s.platform_root_domain in {"localhost", ""}:
        errors.append("PLATFORM_ROOT_DOMAIN must be a real domain in production")
    if s.is_production and s.jwt_secret == "dev-insecure-change-me":  # noqa: S105
        errors.append("JWT_SECRET must be set in production")
    if s.is_production and s.session_hash_secret == "dev-insecure-change-me":  # noqa: S105
        errors.append("SESSION_HASH_SECRET must be set in production")
    return errors

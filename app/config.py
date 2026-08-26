"""Academy product configuration layered on the kernel settings contract."""

from __future__ import annotations

from dotmac_kernel.config import Settings as KernelSettings
from dotmac_kernel.config import validate_settings as validate_kernel_settings

# Academy currently contains inline scripts and WebSocket lab consoles. This
# product default is declared by app.assembly's ProductSecurityPolicy;
# CONTENT_SECURITY_POLICY can still override it at deployment time.
ACADEMY_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
    "form-action 'self'; object-src 'none'; img-src 'self' data:; "
    "font-src 'self'; style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:"
)


class Settings(KernelSettings):
    """Kernel settings plus values owned only by the Academy product."""

    # IANA zone for instructor-entered wall-clock times (sessions/timetables).
    academy_timezone: str = "Africa/Lagos"
    # Lab orchestration (Increment 2).
    max_concurrent_labs: int = 20
    lab_workdir: str = "/home/dotmac/labs"
    lab_idle_minutes: int = 60
    # Address the app DIALS to reach a lab console. Same-host deployments keep the
    # loopback default; when the lab worker runs on a separate KVM host, set this
    # to that host's private/tunnel address (e.g. its WireGuard IP).
    lab_console_host: str = "127.0.0.1"
    # Address ttyd BINDS when this process spawns a console. Deliberately a
    # SEPARATE knob from ``lab_console_host``: on the app host the dial address is
    # REMOTE, and ttyd cannot bind an address the local host does not own — it
    # retries the bind forever at 100% CPU and never listens. Empty means "same as
    # ``lab_console_host``", which is correct on a single-host deployment and on
    # the lab host itself, where the tunnel address IS local.
    lab_console_bind_host: str = ""
    # Port probed on the lab host for the academy_lab_host_up health gauge.
    lab_host_probe_port: int = 22

    # GlitchTip (Sentry protocol) error tracking — inert unless BOTH are set.
    glitchtip_dsn: str = ""
    glitchtip_enabled: bool = False
    glitchtip_traces_sample_rate: float = 0.1

    # dotmac_erp training-report push (inert by default — empty URL disables it).
    # On course completion, a signed webhook records the result on the employee's
    # HR record; ERP matches by work email and ignores non-employees.
    erp_webhook_url: str = ""
    erp_webhook_secret: str = ""

    # ERP -> Academy applicant-assessment registration. Inbound and outbound
    # secrets are deliberately different trust directions. The public base URL
    # is used to mint links without trusting the request Host header; allowed
    # return origins are a comma-separated exact-origin allowlist.
    erp_inbound_hmac_secret: str = ""
    erp_assessment_token_secret: str = ""
    erp_inbound_hmac_max_skew_seconds: int = 300
    erp_allowed_return_origins: str = ""
    academy_public_base_url: str = ""

    # Integrator -> Academy managed application lifecycle.  This is a distinct
    # trust direction from the ERP assessment integration and must never reuse
    # its key. Empty means the service port is disabled.
    managed_lifecycle_inbound_hmac_secret: str = ""
    managed_lifecycle_inbound_hmac_max_skew_seconds: int = 300

    # One process-held OIDC provider registration. Empty issuer means the
    # federated login surface is disabled. The protocol is delegated to the
    # exact-pinned dotmac-auth-oidc adapter; authorization remains local.
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_url: str = ""
    oidc_provider_binding: str = "primary"
    oidc_scopes: str = "openid"
    oidc_discovery_url: str = ""
    oidc_http_timeout_seconds: float = 10.0
    oidc_ceremony_ttl_seconds: int = 600
    oidc_clock_skew_seconds: int = 60

    # Email / SMTP (inert by default — empty smtp_host disables sending).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "Dotmac Academy <academy@localhost>"
    smtp_starttls: bool = True
    management_inquiry_recipient: str = "fiberacademy@dotmac.ng"

    # Prometheus /metrics bearer token. Empty (default) = endpoint disabled.
    metrics_token: str = ""

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()


def validate_settings(s: Settings) -> list[str]:
    """Return list of fatal errors (empty if OK). Caller raises if non-empty in prod."""
    errors = validate_kernel_settings(s)
    # Single-tenancy is the kernel's control now (TENANCY=single, which makes it
    # assert at startup that exactly one tenant row exists and bind to it). This
    # repo used to name the slug itself in ACADEMY_TENANT_SLUG; that duplicated
    # an identity the database already holds. Production must still declare the
    # posture, so the requirement moves rather than disappearing.
    if s.is_production and s.tenancy != "single":
        errors.append(
            "TENANCY must be 'single' in production — this is a single-tenant "
            "deployment and the kernel's startup assertion is what enforces it"
        )
    if s.is_production and not s.csrf_enabled:
        errors.append("CSRF_ENABLED must be true in production")
    if s.is_production and not s.rate_limit_enabled:
        errors.append("RATE_LIMIT_ENABLED must be true in production")
    if s.rate_limit_requests <= 0 or s.rate_limit_window_seconds <= 0:
        errors.append("rate-limit request and window values must be positive")
    if s.is_production and s.smtp_host and not s.smtp_starttls:
        errors.append("SMTP_STARTTLS must be true when SMTP is configured in production")
    if s.erp_inbound_hmac_max_skew_seconds <= 0:
        errors.append("ERP_INBOUND_HMAC_MAX_SKEW_SECONDS must be positive")
    if s.managed_lifecycle_inbound_hmac_max_skew_seconds <= 0:
        errors.append("MANAGED_LIFECYCLE_INBOUND_HMAC_MAX_SKEW_SECONDS must be positive")
    oidc_values = (s.oidc_issuer, s.oidc_client_id, s.oidc_client_secret, s.oidc_redirect_url)
    if any(oidc_values) and not all(oidc_values):
        errors.append(
            "OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_REDIRECT_URL " "must be configured together"
        )
    if s.oidc_issuer and not s.oidc_issuer.startswith("https://"):
        errors.append("OIDC_ISSUER must use HTTPS")
    if s.oidc_redirect_url and not s.oidc_redirect_url.startswith("https://"):
        errors.append("OIDC_REDIRECT_URL must use HTTPS")
    if s.oidc_discovery_url and not s.oidc_discovery_url.startswith("https://"):
        errors.append("OIDC_DISCOVERY_URL must use HTTPS")
    if "openid" not in s.oidc_scopes.split():
        errors.append("OIDC_SCOPES must include openid")
    if not s.oidc_provider_binding.strip():
        errors.append("OIDC_PROVIDER_BINDING must not be blank")
    if s.oidc_http_timeout_seconds <= 0 or s.oidc_ceremony_ttl_seconds <= 0 or s.oidc_clock_skew_seconds < 0:
        errors.append("OIDC timeout/ceremony TTL must be positive and clock skew non-negative")
    if s.erp_inbound_hmac_secret:
        if not s.erp_assessment_token_secret:
            errors.append("ERP_ASSESSMENT_TOKEN_SECRET is required when ERP inbound integration is enabled")
        if not s.erp_allowed_return_origins:
            errors.append("ERP_ALLOWED_RETURN_ORIGINS is required when ERP inbound integration is enabled")
        if not s.academy_public_base_url:
            errors.append("ACADEMY_PUBLIC_BASE_URL is required when ERP inbound integration is enabled")
        if s.erp_webhook_secret and s.erp_inbound_hmac_secret == s.erp_webhook_secret:
            errors.append("ERP inbound and outbound HMAC secrets must be distinct")
    if s.managed_lifecycle_inbound_hmac_secret and s.managed_lifecycle_inbound_hmac_secret in {
        s.erp_inbound_hmac_secret,
        s.erp_webhook_secret,
    }:
        errors.append("managed lifecycle and ERP HMAC secrets must be distinct")
    if s.is_production and s.academy_public_base_url and not s.academy_public_base_url.startswith("https://"):
        errors.append("ACADEMY_PUBLIC_BASE_URL must use HTTPS in production")
    return errors

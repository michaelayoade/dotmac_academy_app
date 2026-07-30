"""GlitchTip (Sentry-protocol) error tracking — off unless a DSN is configured.

Mirrors the dotmac_sub convention: the SDK is optional at runtime and the whole
subsystem is inert when ``GLITCHTIP_DSN`` is empty or ``GLITCHTIP_ENABLED`` is
false, so a dev box or an unconfigured deployment behaves exactly as before.

PII is not sent by default: applicant and student records are personal data,
and a crash report is not a lawful basis for shipping it to another system.
The request id the observability middleware already generates is attached as a
tag instead, so a GlitchTip issue can be joined to the Loki request logs.
"""

from __future__ import annotations

import logging

from app.config import settings

logger = logging.getLogger(__name__)


def init_error_tracking() -> bool:
    """Initialise error tracking. Returns True when it was actually enabled."""
    if not settings.glitchtip_enabled or not settings.glitchtip_dsn:
        return False
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration
        from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
    except ImportError:
        logger.warning("sentry-sdk not installed; error tracking disabled")
        return False

    try:
        sentry_sdk.init(
            dsn=settings.glitchtip_dsn,
            environment=settings.environment,
            traces_sample_rate=settings.glitchtip_traces_sample_rate,
            server_name="academy",
            integrations=[
                FastApiIntegration(transaction_style="endpoint"),
                SqlalchemyIntegration(),
                LoggingIntegration(level=logging.WARNING, event_level=logging.ERROR),
            ],
            send_default_pii=False,
        )
    except Exception as exc:  # never let telemetry setup break startup
        logger.warning("failed to configure GlitchTip: %s", exc)
        return False
    logger.info("GlitchTip error tracking enabled (environment=%s)", settings.environment)
    return True


def tag_request(request_id: str) -> None:
    """Tag the current scope with the request id (joins issues to Loki logs)."""
    if not settings.glitchtip_enabled or not settings.glitchtip_dsn:
        return
    try:
        import sentry_sdk

        sentry_sdk.set_tag("request_id", request_id)
    except Exception:  # pragma: no cover - telemetry must never raise
        logger.debug("failed to tag request id", exc_info=True)

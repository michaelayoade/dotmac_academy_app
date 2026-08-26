"""Compose the published OIDC adapter with Academy's local identity owner."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from dotmac_auth_oidc import (
    PER_REQUEST_STATE_STORE,
    OIDCClient,
    OIDCError,
    RelyingPartyConfig,
    StateStore,
)
from sqlalchemy.orm import Session

from app.config import settings
from app.services.external_identity import FinalizedExternalLogin, finalize_external_login
from app.services.oidc_state_store import PostgresStateStore

logger = logging.getLogger(__name__)


class LoginRefused(Exception):
    """One public refusal for protocol, binding, account and session failures."""


@dataclass(frozen=True, slots=True)
class StartedLogin:
    url: str
    state: str
    expires_at: datetime


_CLIENT: OIDCClient | None = None


def _client() -> OIDCClient:
    global _CLIENT
    if _CLIENT is None:
        if not settings.oidc_issuer:
            raise LoginRefused
        _CLIENT = OIDCClient(
            RelyingPartyConfig(
                provider_binding=settings.oidc_provider_binding,
                issuer=settings.oidc_issuer,
                client_id=settings.oidc_client_id,
                client_secret=settings.oidc_client_secret,
                redirect_uri=settings.oidc_redirect_url,
                scopes=tuple(settings.oidc_scopes.split()),
                discovery_url=settings.oidc_discovery_url or None,
            ),
            state_store=PER_REQUEST_STATE_STORE,
            timeout=settings.oidc_http_timeout_seconds,
            leeway=settings.oidc_clock_skew_seconds,
        )
    return _CLIENT


def _store(db: Session, *, tenant_id: UUID) -> StateStore:
    return PostgresStateStore(
        db,
        tenant_id=tenant_id,
        provider_binding=settings.oidc_provider_binding,
    )


def begin_login(db: Session, *, tenant_id: UUID) -> StartedLogin:
    ttl = settings.oidc_ceremony_ttl_seconds
    try:
        # The adapter stores state before fetching discovery. A failed fetch
        # rolls this SAVEPOINT back, so returning a generic refusal cannot
        # commit an orphaned ceremony.
        with db.begin_nested():
            started = _client().start_login(
                return_to="/",
                ttl_seconds=ttl,
                state_store=_store(db, tenant_id=tenant_id),
            )
    except OIDCError as exc:
        logger.warning(
            "Academy external login could not start for tenant %s (%s)",
            tenant_id,
            type(exc).__name__,
        )
        raise LoginRefused from exc
    return StartedLogin(
        url=started.url,
        state=started.state,
        expires_at=datetime.now(UTC) + timedelta(seconds=ttl),
    )


def complete_login(
    db: Session,
    *,
    tenant_id: UUID,
    code: str,
    state: str,
    stored_state: str | None,
) -> FinalizedExternalLogin:
    try:
        verified = _client().complete_login(
            code=code,
            state_parameter=state,
            stored_state=stored_state or "",
            ttl_seconds=settings.oidc_ceremony_ttl_seconds,
            state_store=_store(db, tenant_id=tenant_id),
        )
    except OIDCError as exc:
        logger.warning(
            "Academy external login protocol refused tenant %s (%s)",
            tenant_id,
            type(exc).__name__,
        )
        raise LoginRefused from exc

    completed = finalize_external_login(
        db,
        tenant_id=tenant_id,
        provider_binding=settings.oidc_provider_binding,
        issuer=verified.issuer,
        subject=verified.subject,
    )
    if completed is None:
        # No email/name/JIT fallback. An unbound or disabled exact subject is
        # indistinguishable at the browser boundary.
        raise LoginRefused
    return completed


__all__ = ["LoginRefused", "StartedLogin", "begin_login", "complete_login"]

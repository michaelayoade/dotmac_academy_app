"""The Academy OIDC ceremony store is shared and single-use."""

from __future__ import annotations

from time import time

from dotmac_auth_oidc import LoginState

from app.services.oidc_state_store import PostgresStateStore, state_hash


def _state(state_id: str = "opaque-state") -> LoginState:
    return LoginState(
        state_id=state_id,
        nonce="nonce",
        code_verifier="v" * 86,
        redirect_uri="https://academy.test/login/callback",
        issued_at=int(time()),
        return_to="/",
    )


def test_state_is_stored_hashed_and_consumed_once(admin_session, tenant_a) -> None:
    store = PostgresStateStore(
        admin_session,
        tenant_id=tenant_a.id,
        provider_binding="customer-keycloak",
    )
    state = _state()
    store.put(state, ttl_seconds=600)

    assert store.take(state.state_id) == state
    assert store.take(state.state_id) is None
    assert state_hash(state.state_id) != state.state_id


def test_provider_binding_change_consumes_and_refuses_the_ceremony(admin_session, tenant_a) -> None:
    original = PostgresStateStore(
        admin_session,
        tenant_id=tenant_a.id,
        provider_binding="customer-keycloak",
    )
    changed = PostgresStateStore(
        admin_session,
        tenant_id=tenant_a.id,
        provider_binding="different-registration",
    )
    state = _state("provider-bound-state")
    original.put(state, ttl_seconds=600)

    assert changed.take(state.state_id) is None
    assert original.take(state.state_id) is None

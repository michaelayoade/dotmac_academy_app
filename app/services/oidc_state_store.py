"""Shared, atomic server-side OIDC ceremony storage for Academy workers."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import UUID, uuid4

from dotmac_auth_oidc import LoginState
from sqlalchemy import text
from sqlalchemy.orm import Session

CEREMONY_TABLE: Final[str] = "public.academy_oidc_login_states"

_SWEEP_SQL: Final[str] = (
    f"DELETE FROM {CEREMONY_TABLE} "  # noqa: S608 - constant table, bound values
    "WHERE tenant_id = :tenant_id AND expires_at <= now()"
)
_INSERT_SQL: Final[str] = (
    f"INSERT INTO {CEREMONY_TABLE} ("  # noqa: S608 - constant table, bound values
    "id, tenant_id, state_hash, code_verifier, nonce, redirect_uri, "
    "return_to, issued_at, provider_binding, expires_at) VALUES ("
    ":id, :tenant_id, :state_hash, :code_verifier, :nonce, :redirect_uri, "
    ":return_to, :issued_at, :provider_binding, :expires_at)"
)
_CONSUME_SQL: Final[str] = (
    f"DELETE FROM {CEREMONY_TABLE} "  # noqa: S608 - constant table, bound values
    "WHERE tenant_id = :tenant_id AND state_hash = :state_hash "
    "AND expires_at > now() "
    "RETURNING code_verifier, nonce, redirect_uri, return_to, issued_at, provider_binding"
)


def state_hash(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


class PostgresStateStore:
    """Request-bound store whose ``take`` is one DELETE … RETURNING.

    The request's existing transaction remains the one authority. No process
    local store is selectable, so a ceremony started on one worker can finish
    on another.
    """

    __slots__ = ("_binding", "_db", "_tenant_id")

    def __init__(self, db: Session, *, tenant_id: UUID, provider_binding: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._binding = provider_binding

    def put(self, state: LoginState, *, ttl_seconds: int) -> None:
        self._db.execute(text(_SWEEP_SQL), {"tenant_id": str(self._tenant_id)})
        self._db.execute(
            text(_INSERT_SQL),
            {
                "id": str(uuid4()),
                "tenant_id": str(self._tenant_id),
                "state_hash": state_hash(state.state_id),
                "code_verifier": state.code_verifier,
                "nonce": state.nonce,
                "redirect_uri": state.redirect_uri,
                "return_to": state.return_to,
                "issued_at": state.issued_at,
                "provider_binding": self._binding,
                "expires_at": datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            },
        )

    def take(self, state_id: str) -> LoginState | None:
        row = (
            self._db.execute(
                text(_CONSUME_SQL),
                {
                    "tenant_id": str(self._tenant_id),
                    "state_hash": state_hash(state_id),
                },
            )
            .mappings()
            .first()
        )
        if row is None or row["provider_binding"] != self._binding:
            return None
        return LoginState(
            state_id=state_id,
            nonce=row["nonce"],
            code_verifier=row["code_verifier"],
            redirect_uri=row["redirect_uri"],
            issued_at=row["issued_at"],
            return_to=row["return_to"],
        )


__all__ = ["CEREMONY_TABLE", "PostgresStateStore", "state_hash"]

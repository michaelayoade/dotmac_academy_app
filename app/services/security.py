"""Small auth primitives for the starter.

Uses stdlib-only PBKDF2 and HS256 JWTs to keep the skeleton dependency-light.
Production apps may swap this module for a dedicated auth package without changing
the tenant-bound contracts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.config import settings

PBKDF2_ITERATIONS = 210_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}"
        f"${base64.urlsafe_b64encode(salt).decode()}"
        f"${base64.urlsafe_b64encode(digest).decode()}"
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, iterations, salt_b64, digest_b64 = password_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def issue_access_token(person_id: UUID, tenant_id: UUID) -> tuple[str, datetime]:
    expires_at = datetime.now(UTC) + timedelta(seconds=settings.jwt_ttl_seconds)
    payload = {
        "sub": str(person_id),
        "tenant_id": str(tenant_id),
        "exp": int(expires_at.timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    return _encode_jwt(payload), expires_at


def decode_access_token(token: str) -> dict[str, object] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = _sign(signing_input)
    if not hmac.compare_digest(expected, parts[2]):
        return None
    try:
        payload = json.loads(_b64decode(parts[1]).decode())
    except (ValueError, json.JSONDecodeError):
        return None
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < int(datetime.now(UTC).timestamp()):
        return None
    return payload


def hash_token(token: str) -> str:
    return hmac.new(
        settings.session_hash_secret.encode(),
        token.encode(),
        hashlib.sha256,
    ).hexdigest()


def _encode_jwt(payload: dict[str, object]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    return f"{header_b64}.{payload_b64}.{_sign(signing_input)}"


def _sign(signing_input: bytes) -> str:
    digest = hmac.new(settings.jwt_secret.encode(), signing_input, hashlib.sha256).digest()
    return _b64encode(digest)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode())

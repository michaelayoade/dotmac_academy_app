"""CSRF, rate-limit, and observability middleware tests."""

from __future__ import annotations

import asyncio
from http import cookies
from typing import Any
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.config import settings, validate_settings
from app.middleware.csrf import CSRF_COOKIE, CSRFMiddleware
from app.middleware.observability import ObservabilityMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.services.platform_auth import require_platform_admin_token
from app.services.tenant_paths import is_platform_path


def test_csrf_sets_cookie_on_safe_request_and_blocks_cookie_post_without_header():
    app = CSRFMiddleware(_ok_app)

    get_response = _run(app, method="GET", path="/form")
    assert get_response["status"] == 200
    csrf_cookie = _cookie_value(get_response, CSRF_COOKIE)
    assert csrf_cookie is not None

    post_response = _run(
        app,
        method="POST",
        path="/form",
        headers=[(b"cookie", f"{CSRF_COOKIE}={csrf_cookie}".encode())],
    )
    assert post_response["status"] == 403


def test_csrf_allows_matching_double_submit_token():
    app = CSRFMiddleware(_ok_app)

    response = _run(
        app,
        method="POST",
        path="/form",
        headers=[
            (b"cookie", f"{CSRF_COOKIE}=known-token".encode()),
            (b"x-csrf-token", b"known-token"),
        ],
    )
    assert response["status"] == 200


def test_rate_limit_key_isolated_by_path():
    app = RateLimitMiddleware(_ok_app, requests=1, window_seconds=60)

    assert _run(app, method="GET", path="/a")["status"] == 200
    assert _run(app, method="GET", path="/a")["status"] == 429
    assert _run(app, method="GET", path="/b")["status"] == 200


def test_rate_limit_key_isolated_by_tenant():
    app = RateLimitMiddleware(_ok_app, requests=1, window_seconds=60)
    tenant_a = _Tenant(str(uuid4()))
    tenant_b = _Tenant(str(uuid4()))

    assert _run(app, method="GET", path="/foo", tenant=tenant_a)["status"] == 200
    assert _run(app, method="GET", path="/foo", tenant=tenant_a)["status"] == 429
    assert _run(app, method="GET", path="/foo", tenant=tenant_b)["status"] == 200


def test_observability_generates_request_id_by_default():
    app = ObservabilityMiddleware(_ok_app)

    response = _run(
        app,
        method="GET",
        path="/ping",
        headers=[(b"x-request-id", b"untrusted-id")],
    )
    assert response["status"] == 200
    response_request_ids = [
        value for key, value in response["headers"] if key == b"x-request-id"
    ]
    assert response_request_ids
    assert response_request_ids[0] != b"untrusted-id"


def test_observability_can_trust_inbound_request_id():
    app = ObservabilityMiddleware(_ok_app, trust_inbound_request_id=True)

    response = _run(
        app,
        method="GET",
        path="/ping",
        headers=[(b"x-request-id", b"req-123")],
    )
    assert response["status"] == 200
    assert (b"x-request-id", b"req-123") in response["headers"]


def test_platform_paths_only_allowed_on_root_host():
    assert is_platform_path("/platform/tenants", "localhost", "localhost") is True
    assert is_platform_path("/platform/tenants", "unknown.localhost", "localhost") is False
    assert is_platform_path("/health", "unknown.localhost", "localhost") is True


def test_platform_admin_token_required(monkeypatch):
    monkeypatch.setattr(settings, "platform_admin_token", "secret-token")

    require_platform_admin_token(None, "secret-token")
    require_platform_admin_token("Bearer secret-token", None)

    with pytest.raises(HTTPException) as exc:
        require_platform_admin_token(None, "wrong")
    assert exc.value.status_code == 401


def test_platform_admin_token_required_in_production(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "database_url", "postgresql://app")
    monkeypatch.setattr(settings, "platform_database_url", "postgresql://platform")
    monkeypatch.setattr(settings, "trusted_hosts", "academy.example.com")
    monkeypatch.setattr(settings, "platform_root_domain", "academy.example.com")
    monkeypatch.setattr(settings, "jwt_secret", "jwt-secret")
    monkeypatch.setattr(settings, "session_hash_secret", "hash-secret")
    monkeypatch.setattr(settings, "platform_admin_token", "")

    assert "PLATFORM_ADMIN_TOKEN must be set in production" in validate_settings(settings)


async def _ok_app(scope, receive, send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": b'{"ok":true}'})


def _run(
    app,
    *,
    method: str,
    path: str,
    headers: list[tuple[bytes, bytes]] | None = None,
    tenant: object | None = None,
) -> dict[str, Any]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers or [],
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "state": {"tenant": tenant} if tenant is not None else {},
    }
    asyncio.run(app(scope, receive, send))
    start = next(message for message in messages if message["type"] == "http.response.start")
    return {"status": start["status"], "headers": start["headers"], "messages": messages}


def _cookie_value(response: dict[str, Any], name: str) -> str | None:
    jar = cookies.SimpleCookie()
    for header, value in response["headers"]:
        if header == b"set-cookie":
            jar.load(value.decode())
    morsel = jar.get(name)
    return morsel.value if morsel is not None else None


class _Tenant:
    def __init__(self, tenant_id: str) -> None:
        self.id = tenant_id

"""Tenant-aware in-memory rate limiting middleware.

This is intentionally process-local for the starter. Production deployments should
replace the store with Redis using the same key shape.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque

from fastapi.responses import JSONResponse
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        enabled: bool = True,
        requests: int = 120,
        window_seconds: int = 60,
    ) -> None:
        self.app = app
        self.enabled = enabled
        self.requests = requests
        self.window_seconds = window_seconds
        self._hits: dict[str, Deque[float]] = defaultdict(deque)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        if not self.enabled or request.url.path == "/health":
            await self.app(scope, receive, send)
            return

        key = _rate_limit_key(request)
        now = time.monotonic()
        hits = self._hits[key]
        while hits and hits[0] <= now - self.window_seconds:
            hits.popleft()
        if len(hits) >= self.requests:
            retry_after = max(1, int(self.window_seconds - (now - hits[0])))
            response = JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": str(retry_after)},
            )
            await response(scope, receive, send)
            return
        hits.append(now)
        await self.app(scope, receive, send)


def _rate_limit_key(request: Request) -> str:
    tenant = getattr(request.state, "tenant", None)
    tenant_key = str(tenant.id) if tenant is not None else "platform"
    client_ip = request.client.host if request.client else "unknown"
    return f"rate_limit:{tenant_key}:{client_ip}:{request.url.path}"

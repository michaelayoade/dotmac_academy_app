"""Request observability middleware."""

from __future__ import annotations

import logging
import time
from uuid import uuid4

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("app.requests")


class ObservabilityMiddleware:
    def __init__(self, app: ASGIApp, *, trust_inbound_request_id: bool = False) -> None:
        self.app = app
        self.trust_inbound_request_id = trust_inbound_request_id

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        inbound_request_id = request.headers.get("x-request-id")
        request_id = (
            inbound_request_id
            if self.trust_inbound_request_id and inbound_request_id
            else str(uuid4())
        )
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.perf_counter()
        status_code = 500

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            tenant = getattr(request.state, "tenant", None)
            logger.info(
                "request",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "tenant_id": str(tenant.id) if tenant is not None else None,
                },
            )

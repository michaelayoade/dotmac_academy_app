"""Academy's narrow instrumentation adapter around the kernel runtime.

Kernel 0.1.0a38 owns construction, product startup checks/hooks, browser
security policy, platform-surface composition, and every generic runtime
control. Academy keeps only product-specific request metrics and GlitchTip
request correlation here.
"""

from __future__ import annotations

import logging
import time

from dotmac_kernel import create_app
from fastapi import FastAPI
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.assembly import assembly

logger = logging.getLogger(__name__)


class AcademyInstrumentationMiddleware:
    """Add Academy metrics and GlitchTip correlation to kernel observability."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        started = time.perf_counter()
        status_code = 500

        async def send_with_instrumentation(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                request_id = MutableHeaders(scope=message).get("x-request-id")
                if request_id:
                    from app.error_tracking import tag_request

                    tag_request(request_id)
            await send(message)

        try:
            await self.app(scope, receive, send_with_instrumentation)
        finally:
            try:
                from app.metrics import observe_request

                route = getattr(scope.get("route"), "path", None) or "(unmatched)"
                observe_request(
                    method=request.method,
                    route=route,
                    status_code=status_code,
                    duration_seconds=time.perf_counter() - started,
                )
            except Exception:  # telemetry must never break a request
                logger.debug("metrics observation failed", exc_info=True)


def create_academy_app() -> FastAPI:
    """Build Academy through the public kernel assembly contract."""
    app = create_app(assembly)
    app.add_middleware(AcademyInstrumentationMiddleware)
    return app


__all__ = [
    "AcademyInstrumentationMiddleware",
    "create_academy_app",
]

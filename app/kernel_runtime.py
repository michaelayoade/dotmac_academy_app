"""Academy's narrow instrumentation adapter around the kernel runtime.

Kernel 0.1.0a38 owns construction, product startup checks/hooks, browser
security policy, platform-surface composition, and every generic runtime
control. Academy keeps only product-specific request metrics and GlitchTip
request correlation here.
"""

from __future__ import annotations

import logging
import re
import time
from urllib.parse import urlsplit

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


# The ONLY unsafe-method route family exempted from the kernel's double-submit
# CSRF header: POSTs to a node's console sub-resources (RouterOS WebFig talks to
# ``POST .../console/<node>/jsproxy`` from vendor JavaScript we cannot modify to
# add an ``X-CSRF-Token`` header). Everything else keeps full CSRF protection.
_CONSOLE_POST_PATH = re.compile(r"^/labs/instances/[0-9a-fA-F-]{36}/console/[A-Za-z0-9_.-]+/[^?#]+$")


def _is_console_post_path(path: str) -> bool:
    return bool(_CONSOLE_POST_PATH.match(path)) and not {"..", "."} & set(path.split("/"))


class ConsoleProxyCsrfBridge:
    """Narrow, fail-closed CSRF bridge for the per-lab console proxy POST.

    The kernel CSRFMiddleware (double-submit cookie/header) has no per-route
    exemption and WebFig cannot send the header. For ``POST`` requests to the
    console sub-resource path only, this middleware supplies the header from
    the request's own ``csrf_token`` cookie **iff** the browser proves the
    request is same-origin: a present ``Origin`` header whose host equals the
    ``Host`` header (browsers always send Origin on same-origin POST and script
    cannot forge or suppress it on a cross-site request) and, when sent,
    ``Sec-Fetch-Site`` of ``same-origin``. Missing or mismatching evidence
    leaves the request untouched, so the kernel rejects it with 403. It adds no
    authentication: owner/tenant/entitlement checks still run in the route.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("method") == "POST" and _is_console_post_path(scope.get("path", "")):
            scope = self._bridged(scope)
        await self.app(scope, receive, send)

    @staticmethod
    def _bridged(scope: Scope) -> Scope:
        headers = list(scope.get("headers", []))
        names = {k.lower() for k, _ in headers}
        if b"x-csrf-token" in names:
            return scope  # a real token is validated by the kernel as usual
        request = Request(scope)
        origin = request.headers.get("origin")
        host = request.headers.get("host")
        cookie = request.cookies.get("csrf_token")
        if not origin or not host or not cookie:
            return scope
        if request.headers.get("sec-fetch-site", "same-origin").lower() != "same-origin":
            return scope
        try:
            parsed_origin = urlsplit(origin)
            forwarded_scheme = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
            request_scheme = forwarded_scheme if forwarded_scheme in {"http", "https"} else request.url.scheme.lower()
            if (
                parsed_origin.scheme.lower() != request_scheme
                or parsed_origin.netloc.lower() != host.lower()
                or parsed_origin.username is not None
                or parsed_origin.password is not None
                or parsed_origin.path not in ("", "/")
                or parsed_origin.query
                or parsed_origin.fragment
            ):
                return scope
        except ValueError:
            return scope
        headers.append((b"x-csrf-token", cookie.encode("latin-1")))
        return {**scope, "headers": headers}


def create_academy_app() -> FastAPI:
    """Build Academy through the public kernel assembly contract."""
    app = create_app(assembly)
    app.add_middleware(ConsoleProxyCsrfBridge)
    app.add_middleware(AcademyInstrumentationMiddleware)
    return app


__all__ = [
    "AcademyInstrumentationMiddleware",
    "ConsoleProxyCsrfBridge",
    "create_academy_app",
]

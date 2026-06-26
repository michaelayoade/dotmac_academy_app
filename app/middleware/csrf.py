"""Double-submit CSRF middleware for browser-cookie flows."""

from __future__ import annotations

import hmac
import secrets

from fastapi.responses import JSONResponse
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "x-csrf-token"


class CSRFMiddleware:
    def __init__(self, app: ASGIApp, *, enabled: bool = True) -> None:
        self.app = app
        self.enabled = enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        if request.method not in SAFE_METHODS:
            cookie_token = request.cookies.get(CSRF_COOKIE)
            header_token = request.headers.get(CSRF_HEADER)
            if request.cookies and not _valid_csrf_token(cookie_token, header_token):
                response = JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF check failed"},
                )
                await response(scope, receive, send)
                return

        set_cookie = request.method in SAFE_METHODS and CSRF_COOKIE not in request.cookies

        async def send_with_csrf(message: Message) -> None:
            if set_cookie and message["type"] == "http.response.start":
                token = secrets.token_urlsafe(32)
                cookie = f"{CSRF_COOKIE}={token}; Path=/; SameSite=lax"
                if request.url.scheme == "https":
                    cookie += "; Secure"
                headers = list(message.get("headers", []))
                headers.append((b"set-cookie", cookie.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_csrf)


def _valid_csrf_token(cookie_token: str | None, header_token: str | None) -> bool:
    if not cookie_token or not header_token:
        return False
    return hmac.compare_digest(cookie_token, header_token)

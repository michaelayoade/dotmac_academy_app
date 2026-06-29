"""Header filtering helpers for lab console reverse proxies."""

from __future__ import annotations

from collections.abc import Mapping

HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)
APP_ONLY_REQUEST_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "x-csrf-token",
        "x-platform-admin-token",
    }
)
APP_ONLY_RESPONSE_HEADERS = frozenset({"set-cookie"})


def proxy_request_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return browser request headers safe to forward to a lab console."""
    blocked = HOP_BY_HOP_HEADERS | APP_ONLY_REQUEST_HEADERS
    return {k: v for k, v in headers.items() if k.lower() not in blocked}


def proxy_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return upstream response headers safe to send from the academy origin."""
    blocked = HOP_BY_HOP_HEADERS | APP_ONLY_RESPONSE_HEADERS
    return {k: v for k, v in headers.items() if k.lower() not in blocked}

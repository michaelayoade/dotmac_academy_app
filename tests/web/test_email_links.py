"""Emailed links must be absolute: a mail client cannot open a bare path."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, FastAPI
from starlette.requests import Request

from app.web.email_links import absolute_surface_link


def _request(host: str = "alpha.example.test") -> Request:
    app = FastAPI()
    router = APIRouter()

    @router.get("/reset", name="reset_form")
    def reset_form():  # pragma: no cover - routing target only
        return None

    app.include_router(router)
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/forgot",
            "query_string": b"",
            "root_path": "",
            "scheme": "https",
            "server": (host, 443),
            "headers": [(b"host", host.encode())],
            "router": app.router,
            "app": app,
        }
    )


def test_link_is_absolute_with_scheme_host_path_and_encoded_token():
    link = absolute_surface_link(_request(), "reset_form", token="a b&c=d")
    parts = urlsplit(link)
    assert (parts.scheme, parts.netloc, parts.path) == ("https", "alpha.example.test", "/reset")
    assert parse_qs(parts.query) == {"token": ["a b&c=d"]}
    assert link.startswith("https://alpha.example.test/reset?token=")

"""Structural guards on the registered route table.

A route decorator binds to whatever function is defined immediately below it. If a
private helper drifts in between, the helper silently becomes the handler and the
real one is never registered — the endpoint then 422s on the helper's own args.
That shipped once (POST /apply). These guards make it a test failure, not an outage.
"""

from __future__ import annotations

from fastapi.routing import APIRoute

from app.main import app

_ROUTES = [r for r in app.routes if isinstance(r, APIRoute)]


def test_no_private_helper_is_registered_as_a_handler():
    private = [f"{sorted(r.methods)} {r.path} -> {r.endpoint.__name__}" for r in _ROUTES if r.endpoint.__name__.startswith("_")]
    assert private == [], f"private helpers registered as route handlers: {private}"


def test_public_intake_endpoints_are_registered():
    registered = {(m, r.path) for r in _ROUTES for m in r.methods}
    for method, path in [
        ("GET", "/apply"),
        ("POST", "/apply"),
        ("GET", "/apply/assessment"),
        ("POST", "/apply/assessment"),
    ]:
        assert (method, path) in registered, f"{method} {path} is not registered"

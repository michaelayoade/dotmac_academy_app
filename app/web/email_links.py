"""Absolute links for emails and other off-site use.

``surface_path`` returns only a path, which a mail client cannot open. The
origin is the request's own scheme and host, exactly as ``request.url_for`` gave
before the surface facets: the host has already been resolved to a tenant by
``require_tenant`` before any link is built.
"""

from __future__ import annotations

from urllib.parse import urlencode

from dotmac_kernel.web_surfaces import surface_path


def absolute_surface_link(request, local: str, **query: str) -> str:
    """Return ``<scheme>://<host><surface path>?<query>`` for a sibling route."""
    origin = str(request.base_url.replace(path="", query="", fragment="")).rstrip("/")
    link = f"{origin}{surface_path(request, local)}"
    return f"{link}?{urlencode(query)}" if query else link

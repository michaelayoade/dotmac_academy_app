"""Pure helpers for the lab console reverse proxy (``app.web.labs``).

Kept separate from the route module so the security-relevant string handling
(management-address validation, path validation, cookie/redirect confinement)
is small, importable and testable on its own.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote, urlsplit

from fastapi import HTTPException, Request


def safe_mgmt_address(value: object) -> str | None:
    """Accept only a plain private IPv4 literal as a RouterOS management address.

    The value is persisted by the lab worker from containerlab inspect output,
    but it is interpolated into an upstream URL, so a malformed value (a host
    name, ``user@host``, a port, ``::1``, metadata/link-local, loopback) must
    never become an SSRF target.
    """
    try:
        ip = ipaddress.IPv4Address(str(value))
    except ValueError:
        return None
    if not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return None
    return str(ip)


# Device cookies are namespaced so they can never collide with (or overwrite)
# Academy's ``session`` / ``csrf_token`` cookies, and scoped to the proxy path.
DEVICE_COOKIE_PREFIX = "wf_"
COOKIE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
COOKIE_VALUE_RE = re.compile(r"^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]{0,2048}$")
MAX_DEVICE_COOKIES = 8


def safe_subpath(subpath: str) -> str:
    """Validate and percent-encode a console sub-resource path.

    ``subpath`` arrives already decoded, so a ``%2e%2e`` or ``%3F`` in the URL
    would otherwise become a literal ``..`` or ``?`` once concatenated onto the
    upstream URL. Reject traversal/oddities outright and re-encode the rest so
    the value can only ever be a path below the node's own root.
    """
    if any(ord(c) < 0x20 or ord(c) == 0x7F or c == "\\" for c in subpath):
        raise HTTPException(status_code=400, detail="invalid console path")
    if subpath.startswith("/") or "//" in subpath:
        raise HTTPException(status_code=400, detail="invalid console path")
    if any(seg in ("..", ".") for seg in subpath.split("/")):
        raise HTTPException(status_code=400, detail="invalid console path")
    return quote(subpath, safe="/:@!$&'()*+,;=-._~")


def device_cookie_header(request: Request) -> str | None:
    """Rebuild the Cookie header from device-namespaced cookies only."""
    pairs = []
    for name, value in request.cookies.items():
        if name.startswith(DEVICE_COOKIE_PREFIX) and COOKIE_VALUE_RE.match(value):
            real = name[len(DEVICE_COOKIE_PREFIX) :]
            if COOKIE_NAME_RE.match(real):
                pairs.append(f"{real}={value}")
    return "; ".join(pairs[:MAX_DEVICE_COOKIES]) or None


def rewrite_set_cookie(raw: str, prefix: str, secure: bool) -> str | None:
    """Re-issue a device cookie namespaced, path-scoped and HttpOnly, or drop it."""
    parts = [p.strip() for p in raw.split(";")]
    name, sep, value = parts[0].partition("=")
    name = name.strip()
    if not sep or not COOKIE_NAME_RE.match(name) or not COOKIE_VALUE_RE.match(value.strip()):
        return None
    out = f"{DEVICE_COOKIE_PREFIX}{name}={value.strip()}; Path={prefix}/; HttpOnly; SameSite=Strict"
    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        if key.strip().lower() == "max-age" and re.fullmatch(r"-?\d{1,10}", val.strip()):
            out += f"; Max-Age={val.strip()}"
    return out + ("; Secure" if secure else "")


def rewrite_location(location: str, target: str, prefix: str) -> str | None:
    """Keep a device redirect inside the proxy prefix; drop foreign redirects."""
    base = urlsplit(target)
    loc = urlsplit(location)
    if loc.scheme or loc.netloc:
        if loc.scheme != base.scheme or loc.netloc != base.netloc:
            return None
    path = loc.path or "/"
    if not path.startswith("/"):
        return location  # relative: resolves under the proxy prefix on its own
    if path.startswith(prefix + "/"):
        return location if not (loc.scheme or loc.netloc) else path
    out = prefix + path
    return out + (f"?{loc.query}" if loc.query else "")

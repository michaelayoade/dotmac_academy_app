# Ported at new-composition genesis (web layer wave).
from __future__ import annotations

from datetime import UTC, datetime

from dotmac_kernel.templating import render

from app.services.localtime import academy_tz_label, to_local
from app.ui import template_globals
from app.web.context import nav_context


def _datefmt(dt):
    """Compact human date-time for dashboard chips, e.g. 'Aug 03, 14:00'."""
    if dt is None:
        return ""
    return dt.strftime("%b %d, %H:%M")


def _elapsed(dt: datetime | None) -> str:
    """Compact age for polling surfaces, e.g. '42s ago' or '3 min ago'.

    Stored timestamps are UTC; a naive value is read as UTC rather than
    crashing a page render. Future timestamps (clock skew) clamp to
    'just now' instead of rendering a negative age.
    """
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    seconds = max(0, int((datetime.now(UTC) - dt).total_seconds()))
    if seconds < 5:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} hr ago"
    days = seconds // 86400
    return f"{days} day{'s' if days != 1 else ''} ago"


_PRODUCT_FILTERS = {"localtime": to_local, "datefmt": _datefmt, "elapsed": _elapsed}


class _ProductTemplates:
    """Compatibility spelling backed solely by Kernel's public render port."""

    def TemplateResponse(self, *args, **kwargs):
        # Starlette supports both (name, context) and (request, name, context).
        fields = (
            ("name", "context", "status_code")
            if args and isinstance(args[0], str)
            else ("request", "name", "context", "status_code")
        )
        if len(args) > len(fields):
            raise TypeError("unsupported positional TemplateResponse arguments")
        values = dict(kwargs)
        for key, value in zip(fields, args, strict=False):
            if key in values:
                raise TypeError(f"multiple values for {key}")
            values[key] = value
        unsupported = values.keys() - {"request", "name", "context", "status_code"}
        if unsupported:
            raise TypeError(f"unsupported TemplateResponse arguments: {sorted(unsupported)}")
        context = dict(values.get("context") or {})
        request = values.get("request", context.get("request"))
        if request is None or "name" not in values:
            raise TypeError("TemplateResponse requires request and name")
        navigation = nav_context(request)
        context = {**template_globals(), "academy_tz_label": academy_tz_label(), **context, **navigation}
        if context.get("lifecycle_page"):
            brand = dict(context["brand"])
            brand["name"] = navigation["branding_name"]
            brand["mark"] = brand["name"][:1]
            context["brand"] = brand
        return render(
            request, values["name"], context, status_code=values.get("status_code", 200), filters=_PRODUCT_FILTERS
        )


templates = _ProductTemplates()

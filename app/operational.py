"""Academy-owned operational routes.

The kernel owns generic liveness at ``/health``. Academy owns the metrics it
emits about its learning, admissions, and lab pipelines, so that endpoint stays
with the product and is mounted through the Academy feature manifest.
"""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.config import settings
from app.metrics import refresh_lab_host_probe, refresh_pipeline_metrics, render

router = APIRouter()


@router.get("/metrics", include_in_schema=False)
def metrics(request: Request) -> Response:
    """Render bearer-gated Prometheus metrics, or appear absent when disabled."""
    supplied = (request.headers.get("authorization") or "").removeprefix("Bearer ").strip()
    token = settings.metrics_token
    if not token or not supplied or not hmac.compare_digest(supplied, token):
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    refresh_lab_host_probe(settings.lab_console_host, settings.lab_host_probe_port)
    refresh_pipeline_metrics()
    payload, content_type = render()
    return Response(content=payload, media_type=content_type)


__all__ = ["router"]

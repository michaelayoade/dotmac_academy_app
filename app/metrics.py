"""Prometheus metrics — bounded HTTP instrumentation for the observe stack.

Cardinality is deliberately bounded (the cross-Dotmac metrics-safety rule):
the route label is the MATCHED route template (``/courses/{slug}``), never the
raw path, and unmatched requests collapse into a single ``(unmatched)`` bucket
so scanners cannot mint label values.

Gunicorn runs multiple workers, each with its own process registry, so prod
must set ``PROMETHEUS_MULTIPROC_DIR`` (a per-boot scratch dir, e.g. a systemd
``RuntimeDirectory``); the client library then aggregates across workers at
scrape time. Without the env var (dev, tests, single process) the default
in-process registry is used.

The ``/metrics`` endpoint itself lives in ``app.main`` and is inert unless
``METRICS_TOKEN`` is configured — the app is on the public internet, and
operational metrics are internal.
"""

from __future__ import annotations

import os

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
    multiprocess,
)

HTTP_REQUESTS = Counter(
    "academy_http_requests_total",
    "HTTP requests by method, matched route template, and status class.",
    ("method", "route", "status"),
)

HTTP_DURATION = Histogram(
    "academy_http_request_duration_seconds",
    "HTTP request duration by matched route template.",
    ("method", "route"),
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


def observe_request(*, method: str, route: str, status_code: int, duration_seconds: float) -> None:
    status = f"{status_code // 100}xx"
    HTTP_REQUESTS.labels(method=method, route=route, status=status).inc()
    HTTP_DURATION.labels(method=method, route=route).observe(duration_seconds)


def render() -> tuple[bytes, str]:
    """(payload, content_type) for the /metrics response.

    In multiprocess mode a fresh registry aggregates every worker's mmap'd
    series; otherwise the default in-process registry is served directly.
    """
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return generate_latest(registry), CONTENT_TYPE_LATEST
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST

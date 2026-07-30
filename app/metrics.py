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

import logging
import os
import socket
import time

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
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


# Labs run on a separate KVM host reached over a private link (WireGuard). If
# that link drops, provisioning still succeeds but every console 502s — a
# silent failure for students. This gauge makes it alertable.
# multiprocess_mode="max": each gunicorn worker probes independently; one
# worker reaching the lab host is enough to call the link up.
LAB_HOST_UP = Gauge(
    "academy_lab_host_up",
    "1 when the lab host answers on its console/tunnel address, else 0.",
    multiprocess_mode="max",
)

# Pipeline state, as bounded snapshots. Labels are closed enumerations from the
# models (7 applicant statuses, 5 lab statuses), so cardinality cannot grow with
# traffic or data volume — per the Dotmac metrics-scrape safety rule. Refreshed
# from ONE cheap grouped COUNT per family, cached, so scrapes carry a fixed
# query budget rather than scaling with scrape frequency.
APPLICANTS_BY_STATUS = Gauge(
    "academy_applicants",
    "Applicants by admissions pipeline status.",
    ("status",),
    multiprocess_mode="max",
)

LAB_INSTANCES_BY_STATUS = Gauge(
    "academy_lab_instances",
    "Lab instances by lifecycle status.",
    ("status",),
    multiprocess_mode="max",
)

LAB_CAPACITY = Gauge(
    "academy_lab_capacity",
    "Configured maximum concurrent lab instances.",
    multiprocess_mode="max",
)

ENTRANCE_SITTINGS = Gauge(
    "academy_entrance_sittings",
    "Graded entrance sittings by validity ('valid', 'invalid').",
    ("validity",),
    multiprocess_mode="max",
)

_PROBE_TTL_SECONDS = 30.0
_PROBE_TIMEOUT_SECONDS = 2.0
_last_probe: tuple[float, float] = (0.0, 0.0)  # (checked_at, value)

_PIPELINE_TTL_SECONDS = 60.0
_last_pipeline_refresh = 0.0

logger = logging.getLogger(__name__)


def observe_request(*, method: str, route: str, status_code: int, duration_seconds: float) -> None:
    status = f"{status_code // 100}xx"
    HTTP_REQUESTS.labels(method=method, route=route, status=status).inc()
    HTTP_DURATION.labels(method=method, route=route).observe(duration_seconds)


def refresh_lab_host_probe(host: str, port: int) -> None:
    """Refresh :data:`LAB_HOST_UP` with a cached TCP reachability probe.

    Called on scrape rather than from a background task so it works uniformly
    across gunicorn workers. Cached for ``_PROBE_TTL_SECONDS`` and bounded by a
    short timeout, so a down lab host cannot slow scrapes down materially.
    A same-host deployment (loopback) is trivially up.
    """
    global _last_probe
    now = time.monotonic()
    checked_at, value = _last_probe
    if checked_at and (now - checked_at) < _PROBE_TTL_SECONDS:
        LAB_HOST_UP.set(value)
        return
    try:
        with socket.create_connection((host, port), timeout=_PROBE_TIMEOUT_SECONDS):
            value = 1.0
    except OSError:
        value = 0.0
    except Exception:  # never let a probe break a scrape
        logger.debug("lab host probe failed unexpectedly", exc_info=True)
        value = 0.0
    _last_probe = (now, value)
    LAB_HOST_UP.set(value)


def refresh_pipeline_metrics() -> None:
    """Refresh the admissions/lab snapshot gauges from the database.

    Cached for ``_PIPELINE_TTL_SECONDS``; three grouped COUNTs per refresh, so
    the query cost is fixed regardless of how often Prometheus scrapes. Failures
    are swallowed — stale gauges are far better than a broken scrape (and the
    scrape target going down would mask everything else).
    """
    global _last_pipeline_refresh
    now = time.monotonic()
    if _last_pipeline_refresh and (now - _last_pipeline_refresh) < _PIPELINE_TTL_SECONDS:
        return
    _last_pipeline_refresh = now
    try:
        from sqlalchemy import func, select

        from app.models.admissions import APPLICANT_STATUSES, Applicant
        from app.models.lab import LabInstance
        from app.services import lab_jobs

        with lab_jobs.admin_session() as db:
            counts: dict[str, int] = {
                str(k): int(v)
                for k, v in db.execute(select(Applicant.status, func.count()).group_by(Applicant.status)).all()
            }
            # Emit every known status, including zeros: a status that vanishes
            # from the query would otherwise keep its last value forever.
            for status in APPLICANT_STATUSES:
                APPLICANTS_BY_STATUS.labels(status=status).set(counts.get(status, 0))

            lab_counts: dict[str, int] = {
                str(k): int(v)
                for k, v in db.execute(select(LabInstance.status, func.count()).group_by(LabInstance.status)).all()
            }
            for status in ("queued", "provisioning", "active", "error", "reaped"):
                LAB_INSTANCES_BY_STATUS.labels(status=status).set(lab_counts.get(status, 0))

            sittings: dict[bool | None, int] = {
                k: int(v)
                for k, v in db.execute(
                    select(Applicant.assessment_valid, func.count())
                    .where(Applicant.assessment_taken_at.is_not(None))
                    .group_by(Applicant.assessment_valid)
                ).all()
            }
            ENTRANCE_SITTINGS.labels(validity="valid").set(sittings.get(True, 0))
            ENTRANCE_SITTINGS.labels(validity="invalid").set(sittings.get(False, 0) + sittings.get(None, 0))

            from app.services.settings_store import effective

            LAB_CAPACITY.set(effective(db).max_concurrent_labs)
    except Exception:  # never let a metrics query break a scrape
        logger.debug("pipeline metrics refresh failed", exc_info=True)


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

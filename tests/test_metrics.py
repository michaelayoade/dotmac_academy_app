"""Prometheus /metrics — token gating and bounded instrumentation."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import settings
from tests.conftest import client_for


def test_metrics_disabled_without_token_config(app_client, tenant_a, monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", "")
    a = client_for(TestClient(app_client.app), tenant_a.slug)
    assert a.get("/metrics").status_code == 404
    assert a.get("/metrics", headers={"Authorization": "Bearer anything"}).status_code == 404


def test_metrics_requires_matching_bearer(app_client, tenant_a, monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", "sekrit-scrape-token")
    a = client_for(TestClient(app_client.app), tenant_a.slug)
    assert a.get("/metrics").status_code == 404
    assert a.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 404

    r = a.get("/metrics", headers={"Authorization": "Bearer sekrit-scrape-token"})
    assert r.status_code == 200
    assert "academy_http_requests_total" in r.text


def test_metrics_use_route_template_not_raw_path(app_client, tenant_a, monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", "sekrit-scrape-token")
    a = client_for(TestClient(app_client.app), tenant_a.slug)
    a.get("/health")
    a.get("/no-such-page-xyzzy-12345")

    r = a.get("/metrics", headers={"Authorization": "Bearer sekrit-scrape-token"})
    assert 'route="/health"' in r.text
    # 404s collapse into the single unmatched bucket — no scanner-minted labels.
    assert "xyzzy" not in r.text
    assert 'route="(unmatched)"' in r.text


def test_lab_host_probe_reports_up_and_down(app_client, tenant_a, monkeypatch):
    """The lab-link gauge flips with reachability and is cached between probes."""
    import app.metrics as m

    monkeypatch.setattr(settings, "metrics_token", "sekrit-scrape-token")
    a = client_for(TestClient(app_client.app), tenant_a.slug)

    calls: list[tuple] = []

    class _Sock:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _ok(addr, timeout=None):
        calls.append(addr)
        return _Sock()

    monkeypatch.setattr(m, "_last_probe", (0.0, 0.0))
    monkeypatch.setattr(m.socket, "create_connection", _ok)
    r = a.get("/metrics", headers={"Authorization": "Bearer sekrit-scrape-token"})
    assert "academy_lab_host_up 1.0" in r.text
    assert calls  # probe actually ran

    # Second scrape inside the TTL reuses the cached value (no new connection).
    before = len(calls)
    a.get("/metrics", headers={"Authorization": "Bearer sekrit-scrape-token"})
    assert len(calls) == before

    def _refused(addr, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr(m, "_last_probe", (0.0, 0.0))
    monkeypatch.setattr(m.socket, "create_connection", _refused)
    r = a.get("/metrics", headers={"Authorization": "Bearer sekrit-scrape-token"})
    assert "academy_lab_host_up 0.0" in r.text

"""Academy stays a thin, single-tenant assembly over dotmac-kernel."""

from __future__ import annotations

import ast
from pathlib import Path

from dotmac_ui import static_dir
from fastapi.testclient import TestClient

from app.assembly import academy_feature, assembly
from app.config import ACADEMY_CONTENT_SECURITY_POLICY
from app.main import app
from app.ui import UI_STYLESHEET_URL

ROOT = Path(__file__).resolve().parents[2]


def test_main_does_not_construct_fastapi_or_register_runtime_controls() -> None:
    tree = ast.parse((ROOT / "app" / "main.py").read_text(encoding="utf-8"))
    calls = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert "FastAPI" not in calls
    assert "add_middleware" not in calls
    assert "include_router" not in calls


def test_assembly_declares_academy_domain_without_claiming_migration_lineage() -> None:
    assert assembly.name == "dotmac_academy_app"
    assert assembly.tenancy == "single"
    assert assembly.platform_surface_enabled is False
    assert assembly.modules == (academy_feature,)
    assert academy_feature.name == "academy"
    assert assembly.startup_checks
    assert assembly.startup_hooks
    assert assembly.security_policy.content_security_policy == ACADEMY_CONTENT_SECURITY_POLICY
    assert assembly.security_policy.cross_origin_opener_policy == "same-origin"
    assert assembly.security_policy.cross_origin_resource_policy == "same-origin"
    assert assembly.packaged_static_dirs == (static_dir(),)
    assert assembly.stylesheets == (UI_STYLESHEET_URL,)


def test_platform_url_is_not_an_online_control_plane(monkeypatch) -> None:
    monkeypatch.setattr(
        "dotmac_kernel.middleware.tenant.TenantResolverMiddleware._resolve",
        lambda _self, _host: None,
    )
    response = TestClient(app).get("/platform", headers={"host": "localhost"})
    assert response.status_code == 404


def test_runtime_has_no_pre_a38_compatibility_adapters() -> None:
    source = (ROOT / "app" / "kernel_runtime.py").read_text(encoding="utf-8")
    assert "original_router" not in source
    assert "kernel_settings" not in source
    assert "AcademyBrowserIsolationMiddleware" not in source


def test_kernel_applies_the_declared_product_browser_policy() -> None:
    response = TestClient(app).get("/health")
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"


def test_health_and_static_assets_do_not_resolve_a_tenant(monkeypatch) -> None:
    def _must_not_resolve(_self, _host):
        raise AssertionError("health/static must bypass the tenant store")

    monkeypatch.setattr(
        "dotmac_kernel.middleware.tenant.TenantResolverMiddleware._resolve",
        _must_not_resolve,
    )
    client = TestClient(app)
    assert client.get("/health", headers={"host": "unresolved.invalid"}).status_code == 200
    assert client.get("/static/htmx.min.js", headers={"host": "unresolved.invalid"}).status_code == 200


def test_kernel_owns_the_generic_middleware_stack() -> None:
    modules = {entry.cls.__module__ for entry in app.user_middleware}
    assert {
        "dotmac_kernel.middleware.csrf",
        "dotmac_kernel.middleware.observability",
        "dotmac_kernel.middleware.rate_limit",
        "dotmac_kernel.middleware.security_headers",
        "dotmac_kernel.middleware.tenant",
    } <= modules

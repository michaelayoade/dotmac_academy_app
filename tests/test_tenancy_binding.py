"""The single-tenant lockdown must actually be armed, not merely configured.

This exists because it once wasn't. ``TENANCY=single`` was set, but Academy
hand-built its lifespan and therefore never ran the kernel assertion. These
tests exercise the lifespan installed by ``create_app`` through Academy's real
ASGI app, so reading the setting without adopting the behavior cannot recur.

A control that is configured but not armed is worse than one that is absent:
the configuration is evidence that someone thought about it.
"""

from __future__ import annotations

import pytest
from dotmac_kernel.tenancy import clear_single_tenant_binding, single_tenant_binding
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(autouse=True)
def _unbound():
    clear_single_tenant_binding()
    yield
    clear_single_tenant_binding()


def test_single_tenancy_binds_at_startup(monkeypatch) -> None:
    """The property the outage lacked: after startup, the binding is set."""
    from dotmac_kernel.config import settings as kernel_settings

    monkeypatch.setattr(kernel_settings, "tenancy", "single", raising=False)
    monkeypatch.setattr(kernel_settings, "seed_on_startup", False, raising=False)
    monkeypatch.setattr("dotmac_kernel.app_factory._required_setting_errors", lambda: [], raising=False)
    monkeypatch.setattr("dotmac_kernel.db.resolver_session", _fake_resolver(["academy"]), raising=False)
    with TestClient(app):
        assert single_tenant_binding() == "academy"


def test_multi_tenancy_binds_nothing(monkeypatch) -> None:
    from dotmac_kernel.config import settings as kernel_settings

    monkeypatch.setattr(kernel_settings, "tenancy", "multi", raising=False)
    monkeypatch.setattr(kernel_settings, "seed_on_startup", False, raising=False)
    monkeypatch.setattr("dotmac_kernel.app_factory._required_setting_errors", lambda: [], raising=False)
    with TestClient(app):
        assert single_tenant_binding() is None


def test_two_tenants_is_fatal_and_binds_nothing(monkeypatch) -> None:
    """Refusing to boot is the point; binding one of two would pick a winner."""
    from dotmac_kernel.config import settings as kernel_settings

    monkeypatch.setattr(kernel_settings, "tenancy", "single", raising=False)
    monkeypatch.setattr(kernel_settings, "environment", "production", raising=False)
    monkeypatch.setattr(kernel_settings, "seed_on_startup", False, raising=False)
    monkeypatch.setattr("dotmac_kernel.app_factory.validate_settings", lambda _settings: [], raising=False)
    monkeypatch.setattr("dotmac_kernel.app_factory._required_setting_errors", lambda: [], raising=False)
    monkeypatch.setattr(
        "dotmac_kernel.db.resolver_session",
        _fake_resolver(["academy", "someone-else"]),
        raising=False,
    )
    with pytest.raises(RuntimeError, match="someone-else"):
        with TestClient(app):
            pass
    assert single_tenant_binding() is None


def _fake_resolver(slugs: list[str]):
    from contextlib import contextmanager

    class _T:
        def __init__(self, slug: str) -> None:
            self.slug = slug

    class _Q:
        def order_by(self, *_a):
            return self

        def all(self):
            return [_T(s) for s in slugs]

    class _S:
        def query(self, *_a):
            return _Q()

    @contextmanager
    def _r():
        yield _S()

    return _r

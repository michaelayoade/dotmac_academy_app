"""The single-tenant lockdown must actually be armed, not merely configured.

This exists because it once wasn't. `TENANCY=single` was set, config validation
demanded and got it, and everything looked right — while
`single_tenant_binding()` returned `None` and `TenantResolverMiddleware` passed
every tenant through. The kernel performs the assertion inside `create_app`'s
lifespan, and this app is built by hand, so none of it ran.

A control that is configured but not armed is worse than one that is absent:
the configuration is evidence that someone thought about it.
"""

from __future__ import annotations

import pytest
from dotmac_kernel.tenancy import clear_single_tenant_binding, single_tenant_binding

from app.main import _bind_single_tenant_or_fail


@pytest.fixture(autouse=True)
def _unbound():
    clear_single_tenant_binding()
    yield
    clear_single_tenant_binding()


def test_single_tenancy_binds_at_startup(admin_session, tenant_a, monkeypatch) -> None:
    """The property the outage lacked: after startup, the binding is set."""
    from dotmac_kernel.config import settings as kernel_settings

    monkeypatch.setattr(kernel_settings, "tenancy", "single", raising=False)
    monkeypatch.setattr(
        "dotmac_kernel.db.resolver_session", _fake_resolver(["academy"]), raising=False
    )
    assert _bind_single_tenant_or_fail() == []
    assert single_tenant_binding() == "academy"


def test_multi_tenancy_binds_nothing(monkeypatch) -> None:
    from dotmac_kernel.config import settings as kernel_settings

    monkeypatch.setattr(kernel_settings, "tenancy", "multi", raising=False)
    assert _bind_single_tenant_or_fail() == []
    assert single_tenant_binding() is None


def test_two_tenants_is_fatal_and_binds_nothing(monkeypatch) -> None:
    """Refusing to boot is the point; binding one of two would pick a winner."""
    from dotmac_kernel.config import settings as kernel_settings

    monkeypatch.setattr(kernel_settings, "tenancy", "single", raising=False)
    monkeypatch.setattr(
        "dotmac_kernel.db.resolver_session",
        _fake_resolver(["academy", "someone-else"]),
        raising=False,
    )
    errors = _bind_single_tenant_or_fail()
    assert len(errors) == 1
    assert "someone-else" in errors[0], "the message must name what it found"
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

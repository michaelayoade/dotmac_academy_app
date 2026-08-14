"""Test fixtures.

Two-tenant setup: every isolation test gets `tenant_a` and `tenant_b` and a
`client_for(tenant)` helper that issues requests against the right subdomain.

These tests REQUIRE a real Postgres with RLS — SQLite has no RLS. CI/dev should
spin up a disposable Postgres (testcontainers, docker compose, or a per-test schema).

This skeleton uses `os.getenv("TEST_DATABASE_URL")` — set it before running tests.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker


@pytest.fixture(scope="session")
def admin_engine():
    url = os.getenv("TEST_MIGRATION_DATABASE_URL") or os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set — these tests require a real Postgres")
    engine = create_engine(url, future=True)
    yield engine
    engine.dispose()


@pytest.fixture(autouse=True)
def _set_database_url(monkeypatch):
    """Pin DATABASE_URL for the app under test to the TEST_DATABASE_URL."""
    url = os.getenv("TEST_DATABASE_URL")
    if url:
        monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("PLATFORM_ROOT_DOMAIN", "localhost")


@pytest.fixture(autouse=True)
def _no_real_console_spawn(monkeypatch):
    """A test may never launch a real ttyd. Enforced globally, not per-test.

    ``provision`` calls :func:`app.services.lab_lifecycle.start_console`, which
    ``Popen``s a real ttyd whenever the binary is installed — so on any host that
    has ttyd, a provision test spawned a daemon that outlived the run, while the
    test's rollback removed the row that would have identified it. That is exactly
    how the academy host accumulated 14 orphaned consoles, 4 of them spinning at
    99% CPU for up to 15 days.

    Patching per-test is not enough: the tests that leaked were the ones that
    forgot to. This fixture makes forgetting harmless, and the default return of
    ``None`` matches "console unavailable", which ``provision`` already tolerates.
    Tests that exercise ``start_console`` itself patch ``subprocess.Popen``
    directly and are unaffected by this.
    """
    from app.services import lab_lifecycle

    monkeypatch.setattr(lab_lifecycle, "start_console", lambda cname, base_path: None)


@pytest.fixture
def admin_session(admin_engine) -> Generator[Session, None, None]:
    """Connection as app_admin — RLS bypassed. Used by fixtures to set up data."""
    SessionLocal = sessionmaker(bind=admin_engine, autocommit=False, autoflush=False)
    db = SessionLocal()
    try:
        yield db
        db.rollback()  # keep test DB clean — explicit commits required where needed
    finally:
        db.close()


@pytest.fixture
def app_user_session() -> Generator[Session, None, None]:
    """Connection as app_user for RLS visibility assertions."""
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set — these tests require a real Postgres")
    engine = create_engine(url, future=True)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = SessionLocal()
    try:
        yield db
        db.rollback()
    finally:
        db.close()
        engine.dispose()


def _make_tenant(admin_session: Session, slug: str, name: str):
    from app.models.tenant import Tenant

    # Self-heal: clear any aborted-transaction state and any leftover tenant with
    # this slug (from an interrupted run, or a prior test that left the session
    # aborted — psycopg silently ignores the teardown DELETE in that case, so the
    # row survives and the next test collides on the unique slug).
    admin_session.rollback()
    admin_session.execute(text("DELETE FROM tenants WHERE slug = :s"), {"s": slug})
    admin_session.commit()
    t = Tenant(slug=slug, name=name)
    admin_session.add(t)
    admin_session.commit()
    admin_session.refresh(t)
    return t


def _drop_tenant(admin_session: Session, t) -> None:
    admin_session.rollback()  # clear any aborted tx the test left behind
    admin_session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": str(t.id)})
    admin_session.commit()


@pytest.fixture
def tenant_a(admin_session: Session):
    t = _make_tenant(admin_session, "alpha", "Alpha Test Tenant")
    yield t
    _drop_tenant(admin_session, t)


@pytest.fixture
def tenant_b(admin_session: Session):
    t = _make_tenant(admin_session, "beta", "Beta Test Tenant")
    yield t
    _drop_tenant(admin_session, t)


@pytest.fixture
def app_client():
    """TestClient that lets you set Host header per request."""
    from app.main import app

    return TestClient(app)


def client_for(client: TestClient, tenant_slug: str) -> TestClient:
    """Wrap a TestClient so every request carries Host: {slug}.localhost."""
    client.headers.update({"Host": f"{tenant_slug}.localhost"})
    return client


@pytest.fixture
def api_actor(admin_session):
    """Create a real tenant account and return its authenticated API context."""

    def _create(client: TestClient, tenant, *, role: str = "admin", email: str | None = None):
        from app.services.accounts import create_user

        password = "correct horse battery staple"
        email = email or f"{role}-{uuid4().hex[:10]}@test.example"
        admin_session.rollback()
        person = create_user(
            admin_session,
            tenant_id=tenant.id,
            email=email,
            first_name=role.title(),
            last_name="Tester",
            password=password,
            role=role,
        )
        admin_session.commit()
        admin_session.refresh(person)

        scoped = client_for(client, tenant.slug)
        response = scoped.post(
            "/auth/login",
            json={"email": email, "password": password},
        )
        assert response.status_code == 200, response.text
        token = response.json()["access_token"]
        return {
            "headers": {"Authorization": f"Bearer {token}"},
            "person": person,
            "token": token,
        }

    return _create

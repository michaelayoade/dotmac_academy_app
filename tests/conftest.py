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
    """Migration/superuser connection (postgres in CI), not the worker role.

    Bound to ``TEST_MIGRATION_DATABASE_URL`` (falling back to
    ``TEST_DATABASE_URL``), which in CI authenticates as the ``postgres``
    superuser used to run migrations — it is not RLS-bypassed via the
    ``app_admin`` role. Dedicated worker privilege tests use the separate
    ``lab_worker_engine``/``lab_worker_session`` fixtures below.
    """
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
    """Migration/superuser session used by fixtures to set up cross-tenant data.

    Bound to ``admin_engine`` — see that fixture's docstring: this is the
    migration/superuser connection, not an ``app_admin`` connection.
    """
    SessionLocal = sessionmaker(bind=admin_engine, autocommit=False, autoflush=False)
    db = SessionLocal()
    try:
        yield db
        db.rollback()  # keep test DB clean — explicit commits required where needed
    finally:
        db.close()


@pytest.fixture(scope="session")
def lab_worker_engine():
    """Real ``academy_lab_worker`` engine, bound exclusively to the test DSN.

    Skips cleanly when the env var is absent so local dev without a lab-worker
    DSN configured is unaffected. Deliberately does NOT fall back to
    ``TEST_MIGRATION_DATABASE_URL``/``TEST_DATABASE_URL`` like ``admin_engine``
    does — this fixture's whole purpose is to guarantee the connection actually
    authenticates as ``academy_lab_worker``, so a silent fallback to another role would
    defeat it.
    """
    url = os.getenv("TEST_LAB_WORKER_DATABASE_URL")
    if not url:
        pytest.skip("TEST_LAB_WORKER_DATABASE_URL not set — lab-worker privilege tests skipped")
    engine = create_engine(url, future=True)
    with engine.connect() as conn:
        current_user = conn.execute(text("SELECT current_user")).scalar()
        if current_user != "academy_lab_worker":
            raise AssertionError(
                f"TEST_LAB_WORKER_DATABASE_URL authenticated as {current_user!r}, not academy_lab_worker"
            )
        bypassrls = conn.execute(
            text("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'academy_lab_worker'")
        ).scalar()
        if not bypassrls:
            raise AssertionError("academy_lab_worker role does not have rolbypassrls = true")
        safe_posture = conn.execute(
            text(
                """SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
                    AND NOT rolreplication AND NOT rolinherit
                    AND NOT EXISTS (
                        SELECT 1 FROM pg_auth_members m
                        WHERE m.member = r.oid OR m.roleid = r.oid
                    )
                FROM pg_roles r
                WHERE r.rolname = 'academy_lab_worker'"""
            )
        ).scalar()
        if not safe_posture:
            raise AssertionError("academy_lab_worker has unsafe attributes or memberships")
        owns = conn.execute(
            text(
                """SELECT EXISTS (
                    SELECT 1 FROM pg_database
                    WHERE datname = current_database()
                      AND pg_get_userbyid(datdba) = 'academy_lab_worker'
                ) OR EXISTS (
                    SELECT 1 FROM pg_namespace
                    WHERE pg_get_userbyid(nspowner) = 'academy_lab_worker'
                      AND nspname NOT IN ('pg_catalog', 'information_schema')
                      AND nspname NOT LIKE 'pg_toast%'
                ) OR EXISTS (
                    SELECT 1 FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE pg_get_userbyid(c.relowner) = 'academy_lab_worker'
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND n.nspname NOT LIKE 'pg_toast%'
                      AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
                )"""
            )
        ).scalar()
        if owns:
            raise AssertionError("academy_lab_worker must not own database, schema, or application relations")
    yield engine
    engine.dispose()


@pytest.fixture
def lab_worker_session(lab_worker_engine) -> Generator[Session, None, None]:
    """Real dedicated worker session for asserting the live ACL matrix."""
    SessionLocal = sessionmaker(bind=lab_worker_engine, autocommit=False, autoflush=False)
    db = SessionLocal()
    try:
        yield db
        db.rollback()
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

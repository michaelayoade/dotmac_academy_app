"""Durable account lockout policy through the real login transaction boundary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.models.auth import UserCredential
from app.services.accounts import create_user
from tests.conftest import client_for


def test_repeated_failures_lock_account_and_success_resets_counter(
    app_client,
    admin_session,
    tenant_a,
):
    password = "correct horse battery staple"
    person = create_user(
        admin_session,
        tenant_id=tenant_a.id,
        email="locked@example.com",
        first_name="Locked",
        last_name="User",
        password=password,
        role="student",
    )
    admin_session.commit()
    client = client_for(app_client, tenant_a.slug)

    for _ in range(5):
        response = client.post(
            "/auth/login",
            json={"email": person.email, "password": "wrong-password"},
        )
        assert response.status_code == 401

    admin_session.rollback()
    credential = admin_session.scalars(
        select(UserCredential)
        .where(UserCredential.tenant_id == tenant_a.id)
        .where(UserCredential.person_id == person.id)
    ).one()
    assert credential.failed_login_attempts == 5
    assert credential.locked_until is not None
    assert credential.locked_until > datetime.now(UTC)

    # Correct credentials remain neutral while the lock is active.
    assert (
        client.post(
            "/auth/login",
            json={"email": person.email, "password": password},
        ).status_code
        == 401
    )

    credential.locked_until = datetime.now(UTC) - timedelta(seconds=1)
    admin_session.commit()
    success = client.post(
        "/auth/login",
        json={"email": person.email, "password": password},
    )
    assert success.status_code == 200

    admin_session.rollback()
    admin_session.refresh(credential)
    assert credential.failed_login_attempts == 0
    assert credential.locked_until is None

"""Account lifecycle service: password reset + invitations (Slice 3b)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.models.auth import UserCredential
from app.models.person import Person
from app.services.exceptions import BadRequestError, ConflictError
from app.services.lifecycle import (
    accept_invite,
    invite_user,
    request_password_reset,
    reset_password,
    set_account_status,
)
from app.services.security import hash_password, verify_password
from app.services.web_auth import authenticate


def _account(db, tid, email="u@a.edu", pw="origpass1"):
    p = Person(tenant_id=tid, email=email, first_name="U", last_name="X")
    db.add(p)
    db.flush()
    db.add(UserCredential(tenant_id=tid, person_id=p.id, email=email,
                          password_hash=hash_password(pw)))
    db.flush()
    return p


def test_password_reset_round_trip(admin_session, tenant_a):
    tid = tenant_a.id
    p = _account(admin_session, tid)
    raw = request_password_reset(admin_session, tenant_id=tid, email="U@a.edu")
    assert raw is not None
    reset_password(admin_session, tenant_id=tid, raw=raw, new_password="brandnew9")

    cred = admin_session.scalars(
        __import__("sqlalchemy").select(UserCredential)
        .where(UserCredential.person_id == p.id)
    ).first()
    assert verify_password("brandnew9", cred.password_hash)
    assert not verify_password("origpass1", cred.password_hash)

    # Token is single-use.
    with pytest.raises(BadRequestError):
        reset_password(admin_session, tenant_id=tid, raw=raw, new_password="another9x")
    admin_session.rollback()


def test_password_reset_unknown_email_returns_none(admin_session, tenant_a):
    raw = request_password_reset(admin_session, tenant_id=tenant_a.id, email="nobody@a.edu")
    assert raw is None
    admin_session.rollback()


def test_reset_rejects_expired_token(admin_session, tenant_a):
    tid = tenant_a.id
    _account(admin_session, tid)
    past = datetime.now(UTC) - timedelta(hours=10)
    raw = request_password_reset(admin_session, tenant_id=tid, email="u@a.edu", now=past)
    with pytest.raises(BadRequestError):
        reset_password(admin_session, tenant_id=tid, raw=raw, new_password="brandnew9")
    admin_session.rollback()


def test_invite_then_accept_creates_credential(admin_session, tenant_a):
    tid = tenant_a.id
    person, token = invite_user(admin_session, tenant_id=tid, email="new@a.edu",
                                first_name="Ne", last_name="W", role="student")
    # No credential yet.
    assert admin_session.scalars(
        __import__("sqlalchemy").select(UserCredential)
        .where(UserCredential.person_id == person.id)).first() is None

    accept_invite(admin_session, tenant_id=tid, raw=token, password="welcome12")
    cred = admin_session.scalars(
        __import__("sqlalchemy").select(UserCredential)
        .where(UserCredential.person_id == person.id)).first()
    assert cred is not None and verify_password("welcome12", cred.password_hash)

    # Invite token is single-use.
    with pytest.raises(BadRequestError):
        accept_invite(admin_session, tenant_id=tid, raw=token, password="welcome12")
    admin_session.rollback()


def test_suspended_account_cannot_authenticate(admin_session, tenant_a):
    tid = tenant_a.id
    p = _account(admin_session, tid, email="susp@a.edu", pw="origpass1")
    # Active → authenticates.
    assert authenticate(admin_session, tid, "susp@a.edu", "origpass1") is not None
    # Suspend → blocked even with correct password.
    set_account_status(admin_session, tenant_id=tid, person_id=p.id, status="suspended")
    assert authenticate(admin_session, tid, "susp@a.edu", "origpass1") is None
    # Reactivate → allowed again.
    set_account_status(admin_session, tenant_id=tid, person_id=p.id, status="active")
    assert authenticate(admin_session, tid, "susp@a.edu", "origpass1") is not None
    admin_session.rollback()


def test_invite_existing_email_conflicts(admin_session, tenant_a):
    tid = tenant_a.id
    _account(admin_session, tid, email="dup@a.edu")
    with pytest.raises(ConflictError):
        invite_user(admin_session, tenant_id=tid, email="dup@a.edu",
                    first_name="D", last_name="U", role="student")
    admin_session.rollback()

"""Account lifecycle service: password reset + invitations (Slice 3b)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.models.account_token import AccountToken
from app.models.auth import AuthSession, UserCredential
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
from app.services.web_auth import authenticate, start_session


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


def test_password_reset_credentialless_invitee_returns_none(admin_session, tenant_a):
    person = Person(
        tenant_id=tenant_a.id,
        email="invited@a.edu",
        first_name="Invited",
        last_name="Learner",
    )
    admin_session.add(person)
    admin_session.flush()

    assert (
        request_password_reset(
            admin_session,
            tenant_id=tenant_a.id,
            email=" invited@A.EDU ",
        )
        is None
    )
    admin_session.rollback()


def test_password_reset_updates_all_credentials_for_person(admin_session, tenant_a):
    tid = tenant_a.id
    email = f"u-{uuid4().hex}@a.edu"
    old_password = f"old-{uuid4().hex}"
    new_password = f"new-{uuid4().hex}"
    stale_password = f"stale-{uuid4().hex}"
    person = _account(admin_session, tid, email=email, pw=old_password)
    stale = UserCredential(
        tenant_id=tid,
        person_id=person.id,
        email=f"stale-{uuid4().hex}@a.edu",
        password_hash=hash_password(stale_password),
    )
    admin_session.add(stale)
    admin_session.flush()

    raw = request_password_reset(admin_session, tenant_id=tid, email=email)
    assert raw is not None
    reset_password(admin_session, tenant_id=tid, raw=raw, new_password=new_password)

    credentials = admin_session.scalars(
        __import__("sqlalchemy").select(UserCredential)
        .where(UserCredential.tenant_id == tid)
        .where(UserCredential.person_id == person.id)
    ).all()
    assert len(credentials) == 2
    assert all(verify_password(new_password, cred.password_hash) for cred in credentials)
    assert all(not verify_password(old_password, cred.password_hash) for cred in credentials)
    assert all(not verify_password(stale_password, cred.password_hash) for cred in credentials)
    admin_session.rollback()


def test_reset_rejects_expired_token(admin_session, tenant_a):
    tid = tenant_a.id
    _account(admin_session, tid)
    past = datetime.now(UTC) - timedelta(hours=10)
    raw = request_password_reset(admin_session, tenant_id=tid, email="u@a.edu", now=past)
    with pytest.raises(BadRequestError):
        reset_password(admin_session, tenant_id=tid, raw=raw, new_password="brandnew9")
    admin_session.rollback()


def test_reset_clears_lockout_revokes_sessions_and_invalidates_other_tokens(admin_session, tenant_a):
    tid = tenant_a.id
    person = _account(admin_session, tid, email="locked-reset@a.edu")
    credential = admin_session.scalars(
        __import__("sqlalchemy").select(UserCredential).where(UserCredential.person_id == person.id)
    ).one()
    credential.failed_login_attempts = 5
    credential.locked_until = datetime.now(UTC) + timedelta(minutes=15)
    start_session(admin_session, tid, person.id)
    stale_token = request_password_reset(
        admin_session,
        tenant_id=tid,
        email=" LOCKED-RESET@A.EDU ",
    )
    current_token = request_password_reset(admin_session, tenant_id=tid, email="locked-reset@a.edu")
    assert stale_token is not None
    assert current_token is not None

    reset_password(admin_session, tenant_id=tid, raw=current_token, new_password="unlocked-password")

    assert credential.failed_login_attempts == 0
    assert credential.locked_until is None
    sessions = admin_session.scalars(
        __import__("sqlalchemy").select(AuthSession).where(AuthSession.person_id == person.id)
    ).all()
    assert sessions and all(session.revoked_at is not None for session in sessions)
    tokens = admin_session.scalars(
        __import__("sqlalchemy")
        .select(AccountToken)
        .where(AccountToken.person_id == person.id)
        .where(AccountToken.kind == "password_reset")
    ).all()
    assert len(tokens) == 2
    assert all(token.used_at is not None for token in tokens)
    with pytest.raises(BadRequestError):
        reset_password(admin_session, tenant_id=tid, raw=stale_token, new_password="another-password")
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

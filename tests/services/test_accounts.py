"""TDD tests for the account-creation service (app/services/accounts.py)."""

from __future__ import annotations

import pytest

from app.models.auth import UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole, Role
from app.services.accounts import create_user
from app.services.security import verify_password


def _cleanup(admin_session, tenant_id):
    admin_session.query(UserCredential).filter(UserCredential.tenant_id == tenant_id).delete()
    admin_session.query(PersonRole).filter(PersonRole.tenant_id == tenant_id).delete()
    admin_session.query(Person).filter(Person.tenant_id == tenant_id).delete()
    admin_session.query(Role).filter(Role.tenant_id == tenant_id).delete()
    admin_session.commit()


def test_create_user_makes_person_credential_and_role(admin_session, tenant_a):
    person = create_user(
        admin_session,
        tenant_id=tenant_a.id,
        email="newstudent@a.edu",
        first_name="New",
        last_name="Student",
        password="password1",
        role="student",
    )
    admin_session.commit()

    # Person created and tenant-scoped.
    assert person.tenant_id == tenant_a.id
    db_person = admin_session.query(Person).filter(
        Person.tenant_id == tenant_a.id, Person.email == "newstudent@a.edu"
    ).one()
    assert db_person.id == person.id

    # Credential created and verifies against the plaintext password.
    cred = admin_session.query(UserCredential).filter(
        UserCredential.tenant_id == tenant_a.id, UserCredential.person_id == person.id
    ).one()
    assert cred.password_hash != "password1"
    assert verify_password("password1", cred.password_hash)

    # Student role exists for the tenant and is granted to the person.
    student_role = admin_session.query(Role).filter(
        Role.tenant_id == tenant_a.id, Role.slug == "student"
    ).one()
    grant = admin_session.query(PersonRole).filter(
        PersonRole.tenant_id == tenant_a.id, PersonRole.person_id == person.id
    ).one()
    assert grant.role_id == student_role.id

    _cleanup(admin_session, tenant_a.id)


def test_create_user_duplicate_email_raises(admin_session, tenant_a):
    create_user(
        admin_session,
        tenant_id=tenant_a.id,
        email="dupe@a.edu",
        first_name="A",
        last_name="B",
        password="password1",
        role="student",
    )
    admin_session.flush()
    with pytest.raises(ValueError):
        create_user(
            admin_session,
            tenant_id=tenant_a.id,
            email="dupe@a.edu",
            first_name="C",
            last_name="D",
            password="password2",
            role="instructor",
        )
    admin_session.rollback()
    _cleanup(admin_session, tenant_a.id)


def test_create_user_invalid_role_raises(admin_session, tenant_a):
    with pytest.raises(ValueError):
        create_user(
            admin_session,
            tenant_id=tenant_a.id,
            email="bad@a.edu",
            first_name="A",
            last_name="B",
            password="password1",
            role="superuser",
        )
    admin_session.rollback()
    _cleanup(admin_session, tenant_a.id)

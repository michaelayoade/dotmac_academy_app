"""Regression coverage for the shared account invitation/enrolment owner."""

from __future__ import annotations

from sqlalchemy import func, select

from app.models.account_token import AccountToken
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.person import Person
from app.services.account_invitations import CohortAssignment, invite_and_enroll
from app.services.security import hash_password


def _cohort(db, tenant_id):
    cohort = Cohort(
        tenant_id=tenant_id,
        name="Invitation Cohort",
        discipline="networking",
        status="active",
    )
    db.add(cohort)
    db.flush()
    return cohort


def test_new_user_invitation_is_canonical_and_enrolled(admin_session, tenant_a):
    cohort = _cohort(admin_session, tenant_a.id)

    result = invite_and_enroll(
        admin_session,
        tenant_id=tenant_a.id,
        email="  NEW.Student@Example.COM ",
        first_name="New",
        last_name="Student",
        role="student",
        assignments=(CohortAssignment(cohort=cohort),),
    )

    assert result.created_person is True
    assert result.had_credential is False
    assert result.token is not None
    assert result.person.email == "new.student@example.com"
    assert (
        admin_session.scalar(
            select(func.count())
            .select_from(Enrollment)
            .where(Enrollment.person_id == result.person.id)
            .where(Enrollment.cohort_id == cohort.id)
        )
        == 1
    )
    admin_session.rollback()


def test_existing_user_without_credentials_is_reinvited_idempotently(admin_session, tenant_a):
    cohort = _cohort(admin_session, tenant_a.id)
    person = Person(
        tenant_id=tenant_a.id,
        email="pending@example.com",
        first_name="Pending",
        last_name="Student",
    )
    admin_session.add(person)
    admin_session.flush()

    first = invite_and_enroll(
        admin_session,
        tenant_id=tenant_a.id,
        email=" PENDING@EXAMPLE.COM ",
        first_name="Ignored",
        last_name="Ignored",
        role="student",
        assignments=(CohortAssignment(cohort=cohort),),
    )
    second = invite_and_enroll(
        admin_session,
        tenant_id=tenant_a.id,
        email="pending@example.com",
        first_name="Ignored",
        last_name="Ignored",
        role="student",
        assignments=(CohortAssignment(cohort=cohort),),
    )

    assert first.person.id == person.id == second.person.id
    assert first.token is not None and second.token is not None and first.token != second.token
    assert (
        admin_session.scalar(
            select(func.count())
            .select_from(Person)
            .where(Person.tenant_id == tenant_a.id)
            .where(func.lower(func.btrim(Person.email)) == "pending@example.com")
        )
        == 1
    )
    assert (
        admin_session.scalar(
            select(func.count())
            .select_from(Enrollment)
            .where(Enrollment.person_id == person.id)
            .where(Enrollment.cohort_id == cohort.id)
        )
        == 1
    )
    tokens = admin_session.scalars(
        select(AccountToken)
        .where(AccountToken.person_id == person.id)
        .where(AccountToken.kind == "invite")
        .order_by(AccountToken.created_at)
    ).all()
    assert len(tokens) == 2
    assert sum(token.used_at is None for token in tokens) == 1
    admin_session.rollback()


def test_existing_user_with_credentials_is_enrolled_without_activation(admin_session, tenant_a):
    cohort = _cohort(admin_session, tenant_a.id)
    person = Person(
        tenant_id=tenant_a.id,
        email="member@example.com",
        first_name="Existing",
        last_name="Member",
    )
    admin_session.add(person)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant_a.id,
            person_id=person.id,
            email="member@example.com",
            password_hash=hash_password("existing-password"),
        )
    )
    admin_session.flush()

    result = invite_and_enroll(
        admin_session,
        tenant_id=tenant_a.id,
        email=" MEMBER@example.com ",
        first_name="Existing",
        last_name="Member",
        role="student",
        assignments=(CohortAssignment(cohort=cohort),),
    )
    repeated = invite_and_enroll(
        admin_session,
        tenant_id=tenant_a.id,
        email="member@example.com",
        first_name="Existing",
        last_name="Member",
        role="student",
        assignments=(CohortAssignment(cohort=cohort),),
    )

    assert result.person.id == person.id == repeated.person.id
    assert result.had_credential is True
    assert result.token is None and repeated.token is None
    assert (
        admin_session.scalar(
            select(func.count())
            .select_from(Enrollment)
            .where(Enrollment.person_id == person.id)
            .where(Enrollment.cohort_id == cohort.id)
        )
        == 1
    )
    assert (
        admin_session.scalar(
            select(func.count())
            .select_from(AccountToken)
            .where(AccountToken.person_id == person.id)
            .where(AccountToken.kind == "invite")
        )
        == 0
    )
    admin_session.rollback()


def test_already_enrolled_user_is_reactivated_without_duplicate(admin_session, tenant_a):
    cohort = _cohort(admin_session, tenant_a.id)
    person = Person(
        tenant_id=tenant_a.id,
        email="returning@example.com",
        first_name="Returning",
        last_name="Student",
    )
    admin_session.add(person)
    admin_session.flush()
    enrollment = Enrollment(
        tenant_id=tenant_a.id,
        cohort_id=cohort.id,
        person_id=person.id,
        role_in_cohort="student",
        status="dropped",
    )
    admin_session.add(enrollment)
    admin_session.flush()

    invite_and_enroll(
        admin_session,
        tenant_id=tenant_a.id,
        email=person.email,
        first_name=person.first_name,
        last_name=person.last_name,
        role="student",
        assignments=(CohortAssignment(cohort=cohort),),
    )

    assert enrollment.status == "active"
    assert (
        admin_session.scalar(
            select(func.count())
            .select_from(Enrollment)
            .where(Enrollment.person_id == person.id)
            .where(Enrollment.cohort_id == cohort.id)
        )
        == 1
    )
    admin_session.rollback()

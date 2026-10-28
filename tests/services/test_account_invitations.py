"""Regression coverage for the shared account invitation/enrolment owner."""

from __future__ import annotations

import pytest
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
        actor_is_admin=True,
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
        actor_is_admin=True,
        assignments=(CohortAssignment(cohort=cohort),),
    )
    second = invite_and_enroll(
        admin_session,
        tenant_id=tenant_a.id,
        email="pending@example.com",
        first_name="Ignored",
        last_name="Ignored",
        role="student",
        actor_is_admin=True,
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
        actor_is_admin=True,
        assignments=(CohortAssignment(cohort=cohort),),
    )
    repeated = invite_and_enroll(
        admin_session,
        tenant_id=tenant_a.id,
        email="member@example.com",
        first_name="Existing",
        last_name="Member",
        role="student",
        actor_is_admin=True,
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
        # A student-role enrollment reactivates for any instructor, admin or
        # not — actor_is_admin=False proves this case is never gated.
        actor_is_admin=False,
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


def test_reactivation_description_names_the_prior_status(admin_session, tenant_a):
    """The description string _apply_assignment returns must distinguish a
    reactivation from a genuinely new enrollment — this is what makes the
    reactivation visible on the invite_to_cohort web surface at all."""
    cohort = _cohort(admin_session, tenant_a.id)
    person = Person(
        tenant_id=tenant_a.id,
        email="was-waitlisted@example.com",
        first_name="Was",
        last_name="Waitlisted",
    )
    admin_session.add(person)
    admin_session.flush()
    enrollment = Enrollment(
        tenant_id=tenant_a.id,
        cohort_id=cohort.id,
        person_id=person.id,
        role_in_cohort="student",
        status="waitlisted",
    )
    admin_session.add(enrollment)
    admin_session.flush()

    result = invite_and_enroll(
        admin_session,
        tenant_id=tenant_a.id,
        email=person.email,
        first_name=person.first_name,
        last_name=person.last_name,
        role="student",
        actor_is_admin=False,
        assignments=(CohortAssignment(cohort=cohort),),
    )

    assert any("reactivated (was waitlisted)" in item for item in result.assignments)
    admin_session.rollback()


def test_invite_and_enroll_never_downgrades_an_existing_instructor_to_student(admin_session, tenant_a):
    """Fix 2: /invite and /enroll (and the admin Users page's invite path,
    which shares this same function) must never silently demote an existing
    cohort instructor to student — unconditionally, no opt-out."""
    cohort = _cohort(admin_session, tenant_a.id)
    person = Person(
        tenant_id=tenant_a.id,
        email="instructor@example.com",
        first_name="Existing",
        last_name="Instructor",
    )
    admin_session.add(person)
    admin_session.flush()
    enrollment = Enrollment(
        tenant_id=tenant_a.id,
        cohort_id=cohort.id,
        person_id=person.id,
        role_in_cohort="instructor",
        status="active",
    )
    admin_session.add(enrollment)
    admin_session.flush()

    result = invite_and_enroll(
        admin_session,
        tenant_id=tenant_a.id,
        email=person.email,
        first_name=person.first_name,
        last_name=person.last_name,
        role="student",  # would normally resolve member_role="student"
        # Already active (no status transition here), so this is not gated
        # even for a non-admin actor — proves the gate is about REACTIVATION,
        # not the role preservation itself.
        actor_is_admin=False,
        assignments=(CohortAssignment(cohort=cohort),),
    )

    assert enrollment.role_in_cohort == "instructor"  # NOT demoted
    assert enrollment.status == "active"  # the status line is untouched/still runs
    assert any("already an instructor, role unchanged" in item for item in result.assignments)
    admin_session.rollback()


def test_apply_assignment_direct_call_preserves_instructor_role(admin_session, tenant_a):
    """Same guarantee exercised directly against _apply_assignment (the single
    function both the instructor route and the admin Users route share).

    actor_is_admin=True here: this test specifically checks that an ADMIN
    preserves the instructor role while reactivating a dropped instructor
    enrollment — that is still the correct, allowed behavior. A non-admin
    performing this same scenario is refused; see the sibling test below.
    """
    from app.services.account_invitations import _apply_assignment

    cohort = _cohort(admin_session, tenant_a.id)
    person = Person(
        tenant_id=tenant_a.id,
        email="direct-instructor@example.com",
        first_name="Direct",
        last_name="Instructor",
    )
    admin_session.add(person)
    admin_session.flush()
    enrollment = Enrollment(
        tenant_id=tenant_a.id,
        cohort_id=cohort.id,
        person_id=person.id,
        role_in_cohort="instructor",
        status="dropped",
    )
    admin_session.add(enrollment)
    admin_session.flush()

    descriptions = _apply_assignment(
        admin_session,
        tenant_id=tenant_a.id,
        person=person,
        role="student",
        assignment=CohortAssignment(cohort=cohort),
        actor_is_admin=True,
    )

    assert enrollment.role_in_cohort == "instructor"
    assert enrollment.status == "active"
    assert any("already an instructor, role unchanged" in item for item in descriptions)
    admin_session.rollback()


def test_apply_assignment_direct_call_refuses_non_admin_reactivating_instructor(admin_session, tenant_a):
    """The mirror of the test above: a non-admin actor may NOT reactivate a
    dropped instructor-role enrollment through _apply_assignment — this is
    exactly the privilege-restoration gap this fix closes. The enrollment's
    status must be left unchanged (still "dropped") after the refusal."""
    from app.services.account_invitations import _apply_assignment
    from app.services.exceptions import BadRequestError

    cohort = _cohort(admin_session, tenant_a.id)
    person = Person(
        tenant_id=tenant_a.id,
        email="non-admin-instructor@example.com",
        first_name="NonAdmin",
        last_name="Instructor",
    )
    admin_session.add(person)
    admin_session.flush()
    enrollment = Enrollment(
        tenant_id=tenant_a.id,
        cohort_id=cohort.id,
        person_id=person.id,
        role_in_cohort="instructor",
        status="dropped",
    )
    admin_session.add(enrollment)
    admin_session.flush()

    with pytest.raises(BadRequestError):
        _apply_assignment(
            admin_session,
            tenant_id=tenant_a.id,
            person=person,
            role="student",
            assignment=CohortAssignment(cohort=cohort),
            actor_is_admin=False,
        )

    assert enrollment.role_in_cohort == "instructor"
    assert enrollment.status == "dropped"
    admin_session.rollback()


def test_apply_assignment_still_sets_role_for_a_genuinely_new_student(admin_session, tenant_a):
    """Sanity check for the fix's near-miss: a brand-new enrollment (no
    existing instructor role) still gets member_role set normally."""
    from app.services.account_invitations import _apply_assignment

    cohort = _cohort(admin_session, tenant_a.id)
    person = Person(
        tenant_id=tenant_a.id,
        email="brand-new@example.com",
        first_name="Brand",
        last_name="New",
    )
    admin_session.add(person)
    admin_session.flush()

    descriptions = _apply_assignment(
        admin_session,
        tenant_id=tenant_a.id,
        person=person,
        role="student",
        assignment=CohortAssignment(cohort=cohort),
        # Brand-new enrollment: activate_enrollment is never reached, so this
        # value is inert here — passed because the signature has no default.
        actor_is_admin=False,
    )
    # _apply_assignment itself never flushes (invite_and_enroll does, once,
    # after all assignments) — flush here since this test calls it directly.
    admin_session.flush()

    enrollment = admin_session.scalars(
        select(Enrollment).where(Enrollment.cohort_id == cohort.id).where(Enrollment.person_id == person.id)
    ).first()
    assert enrollment.role_in_cohort == "student"
    assert descriptions == [f"{cohort.name} cohort as student"]
    admin_session.rollback()

"""Roster service: bulk enroll + roster-state transitions (Slice 3a)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.cohort import Cohort, Enrollment
from app.models.person import Person
from app.services.exceptions import NotFoundError
from app.services.roster import bulk_enroll, set_roster_state


def _cohort(db, tid):
    coh = Cohort(tenant_id=tid, name="C", discipline="networking", status="active")
    db.add(coh)
    db.flush()
    return coh


def _person(db, tid, email):
    p = Person(tenant_id=tid, email=email, first_name="P", last_name="X")
    db.add(p)
    db.flush()
    return p


def test_bulk_enroll_reports_each_email(admin_session, tenant_a):
    tid = tenant_a.id
    coh = _cohort(admin_session, tid)
    _person(admin_session, tid, "a@x.edu")
    _person(admin_session, tid, "b@x.edu")

    res = bulk_enroll(admin_session, tenant_id=tid, cohort_id=coh.id,
                      emails=["a@x.edu", "B@x.edu", "ghost@x.edu", "a@x.edu"], actor_is_admin=False)
    assert sorted(res["enrolled"]) == ["a@x.edu", "b@x.edu"]  # dedup + case-insensitive
    assert res["not_found"] == ["ghost@x.edu"]

    n = admin_session.query(Enrollment).filter(
        Enrollment.tenant_id == tid, Enrollment.cohort_id == coh.id,
        Enrollment.status == "active").count()
    assert n == 2

    # Idempotent re-run reports already_active.
    res2 = bulk_enroll(admin_session, tenant_id=tid, cohort_id=coh.id, emails=["a@x.edu"], actor_is_admin=False)
    assert res2["already_active"] == ["a@x.edu"]
    admin_session.rollback()


def test_set_roster_state_drop_and_reactivate(admin_session, tenant_a):
    tid = tenant_a.id
    coh = _cohort(admin_session, tid)
    p = _person(admin_session, tid, "c@x.edu")
    bulk_enroll(admin_session, tenant_id=tid, cohort_id=coh.id, emails=["c@x.edu"], actor_is_admin=False)

    set_roster_state(admin_session, tenant_id=tid, cohort_id=coh.id, person_id=p.id, state="dropped")
    enr = admin_session.scalars(
        __import__("sqlalchemy").select(Enrollment)
        .where(Enrollment.cohort_id == coh.id).where(Enrollment.person_id == p.id)
    ).first()
    assert enr.status == "dropped"

    # bulk_enroll reactivates a dropped STUDENT member regardless of
    # actor_is_admin — the admin gate only applies to non-student enrollments.
    res = bulk_enroll(admin_session, tenant_id=tid, cohort_id=coh.id, emails=["c@x.edu"], actor_is_admin=False)
    assert res["reactivated"] == ["c@x.edu"]
    admin_session.rollback()


def test_invalid_state_and_missing_enrollment_raise(admin_session, tenant_a):
    tid = tenant_a.id
    coh = _cohort(admin_session, tid)
    p = _person(admin_session, tid, "d@x.edu")
    with pytest.raises(NotFoundError):
        set_roster_state(admin_session, tenant_id=tid, cohort_id=coh.id, person_id=p.id, state="bogus")
    with pytest.raises(NotFoundError):
        set_roster_state(admin_session, tenant_id=tid, cohort_id=coh.id, person_id=p.id, state="dropped")
    admin_session.rollback()


def test_bulk_enroll_reactivating_non_student_enrollment_is_admin_gated(admin_session, tenant_a):
    """The privilege-restoration gap this fix closes: bulk_enroll must refuse
    to reactivate a dropped non-student (e.g. instructor-role) enrollment for
    a non-admin actor — categorized into "admin_required" (bulk_enroll's
    existing per-email-outcome contract, matching "not_found"), NOT a raised
    exception — and succeed (categorized "reactivated") for an admin actor."""
    tid = tenant_a.id
    coh = _cohort(admin_session, tid)
    p = _person(admin_session, tid, "instr@x.edu")
    enrollment = Enrollment(
        tenant_id=tid, cohort_id=coh.id, person_id=p.id, role_in_cohort="instructor", status="dropped",
    )
    admin_session.add(enrollment)
    admin_session.flush()

    res = bulk_enroll(admin_session, tenant_id=tid, cohort_id=coh.id, emails=["instr@x.edu"], actor_is_admin=False)
    assert res["admin_required"] == ["instr@x.edu"]
    assert res["reactivated"] == []
    admin_session.refresh(enrollment)
    assert enrollment.status == "dropped"  # unchanged after the refusal

    res2 = bulk_enroll(admin_session, tenant_id=tid, cohort_id=coh.id, emails=["instr@x.edu"], actor_is_admin=True)
    assert res2["reactivated"] == ["instr@x.edu"]
    assert res2["admin_required"] == []
    admin_session.refresh(enrollment)
    assert enrollment.status == "active"
    admin_session.rollback()


def test_bulk_enroll_continues_batch_after_a_refused_reactivation(admin_session, tenant_a):
    """A refused reactivation for one email must not abort the rest of the
    same call's batch — proves no unintended abort-on-first-refusal behavior."""
    tid = tenant_a.id
    coh = _cohort(admin_session, tid)
    peer = _person(admin_session, tid, "peer@x.edu")
    fresh = _person(admin_session, tid, "fresh@x.edu")
    enrollment = Enrollment(
        tenant_id=tid, cohort_id=coh.id, person_id=peer.id, role_in_cohort="instructor", status="dropped",
    )
    admin_session.add(enrollment)
    admin_session.flush()

    res = bulk_enroll(
        admin_session, tenant_id=tid, cohort_id=coh.id,
        emails=["peer@x.edu", "fresh@x.edu"], actor_is_admin=False,
    )
    assert res["admin_required"] == ["peer@x.edu"]
    assert res["enrolled"] == ["fresh@x.edu"]

    admin_session.refresh(enrollment)
    assert enrollment.status == "dropped"  # refused, unchanged
    fresh_enr = admin_session.scalars(
        select(Enrollment).where(Enrollment.cohort_id == coh.id).where(Enrollment.person_id == fresh.id)
    ).first()
    assert fresh_enr is not None and fresh_enr.status == "active"  # rest of the batch still applied
    admin_session.rollback()

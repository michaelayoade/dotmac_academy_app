"""Roster service: bulk enroll + roster-state transitions (Slice 3a)."""

from __future__ import annotations

import pytest

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
                      emails=["a@x.edu", "B@x.edu", "ghost@x.edu", "a@x.edu"])
    assert sorted(res["enrolled"]) == ["a@x.edu", "b@x.edu"]  # dedup + case-insensitive
    assert res["not_found"] == ["ghost@x.edu"]

    n = admin_session.query(Enrollment).filter(
        Enrollment.tenant_id == tid, Enrollment.cohort_id == coh.id,
        Enrollment.status == "active").count()
    assert n == 2

    # Idempotent re-run reports already_active.
    res2 = bulk_enroll(admin_session, tenant_id=tid, cohort_id=coh.id, emails=["a@x.edu"])
    assert res2["already_active"] == ["a@x.edu"]
    admin_session.rollback()


def test_set_roster_state_drop_and_reactivate(admin_session, tenant_a):
    tid = tenant_a.id
    coh = _cohort(admin_session, tid)
    p = _person(admin_session, tid, "c@x.edu")
    bulk_enroll(admin_session, tenant_id=tid, cohort_id=coh.id, emails=["c@x.edu"])

    set_roster_state(admin_session, tenant_id=tid, cohort_id=coh.id, person_id=p.id, state="dropped")
    enr = admin_session.scalars(
        __import__("sqlalchemy").select(Enrollment)
        .where(Enrollment.cohort_id == coh.id).where(Enrollment.person_id == p.id)
    ).first()
    assert enr.status == "dropped"

    # bulk_enroll reactivates a dropped member.
    res = bulk_enroll(admin_session, tenant_id=tid, cohort_id=coh.id, emails=["c@x.edu"])
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

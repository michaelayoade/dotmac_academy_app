"""Onboarding workflow: seeding on accept, completion, and the enrolment gate."""

from __future__ import annotations

import uuid

import pytest

from app.models.admissions import Applicant
from app.models.cohort import Cohort
from app.models.track import CohortTrack, Track
from app.services import admissions, onboarding
from app.services.exceptions import BadRequestError


def _accepted_applicant(admin_session, tenant):
    cohort = Cohort(
        tenant_id=tenant.id,
        name=f"Onboarding-{uuid.uuid4().hex[:6]}",
        discipline="fiber",
        status="active",
    )
    track = Track(
        tenant_id=tenant.id,
        slug=f"onboarding-{uuid.uuid4().hex[:6]}",
        name="Fiber",
        status="active",
    )
    admin_session.add_all([cohort, track])
    admin_session.flush()
    admin_session.add(
        CohortTrack(
            tenant_id=tenant.id,
            cohort_id=cohort.id,
            track_id=track.id,
            status="active",
        )
    )
    admin_session.flush()
    a = Applicant(
        tenant_id=tenant.id,
        email=f"o{uuid.uuid4().hex[:6]}@a.ex",
        first_name="On",
        last_name="Board",
        status="accepted",
        cohort_id=cohort.id,
        track_id=track.id,
        program=track.name,
    )
    admin_session.add(a)
    admin_session.flush()
    return a


def test_transition_to_onboarding_seeds_tasks(admin_session, tenant_a):
    a = _accepted_applicant(admin_session, tenant_a)
    admissions.transition_applicant(admin_session, applicant_id=a.id, to_status="onboarding")
    tasks = onboarding.list_tasks(admin_session, tenant_id=tenant_a.id, applicant_id=a.id)
    assert [t.key for t in tasks] == [k for k, _ in onboarding.DEFAULT_TASKS]
    assert all(t.status == "pending" for t in tasks)


def test_seed_is_idempotent(admin_session, tenant_a):
    a = _accepted_applicant(admin_session, tenant_a)
    onboarding.seed_tasks(admin_session, tenant_id=tenant_a.id, applicant_id=a.id)
    onboarding.seed_tasks(admin_session, tenant_id=tenant_a.id, applicant_id=a.id)
    tasks = onboarding.list_tasks(admin_session, tenant_id=tenant_a.id, applicant_id=a.id)
    assert len(tasks) == len(onboarding.DEFAULT_TASKS)


def test_is_complete_tracks_task_status(admin_session, tenant_a):
    a = _accepted_applicant(admin_session, tenant_a)
    onboarding.seed_tasks(admin_session, tenant_id=tenant_a.id, applicant_id=a.id)
    assert onboarding.is_complete(admin_session, tenant_id=tenant_a.id, applicant_id=a.id) is False
    for t in onboarding.list_tasks(admin_session, tenant_id=tenant_a.id, applicant_id=a.id):
        onboarding.set_task_status(admin_session, task_id=t.id, status="done")
    assert onboarding.is_complete(admin_session, tenant_id=tenant_a.id, applicant_id=a.id) is True


def test_enroll_blocked_until_onboarding_complete(admin_session, tenant_a):
    a = _accepted_applicant(admin_session, tenant_a)
    admissions.transition_applicant(admin_session, applicant_id=a.id, to_status="onboarding")
    cohort = admin_session.get(Cohort, a.cohort_id)

    with pytest.raises(BadRequestError):
        admissions.enroll_applicant(admin_session, applicant_id=a.id, cohort_id=cohort.id)

    for t in onboarding.list_tasks(admin_session, tenant_id=tenant_a.id, applicant_id=a.id):
        onboarding.set_task_status(admin_session, task_id=t.id, status="done")
    result = admissions.enroll_applicant(admin_session, applicant_id=a.id, cohort_id=cohort.id)
    assert result.status == "enrolled"


def test_complete_task_by_key(admin_session, tenant_a):
    a = _accepted_applicant(admin_session, tenant_a)
    onboarding.seed_tasks(admin_session, tenant_id=tenant_a.id, applicant_id=a.id)
    t = onboarding.complete_task_by_key(
        admin_session, tenant_id=tenant_a.id, applicant_id=a.id, key="entrance_assessment"
    )
    assert t is not None and t.status == "done"
    # Unknown key is a no-op, not an error.
    assert (
        onboarding.complete_task_by_key(admin_session, tenant_id=tenant_a.id, applicant_id=a.id, key="nope")
        is None
    )

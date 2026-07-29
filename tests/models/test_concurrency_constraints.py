"""Database backstops for assessment race conditions."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError

from app.models.assessment import Activity, Submission
from app.models.attempt import ActivityAttempt
from app.models.course import Course
from app.models.person import Person


def _activity_and_person(db, tenant_id):
    course = Course(
        tenant_id=tenant_id,
        slug="race-guards",
        title="Race Guards",
        discipline="networking",
        source_ref="test",
        version=1,
    )
    person = Person(
        tenant_id=tenant_id,
        email="race@example.com",
        first_name="Race",
        last_name="Guard",
    )
    db.add_all([course, person])
    db.flush()
    activity = Activity(
        tenant_id=tenant_id,
        course_id=course.id,
        chapter_number=1,
        type="mcq_test",
        title="Guarded assessment",
        pass_threshold=0.6,
    )
    db.add(activity)
    db.commit()
    return activity, person


def test_attempt_number_is_unique_per_learner_activity(admin_session, tenant_a):
    activity, person = _activity_and_person(admin_session, tenant_a.id)
    admin_session.add_all(
        [
            Submission(
                tenant_id=tenant_a.id,
                activity_id=activity.id,
                person_id=person.id,
                answers={},
                attempt_no=1,
            ),
            Submission(
                tenant_id=tenant_a.id,
                activity_id=activity.id,
                person_id=person.id,
                answers={},
                attempt_no=1,
            ),
        ]
    )
    with pytest.raises(IntegrityError):
        admin_session.flush()
    admin_session.rollback()


def test_only_one_randomized_attempt_may_remain_open(admin_session, tenant_a):
    activity, person = _activity_and_person(admin_session, tenant_a.id)
    now = datetime.now(UTC)
    admin_session.add_all(
        [
            ActivityAttempt(
                tenant_id=tenant_a.id,
                activity_id=activity.id,
                person_id=person.id,
                question_ext_ids=["q1"],
                started_at=now,
            ),
            ActivityAttempt(
                tenant_id=tenant_a.id,
                activity_id=activity.id,
                person_id=person.id,
                question_ext_ids=["q2"],
                started_at=now,
            ),
        ]
    )
    with pytest.raises(IntegrityError):
        admin_session.flush()
    admin_session.rollback()

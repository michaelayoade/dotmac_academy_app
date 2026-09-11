from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.assessment import Activity
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.models.track import CohortTrack, Track, TrackCourse
from app.services.entitlements import accessible_course_ids
from app.services.exceptions import BadRequestError, NotFoundError
from app.services.tracks import (
    add_courses_to_cohort_track,
    clear_enrollment_track,
    create_cohort_track,
    list_cohort_tracks,
    reorder_track_courses,
)


def _course(db, tenant, slug, title):
    course = Course(
        tenant_id=tenant.id,
        slug=slug,
        title=title,
        discipline="networking",
        source_ref="test",
        version=1,
        status="published",
    )
    db.add(course)
    db.flush()
    return course


def test_track_assignment_restricts_access_within_cohort(admin_session, tenant_a):
    cohort = Cohort(tenant_id=tenant_a.id, name="July Intake", discipline="networking", status="active")
    learner = Person(tenant_id=tenant_a.id, email="track-learner@a.edu", first_name="Track", last_name="Learner")
    course_a = _course(admin_session, tenant_a, "fiber-a", "Fiber A")
    course_b = _course(admin_session, tenant_a, "fiber-b", "Fiber B")
    admin_session.add_all([cohort, learner])
    admin_session.flush()

    track_a = create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, name="Fiber Track", course_ids=[course_a.id]
    )
    track_b = create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, name="Support Track", course_ids=[course_b.id]
    )
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id,
            cohort_id=cohort.id,
            person_id=learner.id,
            track_id=track_a.id,
            role_in_cohort="student",
            status="active",
        )
    )
    admin_session.commit()

    ids = accessible_course_ids(admin_session, tenant_id=tenant_a.id, person_id=learner.id)

    assert course_a.id in ids
    assert course_b.id not in ids
    assert admin_session.scalars(
        select(CourseOffering)
        .where(CourseOffering.tenant_id == tenant_a.id)
        .where(CourseOffering.cohort_id == cohort.id)
    ).all()
    assert track_b.id != track_a.id


def test_null_track_enrollment_keeps_existing_cohort_wide_access(admin_session, tenant_a):
    cohort = Cohort(tenant_id=tenant_a.id, name="Legacy Intake", discipline="networking", status="active")
    learner = Person(tenant_id=tenant_a.id, email="legacy-learner@a.edu", first_name="Legacy", last_name="Learner")
    course_a = _course(admin_session, tenant_a, "legacy-a", "Legacy A")
    course_b = _course(admin_session, tenant_a, "legacy-b", "Legacy B")
    admin_session.add_all([cohort, learner])
    admin_session.flush()
    admin_session.add_all(
        [
            CourseOffering(tenant_id=tenant_a.id, cohort_id=cohort.id, course_id=course_a.id, status="active"),
            CourseOffering(tenant_id=tenant_a.id, cohort_id=cohort.id, course_id=course_b.id, status="active"),
            Enrollment(
                tenant_id=tenant_a.id,
                cohort_id=cohort.id,
                person_id=learner.id,
                role_in_cohort="student",
                status="active",
            ),
        ]
    )
    admin_session.commit()

    ids = accessible_course_ids(admin_session, tenant_id=tenant_a.id, person_id=learner.id)

    assert ids == {course_a.id, course_b.id}


def test_create_cohort_track_links_courses_and_offerings(admin_session, tenant_a):
    cohort = Cohort(tenant_id=tenant_a.id, name="Build Intake", discipline="networking", status="active")
    course = _course(admin_session, tenant_a, "build-course", "Build Course")
    admin_session.add(cohort)
    admin_session.flush()

    track = create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, name="Build Track", course_ids=[course.id]
    )
    admin_session.commit()

    assert admin_session.scalars(select(Track).where(Track.id == track.id)).first() is not None
    assert admin_session.scalars(select(CohortTrack).where(CohortTrack.track_id == track.id)).first() is not None
    assert (
        admin_session.scalars(select(TrackCourse).where(TrackCourse.track_id == track.id)).first().course_id
        == course.id
    )
    assert (
        admin_session.scalars(select(CourseOffering).where(CourseOffering.course_id == course.id)).first() is not None
    )


def test_create_cohort_track_orders_courses_by_explicit_position(admin_session, tenant_a):
    """1a: a position hint controls order_index; ties break by submission
    order, and unpositioned courses append after all positioned ones."""
    cohort = Cohort(tenant_id=tenant_a.id, name="Order Intake", discipline="networking", status="active")
    course_a = _course(admin_session, tenant_a, "order-a", "Order A")
    course_b = _course(admin_session, tenant_a, "order-b", "Order B")
    course_c = _course(admin_session, tenant_a, "order-c", "Order C")  # no position hint
    admin_session.add(cohort)
    admin_session.flush()

    # Submitted in alphabetical (a, b, c) order but B should come first.
    track = create_cohort_track(
        admin_session,
        tenant_id=tenant_a.id,
        cohort_id=cohort.id,
        name="Ordered Track",
        course_ids=[course_a.id, course_b.id, course_c.id],
        positions={course_a.id: 2, course_b.id: 1},
    )
    admin_session.commit()

    rows = admin_session.scalars(
        select(TrackCourse).where(TrackCourse.track_id == track.id).order_by(TrackCourse.order_index)
    ).all()
    assert [row.course_id for row in rows] == [course_b.id, course_a.id, course_c.id]
    assert [row.order_index for row in rows] == [1, 2, 3]  # dense, never the raw client value


def test_add_courses_to_cohort_track_orders_new_courses_by_position(admin_session, tenant_a):
    """1a: add-courses to an existing track also honors position hints for the
    newly-added batch, appended after the track's existing membership."""
    cohort = Cohort(tenant_id=tenant_a.id, name="Add Intake", discipline="networking", status="active")
    first = _course(admin_session, tenant_a, "add-first", "Add First")
    new_a = _course(admin_session, tenant_a, "add-new-a", "Add New A")
    new_b = _course(admin_session, tenant_a, "add-new-b", "Add New B")
    admin_session.add(cohort)
    admin_session.flush()
    track = create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, name="Add Track", course_ids=[first.id]
    )
    admin_session.flush()

    add_courses_to_cohort_track(
        admin_session,
        tenant_id=tenant_a.id,
        cohort_id=cohort.id,
        track_id=track.id,
        course_ids=[new_a.id, new_b.id],
        positions={new_b.id: 1},
    )
    admin_session.commit()

    rows = admin_session.scalars(
        select(TrackCourse).where(TrackCourse.track_id == track.id).order_by(TrackCourse.order_index)
    ).all()
    assert [row.course_id for row in rows] == [first.id, new_b.id, new_a.id]
    assert [row.order_index for row in rows] == [1, 2, 3]


def test_reorder_track_courses_reassigns_dense_order(admin_session, tenant_a):
    """1b: an admin/instructor can reorder an EXISTING track's courses, not
    just at creation."""
    cohort = Cohort(tenant_id=tenant_a.id, name="Reorder Intake", discipline="networking", status="active")
    course_a = _course(admin_session, tenant_a, "reorder-a", "Reorder A")
    course_b = _course(admin_session, tenant_a, "reorder-b", "Reorder B")
    admin_session.add(cohort)
    admin_session.flush()
    track = create_cohort_track(
        admin_session,
        tenant_id=tenant_a.id,
        cohort_id=cohort.id,
        name="Reorder Track",
        course_ids=[course_a.id, course_b.id],
    )
    admin_session.commit()

    reorder_track_courses(
        admin_session, tenant_id=tenant_a.id, track_id=track.id, ordered_course_ids=[course_b.id, course_a.id]
    )
    admin_session.commit()

    rows = admin_session.scalars(
        select(TrackCourse).where(TrackCourse.track_id == track.id).order_by(TrackCourse.order_index)
    ).all()
    assert [row.course_id for row in rows] == [course_b.id, course_a.id]
    assert [row.order_index for row in rows] == [1, 2]


def test_reorder_track_courses_rejects_a_course_not_in_the_track(admin_session, tenant_a):
    """1b: reorder validates the given id set matches current membership
    exactly — a course that isn't a track member is rejected."""
    cohort = Cohort(tenant_id=tenant_a.id, name="Reorder Reject", discipline="networking", status="active")
    course_a = _course(admin_session, tenant_a, "reject-a", "Reject A")
    stranger = _course(admin_session, tenant_a, "reject-stranger", "Reject Stranger")
    admin_session.add(cohort)
    admin_session.flush()
    track = create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, name="Reject Track", course_ids=[course_a.id]
    )
    admin_session.commit()

    with pytest.raises(BadRequestError):
        reorder_track_courses(
            admin_session, tenant_id=tenant_a.id, track_id=track.id, ordered_course_ids=[stranger.id]
        )

    with pytest.raises(BadRequestError):
        # A subset (missing course_a) is also rejected — must match exactly.
        reorder_track_courses(admin_session, tenant_id=tenant_a.id, track_id=track.id, ordered_course_ids=[])


def test_reorder_track_courses_rejects_duplicate_ids(admin_session, tenant_a):
    cohort = Cohort(tenant_id=tenant_a.id, name="Reorder Dup", discipline="networking", status="active")
    course_a = _course(admin_session, tenant_a, "dup-a", "Dup A")
    course_b = _course(admin_session, tenant_a, "dup-b", "Dup B")
    admin_session.add(cohort)
    admin_session.flush()
    track = create_cohort_track(
        admin_session,
        tenant_id=tenant_a.id,
        cohort_id=cohort.id,
        name="Dup Track",
        course_ids=[course_a.id, course_b.id],
    )
    admin_session.commit()

    with pytest.raises(BadRequestError):
        reorder_track_courses(
            admin_session,
            tenant_id=tenant_a.id,
            track_id=track.id,
            ordered_course_ids=[course_a.id, course_a.id],
        )


def test_reorder_track_courses_unknown_track_raises_not_found(admin_session, tenant_a):
    from uuid import uuid4

    with pytest.raises(NotFoundError):
        reorder_track_courses(admin_session, tenant_id=tenant_a.id, track_id=uuid4(), ordered_course_ids=[])


def test_list_cohort_tracks_flags_zero_activity_courses_live(admin_session, tenant_a):
    """1c: a zero-Activity course is flagged as a warning, computed live at
    render time — not just once at track-creation time — so it also catches
    a course that had its activities removed after the track was built."""
    cohort = Cohort(tenant_id=tenant_a.id, name="Activity Intake", discipline="networking", status="active")
    with_activity = _course(admin_session, tenant_a, "has-activity", "Has Activity")
    without_activity = _course(admin_session, tenant_a, "no-activity", "No Activity")
    admin_session.add(cohort)
    admin_session.flush()
    track = create_cohort_track(
        admin_session,
        tenant_id=tenant_a.id,
        cohort_id=cohort.id,
        name="Activity Track",
        course_ids=[with_activity.id, without_activity.id],
    )
    admin_session.add(
        Activity(
            tenant_id=tenant_a.id,
            course_id=with_activity.id,
            chapter_number=1,
            type="mcq_test",
            title="Quiz",
            pass_threshold=0.6,
        )
    )
    admin_session.commit()

    rows = list_cohort_tracks(admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id)
    item = next(row for row in rows if row["track"].id == track.id)
    assert item["zero_activity_course_ids"] == {without_activity.id}


def test_clear_enrollment_track_nulls_track_id_without_fabricating_completion(admin_session, tenant_a):
    """1d: recovery from a stuck track nulls Enrollment.track_id — it must
    NOT fabricate a CourseCompletion (that would trigger real certificate
    issuance for a course the learner never actually finished)."""
    cohort = Cohort(tenant_id=tenant_a.id, name="Clear Intake", discipline="networking", status="active")
    learner = Person(tenant_id=tenant_a.id, email="clear-learner@a.edu", first_name="Clear", last_name="Learner")
    course = _course(admin_session, tenant_a, "clear-course", "Clear Course")
    admin_session.add_all([cohort, learner])
    admin_session.flush()
    track = create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, name="Clear Track", course_ids=[course.id]
    )
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id,
            cohort_id=cohort.id,
            person_id=learner.id,
            track_id=track.id,
            role_in_cohort="student",
            status="active",
        )
    )
    admin_session.commit()

    from app.models.completion import CourseCompletion

    enrollment = clear_enrollment_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, person_id=learner.id
    )
    admin_session.commit()

    assert enrollment.track_id is None
    assert (
        admin_session.scalar(
            select(CourseCompletion).where(CourseCompletion.person_id == learner.id)
        )
        is None
    )
    # Falls back to full cohort-wide access via the null-track code path.
    ids = accessible_course_ids(admin_session, tenant_id=tenant_a.id, person_id=learner.id)
    assert course.id in ids


def test_clear_enrollment_track_raises_not_found_for_missing_enrollment(admin_session, tenant_a):
    cohort = Cohort(tenant_id=tenant_a.id, name="Clear Missing", discipline="networking", status="active")
    learner = Person(tenant_id=tenant_a.id, email="clear-missing@a.edu", first_name="Clear", last_name="Missing")
    admin_session.add_all([cohort, learner])
    admin_session.commit()

    with pytest.raises(NotFoundError):
        clear_enrollment_track(admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, person_id=learner.id)

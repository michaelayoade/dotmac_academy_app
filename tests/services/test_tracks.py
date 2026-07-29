from __future__ import annotations

from sqlalchemy import select

from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.models.track import CohortTrack, Track, TrackCourse
from app.services.entitlements import accessible_course_ids
from app.services.tracks import create_cohort_track


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

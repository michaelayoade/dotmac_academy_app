"""Tests for the instructor portal — Task 12 (cohorts, enroll, results, override)."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select

from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password
from app.services.tracks import create_cohort_track


def _login_instructor(app_client, admin_session, tenant):
    """Seed an instructor person, log in via TestClient, return Host header dict."""
    roles = ensure_roles(admin_session, tenant.id)
    p = Person(tenant_id=tenant.id, email="i@a.edu", first_name="In", last_name="Str")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant.id,
            person_id=p.id,
            email="i@a.edu",
            password_hash=hash_password("password1"),
        )
    )
    admin_session.add(
        PersonRole(tenant_id=tenant.id, person_id=p.id, role_id=roles["instructor"].id)
    )
    admin_session.commit()

    h = {"Host": "alpha.localhost"}
    # First POST to /login has an empty cookie jar → CSRF middleware skips check.
    # The 303 redirect to "/" is followed (default follow_redirects=True), which triggers
    # a GET "/" that makes the CSRF middleware set the csrf_token cookie in the jar.
    app_client.post("/login", headers=h, data={"email": "i@a.edu", "password": "password1"})
    return h


def _grant_admin(admin_session, tenant):
    """Give the logged-in instructor (i@a.edu) the admin role too.

    Course creation is admin-only and authoring/publishing any course requires
    admin (or a per-course instructor assignment), so authoring tests act as admin.
    """
    from sqlalchemy import select

    roles = ensure_roles(admin_session, tenant.id)
    person = admin_session.scalars(
        select(Person).where(Person.tenant_id == tenant.id).where(Person.email == "i@a.edu")
    ).first()
    admin_session.add(
        PersonRole(tenant_id=tenant.id, person_id=person.id, role_id=roles["admin"].id)
    )
    admin_session.commit()


def test_instructor_can_create_cohort(app_client, admin_session, tenant_a):
    """An instructor can POST to create a cohort; the row lands in the DB."""
    h = _login_instructor(app_client, admin_session, tenant_a)

    # After login (with redirect to "/" followed), the TestClient jar has both
    # `session` and `csrf_token` cookies. Subsequent POSTs must include x-csrf-token.
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        "/instructor/cohorts",
        headers={**h, "x-csrf-token": csrf},
        data={"name": "Abuja 2026", "discipline": "networking"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    # admin_session bypasses RLS; the Cohort committed by get_db is visible here.
    assert (
        admin_session.query(Cohort).filter(Cohort.tenant_id == tenant_a.id).count() == 1
    )


def test_enroll_cross_tenant_404(app_client, admin_session, tenant_a, tenant_b):
    """POSTing to enroll with a cohort owned by a different tenant returns 404."""
    h = _login_instructor(app_client, admin_session, tenant_a)

    # Create a cohort under tenant_b directly (bypasses RLS via admin_session).
    cohort_b = Cohort(tenant_id=tenant_b.id, name="Beta Cohort", discipline="security", status="active")
    admin_session.add(cohort_b)
    admin_session.commit()
    admin_session.refresh(cohort_b)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{cohort_b.id}/enroll",
        headers={**h, "x-csrf-token": csrf},
        data={"email": "nobody@example.com"},
        follow_redirects=False,
    )
    assert r.status_code == 404


def test_bulk_enroll_surfaces_unknown_emails(app_client, admin_session, tenant_a):
    """Finding #6: enrolling reports unknown emails instead of silently no-oping."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    # A real student + a cohort.
    stu = Person(tenant_id=tenant_a.id, email="real@a.edu", first_name="Re", last_name="Al")
    admin_session.add(stu)
    coh = Cohort(tenant_id=tenant_a.id, name="Roster", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.commit()
    admin_session.refresh(coh)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/enroll",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={"emails": "real@a.edu, ghost@a.edu"},
    )
    assert r.status_code == 200
    assert "Enrolled 1" in r.text
    assert "ghost@a.edu" in r.text  # unknown email surfaced
    from app.models.cohort import Enrollment
    n = admin_session.query(Enrollment).filter(
        Enrollment.cohort_id == coh.id, Enrollment.status == "active").count()
    assert n == 1


def test_grading_queue_lists_pending(app_client, admin_session, tenant_a):
    """Finding #4: manual submissions awaiting a score appear in the queue."""
    from app.models.assessment import Activity, Submission
    from app.models.course import Course

    h = _login_instructor(app_client, admin_session, tenant_a)
    learner = Person(tenant_id=tenant_a.id, email="learner@a.edu", first_name="Le", last_name="Ar")
    course = Course(tenant_id=tenant_a.id, slug="mg", title="MG", discipline="networking",
                    source_ref="x", version=1)
    admin_session.add_all([learner, course])
    admin_session.flush()
    act = Activity(tenant_id=tenant_a.id, course_id=course.id, chapter_number=1, type="mcq_test",
                   title="Essay Q", pass_threshold=0.6, grading="manual")
    admin_session.add(act)
    admin_session.flush()
    admin_session.add(Submission(tenant_id=tenant_a.id, activity_id=act.id, person_id=learner.id,
                                 answers={}, attempt_no=1))  # no Score = pending
    admin_session.commit()

    r = app_client.get("/instructor/grading", headers=h)
    assert r.status_code == 200
    assert "Essay Q" in r.text
    assert "learner@a.edu" in r.text


def test_item_analytics_page(app_client, admin_session, tenant_a):
    """Finding #4/#9: per-question difficulty page renders p-values."""
    from app.models.assessment import Activity, Score, Submission
    from app.models.course import Course

    h = _login_instructor(app_client, admin_session, tenant_a)
    learner = Person(tenant_id=tenant_a.id, email="il@a.edu", first_name="Il", last_name="A")
    course = Course(tenant_id=tenant_a.id, slug="ia", title="IA", discipline="networking",
                    source_ref="x", version=1)
    admin_session.add_all([learner, course])
    admin_session.flush()
    act = Activity(tenant_id=tenant_a.id, course_id=course.id, chapter_number=1, type="mcq_test",
                   title="Analytics Quiz", pass_threshold=0.6)
    admin_session.add(act)
    admin_session.flush()
    sub = Submission(tenant_id=tenant_a.id, activity_id=act.id, person_id=learner.id,
                     answers={}, attempt_no=1)
    admin_session.add(sub)
    admin_session.flush()
    admin_session.add(Score(tenant_id=tenant_a.id, submission_id=sub.id, score=10, max_score=10,
                            fraction=1.0, passed=True, source="auto",
                            per_item=[{"id": "q1", "correct": True}]))
    admin_session.commit()

    r = app_client.get(f"/instructor/items/{act.id}", headers=h)
    assert r.status_code == 200
    assert "Analytics Quiz" in r.text
    assert "q1" in r.text


def test_authoring_create_course_and_chapter(app_client, admin_session, tenant_a):
    """Finding #8: instructor creates a draft course and authors a chapter in markdown."""
    from app.models.course import Chapter, Course

    h = _login_instructor(app_client, admin_session, tenant_a)
    _grant_admin(admin_session, tenant_a)
    csrf = app_client.cookies.get("csrf_token", "")
    # Create a draft course.
    r = app_client.post("/instructor/courses",
                        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
                        data={"slug": "authored", "title": "Authored", "discipline": "networking"})
    assert r.status_code == 200
    course = admin_session.scalars(
        __import__("sqlalchemy").select(Course)
        .where(Course.tenant_id == tenant_a.id).where(Course.slug == "authored")
    ).first()
    assert course is not None and course.status == "draft"

    # Author a chapter in markdown.
    r2 = app_client.post(f"/instructor/courses/{course.id}/chapters",
                         headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
                         data={"number": "1", "title": "Intro", "body_md": "# Welcome"})
    assert r2.status_code == 200
    ch = admin_session.scalars(
        __import__("sqlalchemy").select(Chapter)
        .where(Chapter.course_id == course.id).where(Chapter.number == 1)
    ).first()
    assert ch is not None
    assert "<h1>Welcome</h1>" in ch.body_html
    assert ch.body_md == "# Welcome"


def test_publish_course_toggles_status(app_client, admin_session, tenant_a):
    """Finding #8: instructor can publish/unpublish a course."""
    from app.models.course import Course

    h = _login_instructor(app_client, admin_session, tenant_a)
    _grant_admin(admin_session, tenant_a)
    course = Course(tenant_id=tenant_a.id, slug="pub", title="Pub", discipline="networking",
                    source_ref="x", version=1, status="draft")
    admin_session.add(course)
    admin_session.commit()
    admin_session.refresh(course)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(f"/instructor/courses/{course.id}/status",
                        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
                        data={"status_value": "published"})
    assert r.status_code == 200
    admin_session.expire(course)
    assert admin_session.get(Course, course.id).status == "published"


def test_student_forbidden(app_client, admin_session, tenant_a):
    """A user with only the student role gets 403 on any instructor-gated route."""
    roles = ensure_roles(admin_session, tenant_a.id)
    p = Person(tenant_id=tenant_a.id, email="s3@a.edu", first_name="S", last_name="T")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant_a.id,
            person_id=p.id,
            email="s3@a.edu",
            password_hash=hash_password("password1"),
        )
    )
    admin_session.add(
        PersonRole(tenant_id=tenant_a.id, person_id=p.id, role_id=roles["student"].id)
    )
    admin_session.commit()

    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": "s3@a.edu", "password": "password1"})
    assert app_client.get("/instructor/results", headers=h).status_code == 403


def test_create_track_error_renders_inline_message_not_raw_400(app_client, admin_session, tenant_a):
    """Finding #1: create_cohort_track's BadRequestError ("select at least one
    course") must render inline (200 + retarget), not become a raw 400 that
    htmx cannot swap into hx-target="body"."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="Errs", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.commit()
    admin_session.refresh(coh)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/tracks",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={"name": "Empty Track"},  # no course_ids selected -> BadRequestError
    )
    assert r.status_code == 200
    assert "select at least one course" in r.text
    assert r.headers.get("HX-Retarget") == f"#track-form-error-{coh.id}"
    # No track was actually created.
    from app.models.track import Track

    assert (
        admin_session.query(Track).filter(Track.tenant_id == tenant_a.id, Track.name == "Empty Track").count() == 0
    )


def test_add_courses_to_track_error_renders_inline_message(app_client, admin_session, tenant_a):
    """Finding #1: add_courses_to_cohort_track's BadRequestError renders inline."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="Errs2", discipline="networking", status="active")
    course = Course(
        tenant_id=tenant_a.id, slug="c1", title="C1", discipline="networking", source_ref="x", version=1,
        status="published",
    )
    admin_session.add_all([coh, course])
    admin_session.flush()
    track = create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=coh.id, name="T1", course_ids=[course.id]
    )
    admin_session.commit()
    admin_session.refresh(track)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/tracks/{track.id}/courses",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={},  # no course_ids selected -> BadRequestError
    )
    assert r.status_code == 200
    assert "select at least one course" in r.text
    assert r.headers.get("HX-Retarget") == f"#track-courses-error-{track.id}"


def test_roster_track_reassign_error_renders_inline_message(app_client, admin_session, tenant_a):
    """Finding #1: assign_enrollment_track's NotFoundError (unknown track) renders inline."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="Errs3", discipline="networking", status="active")
    stu = Person(tenant_id=tenant_a.id, email="stu3@a.edu", first_name="S", last_name="T")
    admin_session.add_all([coh, stu])
    admin_session.flush()
    admin_session.add(
        Enrollment(tenant_id=tenant_a.id, cohort_id=coh.id, person_id=stu.id, role_in_cohort="student", status="active")
    )
    admin_session.commit()

    bad_track_id = uuid4()
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/roster/{stu.id}/track",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={"track_id": str(bad_track_id)},
    )
    assert r.status_code == 200
    assert "not found" in r.text.lower()
    assert r.headers.get("HX-Retarget") == f"#roster-track-error-{coh.id}-{stu.id}"


def test_draft_courses_excluded_from_track_checkbox_lists(app_client, admin_session, tenant_a):
    """Finding #2: a draft course is hidden from the create-track/add-courses
    checkbox lists (drafts grant nothing per entitlements.py); a published one
    is shown, and the hidden-draft-count note appears."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="DraftTest", discipline="networking", status="active")
    draft = Course(
        tenant_id=tenant_a.id, slug="draft-c", title="Draft Course Title", discipline="networking",
        source_ref="x", version=1, status="draft",
    )
    published = Course(
        tenant_id=tenant_a.id, slug="pub-c", title="Published Course Title", discipline="networking",
        source_ref="x", version=1, status="published",
    )
    admin_session.add_all([coh, draft, published])
    admin_session.commit()

    r = app_client.get("/instructor/cohorts", headers=h)
    assert r.status_code == 200
    assert "Published Course Title" in r.text
    assert "Draft Course Title" not in r.text
    assert "draft course(s) hidden" in r.text


def test_roster_shows_dropped_and_waitlisted_enrollments(app_client, admin_session, tenant_a):
    """Finding #3: the roster table no longer hides non-active-student rows."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="RosterTest", discipline="networking", status="active")
    dropped_p = Person(tenant_id=tenant_a.id, email="dropped@a.edu", first_name="Drop", last_name="Ped")
    waitlisted_p = Person(tenant_id=tenant_a.id, email="wait@a.edu", first_name="Wait", last_name="List")
    admin_session.add_all([coh, dropped_p, waitlisted_p])
    admin_session.flush()
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id, cohort_id=coh.id, person_id=dropped_p.id, role_in_cohort="student",
            status="dropped",
        )
    )
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id, cohort_id=coh.id, person_id=waitlisted_p.id, role_in_cohort="student",
            status="waitlisted",
        )
    )
    admin_session.commit()

    r = app_client.get("/instructor/cohorts", headers=h)
    assert r.status_code == 200
    assert "dropped@a.edu" in r.text
    assert "wait@a.edu" in r.text


def test_non_admin_instructor_forbidden_from_changing_instructor_role_enrollment(app_client, admin_session, tenant_a):
    """Finding #3 authorization: a plain instructor cannot drop/reactivate a
    non-student (e.g. instructor-role) enrollment — that is admin-only,
    because dropping it silently strips that instructor's own authoring
    access via _assigned_course_ids."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="AuthzTest", discipline="networking", status="active")
    other_instructor = Person(tenant_id=tenant_a.id, email="peer@a.edu", first_name="Peer", last_name="Instr")
    admin_session.add_all([coh, other_instructor])
    admin_session.flush()
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id, cohort_id=coh.id, person_id=other_instructor.id, role_in_cohort="instructor",
            status="active",
        )
    )
    admin_session.commit()

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/roster/{other_instructor.id}/state",
        headers={**h, "x-csrf-token": csrf},
        data={"state": "dropped"},
        follow_redirects=False,
    )
    assert r.status_code == 403
    admin_session.expire_all()
    enr = admin_session.scalars(
        select(Enrollment).where(Enrollment.cohort_id == coh.id).where(Enrollment.person_id == other_instructor.id)
    ).first()
    assert enr.status == "active"  # unchanged


def test_admin_can_change_instructor_role_enrollment_state(app_client, admin_session, tenant_a):
    """Finding #3 authorization: an admin CAN drop/reactivate a non-student enrollment."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    _grant_admin(admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="AuthzTest2", discipline="networking", status="active")
    other_instructor = Person(tenant_id=tenant_a.id, email="peer2@a.edu", first_name="Peer", last_name="Instr")
    admin_session.add_all([coh, other_instructor])
    admin_session.flush()
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id, cohort_id=coh.id, person_id=other_instructor.id, role_in_cohort="instructor",
            status="active",
        )
    )
    admin_session.commit()

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/roster/{other_instructor.id}/state",
        headers={**h, "x-csrf-token": csrf},
        data={"state": "dropped"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    admin_session.expire_all()
    enr = admin_session.scalars(
        select(Enrollment).where(Enrollment.cohort_id == coh.id).where(Enrollment.person_id == other_instructor.id)
    ).first()
    assert enr.status == "dropped"


def test_reorder_track_courses_route_updates_order(app_client, admin_session, tenant_a):
    """1b: an instructor can reorder an EXISTING track's courses via the
    track-level route (not nested under a specific cohort)."""
    from app.models.track import TrackCourse

    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="ReorderRoute", discipline="networking", status="active")
    course_a = Course(
        tenant_id=tenant_a.id, slug="rr-a", title="RR A", discipline="networking", source_ref="x", version=1,
        status="published",
    )
    course_b = Course(
        tenant_id=tenant_a.id, slug="rr-b", title="RR B", discipline="networking", source_ref="x", version=1,
        status="published",
    )
    admin_session.add_all([coh, course_a, course_b])
    admin_session.flush()
    track = create_cohort_track(
        admin_session,
        tenant_id=tenant_a.id,
        cohort_id=coh.id,
        name="Route Track",
        course_ids=[course_a.id, course_b.id],
    )
    admin_session.commit()
    admin_session.refresh(track)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/tracks/{track.id}/reorder",
        headers={**h, "x-csrf-token": csrf},
        data={
            "course_ids": [str(course_a.id), str(course_b.id)],
            f"position_{course_b.id}": "1",
            f"position_{course_a.id}": "2",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    admin_session.expire_all()
    rows = admin_session.scalars(
        select(TrackCourse).where(TrackCourse.track_id == track.id).order_by(TrackCourse.order_index)
    ).all()
    assert [row.course_id for row in rows] == [course_b.id, course_a.id]


def test_reorder_track_courses_route_rejects_mismatched_membership(app_client, admin_session, tenant_a):
    """1b: reordering with an id that isn't in the track renders inline,
    same as the other track-form BadRequestError handlers."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="ReorderReject", discipline="networking", status="active")
    course = Course(
        tenant_id=tenant_a.id, slug="rr-only", title="RR Only", discipline="networking", source_ref="x", version=1,
        status="published",
    )
    admin_session.add_all([coh, course])
    admin_session.flush()
    track = create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=coh.id, name="Reject Route Track", course_ids=[course.id]
    )
    admin_session.commit()
    admin_session.refresh(track)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/tracks/{track.id}/reorder",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={"course_ids": [str(uuid4())]},  # not a member of the track
    )
    assert r.status_code == 200
    assert "must match" in r.text.lower()
    assert r.headers.get("HX-Retarget") == f"#track-reorder-error-{track.id}"


def test_clear_roster_track_forbidden_for_non_admin_instructor(app_client, admin_session, tenant_a):
    """1d: clearing a learner's track is admin-only, regardless of the
    target's role (mirrors change_roster_state's admin gate)."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="ClearForbidden", discipline="networking", status="active")
    course = Course(
        tenant_id=tenant_a.id, slug="clear-c", title="Clear C", discipline="networking", source_ref="x", version=1,
        status="published",
    )
    stu = Person(tenant_id=tenant_a.id, email="clear-stu@a.edu", first_name="C", last_name="S")
    admin_session.add_all([coh, course, stu])
    admin_session.flush()
    track = create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=coh.id, name="Clear Track", course_ids=[course.id]
    )
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id, cohort_id=coh.id, person_id=stu.id, role_in_cohort="student", status="active",
            track_id=track.id,
        )
    )
    admin_session.commit()

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/roster/{stu.id}/track/clear",
        headers={**h, "x-csrf-token": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 403
    admin_session.expire_all()
    enr = admin_session.scalars(
        select(Enrollment).where(Enrollment.cohort_id == coh.id).where(Enrollment.person_id == stu.id)
    ).first()
    assert enr.track_id == track.id  # unchanged


def test_admin_can_clear_a_learners_stuck_track(app_client, admin_session, tenant_a):
    """1d: an admin clearing a learner's track nulls Enrollment.track_id
    (not a fabricated completion) and falls back to cohort-wide access."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    _grant_admin(admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="ClearAdmin", discipline="networking", status="active")
    course = Course(
        tenant_id=tenant_a.id, slug="clear-a-c", title="Clear Admin C", discipline="networking", source_ref="x",
        version=1, status="published",
    )
    stu = Person(tenant_id=tenant_a.id, email="clear-admin-stu@a.edu", first_name="C", last_name="A")
    admin_session.add_all([coh, course, stu])
    admin_session.flush()
    track = create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=coh.id, name="Clear Admin Track", course_ids=[course.id]
    )
    admin_session.add(
        Enrollment(
            tenant_id=tenant_a.id, cohort_id=coh.id, person_id=stu.id, role_in_cohort="student", status="active",
            track_id=track.id,
        )
    )
    admin_session.commit()

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/roster/{stu.id}/track/clear",
        headers={**h, "x-csrf-token": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    admin_session.expire_all()
    enr = admin_session.scalars(
        select(Enrollment).where(Enrollment.cohort_id == coh.id).where(Enrollment.person_id == stu.id)
    ).first()
    assert enr.track_id is None


def test_clear_roster_track_error_renders_inline_message(app_client, admin_session, tenant_a):
    """1d: NotFoundError (no enrollment) renders inline, same as the other
    roster-action handlers."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    _grant_admin(admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="ClearMissing", discipline="networking", status="active")
    stu = Person(tenant_id=tenant_a.id, email="clear-missing@a.edu", first_name="C", last_name="M")
    admin_session.add_all([coh, stu])
    admin_session.commit()

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/roster/{stu.id}/track/clear",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
    )
    assert r.status_code == 200
    assert "not found" in r.text.lower()
    assert r.headers.get("HX-Retarget") == f"#roster-track-clear-error-{coh.id}-{stu.id}"


def test_cohorts_page_shows_zero_activity_course_warning(app_client, admin_session, tenant_a):
    """1c: a zero-Activity course in a track shows a live-computed warning,
    without blocking the track from rendering."""
    from app.models.assessment import Activity

    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="ActivityWarning", discipline="networking", status="active")
    course = Course(
        tenant_id=tenant_a.id, slug="warn-c", title="Warn Course", discipline="networking", source_ref="x",
        version=1, status="published",
    )
    admin_session.add_all([coh, course])
    admin_session.flush()
    create_cohort_track(
        admin_session, tenant_id=tenant_a.id, cohort_id=coh.id, name="Warn Track", course_ids=[course.id]
    )
    admin_session.commit()

    r = app_client.get("/instructor/cohorts", headers=h)
    assert r.status_code == 200
    assert "no activities yet" in r.text.lower()

    # Adding an activity clears the warning on the next render (computed live).
    act = Activity(
        tenant_id=tenant_a.id, course_id=course.id, chapter_number=1, type="mcq_test", title="Q", pass_threshold=0.6
    )
    admin_session.add(act)
    admin_session.commit()
    r2 = app_client.get("/instructor/cohorts", headers=h)
    assert "no activities yet" not in r2.text.lower()


def test_roster_state_change_error_renders_inline_message(app_client, admin_session, tenant_a):
    """Finding #1: set_roster_state's NotFoundError (invalid state) renders inline."""
    h = _login_instructor(app_client, admin_session, tenant_a)
    coh = Cohort(tenant_id=tenant_a.id, name="Errs4", discipline="networking", status="active")
    stu = Person(tenant_id=tenant_a.id, email="stu4@a.edu", first_name="S", last_name="U")
    admin_session.add_all([coh, stu])
    admin_session.flush()
    admin_session.add(
        Enrollment(tenant_id=tenant_a.id, cohort_id=coh.id, person_id=stu.id, role_in_cohort="student", status="active")
    )
    admin_session.commit()

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/cohorts/{coh.id}/roster/{stu.id}/state",
        headers={**h, "x-csrf-token": csrf, "HX-Request": "true"},
        data={"state": "bogus-state"},
    )
    assert r.status_code == 200
    assert "invalid roster state" in r.text.lower()
    assert r.headers.get("HX-Retarget") == f"#roster-state-error-{coh.id}-{stu.id}"

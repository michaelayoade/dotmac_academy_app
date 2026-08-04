"""Tests for the student portal — Task 11 (htmx)."""

from __future__ import annotations

import uuid

from app.models.assessment import Activity, Question, QuestionBank
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Chapter, Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.services.security import hash_password


def _login(app_client, admin_session, tenant):
    p = Person(tenant_id=tenant.id, email="s@a.edu", first_name="S", last_name="L")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant.id,
            person_id=p.id,
            email="s@a.edu",
            password_hash=hash_password("password1"),
        )
    )
    admin_session.commit()
    h = {"Host": "alpha.localhost"}
    # First request has no cookies → CSRF middleware skips the check (empty cookie jar).
    app_client.post("/login", headers=h, data={"email": "s@a.edu", "password": "password1"})
    return p, h


def test_take_test_flow(app_client, admin_session, tenant_a):
    p, h = _login(app_client, admin_session, tenant_a)

    # Seed Course + Chapter + QuestionBank + Question + Activity.
    c = Course(
        tenant_id=tenant_a.id,
        slug="foundation",
        title="F",
        discipline="networking",
        source_ref="x",
        version=1,
    )
    admin_session.add(c)
    admin_session.flush()
    admin_session.add(
        Chapter(
            tenant_id=tenant_a.id,
            course_id=c.id,
            number=3,
            title="Three",
            part="II",
            body_html="<p>body</p>",
            source_hash="h",
            order_index=3,
        )
    )
    bank = QuestionBank(
        tenant_id=tenant_a.id,
        course_id=c.id,
        chapter_number=3,
        kind="chapter",
        version=1,
    )
    admin_session.add(bank)
    admin_session.flush()
    admin_session.add(
        Question(
            tenant_id=tenant_a.id,
            bank_id=bank.id,
            ext_id="q1",
            stem="Pick A",
            type="single",
            options=["A", "B"],
            correct=["A"],
            rubric_category="recall",
            explanation="Because A",
            weight=1,
        )
    )
    act = Activity(
        tenant_id=tenant_a.id,
        course_id=c.id,
        chapter_number=3,
        type="mcq_test",
        bank_id=bank.id,
        title="Ch3",
        pass_threshold=0.6,
    )
    admin_session.add(act)
    admin_session.flush()
    # Entitle the learner: cohort + enrollment + offering for this course.
    coh = Cohort(tenant_id=tenant_a.id, name="C", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.flush()
    admin_session.add(
        Enrollment(tenant_id=tenant_a.id, cohort_id=coh.id, person_id=p.id, role_in_cohort="student", status="active")
    )
    admin_session.add(CourseOffering(tenant_id=tenant_a.id, cohort_id=coh.id, course_id=c.id, status="active"))
    admin_session.commit()

    # GET chapter page — response sets the csrf_token cookie in the TestClient jar.
    r_ch = app_client.get("/courses/foundation/chapters/3", headers=h)
    assert r_ch.status_code == 200

    # Extract csrf token — TestClient (httpx-based) stores cookies from responses.
    csrf = app_client.cookies.get("csrf_token") or r_ch.cookies.get("csrf_token", "")

    # POST submit WITH the x-csrf-token header (required because the client now carries
    # both the session cookie and the csrf_token cookie, so CSRF middleware enforces it).
    r = app_client.post(
        f"/activities/{act.id}/submit",
        headers={**h, "x-csrf-token": csrf},
        data={"q1": "A"},
    )
    assert r.status_code == 200
    assert "Passed" in r.text
    assert "Because A" in r.text


def test_cross_tenant_isolation(app_client, admin_session, tenant_a, tenant_b):
    _login(app_client, admin_session, tenant_a)
    h = {"Host": "alpha.localhost"}

    # Seed Course + QuestionBank + Activity under tenant_b only.
    c_b = Course(
        tenant_id=tenant_b.id,
        slug="foundation",
        title="F",
        discipline="networking",
        source_ref="x",
        version=1,
    )
    admin_session.add(c_b)
    admin_session.flush()
    bank_b = QuestionBank(
        tenant_id=tenant_b.id,
        course_id=c_b.id,
        chapter_number=1,
        kind="chapter",
        version=1,
    )
    admin_session.add(bank_b)
    admin_session.flush()
    act_b = Activity(
        tenant_id=tenant_b.id,
        course_id=c_b.id,
        chapter_number=1,
        type="mcq_test",
        bank_id=bank_b.id,
        title="B-Act",
        pass_threshold=0.6,
    )
    admin_session.add(act_b)
    admin_session.commit()

    # tenant_a user must NOT be able to access tenant_b's activity.
    r = app_client.get(f"/activities/{act_b.id}", headers=h)
    assert r.status_code == 404

    # Nonexistent chapter (no foundation course in tenant_a) → 404.
    r2 = app_client.get("/courses/foundation/chapters/999", headers=h)
    assert r2.status_code == 404


def test_dashboard_lists_multiple_courses(app_client, admin_session, tenant_a):
    """The Learn home lists every course the student is enrolled in (by discipline)."""
    from app.models.cohort import Cohort, Enrollment

    p, h = _login(app_client, admin_session, tenant_a)
    courses = []
    for slug, title in (("foundation", "Network Foundation"), ("fiber-engineering", "Fiber Engineering")):
        c = Course(tenant_id=tenant_a.id, slug=slug, title=title, discipline="networking", source_ref="x", version=1)
        admin_session.add(c)
        admin_session.flush()
        admin_session.add(
            Chapter(
                tenant_id=tenant_a.id,
                course_id=c.id,
                number=1,
                title=f"{title} ch1",
                part="I",
                body_html="<p>x</p>",
                source_hash="h",
                order_index=1,
            )
        )
        courses.append(c)
    coh = Cohort(tenant_id=tenant_a.id, name="Abuja", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.flush()
    admin_session.add(
        Enrollment(tenant_id=tenant_a.id, cohort_id=coh.id, person_id=p.id, role_in_cohort="student", status="active")
    )
    for c in courses:
        admin_session.add(CourseOffering(tenant_id=tenant_a.id, cohort_id=coh.id, course_id=c.id, status="active"))
    admin_session.commit()
    try:
        r = app_client.get("/", headers=h)
        assert r.status_code == 200
        assert "Network Foundation" in r.text and "Fiber Engineering" in r.text
        assert "/courses/fiber-engineering/chapters/1" in r.text
    finally:
        # Clean up committed rows (chapters cascade from courses) so this test
        # leaves no residue in the shared test DB.
        admin_session.query(Course).filter(Course.tenant_id == tenant_a.id).delete()
        admin_session.commit()


def test_chapter_lists_multiple_activities(app_client, admin_session, tenant_a):
    p, h = _login(app_client, admin_session, tenant_a)
    slug = f"multi-activity-{uuid.uuid4().hex[:8]}"
    c = Course(
        tenant_id=tenant_a.id,
        slug=slug,
        title="Multi Activity",
        discipline="networking",
        source_ref="x",
        version=1,
    )
    admin_session.add(c)
    admin_session.flush()
    admin_session.add(
        Chapter(
            tenant_id=tenant_a.id,
            course_id=c.id,
            number=14,
            title="Fourteen",
            part="II",
            body_html="<h2>Read this</h2><p>body</p>",
            source_hash="h",
            order_index=14,
        )
    )
    lab = Activity(
        tenant_id=tenant_a.id,
        course_id=c.id,
        chapter_number=14,
        type="lab",
        title="Router lab",
        pass_threshold=0.7,
    )
    test = Activity(
        tenant_id=tenant_a.id,
        course_id=c.id,
        chapter_number=14,
        type="mcq_test",
        title="Chapter 14 test",
        pass_threshold=0.0,
    )
    admin_session.add_all([lab, test])
    coh = Cohort(tenant_id=tenant_a.id, name="C", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.flush()
    admin_session.add(
        Enrollment(tenant_id=tenant_a.id, cohort_id=coh.id, person_id=p.id, role_in_cohort="student", status="active")
    )
    admin_session.add(CourseOffering(tenant_id=tenant_a.id, cohort_id=coh.id, course_id=c.id, status="active"))
    admin_session.commit()
    try:
        r = app_client.get(f"/courses/{slug}/chapters/14", headers=h)
        assert r.status_code == 200
        assert "Chapter activities" in r.text
        assert "Chapter 14 test" in r.text
        assert "Router lab" in r.text
        assert f"/activities/{test.id}" in r.text
        assert f"/labs/{lab.id}" in r.text
        assert 'id="chapter-test-link"' in r.text
    finally:
        admin_session.query(Course).filter(Course.tenant_id == tenant_a.id, Course.slug == slug).delete()
        admin_session.commit()


# ---------------------------------------------------------------------------
# Subtopic progress is server state, not browser state
# ---------------------------------------------------------------------------


def _seed_entitled_chapter(admin_session, tenant, person, *, slug, body_html):
    """A course the learner may study, with one chapter and one activity."""
    c = Course(tenant_id=tenant.id, slug=slug, title="SP", discipline="networking",
               source_ref="x", version=1)
    admin_session.add(c)
    admin_session.flush()
    admin_session.add(
        Chapter(tenant_id=tenant.id, course_id=c.id, number=1, title="One", part="I",
                body_html=body_html, source_hash="sh", order_index=1)
    )
    bank = QuestionBank(tenant_id=tenant.id, course_id=c.id, chapter_number=1, kind="chapter", version=1)
    admin_session.add(bank)
    admin_session.flush()
    admin_session.add(
        Question(tenant_id=tenant.id, bank_id=bank.id, ext_id="q1", stem="Pick A", type="single",
                 options=["A", "B"], correct=["A"], rubric_category="recall", explanation="", weight=1)
    )
    admin_session.add(
        Activity(tenant_id=tenant.id, course_id=c.id, chapter_number=1, type="mcq_test",
                 bank_id=bank.id, title="Ch1 test", pass_threshold=0.6)
    )
    coh = Cohort(tenant_id=tenant.id, name=f"C-{slug}", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.flush()
    admin_session.add(
        Enrollment(tenant_id=tenant.id, cohort_id=coh.id, person_id=person.id,
                   role_in_cohort="student", status="active")
    )
    admin_session.add(CourseOffering(tenant_id=tenant.id, cohort_id=coh.id, course_id=c.id, status="active"))
    admin_session.commit()
    return c


def test_subtopic_progress_survives_a_new_browser_session(app_client, admin_session, tenant_a):
    """The bug this replaced: progress lived in window.localStorage, so a learner
    who switched device found the chapter's activities re-locked with nothing on
    the server to show the work was done. A fresh cookie jar is that new device."""
    p, h = _login(app_client, admin_session, tenant_a)
    _seed_entitled_chapter(
        admin_session, tenant_a, p, slug="subtopics", body_html="<h2>Alpha</h2><h2>Beta</h2>"
    )

    r = app_client.get("/courses/subtopics/chapters/1", headers=h)
    assert r.status_code == 200
    # Nothing done yet: the activity link is rendered locked, server-side.
    assert 'class="chapter-activity-link btn-ghost justify-between gap-3 action-disabled"' in r.text
    assert 'data-subtopics-complete="false"' in r.text

    csrf = app_client.cookies.get("csrf_token") or ""
    hh = {**h, "x-csrf-token": csrf}
    for slug in ("alpha", "beta"):
        rp = app_client.post(f"/courses/subtopics/chapters/1/subtopics/{slug}/complete", headers=hh)
        assert rp.status_code == 200, rp.text
    assert rp.json()["chapter_complete"] is True

    # A brand-new client — no cookies, no localStorage, a different device.
    app_client.cookies.clear()
    app_client.post("/login", headers=h, data={"email": "s@a.edu", "password": "password1"})
    r2 = app_client.get("/courses/subtopics/chapters/1", headers=h)
    assert r2.status_code == 200
    assert 'data-subtopics-complete="true"' in r2.text
    assert 'data-subtopic-done="true"' in r2.text
    # ...and the activity link now arrives unlocked, without JavaScript running.
    assert "chapter-activity-link" in r2.text
    assert 'class="chapter-activity-link btn-ghost justify-between gap-3 action-disabled"' not in r2.text


def test_unknown_subtopic_slug_is_rejected(app_client, admin_session, tenant_a):
    """The slug is content-derived and arrives from the client, so it is checked
    against the chapter's real headings rather than stored on trust."""
    p, h = _login(app_client, admin_session, tenant_a)
    _seed_entitled_chapter(admin_session, tenant_a, p, slug="subtopics2", body_html="<h2>Alpha</h2>")

    app_client.get("/courses/subtopics2/chapters/1", headers=h)
    hh = {**h, "x-csrf-token": app_client.cookies.get("csrf_token") or ""}
    r = app_client.post("/courses/subtopics2/chapters/1/subtopics/not-a-heading/complete", headers=hh)
    assert r.status_code == 404


def test_subtopic_progress_requires_course_access(app_client, admin_session, tenant_a):
    """Without the entitlement gate a learner could write progress — and feed the
    activity gate — for a course they cannot open."""
    p, h = _login(app_client, admin_session, tenant_a)
    c = Course(tenant_id=tenant_a.id, slug="notmine", title="NM", discipline="networking",
               source_ref="x", version=1)
    admin_session.add(c)
    admin_session.flush()
    admin_session.add(
        Chapter(tenant_id=tenant_a.id, course_id=c.id, number=1, title="One", part="I",
                body_html="<h2>Alpha</h2>", source_hash="sh2", order_index=1)
    )
    admin_session.commit()

    app_client.get("/", headers=h)  # obtain a csrf cookie
    hh = {**h, "x-csrf-token": app_client.cookies.get("csrf_token") or ""}
    r = app_client.post("/courses/notmine/chapters/1/subtopics/alpha/complete", headers=hh)
    assert r.status_code == 403

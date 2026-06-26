"""Tests for the student portal — Task 11 (htmx)."""

from __future__ import annotations

from app.services.security import hash_password
from app.models.person import Person
from app.models.auth import UserCredential
from app.models.course import Course, Chapter
from app.models.assessment import QuestionBank, Question, Activity


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
    admin_session.commit()

    # GET chapter page — response sets the csrf_token cookie in the TestClient jar.
    r_ch = app_client.get(f"/courses/foundation/chapters/3", headers=h)
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

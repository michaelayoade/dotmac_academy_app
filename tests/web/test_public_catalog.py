"""Public landing + catalog: the anonymous web presence (ADR 0003).

``Course.listed`` is the single selector for the public projection; these
tests pin the contract: anonymous ``/`` renders the landing (not a /login
redirect), ``/courses`` shows exactly the listed published courses, and the
signed-in ``/`` behaviour is unchanged.
"""

from __future__ import annotations

from app.models.course import Course

H = {"Host": "alpha.localhost"}


def _seed_courses(admin_session, tid):
    listed = Course(
        tenant_id=tid, slug="fiber-basics", title="Fiber Basics",
        discipline="networking", source_ref="t@1", listed=True,
    )
    unlisted_internal = Course(
        tenant_id=tid, slug="instructor-guide", title="Instructor Guide",
        discipline="teaching", source_ref="t@1", listed=False,
    )
    unlisted_mgmt = Course(
        tenant_id=tid, slug="mgmt-team-leadership", title="Leading a Team",
        discipline="management", source_ref="t@1", listed=False,
    )
    draft_listed = Course(
        tenant_id=tid, slug="draft-course", title="Draft Course",
        discipline="networking", source_ref="t@1", listed=True, status="draft",
    )
    admin_session.add_all([listed, unlisted_internal, unlisted_mgmt, draft_listed])
    admin_session.commit()


def test_anonymous_root_renders_landing_not_login_redirect(app_client, admin_session, tenant_a):
    _seed_courses(admin_session, tenant_a.id)
    r = app_client.get("/", headers=H, follow_redirects=False)
    assert r.status_code == 200
    assert "Browse the courses" in r.text


def test_public_courses_shows_only_listed_published(app_client, admin_session, tenant_a):
    _seed_courses(admin_session, tenant_a.id)
    r = app_client.get("/courses", headers=H)
    assert r.status_code == 200
    assert "Fiber Basics" in r.text
    assert "Instructor Guide" not in r.text     # unlisted internal
    assert "Leading a Team" not in r.text       # internal discipline, unlisted
    assert "Draft Course" not in r.text         # listed but not published


def test_signed_in_root_still_learn_home(app_client, admin_session, tenant_a):
    from app.models.auth import UserCredential
    from app.models.person import Person
    from app.services.security import hash_password

    _seed_courses(admin_session, tenant_a.id)
    p = Person(tenant_id=tenant_a.id, email="pl@alpha.edu", first_name="Pat", last_name="Lu")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(UserCredential(tenant_id=tenant_a.id, person_id=p.id,
                                     email="pl@alpha.edu",
                                     password_hash=hash_password("password1")))
    admin_session.commit()

    app_client.get("/login", headers=H)
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        "/login",
        data={"email": "pl@alpha.edu", "password": "password1"},
        headers={**H, "x-csrf-token": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303 and "session" in r.cookies
    r = app_client.get("/", headers=H, follow_redirects=False)
    assert r.status_code == 200
    # Learn Home, not the public landing.
    assert "Browse the courses" not in r.text

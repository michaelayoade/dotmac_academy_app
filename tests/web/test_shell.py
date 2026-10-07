"""Shell tests (Task 3 of increment 3a) — role-aware app shell HTML.

Drives the refactored base.html + shell partials end-to-end via the nav context
processor. Reuses the login pattern from tests/web/test_learn.py.
"""

from __future__ import annotations

import re

from app.models.auth import UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password


def _login(app_client, admin_session, tenant, *, email, role=None):
    """Seed a person (+credential, +optional role) and log them in.

    Returns (person, headers).
    """
    p = Person(tenant_id=tenant.id, email=email, first_name="Ada", last_name="Lovelace")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant.id,
            person_id=p.id,
            email=email,
            password_hash=hash_password("password1"),
        )
    )
    if role is not None:
        roles = ensure_roles(admin_session, tenant.id)
        admin_session.add(
            PersonRole(tenant_id=tenant.id, person_id=p.id, role_id=roles[role].id)
        )
    admin_session.commit()
    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": email, "password": "password1"})
    return p, h


def _collapse(text: str) -> str:
    """Collapse whitespace so assertions are robust to template formatting."""
    return re.sub(r"\s+", " ", text)


def test_student_shell_shows_learn_only(app_client, admin_session, tenant_a):
    p, h = _login(app_client, admin_session, tenant_a, email="student@a.edu")

    r = app_client.get("/progress", headers=h)
    assert r.status_code == 200
    body = _collapse(r.text)

    # Learn area tab + the Learn sidebar (Progress) are present.
    assert "Learn" in body
    assert "Progress" in body
    # The user menu shows the person's name.
    assert "Ada" in body and "Lovelace" in body
    # No higher-privilege areas leak to a student.
    assert "Teaching" not in body
    assert "Admin" not in body


def test_learning_workspace_requires_sign_in(app_client):
    response = app_client.get("/learn", headers={"Host": "alpha.localhost"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_instructor_can_switch_between_learning_and_teaching(app_client, admin_session, tenant_a):
    _p, h = _login(
        app_client,
        admin_session,
        tenant_a,
        email="dual-mode@a.edu",
        role="instructor",
    )

    # Keep Teaching as the default landing workspace for instructor-only users.
    root = app_client.get("/", headers=h, follow_redirects=False)
    assert root.status_code == 303
    assert root.headers["location"] == "/instructor"

    learning = app_client.get("/learn", headers=h)
    assert learning.status_code == 200
    assert 'aria-label="Workspace mode"' in learning.text
    assert 'href="/learn"' in learning.text
    assert 'href="/instructor"' in learning.text
    assert 'aria-label="Switch to Learning workspace" aria-current="page"' in learning.text

    teaching = app_client.get("/instructor", headers=h)
    assert teaching.status_code == 200
    assert 'aria-label="Switch to Teaching workspace" aria-current="page"' in teaching.text


def test_admin_shell_shows_all_areas(app_client, admin_session, tenant_a):
    p, h = _login(app_client, admin_session, tenant_a, email="admin@a.edu", role="admin")

    # On /progress the current area is Learn, but the TABS show every area.
    r = app_client.get("/progress", headers=h)
    assert r.status_code == 200
    body = _collapse(r.text)
    assert "Learn" in body
    assert "Teaching" in body
    assert "Admin" in body

    # On an admin page the SIDEBAR carries the admin items.
    r2 = app_client.get("/admin/settings", headers=h)
    assert r2.status_code == 200
    body2 = _collapse(r2.text)
    assert "Settings" in body2
    assert "Users" in body2

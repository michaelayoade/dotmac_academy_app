"""Cross-role nav integration (Task 10).

Proves the shell wiring is internally consistent:
  * every sidebar link in every area an admin can see resolves to a real route
    (not a 404), so nothing in the nav dead-ends;
  * the brand link points at the first area the current user may enter;
  * a student's shell leaks no Teaching/Admin links.
"""

from __future__ import annotations

import pytest

from app.models.auth import UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password
from app.web.nav import areas_for_roles

PLATFORM_TOKEN = "test-platform-admin-token"


@pytest.fixture(autouse=True)
def _platform_token(monkeypatch):
    """Configure the platform-admin secret so /admin/settings is reachable.

    (That route is gated by a separate platform-admin token dependency; without a
    configured secret it fails closed, which is unrelated to nav wiring.)
    """
    from app.config import settings

    # platform_admin_token only exists once the platform-auth work lands; guard so
    # these tests are correct whether or not /admin/settings is token-gated.
    if hasattr(settings, "platform_admin_token"):
        monkeypatch.setattr(settings, "platform_admin_token", PLATFORM_TOKEN)


def _seed_login(app_client, admin_session, tenant, email, role_slug):
    roles = ensure_roles(admin_session, tenant.id)
    p = Person(tenant_id=tenant.id, email=email, first_name="Nav", last_name="User")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(tenant_id=tenant.id, person_id=p.id, email=email,
                       password_hash=hash_password("password1"))
    )
    admin_session.add(
        PersonRole(tenant_id=tenant.id, person_id=p.id, role_id=roles[role_slug].id)
    )
    admin_session.commit()
    h = {"Host": "alpha.localhost", "x-platform-admin-token": PLATFORM_TOKEN}
    app_client.post("/login", headers=h, data={"email": email, "password": "password1"})
    return h


def test_admin_every_sidebar_link_resolves(app_client, admin_session, tenant_a):
    """No nav link dead-ends for an admin (who can see every area)."""
    h = _seed_login(app_client, admin_session, tenant_a, "admin@a.edu", "admin")
    for area in areas_for_roles(is_instructor=True, is_admin=True):
        for item in area["sidebar"]:
            r = app_client.get(item["path"], headers=h, follow_redirects=False)
            assert r.status_code in (200, 302, 303), (
                f"{area['key']} sidebar link {item['path']} -> {r.status_code}"
            )


def test_brand_links_to_first_permitted_area_home(app_client, admin_session, tenant_a):
    h = _seed_login(app_client, admin_session, tenant_a, "brand@a.edu", "admin")
    r = app_client.get("/progress", headers=h)
    assert r.status_code == 200
    first_home = areas_for_roles(is_instructor=True, is_admin=True)[0]["home"]
    assert f'href="{first_home}"' in r.text


def test_student_shell_has_no_teaching_or_admin_links(app_client, admin_session, tenant_a):
    h = _seed_login(app_client, admin_session, tenant_a, "stud@a.edu", "student")
    r = app_client.get("/", headers=h)
    assert r.status_code == 200
    # Neither the higher-area tabs nor their routes leak into a student's shell.
    assert "Teaching" not in r.text
    assert "Admin" not in r.text
    assert "/instructor" not in r.text
    assert "/admin" not in r.text

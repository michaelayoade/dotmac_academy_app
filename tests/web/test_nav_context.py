"""Dict-level tests for the role lookup + nav config (Task 2 of increment 3a).

HTML/shell tab assertions live in the Task 3 shell tests.
"""

from __future__ import annotations

from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.roles import role_slugs
from app.web import nav


def test_areas_for_roles_student():
    assert [a["key"] for a in nav.areas_for_roles(False, False)] == ["learn"]


def test_areas_for_roles_instructor():
    # A pure instructor (not also admin) gets the teaching area only — the learner
    # "learn" area is intentionally hidden for instructor-only accounts.
    assert [a["key"] for a in nav.areas_for_roles(True, False)] == ["teaching"]


def test_areas_for_roles_admin():
    assert [a["key"] for a in nav.areas_for_roles(False, True)] == [
        "learn",
        "teaching",
        "admin",
    ]


def test_area_for_path():
    assert nav.area_for_path("/instructor/cohorts") == "teaching"
    assert nav.area_for_path("/reports") == "teaching"
    assert nav.area_for_path("/admin/settings") == "admin"
    assert nav.area_for_path("/progress") == "learn"
    assert nav.area_for_path("/") == "learn"


def test_role_slugs_returns_held_roles(admin_session, tenant_a):
    roles = ensure_roles(admin_session, tenant_a.id)
    p = Person(tenant_id=tenant_a.id, email="r@a.edu", first_name="Role", last_name="Holder")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        PersonRole(tenant_id=tenant_a.id, person_id=p.id, role_id=roles["instructor"].id)
    )
    admin_session.commit()

    assert role_slugs(admin_session, tenant_a.id, p.id) == {"instructor"}

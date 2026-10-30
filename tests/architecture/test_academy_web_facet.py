"""C1.1: the secured staff_admin facet carries Academy's legacy web surface.

No-DB spec/registry assertions in the style of test_kernel_assembly.py.
Constructed-app assertions import app.main inside the test so spec-level
checks stay collectible even while construction is blocked.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

from dotmac_kernel.modules import ModuleRegistry
from dotmac_kernel.permissions import PermissionCatalogue
from dotmac_kernel.web_surfaces import BrowserSecurityPlane, WebSurfaceRegistry

from app.assembly import assembly

ROOT = Path(__file__).resolve().parents[2]

ENTRY_ROUTES = {
    "login_form",
    "login",
    "logout",
    "forgot_form",
    "forgot_submit",
    "reset_form",
    "reset_submit",
    "accept_form",
    "accept_submit",
    "apply_form",
    "submit_apply",
    "assessment_page",
    "assessment_start",
    "assessment_autosave",
    "assessment_submit",
    "onboarding_page",
    "confirm_details",
    "acknowledge_orientation",
    "resend_assessment",
    "courses_list",
    "management_enrollment_form",
    "submit_management_enrollment",
    "home",
    "learn_home",
    "calendar_feed",
}

STANDARD_ROLES = {"student", "instructor", "admin"}


def _enabled_manifests():
    return list(ModuleRegistry(assembly.modules).enabled_order())


def _registry() -> WebSurfaceRegistry:
    return WebSurfaceRegistry(
        manifests=_enabled_manifests(),
        facets=list(assembly.web_facets),
        authentication_profiles=list(assembly.authentication_profiles),
        ui_contract_version=assembly.ui_contract_version,
    )


def test_single_staff_admin_facet_at_root() -> None:
    assert len(assembly.web_facets) == 1
    facet = assembly.web_facets[0]
    assert facet.code == "staff_admin"
    assert facet.url_prefix == "/"
    assert facet.shell.name == "base.html"
    assert facet.authentication_profile == "academy_tenant_session"
    assert facet.admission_permission == "academy.web.access"
    assert facet.login_route.route_name == "login_form"
    assert facet.logout_route.route_name == "logout"
    assert facet.landing_route is None


def test_authentication_profile_is_tenant_cookie_session() -> None:
    assert len(assembly.authentication_profiles) == 1
    profile = assembly.authentication_profiles[0]
    assert profile.code == "academy_tenant_session"
    assert profile.security_plane is BrowserSecurityPlane.TENANT
    assert profile.session is not None
    assert profile.session.cookie_name == "session"
    assert profile.session.cookie_path == "/"


def test_admission_permission_owned_by_academy_and_bound_to_standard_roles() -> None:
    catalogue = PermissionCatalogue.from_manifests(assembly.modules)
    assert catalogue.owner("academy.web.access") == "academy"
    spec = catalogue.spec("academy.web.access")
    assert set(spec.default_roles) == STANDARD_ROLES

    assert {definition.code for definition in assembly.role_definitions} == STANDARD_ROLES
    assert len(assembly.role_grant_profiles) == 1
    grants = assembly.role_grant_profiles[0].grants
    assert {(grant.role_code, grant.permission_code) for grant in grants} == {
        (role, "academy.web.access") for role in STANDARD_ROLES
    }


def test_registry_yields_one_legacy_surface_with_exact_entry_routes() -> None:
    registry = _registry()
    surfaces = registry.surfaces
    assert len(surfaces) == 1
    surface = surfaces[0]
    assert surface.owner == "academy"
    assert surface.contribution.code == "legacy"
    assert surface.legacy is True
    assert len(surface.contribution.routers) == 27

    facet = registry.facet("staff_admin")
    assert {ref.route_name for ref in facet.entry_routes} == ENTRY_ROUTES
    assert len(facet.entry_routes) == 25
    for name in ENTRY_ROUTES:
        assert registry.is_entry_route(facet="staff_admin", owner="academy", surface="legacy", route_name=name)

    # Sampled guarded routes exist on the surface but are not entries.
    route_names = {
        route.name for router in surface.contribution.routers for route in router.routes if route.name
    }
    for guarded in ("cohorts_list", "users_list", "chapter", "applications_page"):
        assert guarded in route_names
        assert not registry.is_entry_route(
            facet="staff_admin", owner="academy", surface="legacy", route_name=guarded
        )


def test_constructed_app_has_websocket_route_and_qualified_web_names() -> None:
    from app.main import app

    # url_path_for is the public route-registry probe: it resolves only when a
    # route with that exact (qualified) name is mounted on the constructed app.
    assert str(app.url_path_for("web:staff_admin:academy:legacy:login_form")) == "/login"
    assert str(app.url_path_for("web:staff_admin:academy:legacy:home")) == "/"
    assert str(app.url_path_for("web:staff_admin:academy:legacy:learn_home")) == "/learn"
    ws_path = str(
        app.url_path_for(
            "console_ws",
            instance_id="00000000-0000-0000-0000-000000000001",
            node="node-1",
        )
    )
    assert ws_path == "/labs/instances/00000000-0000-0000-0000-000000000001/console/node-1/ws"

    registry = app.state.web_surface_registry
    assert {ref.route_name for ref in registry.facet("staff_admin").entry_routes} == ENTRY_ROUTES


def test_canonical_identity_fixtures_do_not_claim_reference_runtime() -> None:
    # Subprocess canary (style of test_academy_database_runtime): importing the
    # fixture plugin must not load dotmac_kernel.db, which would claim the
    # reference-runtime slot before create_app binds Academy's runtime.
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                """
                import sys

                import tests.canonical_identity_fixtures  # noqa: F401

                assert "dotmac_kernel.db" not in sys.modules
                """
            ),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, "isolated fixture canary failed; inspect securely in hosted CI"

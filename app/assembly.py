"""The Academy product assembly.

Academy owns learning, admissions, lab, reporting, and product workflows. The
kernel owns application construction, tenancy startup, the generic security
middleware stack, liveness, static/template layering, and error translation.

Academy's retained product tables stay product-owned. The installed Learning
manifest owns its stateful namespace independently of Academy route visibility.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Final

from dotmac_kernel import ProductAssemblySpec, ProductSecurityPolicy
from dotmac_kernel.api_documentation import environment_api_documentation_policy
from dotmac_kernel.permission_provisioning import RoleDefinition, RoleGrant, RoleGrantProfile
from dotmac_kernel.web_deps import TENANT_COOKIE_AUTHENTICATION
from dotmac_kernel.web_surfaces import (
    AuthenticationProfileBinding,
    BrowserSecurityPlane,
    BrowserSessionPolicy,
    NavigationRegion,
    TemplateRef,
    WebFacetMount,
    WebRouteRef,
)
from dotmac_ui import static_dir

from app.academy_declarations import ACADEMY_FEATURE_DECLARATION
from app.api.admissions import router as admissions_router
from app.api.auth import router as auth_router
from app.api.erp_applicant_assessments import router as erp_applicant_assessments_router
from app.api.persons import router as persons_router
from app.api.rbac import router as rbac_router
from app.config import ACADEMY_CONTENT_SECURITY_POLICY, settings, validate_settings
from app.database_runtime import get_academy_database_runtime
from app.error_tracking import init_error_tracking
from app.operational import router as operational_router
from app.owner_composition import compose_owner_declarations
from app.ui import UI_CONTRACT_VERSION, UI_STYLESHEET_URL
from app.web.account import router as web_account_router
from app.web.accounts import router as web_accounts_router
from app.web.admin_home import router as web_admin_router
from app.web.applications import router as web_applications_router
from app.web.apply import router as web_apply_router
from app.web.audit import router as web_audit_router
from app.web.auth import router as web_auth_router
from app.web.bookmarks import router as web_bookmarks_router
from app.web.calendar_feed import router as web_calendar_feed_router
from app.web.catalog import router as web_catalog_router
from app.web.gradebook import router as web_gradebook_router
from app.web.instructor import router as web_instructor_router
from app.web.lab_admin import router as web_lab_admin_router
from app.web.labs import router as web_labs_router
from app.web.labs import ws_router as web_labs_ws_router
from app.web.learn import router as web_learn_router
from app.web.lifecycle import router as web_lifecycle_router
from app.web.notifications import router as web_notifications_router
from app.web.onboarding import router as web_onboarding_router
from app.web.reminders_admin import router as web_reminders_admin_router
from app.web.reports import router as web_reports_router
from app.web.search import router as web_search_router
from app.web.settings import router as web_settings_router
from app.web.success_queue import router as web_success_queue_router
from app.web.teaching import router as web_teaching_router
from app.web.timetable import router as web_timetable_router
from app.web.todo import router as web_todo_router

_ROOT = Path(__file__).resolve().parent.parent

# Stable product identity is deliberately distinct from the underscore-form
# source-repository and Python-distribution coordinate ``dotmac_academy_app``.
# Neither spelling is a normalization of the other.
PRODUCT_ID: Final = "dotmac-academy"


def _academy_configuration_errors() -> list[str]:
    """Validate the product-owned settings inside the kernel lifespan."""
    return validate_settings(settings)


def _initialize_error_tracking() -> None:
    """Run Academy telemetry setup as an ordered product startup hook."""
    init_error_tracking(server_name=PRODUCT_ID)


academy_feature = replace(
    ACADEMY_FEATURE_DECLARATION,
    routers=(
        auth_router,
        erp_applicant_assessments_router,
        persons_router,
        admissions_router,
        rbac_router,
        operational_router,
    ),
    web_routers=(
        web_auth_router,
        web_lifecycle_router,
        web_instructor_router,
        web_accounts_router,
        web_applications_router,
        web_apply_router,
        web_onboarding_router,
        web_lab_admin_router,
        web_labs_router,
        web_labs_ws_router,
        web_catalog_router,
        web_search_router,
        web_learn_router,
        web_todo_router,
        web_calendar_feed_router,
        web_reports_router,
        web_gradebook_router,
        web_settings_router,
        web_teaching_router,
        web_timetable_router,
        web_audit_router,
        web_admin_router,
        web_notifications_router,
        web_account_router,
        web_reminders_admin_router,
        web_bookmarks_router,
        web_success_queue_router,
    ),
)

# One immutable installed-owner declaration source, independent of route switches.
OWNER_DECLARATIONS = compose_owner_declarations(academy_feature)

assembly = ProductAssemblySpec(
    name=PRODUCT_ID,
    modules=OWNER_DECLARATIONS,
    role_definitions=(
        RoleDefinition("student"),
        RoleDefinition("instructor"),
        RoleDefinition("admin"),
    ),
    # Exact compatibility shadow of PermissionSpec.default_roles — keep in
    # lockstep; the plan writes nothing, authorize_party reads default_roles.
    role_grant_profiles=(
        RoleGrantProfile(
            code="academy.web",
            version=1,
            grants=(
                RoleGrant("student", "academy.web.access"),
                RoleGrant("instructor", "academy.web.access"),
                RoleGrant("admin", "academy.web.access"),
            ),
        ),
    ),
    database_runtime=get_academy_database_runtime(),
    require_database_runtime=True,
    api_documentation=environment_api_documentation_policy(settings.environment),
    disabled_modules=frozenset(settings.disabled_feature_set),
    tenancy="single",
    platform_surface_enabled=False,
    web_enabled=settings.web_enabled,
    ui_contract_version=UI_CONTRACT_VERSION,
    web_facets=(
        WebFacetMount(
            # Kernel-mandated legacy label; audience = all Academy web.
            code="staff_admin",
            url_prefix="/",
            shell=TemplateRef("base.html"),
            authentication_profile="academy_tenant_session",
            admission_permission="academy.web.access",
            navigation_regions=(NavigationRegion("primary"),),
            entry_routes=(
                WebRouteRef("academy", "legacy", "login_form"),
                WebRouteRef("academy", "legacy", "login"),
                WebRouteRef("academy", "legacy", "logout"),
                WebRouteRef("academy", "legacy", "forgot_form"),
                WebRouteRef("academy", "legacy", "forgot_submit"),
                WebRouteRef("academy", "legacy", "reset_form"),
                WebRouteRef("academy", "legacy", "reset_submit"),
                WebRouteRef("academy", "legacy", "accept_form"),
                WebRouteRef("academy", "legacy", "accept_submit"),
                WebRouteRef("academy", "legacy", "apply_form"),
                WebRouteRef("academy", "legacy", "submit_apply"),
                WebRouteRef("academy", "legacy", "assessment_page"),
                WebRouteRef("academy", "legacy", "assessment_start"),
                WebRouteRef("academy", "legacy", "assessment_autosave"),
                WebRouteRef("academy", "legacy", "assessment_submit"),
                WebRouteRef("academy", "legacy", "onboarding_page"),
                WebRouteRef("academy", "legacy", "confirm_details"),
                WebRouteRef("academy", "legacy", "acknowledge_orientation"),
                WebRouteRef("academy", "legacy", "resend_assessment"),
                WebRouteRef("academy", "legacy", "courses_list"),
                WebRouteRef("academy", "legacy", "management_enrollment_form"),
                WebRouteRef("academy", "legacy", "submit_management_enrollment"),
                WebRouteRef("academy", "legacy", "home"),
                WebRouteRef("academy", "legacy", "learn_home"),
                WebRouteRef("academy", "legacy", "calendar_feed"),
            ),
            login_route=WebRouteRef("academy", "legacy", "login_form"),
            # landing_route intentionally None: Academy handlers compute their
            # own post-login redirects (app/web/auth.py).
            logout_route=WebRouteRef("academy", "legacy", "logout"),
        ),
    ),
    authentication_profiles=(
        AuthenticationProfileBinding(
            code="academy_tenant_session",
            provider=TENANT_COOKIE_AUTHENTICATION,
            session=BrowserSessionPolicy(cookie_name="session", cookie_path="/"),
            security_plane=BrowserSecurityPlane.TENANT,
        ),
    ),
    startup_checks=(_academy_configuration_errors,),
    startup_hooks=(_initialize_error_tracking,),
    security_policy=ProductSecurityPolicy(
        content_security_policy=ACADEMY_CONTENT_SECURITY_POLICY,
        cross_origin_opener_policy="same-origin",
        cross_origin_resource_policy="same-origin",
    ),
    assembly_template_dir=_ROOT / "templates",
    assembly_static_dir=_ROOT / "static",
    packaged_static_dirs=(static_dir(),),
    stylesheets=(UI_STYLESHEET_URL,),
    assembly_migrations=_ROOT / "alembic" / "identity_assembly_versions",
)

__all__ = ["OWNER_DECLARATIONS", "PRODUCT_ID", "academy_feature", "assembly"]

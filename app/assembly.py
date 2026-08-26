"""The Academy product assembly.

Academy owns learning, admissions, lab, reporting, and product workflows. The
kernel owns application construction, tenancy startup, the generic security
middleware stack, liveness, static/template layering, and error translation.

The single ``FeatureManifest`` is deliberately transitional. Academy's tables
still use the host migration lineage and public schema; declaring a stateful
``ModuleManifest`` before that authority is migrated would falsely claim that
the module already owns an independent namespace and lineage.
"""

from __future__ import annotations

from pathlib import Path

from dotmac_kernel import ProductAssemblySpec, ProductSecurityPolicy
from dotmac_kernel.features import FeatureManifest
from dotmac_ui import static_dir

from app.api.admissions import router as admissions_router
from app.api.auth import router as auth_router
from app.api.erp_applicant_assessments import router as erp_applicant_assessments_router
from app.api.managed_application_lifecycle import router as managed_application_lifecycle_router
from app.api.persons import router as persons_router
from app.api.rbac import router as rbac_router
from app.config import ACADEMY_CONTENT_SECURITY_POLICY, settings, validate_settings
from app.error_tracking import init_error_tracking
from app.operational import router as operational_router
from app.ui import UI_STYLESHEET_URL
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


def _academy_configuration_errors() -> list[str]:
    """Validate the product-owned settings inside the kernel lifespan."""
    return validate_settings(settings)


def _initialize_error_tracking() -> None:
    """Run Academy telemetry setup as an ordered product startup hook."""
    init_error_tracking()


academy_feature = FeatureManifest(
    name="academy",
    capabilities=("academy.application.lifecycle",),
    routers=(
        auth_router,
        erp_applicant_assessments_router,
        managed_application_lifecycle_router,
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

assembly = ProductAssemblySpec(
    name="dotmac_academy_app",
    modules=(academy_feature,),
    tenancy="single",
    platform_surface_enabled=False,
    web_enabled=True,
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
    assembly_migrations=_ROOT / "alembic" / "versions",
)

__all__ = ["academy_feature", "assembly"]

"""Shared route-free Academy declaration for web and migration composition."""

from dotmac_kernel.features import FeatureManifest
from dotmac_kernel.permissions import PermissionSpec

from app.api_identity_declarations import API_IDENTITY_AUDIT_ACTIONS

ACADEMY_FEATURE_DECLARATION = FeatureManifest(
    name="academy",
    audit_actions=API_IDENTITY_AUDIT_ACTIONS,
    permissions=(
        PermissionSpec(
            code="academy.web.access",
            description="Enter the Academy web portal.",
            default_roles=("student", "instructor", "admin"),
        ),
    ),
)

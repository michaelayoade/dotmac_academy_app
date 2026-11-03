"""Shared route-free Academy declaration for web and migration composition."""

from dotmac_kernel.features import FeatureManifest
from dotmac_kernel.permissions import PermissionSpec

from app.api_identity_declarations import API_IDENTITY_AUDIT_ACTIONS

FACILITATOR_AUDIT_ACTIONS = (
    "facilitator_nomination.create", "facilitator_nomination.activate", "facilitator_nomination.revoke",
)

# Written by the Academy credential adapters (app/services/credential_lifecycle.py,
# app/services/password_change.py). Kernel a107 reserves only identity.history_imported
# and credential.password.assigned, so the product declares these four.
CREDENTIAL_LIFECYCLE_AUDIT_ACTIONS = (
    "credential.sessions.revoked",
    "credential.reset.completed",
    "credential.reset_tokens.invalidated",
    "credential.password.changed",
)

ACADEMY_FEATURE_DECLARATION = FeatureManifest(
    name="academy",
    audit_actions=(
        *API_IDENTITY_AUDIT_ACTIONS,
        *FACILITATOR_AUDIT_ACTIONS,
        *CREDENTIAL_LIFECYCLE_AUDIT_ACTIONS,
    ),
    permissions=(
        PermissionSpec(
            code="academy.web.access",
            description="Enter the Academy web portal.",
            default_roles=("student", "instructor", "admin"),
        ),
    ),
)

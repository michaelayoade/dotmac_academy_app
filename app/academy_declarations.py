"""Shared route-free Academy declaration for web and migration composition."""

from dotmac_kernel.features import FeatureManifest

from app.api_identity_declarations import API_IDENTITY_AUDIT_ACTIONS

ACADEMY_FEATURE_DECLARATION = FeatureManifest(
    name="academy",
    audit_actions=API_IDENTITY_AUDIT_ACTIONS,
)

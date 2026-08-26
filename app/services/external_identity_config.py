"""The one process-held local identity-provider registration.

``provider_binding`` is trusted because Academy configured it locally; it is
never accepted merely because an approved command carried the same spelling.
The Settings object is constructed once at process import, so this module does
no environment or secret-store read on a request path.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import settings


@dataclass(frozen=True, slots=True)
class ExternalIdentityRegistration:
    provider_binding: str
    issuer: str


def installed_registration() -> ExternalIdentityRegistration | None:
    provider_binding = settings.oidc_provider_binding.strip()
    issuer = settings.oidc_issuer.strip()
    if not provider_binding or not issuer:
        return None
    return ExternalIdentityRegistration(
        provider_binding=provider_binding,
        issuer=issuer,
    )


def configuration_matches(*, provider_binding: str, issuer: str) -> bool:
    """Exact, case-sensitive corroboration against Academy's registration."""

    installed = installed_registration()
    if installed is None:
        return False
    return provider_binding.strip() == installed.provider_binding and issuer.strip() == installed.issuer


__all__ = [
    "ExternalIdentityRegistration",
    "configuration_matches",
    "installed_registration",
]

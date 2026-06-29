"""Host/path predicates used before tenant context is available."""

from __future__ import annotations


def is_platform_path(path: str, host: str, root: str) -> bool:
    """Return True for paths valid without a resolved tenant."""
    if path in {"/health", "/health/ready"}:
        return True
    return host == root

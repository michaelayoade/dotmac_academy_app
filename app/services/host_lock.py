"""Host-level mutual exclusion for containerlab operations.

Scaffold only — Stream C (lab-worker Phase 4 hardening) replaces this with the
full fcntl-based implementation. Kept minimal here so Streams A/B can import
``HostLockUnavailable`` and typecheck independently while Stream C is written
in parallel.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager


class HostLockUnavailable(RuntimeError):
    """Raised when the host containerlab lock is already held by another process."""


@contextmanager
def host_lock(label: str) -> Iterator[None]:
    """Placeholder — Stream C implements the real fcntl.flock-based lock here."""
    raise NotImplementedError("host_lock is implemented by Stream C")
    yield  # pragma: no cover

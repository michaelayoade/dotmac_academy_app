"""Host-level mutual exclusion for containerlab operations.

``containerlab`` mutates shared host state — the docker bridge, iptables/
nftables rules, ``/etc/hosts`` — that is not namespaced per lab. Two of these
run against the same lab host today with no serialisation between them:
``_lab_worker`` (a continuous 5s-poll loop draining durable operations) and
``_lab_reconcile`` (a 1-minute timer that inspects/repairs runtime drift).
Concurrent ``sudo containerlab`` invocations on different labs can therefore
race on that shared state. This module is the fix: a single host-wide,
non-blocking, crash-safe advisory lock both callers take before touching
containerlab.

Design notes (parallel to `dotmac_starter_mt`'s deployment lock, which is
inspiration only — this module has no dependency on that package):

- **Non-blocking.** ``fcntl.flock(..., LOCK_EX | LOCK_NB)``. A worker or
  reconciler pass that BLOCKED waiting for the lock would stall its whole
  loop; refusing immediately and letting the caller retry on its own natural
  cadence (5s poll / 1min timer) is the safe answer.
- **The refusal names the holder.** The lock file records the holding PID and
  a caller-supplied label. Knowing the lock is held is useless without
  knowing which process holds it.
- **It survives a crash.** An advisory ``fcntl`` lock is released by the
  kernel the instant the holding process exits, however it exits — clean
  return, exception, SIGKILL. A lock implemented as "does this file exist"
  does not have this property, and requires an operator to notice and delete
  a stale lock file by hand.
- **The file is never deleted.** Unlinking it would open a window where one
  process has unlinked the path while another already opened the same inode,
  and both then believe they hold the lock — the classic lockfile race. An
  empty, never-truncated-away file costs nothing to keep around.
"""

from __future__ import annotations

import errno
import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager

from app.config import settings

__all__ = ["HostLockUnavailable", "host_lock", "lock_path"]


class HostLockUnavailable(RuntimeError):
    """Raised when the host containerlab lock is already held by another process."""


def lock_path(directory: str | os.PathLike[str] | None = None) -> str:
    """Where the single host-wide containerlab lock file lives.

    Deliberately one path, not per-product/per-lab: the incident this guards
    against is two DIFFERENT labs' containerlab invocations mutating the same
    shared host state (bridge, iptables, /etc/hosts) concurrently, so every
    caller — worker and reconciler alike — must contend for the same lock.

    Defaults to ``settings.lab_workdir`` (default ``/home/dotmac/labs``)
    rather than ``/var/lock``: the worker/reconciler already have write
    access there, so this needs no new host permissions. ``ContainerlabEngine``
    passes its own configured ``workdir`` explicitly, which in production is
    always ``settings.lab_workdir`` (both ``_lab_worker`` and
    ``_lab_reconcile`` construct their engine with it) — the two stay
    identical in every real deployment, and the parameter only exists so
    tests can point an engine at an isolated ``tmp_path`` without a real
    lock file colliding with ``settings.lab_workdir`` on the machine
    running the tests.
    """
    base = directory if directory is not None else settings.lab_workdir
    return os.path.join(base, ".academy-containerlab.lock")


def _holder_description(path: str) -> str:
    """Whatever the lock file says about who holds it, without guessing."""
    try:
        with open(path, encoding="utf-8") as fh:
            recorded = fh.read().strip()
    except OSError:
        return "the holder could not be read"
    if not recorded:
        return "the holder is unrecorded"
    return f"held by {recorded!r}"


@contextmanager
def host_lock(
    label: str, *, directory: str | os.PathLike[str] | None = None
) -> Iterator[None]:
    """Hold the exclusive host containerlab lock for the duration of the block.

    Non-blocking: raises :class:`HostLockUnavailable` immediately if another
    process already holds it, naming that holder's recorded PID/label rather
    than blocking the caller's poll loop.

    ``label`` identifies the caller (e.g. ``"academy-lab-worker"`` or
    ``"academy-lab-reconcile"``) so contention messages and the lock file
    itself say who is doing what. ``directory`` overrides where the lock
    file lives (see :func:`lock_path`); omit it to use
    ``settings.lab_workdir``.
    """
    path = lock_path(directory)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                raise
            raise HostLockUnavailable(
                f"containerlab host lock {path} is already held — "
                f"{_holder_description(path)}; refusing to run {label!r} "
                "concurrently with another containerlab operation on this host"
            ) from exc
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()} {label}\n".encode())
        os.fsync(fd)
        try:
            yield
        finally:
            # Released on normal exit AND on the holder crashing — a killed
            # process has this fd closed by the kernel, which drops the
            # fcntl lock automatically. No special crash handling needed.
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

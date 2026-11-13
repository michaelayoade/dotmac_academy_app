"""Hosted-only custody checks using synthetic descriptors; never open host paths."""

import errno
import fcntl
import importlib.util
import os
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "synthetic_cutover_custody", Path(__file__).parents[1] / "candidate_execute.py"
)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def inode(mode, uid=0, links=1):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links)


class SyntheticDescriptors:
    """Model descriptor ownership, including kernel no-follow/directory refusals."""

    def __init__(self):
        self.directory = inode(stat.S_IFDIR | 0o701)
        self.lease = inode(stat.S_IFREG | 0o600)
        self.live = {}
        self.closed = []
        self.open_error = {}
        self.stat_error = {}
        self.sync_error = {}
        self.api = SimpleNamespace(**{name: getattr(os, name) for name in (
            "O_RDONLY", "O_RDWR", "O_CREAT", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC",
        )})
        self.api.open = Mock(side_effect=self.open)
        self.api.close = Mock(side_effect=self.close)
        self.api.fstat = Mock(side_effect=self.fstat)
        self.api.fsync = Mock(side_effect=self.fsync)

    @staticmethod
    def check(condition):
        if not condition:
            raise AssertionError("synthetic descriptor contract violated")

    def open(self, path, flags, mode=None, *, dir_fd=None):
        if path in self.open_error:
            raise self.open_error[path]
        if path == "/":
            fd, value = 10, inode(stat.S_IFDIR | 0o755)
            self.check(dir_fd is None)
        elif path == "root":
            fd, value = 11, self.directory
            self.check(self.live[dir_fd].st_mode == stat.S_IFDIR | 0o755)
        elif path == "academy-host-execution.lock":
            fd, value = 12, self.lease
            self.check(self.live[dir_fd] is self.directory)
            self.check(mode == 0o600)
        else:
            raise AssertionError("unexpected synthetic path")
        if stat.S_ISLNK(value.st_mode) and flags & os.O_NOFOLLOW:
            raise OSError(errno.ELOOP, "synthetic symlink")
        if flags & os.O_DIRECTORY and not stat.S_ISDIR(value.st_mode):
            raise NotADirectoryError(errno.ENOTDIR, "synthetic non-directory")
        self.check(fd not in self.live)
        self.live[fd] = value
        return fd

    def close(self, fd):
        self.check(fd in self.live)
        del self.live[fd]
        self.closed.append(fd)

    def fstat(self, fd):
        self.check(fd in self.live)
        if fd in self.stat_error:
            raise self.stat_error[fd]
        return self.live[fd]

    def fsync(self, fd):
        self.check(fd in self.live)
        if fd in self.sync_error:
            raise self.sync_error[fd]


class Custody(unittest.TestCase):
    def setUp(self):
        self.fs = SyntheticDescriptors()
        self.flock = Mock()
        for name, value in (
            ("os", self.fs.api),
            ("fcntl", SimpleNamespace(flock=self.flock, LOCK_EX=fcntl.LOCK_EX, LOCK_NB=fcntl.LOCK_NB)),
            ("EXECUTION_LOCK_FD", None),
        ):
            patcher = patch.object(P, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def assert_released(self):
        self.assertEqual(self.fs.live, {})
        self.assertIsNone(P.EXECUTION_LOCK_FD)
        self.assertEqual(len(self.fs.closed), len(set(self.fs.closed)))

    def test_protected_traversable_parent_accepts_and_returns_owned_descriptor(self):
        fd = P.directory_fd("/root", root_only=True)
        self.assertEqual(fd, 11)
        self.assertEqual(set(self.fs.live), {11})
        self.assertEqual(self.fs.closed, [10])
        for call in self.fs.api.open.call_args_list:
            self.assertEqual(
                call.args[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
        self.fs.api.close(fd)
        self.assert_released()

    def test_private_parent_still_rejects_traversable_root(self):
        with self.assertRaisesRegex(ValueError, "private_parent"):
            P.directory_fd("/root", root_only=True, private=True)
        self.assertEqual(self.fs.closed, [10, 11])
        self.assert_released()

    def test_private_parent_accepts_root0700(self):
        self.fs.directory = inode(stat.S_IFDIR | 0o700)
        fd = P.directory_fd("/root", root_only=True, private=True)
        self.assertEqual(set(self.fs.live), {fd})
        self.fs.api.close(fd)
        self.assert_released()

    def test_unsafe_directory_owner_or_write_permissions_release_descriptor(self):
        for mode, uid in ((0o721, 0), (0o703, 0), (0o701, 1000)):
            with self.subTest(mode=mode, uid=uid):
                self.fs.directory = inode(stat.S_IFDIR | mode, uid=uid)
                with self.assertRaisesRegex(ValueError, "unsafe_directory"):
                    P.directory_fd("/root", root_only=True)
                self.assertEqual(self.fs.live, {})
        self.assertIsNone(P.EXECUTION_LOCK_FD)

    def test_directory_symlink_and_non_directory_open_refusals_close_ancestor(self):
        for kind, exception in ((stat.S_IFLNK, OSError), (stat.S_IFREG, NotADirectoryError)):
            with self.subTest(kind=kind):
                self.fs.directory = inode(kind | 0o700)
                with self.assertRaises(exception):
                    P.directory_fd("/root", root_only=True)
                self.assertEqual(self.fs.live, {})
        self.assertEqual(self.fs.closed, [10, 10])

    def test_directory_stat_failure_closes_current_descriptor(self):
        self.fs.stat_error[11] = OSError("synthetic stat denied")
        with self.assertRaisesRegex(OSError, "stat denied"):
            P.directory_fd("/root", root_only=True)
        self.assertEqual(self.fs.closed, [10, 11])
        self.assert_released()

    def test_invalid_directory_paths_refuse_before_open(self):
        for path in ("root", "/root/../other"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "directory_path"):
                P.directory_fd(path, root_only=True)
        self.fs.api.open.assert_not_called()
        self.assert_released()

    def test_lease_success_keeps_only_locked_file_descriptor_until_process_exit(self):
        P.host_execution_lock()
        self.assertEqual(P.EXECUTION_LOCK_FD, 12)
        self.assertEqual(self.fs.live, {12: self.fs.lease})
        self.assertEqual(self.fs.closed, [10, 11])
        self.fs.api.open.assert_called_with(
            "academy-host-execution.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=11,
        )
        self.flock.assert_called_once_with(12, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual([c.args for c in self.fs.api.fsync.call_args_list], [(12,), (11,)])
        # No explicit release is exposed by the executor; the process owns the lease.
        self.assertNotIn(12, self.fs.closed)

    def test_lease_reentry_refuses_without_opening_or_releasing_held_fd(self):
        P.EXECUTION_LOCK_FD = 99
        with self.assertRaisesRegex(ValueError, "execution_lease_already_acquired"):
            P.host_execution_lock()
        self.fs.api.open.assert_not_called()
        self.fs.api.close.assert_not_called()
        self.flock.assert_not_called()
        self.assertEqual(P.EXECUTION_LOCK_FD, 99)

    def test_bad_lease_inode_refuses_before_flock_and_releases_all_descriptors(self):
        cases = (
            inode(stat.S_IFREG | 0o640), inode(stat.S_IFREG | 0o400),
            inode(stat.S_IFREG | 0o600, uid=1000), inode(stat.S_IFREG | 0o600, links=2),
            inode(stat.S_IFREG | 0o600, links=0), inode(stat.S_IFDIR | 0o600),
            inode(stat.S_IFIFO | 0o600),
        )
        for value in cases:
            with self.subTest(inode=value):
                self.fs.lease = value
                with self.assertRaisesRegex(ValueError, "execution_lease_inode"):
                    P.host_execution_lock()
                self.assertEqual(self.fs.live, {})
                self.assertIsNone(P.EXECUTION_LOCK_FD)
        self.flock.assert_not_called()
        self.fs.api.fsync.assert_not_called()
        self.assertEqual(self.fs.closed, [10, 12, 11] * len(cases))

    def test_lease_symlink_refuses_at_open_and_releases_parent(self):
        self.fs.lease = inode(stat.S_IFLNK | 0o600)
        with self.assertRaises(OSError) as caught:
            P.host_execution_lock()
        self.assertEqual(caught.exception.errno, errno.ELOOP)
        self.flock.assert_not_called()
        self.assertEqual(self.fs.closed, [10, 11])
        self.assert_released()

    def test_parent_open_failure_propagates_without_lock_or_leaked_ancestor(self):
        self.fs.open_error["root"] = PermissionError("synthetic parent denied")
        with self.assertRaisesRegex(PermissionError, "parent denied"):
            P.host_execution_lock()
        self.flock.assert_not_called()
        self.assertEqual(self.fs.closed, [10])
        self.assert_released()

    def test_lease_open_failure_releases_parent(self):
        self.fs.open_error["academy-host-execution.lock"] = PermissionError("synthetic file denied")
        with self.assertRaisesRegex(PermissionError, "file denied"):
            P.host_execution_lock()
        self.flock.assert_not_called()
        self.assertEqual(self.fs.closed, [10, 11])
        self.assert_released()

    def test_lease_stat_failure_releases_parent_and_file(self):
        self.fs.stat_error[12] = OSError("synthetic inode unavailable")
        with self.assertRaisesRegex(OSError, "inode unavailable"):
            P.host_execution_lock()
        self.flock.assert_not_called()
        self.assertEqual(self.fs.closed, [10, 12, 11])
        self.assert_released()

    def test_contention_and_flock_exceptions_release_descriptors_without_sync(self):
        for error in (BlockingIOError(errno.EWOULDBLOCK, "synthetic busy"), OSError("flock failed"),
                      KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                self.flock.side_effect = error
                with self.assertRaises(type(error)):
                    P.host_execution_lock()
                self.assertEqual(self.fs.live, {})
                self.assertIsNone(P.EXECUTION_LOCK_FD)
        self.fs.api.fsync.assert_not_called()
        self.assertEqual(self.fs.closed, [10, 12, 11] * 3)

    def test_sync_failure_after_flock_never_publishes_or_retains_lease(self):
        for fd in (12, 11):
            with self.subTest(fd=fd):
                self.fs.sync_error = {fd: OSError("synthetic sync failed")}
                with self.assertRaisesRegex(OSError, "sync failed"):
                    P.host_execution_lock()
                self.assertEqual(self.fs.live, {})
                self.assertIsNone(P.EXECUTION_LOCK_FD)
        self.assertEqual(self.fs.closed, [10, 12, 11] * 2)

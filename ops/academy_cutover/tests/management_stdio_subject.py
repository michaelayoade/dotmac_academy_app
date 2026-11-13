"""Exact stdio functions, with no operational configuration or entry point.

Import is reserved for the configured hosted regression; defaults grant no host
or filesystem authority. The test supplies a temporary directory and a closed
synthetic process adapter.
"""

import hashlib
import json
import os
import resource
import shlex
import stat
import subprocess
import sys
import time
from contextlib import ExitStack

if not (
    os.environ.get("GITHUB_ACTIONS") == "true"
    and "pytest" in sys.modules
    and "test_stdin_file_delivery.py::" in os.environ.get("PYTEST_CURRENT_TEST", "")
):
    raise RuntimeError("configured hosted stdio regression required")

BASE = None
SSH = {}
ATTEMPT = "v2"


class Hold(Exception):
    pass


def require(value):
    if not value:
        raise Hold("manual_reconciliation_required")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def exclusive(name):
    fd = os.open(BASE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    return os.fdopen(fd, "wb")


def event(journal, phase, **values):
    journal.write(json.dumps({"phase": phase, "unix": int(time.time()), **values}, sort_keys=True).encode() + b"\n")
    journal.flush()
    os.fsync(journal.fileno())


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (67_108_864, 67_108_864))


def invoke(role, phase, command, journal, payload=None):
    clean = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=/root", *command]
    if role == "lab":
        clean = ["/usr/bin/sudo", "-n", *clean]
    argv = [
        "/usr/bin/ssh", "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oForwardAgent=no",
        "-oClearAllForwardings=yes", "-oConnectTimeout=15", "-oConnectionAttempts=1",
        "-oServerAliveInterval=15", "-oServerAliveCountMax=3", SSH[role], shlex.join(clean),
    ]
    prefix = role + "-" + ATTEMPT + "-" + phase
    stdout_name = prefix + ".stdout.json"
    stderr_name = prefix + ".stderr.log"
    with ExitStack() as stack:
        stdout = stack.enter_context(exclusive(stdout_name))
        stderr = stack.enter_context(exclusive(stderr_name))
        transfer = None
        input_sha = None
        if payload is not None:
            require(type(payload) is bytes and len(payload) <= 4_000_000)
            input_name = prefix + ".stdin.json"
            with exclusive(input_name) as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            fd = os.open(BASE / input_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            transfer = stack.enter_context(os.fdopen(fd, "rb", buffering=0))
            before = os.fstat(transfer.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                    and before.st_size == len(payload) and transfer.read(4_000_001) == payload)
            require(os.lseek(transfer.fileno(), 0, os.SEEK_SET) == 0)
            input_sha = digest(payload)
        process = subprocess.Popen(  # noqa: S603 -- module-owned existing management SSH and finite argv
            argv, stdin=transfer if transfer is not None else subprocess.DEVNULL,
            stdout=stdout, stderr=stderr, shell=False, close_fds=True,
            start_new_session=True, preexec_fn=child_limits,
        )
        event(journal, phase + "_client_started", pid=process.pid, input_sha256=input_sha,
              input_bytes=len(payload) if payload is not None else 0)
        started = time.monotonic()
        held = False
        while True:
            try:
                process.wait(timeout=1)
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() - started > 420 and not held:
                    held = True
                    event(journal, phase + "_observation_deadline_hold", pid=process.pid)
                    print(json.dumps({"role": role, "phase": phase, "status": "manual_hold_live_client"}), flush=True)
                # Keep the same live handle. Elapsed time is not termination or cleanup.
        stdout.flush()
        stderr.flush()
        os.fsync(stdout.fileno())
        os.fsync(stderr.fileno())
        event(journal, phase + "_client_terminal", pid=process.pid, returncode=process.returncode, held=held)
        if transfer is not None:
            consumed = transfer.tell()
            transfer.seek(0)
            require(digest(transfer.read(4_000_001)) == input_sha
                    and file_identity(os.fstat(transfer.fileno())) == file_identity(before)
                    and file_identity(os.lstat(BASE / input_name)) == file_identity(before))
            event(journal, phase + "_input_file_retained", local_read_offset=consumed,
                  input_bytes=len(payload), input_sha256=input_sha,
                  meaning="Local file offset only; remote staging acknowledgement is still required")
        require(not held and process.returncode == 0)
    require((BASE / stderr_name).stat().st_size == 0)
    return json.loads((BASE / stdout_name).read_bytes())


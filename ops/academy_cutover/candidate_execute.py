"""Host-local successor executor. Technical source only; preparation never executes it.

Trusted Linux system Python -I -S, root, one coordinator. Peer observations use
only the fixed approved transport. No installation, authentication provisioning,
approval creation, restore or deletion. Every started phase has an O_EXCL durable
intent; failure preserves it and all partial state. Migration never auto-replays.
Promotion, stop-new and resume are deliberately unsupported pending independent
review of effective environment and candidate process/acceptance producers.
"""

# ruff: noqa: E501 -- fixed contracts and commands remain directly auditable.
import argparse
import email.parser
import fcntl
import hashlib
import io
import json
import os
import pwd
import re
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
import tomllib
import types
import zipfile
from datetime import datetime
from pathlib import Path

OLD = "d12260b6996b18b27e04a784042f764bd583952d"
OLD_SOURCE = "/home/dotmac/projects/academy-v2-csp-stage-" + OLD
OLD_VENV = "/home/dotmac/.local/share/academy-v2-venvs/" + OLD
RELEASE_7EF = "7ef72b3d1c23a5bf4d3268a6cf21a3d46673db46"
PRIOR_PATHS = (
    OLD_SOURCE,
    OLD_VENV,
    "/home/dotmac/projects/academy-v2-release-" + RELEASE_7EF,
    "/home/dotmac/.local/share/academy-v2-venvs/" + RELEASE_7EF,
)
HOSTS = {"web": "vmi2490731", "lab": "academy-labs"}
NAMES = (
    "admin-report",
    "email-digest",
    "email-outbox",
    "erp-training-sync",
    "hr-report",
    "learner-digest",
    "reminders",
)
PHASES = (
    "baseline",
    "quiesce",
    "db-before",
    "migrate-kernel0031",
    "db-after",
    "promote",
    "stop-new",
    "resume",
)
STAGE_HISTORICAL_LIMITS = (
    "independent_artifact_provenance_and_offline_wheel_closure",
    "exact_final_candidate_ci_and_freeze",
    "database_revision_schema_acl_and_migration",
    "fresh_quiescence_gate_epoch_and_sender_exclusion",
    "exact_production_approval",
    "candidate_bound_acceptance_and_active_process_proof",
)
BASELINE_REVISIONS = ["a0011_oidc_login_states"]
FINAL_REVISIONS = ["0031_rate_limit_buckets", "a0011_oidc_login_states"]
MIGRATION_PIPELINE = {"db-before", "migrate-kernel0031", "db-after"}
UNSUPPORTED = {"promote", "stop-new", "resume"}
HR_HASH = "3c0af96dcca4e6b038ad6d390a46d4e65c2feb96ed0d0696e1c5ef54ec0bb45d"  # Historical D122 command.
HR_HASHES = {
    OLD_VENV: HR_HASH,
    "/home/dotmac/.local/share/academy-v2-venvs/"
    + RELEASE_7EF: "6c1791430d224efa5397063573aaf2fca745b747a40e15ccf4af154d12df1417",
}
PROPS = "WorkingDirectory,ExecStart,EnvironmentFiles,Environment,PassEnvironment,UnsetEnvironment,User,Group,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,ReadWritePaths,ReadOnlyPaths,RootDirectory,Type"
SOURCE = VENV = ""  # Set only from strict frozen manifest.
PROCESS_GROUPS = []
SPAWNING = PENDING_INTERRUPT = False
INTERRUPTS = (signal.SIGINT, signal.SIGTERM)
EXECUTION_LOCK_FD = None
_CENSUS_HELPER_MODULES = {}


def require(ok, reason="guard_refused"):
    if not ok:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


sha = digest


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def exact(value, names):
    require(type(value) is dict and set(value) == set(names), "strict_object_fields")
    return value


def hexvalue(value, size=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{" + str(size) + "}", value), "hash_format")
    return value


def decode(raw):
    def pairs(rows):
        out = {}
        for key, val in rows:
            require(key not in out, "duplicate_json_key")
            out[key] = val
        return out

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "nonfinite_json"))


def directory_fd(path, retained=False, root_only=False, private=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "directory_path")
    owners = {0} if root_only else {0, pwd.getpwnam("dotmac").pw_uid}
    retained_roots = (*PRIOR_PATHS, "/home/dotmac/projects/dotmac_academy_v2")
    retained = retained and any(path.is_relative_to(Path(root)) for root in retained_roots)
    legacy = {
        "/home/dotmac/projects",
        "/home/dotmac/.local",
        "/home/dotmac/.local/share",
        "/home/dotmac/.local/share/academy-v2-venvs",
        *retained_roots,
    }
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    current = Path("/")
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            current /= part
            info = os.fstat(fd)
            old_exception = retained and str(current) in legacy and stat.S_IMODE(info.st_mode) == 0o775
            require(info.st_uid in owners and (not info.st_mode & 0o022 or old_exception), "unsafe_directory")
        info = os.fstat(fd)
        if private:
            require(path.parts[1] == "root" and info.st_uid == 0 and not info.st_mode & 0o077, "private_parent")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_bytes(path, limit=200000000, private=False, public_helper=False, strict=True, root_file=False, mode=None):
    path = Path(path)
    retained = any(path.is_relative_to(Path(p)) for p in PRIOR_PATHS)
    retained = retained or path.is_relative_to(Path("/home/dotmac/projects/dotmac_academy_v2"))
    parent = directory_fd(
        path.parent, retained=retained, root_only=private or public_helper or root_file, private=private
    )
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and before.st_size <= limit
                and not before.st_mode & 0o022,
                "regular_bound_mode",
            )
            require(before.st_uid in {0, pwd.getpwnam("dotmac").pw_uid}, "file_owner")
            if root_file:
                require(before.st_uid == 0, "root_file_owner")
            if mode is not None:
                require(stat.S_IMODE(before.st_mode) == mode, "file_exact_mode")
            if private:
                require(before.st_uid == 0 and not before.st_mode & 0o077, "private_file")
            if public_helper:
                require(before.st_uid == 0 and stat.S_IMODE(before.st_mode) == 0o644, "public_helper_root0644")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            require(
                len(raw) <= limit
                and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "read_changed",
            )
            return raw
    finally:
        os.close(parent)


def private(path):
    read_bytes(path, limit=2000000, private=True)
    return Path(path)


def load(path):
    raw = read_bytes(path, limit=2000000, private=True)
    return decode(raw), digest(raw)


def no_links(path):
    path = Path(path)
    parent = directory_fd(path.parent)
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(not stat.S_ISLNK(info.st_mode), "unexpected_symlink")
    finally:
        os.close(parent)
    return path


def pinned(path, expected, private=False):
    require(digest(read_bytes(path, private=private)) == hexvalue(expected), "pinned_file_drift")
    return Path(path)


def common_api():
    """Expose this reviewed module's primitives without importing application code."""
    return types.SimpleNamespace(**globals())


def census_module(m):
    """Load the pinned census verifier from this root-private sibling only."""
    path = Path(__file__).absolute().with_name("candidate_external_census.py")
    raw = read_bytes(path, limit=2000000, private=True)
    require(digest(raw) == hexvalue(m["helpers"]["external_census"]), "census_helper_hash")
    module = types.ModuleType("academy_reviewed_external_census")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)  # noqa: S102 -- pinned root-private stdlib-only helper
    for name in ("load_scope", "verify_receipt_sources"):
        require(callable(getattr(module, name, None)), "census_verifier_api_required")
    return module


def census_scope(m):
    scope, scope_hash = census_module(m).load_scope(common_api(), m)
    hexvalue(scope_hash)
    require(
        type(scope) is dict and scope.get("coverage_complete") is True and scope.get("unresolved_coverage") == [],
        "complete_answered_authority_scope_required",
    )
    return scope, scope_hash


def census_transport_module(m):
    """Load one actual fixed transport instance; its nonce registry is process-local."""
    path = Path(__file__).absolute().with_name("candidate_census_transport.py")
    expected = hexvalue(m["helpers"]["census_transport"])
    raw = read_bytes(path, limit=2_000_000, private=True, root_file=True, mode=0o600)
    require(digest(raw) == expected, "census_transport_actual_source")
    key = (str(path), expected)
    if key not in _CENSUS_HELPER_MODULES:
        module = types.ModuleType("academy_reviewed_census_transport")
        module.__file__ = str(path)
        exec(compile(raw, str(path), "exec"), module.__dict__)  # noqa: S102 -- fixed protected source
        for name in ("validate_profile", "archived_source_ref", "request_current", "verify_current", "observe_local_leaf"):
            require(callable(getattr(module, name, None)), "census_transport_required_api")
        _CENSUS_HELPER_MODULES[key] = module
    return _CENSUS_HELPER_MODULES[key]


def census_domain_module(m):
    """Load the fixed process/domain implementation without application imports."""
    path = Path(__file__).absolute().with_name("candidate_census_domains.py")
    raw = read_bytes(path, limit=2_000_000, private=True, root_file=True, mode=0o600)
    require(digest(raw) == hexvalue(m["helpers"]["census_domains"]), "census_domain_actual_source")
    module = types.ModuleType("academy_reviewed_census_domains")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)  # noqa: S102 -- fixed protected source
    for name in ("collect_role", "require_complete_role_scope", "require_complete_scope"):
        require(callable(getattr(module, name, None)), "census_domain_required_api")
    discovery = path.with_name("candidate_authority_discovery.py")
    raw = read_bytes(discovery, limit=2_000_000, private=True, root_file=True, mode=0o600)
    require(
        digest(raw) == hexvalue(m["helpers"]["census_discovery"]) == module.DISCOVERY_SHA256,
        "census_approved_discovery_actual_source",
    )
    return module


def maintenance_module(m):
    exact(m["maintenance"], ("path", "sha256"))
    hexvalue(m["maintenance"]["sha256"])
    pin = m["helpers"]["maintenance"]
    exact(pin, ("path", "sha256"))
    path = Path(pin["path"])
    require(
        path.is_absolute() and path.name == "candidate_maintenance.py" and ".." not in path.parts,
        "maintenance_helper_path",
    )
    raw = read_bytes(path, limit=2000000, private=True)
    require(digest(raw) == hexvalue(pin["sha256"]), "maintenance_helper_hash")
    module = types.ModuleType("academy_reviewed_maintenance")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)  # noqa: S102 -- exact reviewed root-private stdlib-only helper
    return module


def maintenance_observation(m, evidence, approval, role, status):
    require(status in {"fenced", "adopted_and_fenced", "resumed"}, "maintenance_status")
    return maintenance_module(m).verify_observation(common_api(), m, evidence, approval, role, status)


def baseline_module(m):
    """Load only reviewed root-private sibling bytes, without candidate imports."""
    path = Path(__file__).absolute().with_name("candidate_baseline.py")
    require(path.name == "candidate_baseline.py", "baseline_helper_basename")
    raw = read_bytes(path, limit=2000000, private=True)
    require(digest(raw) == hexvalue(m["helpers"]["candidate_baseline.py"]), "baseline_helper_hash")
    module = types.ModuleType("academy_reviewed_runtime_baseline")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)  # noqa: S102 -- exact hash-reviewed root-private stdlib-only helper
    require(tuple(module.forbidden_runtime_paths()) == PRIOR_PATHS, "baseline_prior_paths")
    return module


def baseline_runtime(m, role):
    spec = m["roles"][role]
    return baseline_module(m).validate_runtime(spec["runtime_baseline"], role, spec["uid"])


def retained_environment_target(m, role):
    return baseline_module(m).environment_file(baseline_runtime(m, role))["target"]


def observed_environment(runtime):
    """Verify the descriptor's one explicit link and canonical regular target."""
    env = runtime["environment"]
    path, target = Path(env["path"]), Path(env["target"])

    def identity(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    anchor = directory_fd(path.parent, retained=True)
    try:
        info = os.stat(path.name, dir_fd=anchor, follow_symlinks=False)
        if env["link_target"] is None:
            require(stat.S_ISREG(info.st_mode) and path == target, "environment_regular_shape")
        else:
            require(
                stat.S_ISLNK(info.st_mode)
                and info.st_uid in (0, pwd.getpwnam("dotmac").pw_uid)
                and os.readlink(path.name, dir_fd=anchor) == env["link_target"],
                "environment_link_drift",
            )
    finally:
        os.close(anchor)
    anchor = directory_fd(target.parent, retained=True)
    try:
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=anchor)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and before.st_size <= 2000000
                and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
                == (env["uid"], env["gid"], env["mode"]),
                "environment_target_metadata",
            )
            raw = stream.read(2000001)
            require(
                identity(before) == identity(os.fstat(stream.fileno()))
                and len(raw) == before.st_size
                and digest(raw) == env["sha256"],
                "environment_target_bytes",
            )
    finally:
        os.close(anchor)
    anchor = directory_fd(path.parent, retained=True)
    try:
        require(
            identity(info) == identity(os.stat(path.name, dir_fd=anchor, follow_symlinks=False)),
            "environment_path_changed",
        )
    finally:
        os.close(anchor)
    return env["sha256"]


def write_new(path, value):
    path = Path(path)
    parent = directory_fd(path.parent, root_only=True, private=True)
    try:
        fd = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent
        )
        with os.fdopen(fd, "wb") as output:
            output.write(canonical(value) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def host_execution_lock():
    """Hold a stable per-host lease across all common and promotion phases."""
    global EXECUTION_LOCK_FD
    require(EXECUTION_LOCK_FD is None, "execution_lease_already_acquired")
    # The protected root-owned directory may allow traversal (for example0701).
    # The lease itself must still be a root-owned, single-link0600 regular file.
    parent = directory_fd("/root", root_only=True)
    fd = None
    try:
        fd = os.open(
            "academy-host-execution.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600,
            "execution_lease_inode",
        )
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(fd)
        os.fsync(parent)
        EXECUTION_LOCK_FD = fd  # O_CLOEXEC; parent retains lease until process exit.
        fd = None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


class ExecuteInterrupted(BaseException):
    pass


class ProcessCleanupUnconfirmed(Exception):
    pass


def interrupt_stage(_signum, _frame):
    global PENDING_INTERRUPT
    if SPAWNING:
        PENDING_INTERRUPT = True
        return
    raise ExecuteInterrupted()


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def cleanup_group(proc):
    """Bounded cleanup of owned session; escaped descendants remain census work."""
    handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in INTERRUPTS}
    result = dict(
        pgid=proc.pid, confirmed=False, term_sent=False, kill_sent=False, child_reaped=False, pipes_closed=False
    )
    try:
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe:
                pipe.close()
        result["pipes_closed"] = True
        for sig, key in ((signal.SIGTERM, "term_sent"), (signal.SIGKILL, "kill_sent")):
            try:
                os.killpg(proc.pid, sig)
                result[key] = True
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    proc.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    continue
                result["child_reaped"] = True
                if not group_present(proc.pid):
                    result["confirmed"] = True
                    return result
                time.sleep(0.05)
        return result
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except BaseException:
            result["kill_retry_unconfirmed"] = True
        return result
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def bounded_communicate(proc, input_bytes, timeout, absolute_deadline=None):
    """Nonblocking bounded read/write, including child stdin and descendant pipes."""
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    pending = memoryview(input_bytes)
    deadline = absolute_deadline if absolute_deadline is not None else time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        for pipe, tag in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, tag)
        if proc.stdin:
            if pending:
                os.set_blocking(proc.stdin.fileno(), False)
                selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                proc.stdin.close()
        while selector.get_map():
            require(time.monotonic() < deadline, "child_timeout")
            for key, _ in selector.select(timeout=min(0.1, max(0, deadline - time.monotonic()))):
                if key.data == "stdin":
                    try:
                        pending = pending[os.write(key.fd, pending[:16384]) :]
                    except BrokenPipeError:
                        require(False, "child_stdin_refused")
                    if not pending:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    data = os.read(key.fd, 65536)
                    if data:
                        outputs[key.data].extend(data)
                        require(len(outputs[key.data]) <= 8000000, "child_output_bound")
                    else:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
    proc.wait(timeout=max(0.01, deadline - time.monotonic()))
    return bytes(outputs["stdout"]), bytes(outputs["stderr"])


def run_group(argv, env, timeout, input_bytes=b"", ddl_authority=None, **kwargs):
    global SPAWNING, PENDING_INTERRUPT
    proc = None
    recorded = False
    ddl_deadline = None
    require(len(input_bytes) <= 65536, "child_stdin_bound")
    if input_bytes:
        kwargs["stdin"] = subprocess.PIPE
    try:
        SPAWNING = True
        try:
            if ddl_authority is not None:
                evidence, phase = ddl_authority
                revalidate_ddl_authority(evidence, phase)
                checked_monotonic = time.monotonic()
                timeout = min(timeout, evidence.a["expires_unix"] - time.time())
                require(timeout > 0, "mutation_approval_deadline")
                ddl_deadline = checked_monotonic + timeout
                if PENDING_INTERRUPT:
                    PENDING_INTERRUPT = False
                    raise ExecuteInterrupted()
            proc = subprocess.Popen(  # noqa: S603 -- fixed module-owned argv, never shell
                argv,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                **kwargs,
            )
        finally:
            SPAWNING = False
        if PENDING_INTERRUPT:
            PENDING_INTERRUPT = False
            raise ExecuteInterrupted()
        if ddl_deadline is not None:
            require(time.monotonic() < ddl_deadline, "ddl_deadline_expired_during_spawn")
        stdout, stderr = bounded_communicate(proc, input_bytes, timeout, absolute_deadline=ddl_deadline)
        if ddl_deadline is not None:
            require(time.monotonic() < ddl_deadline, "ddl_deadline_expired_during_communication")
        outcome = (
            cleanup_group(proc)
            if group_present(proc.pid)
            else dict(
                pgid=proc.pid,
                confirmed=True,
                child_reaped=True,
                pipes_closed=True,
                term_sent=False,
                kill_sent=False,
            )
        )
        PROCESS_GROUPS.append(outcome)
        recorded = True
        require(outcome["confirmed"], "owned_process_group_cleanup_unconfirmed")
        return proc.returncode, stdout, stderr
    except BaseException:
        if proc is not None and not recorded:
            PROCESS_GROUPS.append(cleanup_group(proc))
        elif proc is None:
            PROCESS_GROUPS.append(dict(confirmed=False, spawn_handle_unavailable=True))
        raise


def allowed_inventory_link(path, root, target, runtime=None):
    """Record only explicit link recipes; never read file contents through links."""
    if root == Path(VENV) or str(root) in PRIOR_PATHS[1::2]:
        relative = path.relative_to(root).as_posix()
        if relative == "lib64":
            return target == "lib"
        return (
            relative in ("bin/python", "bin/python3", "bin/python3.12")
            and target in ("python", "python3", "python3.12", "/usr/bin/python3.12")
            and path.resolve(strict=True) == Path("/usr/bin/python3.12")
        )
    if root == Path(SOURCE) and runtime is not None:
        links = {
            ".env": runtime["environment"]["target"],
            **{"static/" + name: upload["target"] for name, upload in runtime["uploads"].items()},
        }
        return links.get(path.relative_to(root).as_posix()) == target
    return False


def stable_exec_start(value):
    marker = "; start_time="
    require(value.count(marker) == 1, "unsupported_execstart_telemetry")
    prefix, tail = value.split(marker)
    fields = prefix[2:].rstrip().split(" ; ")
    require(
        prefix.startswith("{ ")
        and tail
        and len(fields) == 3
        and fields[0].startswith("path=")
        and fields[1].startswith("argv[]=")
        and fields[2] in ("ignore_errors=yes", "ignore_errors=no")
        and not any(c in prefix for c in "\r\n"),
        "unsupported_execstart_prefix",
    )
    return prefix + marker


def configured_start(text):
    """Restricted systemd 257 logical lines; never expand or unescape commands."""
    require("\r" not in text, "unit_carriage_return_refused")
    section, starts, pending = "", [], None
    for physical in text.split("\n"):
        stripped = physical.strip()
        if pending is not None:
            require(
                stripped
                and not stripped.startswith(("#", ";", "["))
                and not re.match(r"[A-Za-z_][A-Za-z0-9_]*\s*=", stripped),
                "execstart_continuation_crossing_refused",
            )
        continued = physical.endswith("\\")
        if continued:
            require(not physical.endswith("\\\\"), "unit_doubled_trailing_backslash")
            require(
                pending is not None or (section == "[Service]" and stripped.startswith("ExecStart=")),
                "continued_non_execstart_requires_review",
            )
        logical = (pending or "") + (physical[:-1] + " " if continued else physical)
        if continued:
            pending = logical
            continue
        pending = None
        line = logical.strip()
        if line.startswith("["):
            section = line
        elif section == "[Service]" and line.startswith("ExecStart="):
            value = line.split("=", 1)[1]
            starts = [*starts, value] if value else []
    require(pending is None, "execstart_continuation_eof")
    require(len(starts) == 1, "single_effective_execstart_required")
    return starts[0]


def render_override(unit, command, expected_hash, runtime_unit):
    """Pure renderer. Reviewed exact hash plus bounded supported command grammar."""
    require(sha(command.encode()) == expected_hash, "configured_command_drift")
    require(not any(c in command for c in "\r\n\\%"), "unsupported_command_escaping")
    argv = shlex.split(command, comments=False)
    if unit == "academy-v2-hr-report":
        require(
            runtime_unit["venv"] in HR_HASHES
            and sha(command.encode()) == HR_HASHES[runtime_unit["venv"]]
            and len(argv) == 3
            and argv[:2] == ["/bin/sh", "-c"],
            "unsupported_hr_wrapper",
        )
        expected = [
            runtime_unit["venv"] + "/bin/python",
            "-m",
            "app.cli",
            "hr-report",
            "--to",
            "${ACADEMY_HR_RECIPIENTS:-hr@dotmac.ng}",
        ]
        require(shlex.split(argv[2]) == expected, "unsupported_hr_arguments")
        replacement = command.replace(runtime_unit["venv"] + "/bin/python", VENV + "/bin/python", 1)
    else:
        require(
            argv
            and argv[0] in [runtime_unit["venv"] + "/bin/" + x for x in ("python", "python3", "uvicorn", "gunicorn")],
            "unsupported_interpreter",
        )
        require(all(re.fullmatch(r"[A-Za-z0-9_./:=,@+*-]+", a) for a in argv), "unsupported_command_argument")
        require(not any(path in command for path in PRIOR_PATHS[::2]), "source_argument_requires_review")
        replacement = command.replace(argv[0], VENV + "/bin/" + Path(argv[0]).name, 1)
    return (
        "[Service]\nWorkingDirectory="
        + SOURCE
        + "\nExecStart=\nExecStart="
        + replacement
        + '\nEnvironment="PYTHONPATH='
        + SOURCE
        + '"\n'
    )


def route_policy(raw):
    rows = json.loads(raw)
    require(type(rows) is list and all(type(x) is dict for x in rows), "route_shape")
    for row in rows:
        if row.get("protocol") == "ra" and "expires" in row:
            require(type(row["expires"]) is int and row["expires"] > 0, "ra_expiry")
            row["expires"] = "positive-integer-ra-lifetime"
    return sorted(rows, key=canonical)


def tree_hash(path, runtime=None):
    """Static inventory; bounded files. Link targets recorded, never traversed."""
    rows = []
    for p in [path, *sorted(path.rglob("*"))]:
        require(len(rows) < 200_000, "inventory_too_large")
        s = p.lstat()
        if "__pycache__" in p.parts or p.suffix == ".pyc":
            continue
        row = [str(p.relative_to(path)), s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
        if stat.S_ISLNK(s.st_mode):
            target = os.readlink(p)
            require(allowed_inventory_link(p, path, target, runtime), "inventory_link_requires_exact_recipe")
            row += ["link", target]
        elif stat.S_ISREG(s.st_mode):
            require(s.st_size < 200_000_000, "inventory_file_too_large")
            row += ["file", sha(read_bytes(p))]
        else:
            require(stat.S_ISDIR(s.st_mode), "inventory_special_file")
            row += ["dir"]
        rows.append(row)
    return sha(canonical(rows))


def snapshot(role, spec, runtime):
    units = ["academy-v2-web"] + ["academy-v2-" + n for n in NAMES] if role == "web" else ["academy-v2-lab-worker"]
    require(set(spec["units"]) == set(units), "unit_manifest_set")
    result = {"units": {}, "proposed_override_sha256": {}}
    primary_runtime = runtime["units"][units[0]]
    result["runtime_baseline_sha256"] = digest(canonical(runtime))
    result["runtime_venv_inventory_sha256"] = {
        venv: tree_hash(Path(venv), runtime) for venv in sorted({u["venv"] for u in runtime["units"].values()})
    }
    result["accepted_venv_inventory_sha256"] = result["runtime_venv_inventory_sha256"][primary_runtime["venv"]]
    require(
        result["accepted_venv_inventory_sha256"] == spec["accepted_venv_inventory_sha256"],
        "observed_primary_venv_drift",
    )
    result["accepted_environment_sha256"] = observed_environment(runtime)
    require(result["accepted_environment_sha256"] == spec["accepted_environment_sha256"], "observed_environment_drift")
    for observed in runtime["units"].values():
        require(
            git_read(observed["source"], "rev-parse", "HEAD") == observed["head"]
            and git_read(observed["source"], "rev-parse", "HEAD^{tree}") == observed["tree"]
            and not git_read(observed["source"], "status", "--porcelain", "--untracked-files=all"),
            "observed_runtime_git",
        )
    wheel = private("/root/academy-candidate-d12260b6/dotmac_kernel-0.1.0a108-py3-none-any.whl")
    require(
        sha(read_bytes(wheel, limit=2000000)) == "a4cd5953c195b29fc8550dc7f048ca403de48f7bb9b09d26c7b5f7608ce17ab9",
        "retained_kernel_wheel_drift",
    )
    with zipfile.ZipFile(io.BytesIO(read_bytes(wheel, limit=2000000))) as archive:
        for entry in archive.infolist():
            name = Path(entry.filename)
            require(not name.is_absolute() and ".." not in name.parts and "\\" not in entry.filename, "wheel_path")
            if entry.is_dir() or (name.name == "RECORD" and name.parent.name.endswith(".dist-info")):
                continue
            require(not any(part.endswith(".data") for part in name.parts), "wheel_layout")
            for venv in result["runtime_venv_inventory_sha256"]:
                installed = Path(venv) / "lib/python3.12/site-packages" / name
                require(not any(p.is_symlink() for p in [installed, *installed.parents]), "installed_kernel_symlink")
                require(read_bytes(installed) == archive.read(entry), "observed_kernel_byte_drift")
    result["accepted_kernel_wheel_sha256"] = sha(read_bytes(wheel, limit=2000000))
    for unit in units:
        runtime_unit = runtime["units"][unit]
        vals = properties(unit, PROPS)
        if unit == units[0]:
            require(
                vals["EnvironmentFiles"] == runtime["environment"]["path"] + " (ignore_errors=no)",
                "primary_environment_file_drift",
            )
        require(vals["WorkingDirectory"] == runtime_unit["source"] and vals["User"] == "dotmac", "live_source_or_user")
        require(not {"PYTHONPATH", "PYTHONHOME"} & set(vals["PassEnvironment"].split()), "manager_python_environment")
        text = read_command(["/usr/bin/systemctl", "cat", unit])
        command = configured_start(text)
        override = render_override(unit, command, spec["units"][unit]["command_sha256"], runtime_unit)
        vals["ExecStart"] = stable_exec_start(vals["ExecStart"])
        # Raw properties may contain credentials: only their canonical digest leaves memory.
        result["units"][unit] = {"properties_sha256": sha(canonical(vals)), "unit_sha256": sha(text.encode())}
        require(result["units"][unit] == spec["units"][unit]["baseline"], "unit_baseline_drift")
        result["proposed_override_sha256"][unit] = sha(override.encode())
    primary = units[0]
    live = properties(primary, "MainPID,ActiveState,SubState")
    require(live["ActiveState"] == "active" and live["SubState"] == "running", "primary_not_running")
    pid = int(live["MainPID"])
    require(pid > 1, "primary_pid")
    proc = Path("/proc") / str(pid)
    argv = proc_bytes(proc / "cmdline").split(b"\0")
    require(proc.stat().st_uid == pwd.getpwnam("dotmac").pw_uid, "primary_process_uid")
    require(os.readlink(proc / "cwd") == primary_runtime["source"], "primary_cwd")
    require(os.readlink(proc / "exe") == os.path.realpath(primary_runtime["venv"] + "/bin/python"), "primary_exe")
    require(
        argv[0].decode()
        in [primary_runtime["venv"] + "/bin/" + n for n in ("python", "python3", "uvicorn", "gunicorn")],
        "primary_interpreter",
    )
    require(sha(proc_bytes(proc / "cmdline")) == spec["primary_cmdline_sha256"], "primary_argv_drift")
    result["primary"] = {
        "pid": pid,
        "start_ticks": proc_ticks(pid),
        "cwd_sha256": sha(primary_runtime["source"].encode()),
        "exe_sha256": sha(read_bytes(Path(os.readlink(proc / "exe")))),
        "argv_sha256": sha(proc_bytes(proc / "cmdline")),
    }
    routes = read_command(["/usr/sbin/ip", "-j", "route", "show", "table", "all"])
    result["route_policy_sha256"] = sha(canonical(route_policy(routes)))
    require(result["route_policy_sha256"] == spec["route_policy_sha256"], "route_policy_drift")
    if role == "web":
        result["timers"] = {}
        for name in NAMES:
            unit = "academy-v2-" + name + ".timer"
            state = properties(unit, "ActiveState,UnitFileState,Unit")
            require(state["ActiveState"] == "active", "timer_not_active")
            result["timers"][unit] = {
                "properties_sha256": sha(canonical(state)),
                "unit_sha256": sha(read_command(["/usr/bin/systemctl", "cat", unit]).encode()),
            }
        require(result["timers"] == spec["timers"], "timer_baseline_drift")
    else:
        guard = properties("academy-v2-console-guard", "ActiveState,SubState,Type,Result,ExecMainStatus,MainPID")
        require(
            guard
            == dict(
                ActiveState="active",
                SubState="exited",
                Type="oneshot",
                Result="success",
                ExecMainStatus="0",
                MainPID="0",
            ),
            "console_guard_drift",
        )
        result["guard_sha256"] = sha(canonical(guard))
        result["nft_sha256"] = sha(read_command(["/usr/sbin/nft", "-s", "list", "ruleset"]).encode())
        require(result["nft_sha256"] == spec["nft_sha256"], "nft_drift")
    return result


def packages(venv, source, locked, required, bootstrap, reviewed_pth):
    allowed = {}
    for package in locked["package"]:
        if "main" in package.get("groups", []):
            allowed.setdefault(normalize(package["name"]), set()).add(package["version"])
    require(set(bootstrap) <= {"pip", "setuptools"}, "bootstrap_name")
    for name, version in bootstrap.items():
        allowed.setdefault(name, set()).add(version)
    site = no_links(venv / "lib/python3.12/site-packages")
    found, metadata = {}, {}
    for p in sorted(site.glob("*.dist-info/METADATA")):
        no_links(p)
        parsed = email.parser.BytesParser().parsebytes(read_bytes(p))
        name, version = normalize(parsed["Name"]), parsed["Version"]
        require(name not in found and version in allowed.get(name, set()), "installed_package_not_locked")
        found[name], metadata[name] = version, digest(read_bytes(p))
    require(set(required) <= set(found) and set(bootstrap) <= set(found), "missing_required_distribution")
    require(all(found[n] == v for n, v in bootstrap.items()), "bootstrap_version_drift")
    pth_import_files = []
    for p in sorted(site.glob("*.pth")):
        raw = read_bytes(p, limit=1000000)
        require(
            str(OLD_SOURCE).encode() not in raw
            and b"/home/dotmac/projects/" not in raw
            and b"/home/dotmac/.local/share/academy-v2-venvs/" not in raw,
            "pth_retained_runtime_path",
        )
        for line in raw.decode("utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            if line.startswith(("import ", "import\t")):
                require(reviewed_pth.get(p.name) == digest(raw), "pth_import_requires_exact_review")
                pth_import_files.append(p.name)
                continue
            target = (site / line).resolve(strict=False)
            require(target.is_relative_to(venv) or target.is_relative_to(source), "pth_external_literal_path")

    return {
        "distributions": found,
        "metadata_sha256": metadata,
        "pth_sha256": {p.name: digest(read_bytes(p)) for p in sorted(site.glob("*.pth"))},
        "pth_import_files_reviewed_by_hash": sorted(set(pth_import_files)),
        "pth_inspection_limit": (
            "Literal paths checked; hash-pinned import lines are not executed or semantically verified."
        ),
    }


def normalize(name):
    require(type(name) is str, "distribution_name")
    return re.sub(r"[-_.]+", "-", name).lower()


def parity(wheels, site, locked):
    result = {}
    allowed = {normalize(p["name"]) for p in locked["package"]}
    for wheel in wheels:
        name = normalize(wheel["distribution"])
        require(name in allowed and name in ("dotmac-kernel", "dotmac-auth-oidc"), "wheel_distribution")
        path = pinned(wheel["path"], wheel["sha256"], private=True)
        with zipfile.ZipFile(io.BytesIO(read_bytes(path, private=True))) as archive:
            for entry in archive.infolist():
                p = Path(entry.filename)
                require(not p.is_absolute() and ".." not in p.parts and "\\" not in entry.filename, "wheel_path")
                if entry.is_dir() or (p.name == "RECORD" and p.parent.name.endswith(".dist-info")):
                    continue
                require(not any(x.endswith(".data") for x in p.parts), "wheel_data_layout")
                installed = site / p
                require(not any(x.is_symlink() for x in [installed, *installed.parents]), "wheel_installed_symlink")
                require(read_bytes(installed) == archive.read(entry), "wheel_byte_parity")
        require(name not in result, "duplicate_wheel_receipt")
        result[name] = wheel["sha256"]
    return result


def services(role):
    return ["academy-v2-web"] + ["academy-v2-" + n for n in NAMES] if role == "web" else ["academy-v2-lab-worker"]


def timers():
    return ["academy-v2-" + n + ".timer" for n in NAMES]


def read_command(args):
    fields = (
        PROPS,
        "MainPID,ActiveState,SubState",
        "ActiveState,UnitFileState,Unit",
        "ActiveState,SubState,Type,Result,ExecMainStatus,MainPID",
    )
    units = services("web") + services("lab") + timers() + ["academy-v2-console-guard"]
    allowed = args in [
        ["/usr/sbin/ip", "-j", "route", "show", "table", "all"],
        ["/usr/sbin/nft", "-s", "list", "ruleset"],
    ]
    allowed = allowed or any(args == ["/usr/bin/systemctl", "cat", u] for u in units)
    allowed = allowed or any(
        args == ["/usr/bin/systemctl", "show", u, "--property=" + f] for u in units for f in fields
    )
    require(allowed, "readonly_argv")
    code, out, _ = run_group(args, clean_env(), 30, stdin=subprocess.DEVNULL)
    require(code == 0 and len(out) <= 8000000, "readonly_command_failed")
    return out.decode().strip()


def properties(unit, fields):
    return dict(
        line.split("=", 1)
        for line in read_command(["/usr/bin/systemctl", "show", unit, "--property=" + fields]).splitlines()
    )


def clean_env():
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }


def stamp(value):
    require(type(value) in {int, float} and 0 <= time.time() - value < 300, "stale_observation")


def validate_manifest(m, role):
    exact(
        m,
        (
            "schema",
            "candidate",
            "tree",
            "source",
            "venv",
            "previous",
            "recovery",
            "retention",
            "self_sha256",
            "plan_sha256",
            "helpers",
            "roles",
            "expected_before",
            "db_source_pins",
            "migration_source_pins",
            "kernel_migration",
            "idle_source_pins",
            "freeze",
            "gate_plan_sha256",
            "maintenance",
            "census_transport",
        ),
    )
    require(m["schema"] == "AcademyExecutionInputs.v7", "manifest_schema")
    for k in ("candidate", "tree"):
        hexvalue(m[k], 40)
    require(
        m["candidate"] != OLD
        and m["source"] == "/srv/academy/releases/" + m["candidate"]
        and m["venv"] == "/srv/academy/venvs/" + m["candidate"],
        "candidate_paths",
    )
    require(
        m["previous"] == OLD
        and m["recovery"] == "fix_forward_v2_only"
        and m["retention"] == "until_explicit_deletion_approval",
        "recovery_retention",
    )
    require(
        m["expected_before"] == BASELINE_REVISIONS,
        "exact_before_revisions",
    )
    exact(
        m["kernel_migration"],
        ("distribution", "version", "relative_module_path", "sha256"),
    )
    kernel = m["kernel_migration"]
    require(
        kernel["distribution"] == "dotmac-kernel"
        and kernel["relative_module_path"] == "dotmac_kernel/migrations/versions/20261109_0031_rate_limit_buckets.py"
        and kernel["sha256"] == "6abbbf72b7fefbc9c9a6ace62edbdc2edda6451967b2ab25216b9acc21dbdebd"
        and type(kernel["version"]) is str
        and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:a[0-9]+|b[0-9]+|rc[0-9]+)?", kernel["version"]),
        "verified_published_kernel_migration_binding",
    )
    exact(m["freeze"], ("path", "sha256"))
    freeze_raw = read_bytes(m["freeze"]["path"], limit=2000000, private=True)
    require(digest(freeze_raw) == hexvalue(m["freeze"]["sha256"]), "frozen_record_bytes")
    frozen = decode(freeze_raw)
    exact(
        frozen,
        (
            "schema",
            "candidate",
            "tree",
            "ci_evidence_sha256",
            "source_review_sha256",
            "dependency_review_sha256",
            "recovery_review_sha256",
            "acceptance_harnesses_sha256",
            "executor_independent_review_sha256",
            "authority_scope",
        ),
    )
    require(
        frozen["schema"] == "AcademyExecutionFreeze.v2"
        and frozen["candidate"] == m["candidate"]
        and frozen["tree"] == m["tree"],
        "frozen_record_identity",
    )
    exact(frozen["authority_scope"], ("path", "sha256"))
    scope_path = frozen["authority_scope"]["path"]
    require(
        type(scope_path) is str
        and Path(scope_path).is_absolute()
        and Path(scope_path).parts[1] == "root"
        and ".." not in Path(scope_path).parts,
        "root_private_authority_scope_path",
    )
    hexvalue(frozen["authority_scope"]["sha256"])
    for k in set(frozen) - {"schema", "candidate", "tree", "authority_scope"}:
        hexvalue(frozen[k])
    exact(
        m["helpers"],
        (
            "candidate_baseline.py",
            "candidate_stage.py",
            "candidate_db_readiness.py",
            "candidate_lab_idle.py",
            "candidate_migration_entry.py",
            "candidate_nginx.py",
            "mail_hold_operator.py",
            "external_census",
            "maintenance",
            "census_domains",
            "census_discovery",
            "census_transport",
        ),
    )
    maintenance_module(m).validate_component(common_api(), m)
    hexvalue(m["gate_plan_sha256"])
    for name, value in m["helpers"].items():
        if name != "maintenance":
            hexvalue(value)
    _, scope_hash = census_scope(m)
    require(scope_hash == frozen["authority_scope"]["sha256"], "frozen_authority_scope_binding")
    census_domain_module(m)
    exact(m["census_transport"], HOSTS)
    transport = census_transport_module(m)
    for peer_role in HOSTS:
        # Static profile validation never opens credentials or assumes this host
        # is the remote caller. Runtime selection verifies the actual other host.
        transport.validate_profile(common_api(), m, peer_role, m["census_transport"][peer_role])
    for field in ("db_source_pins", "migration_source_pins", "idle_source_pins"):
        require(type(m[field]) is dict and bool(m[field]), "source_pin_map")
        for rel, value in m[field].items():
            require(
                type(rel) is str and not Path(rel).is_absolute() and ".." not in Path(rel).parts and "\\" not in rel,
                "source_pin_path",
            )
            hexvalue(value)
    db_files = {
        "alembic/versions/a0011_oidc_login_states.py",
        "alembic.ini",
        "alembic/env.py",
        "app/migration_graph.py",
        "app/config.py",
    }
    exact(m["db_source_pins"], db_files)
    exact(m["migration_source_pins"], db_files | {"app/migration_cli.py"})
    exact(
        m["idle_source_pins"],
        {
            "app/config.py",
            "app/models/lab.py",
            "app/services/lab_operations.py",
            "app/services/lab_lifecycle.py",
            "app/services/lab_jobs.py",
            "app/web/labs.py",
            "pyproject.toml",
            "poetry.lock",
        },
    )
    exact(m["roles"], HOSTS)
    for host_role, spec in m["roles"].items():
        fields = {
            "hostname",
            "uid",
            "baseline",
            "runtime_baseline",
            "staging_manifest_sha256",
            "stage_cache_inventory_sha256",
            "poetry_tool_inventory_sha256",
            "source_inventory_sha256",
            "venv_inventory_sha256",
            "environment_sha256",
            "assets",
            "python_sha256",
            "pyproject_sha256",
            "lock_sha256",
            "bootstrap",
            "required_main_distributions",
            "reviewed_pth_import_sha256",
            "retained_wheels",
        }
        exact(spec, fields)
        runtime = baseline_runtime(m, host_role)
        require(
            runtime["environment"]["sha256"]
            == spec["environment_sha256"]
            == spec["baseline"]["accepted_environment_sha256"],
            "runtime_environment_join",
        )
        require(
            {name: upload["inventory_sha256"] for name, upload in runtime["uploads"].items()} == spec["assets"],
            "runtime_uploads_join",
        )
        require(
            spec["hostname"].split(".")[0] == HOSTS[host_role] and type(spec["uid"]) is int and spec["uid"] > 0,
            "host_role",
        )
        for name in fields - {
            "hostname",
            "uid",
            "baseline",
            "runtime_baseline",
            "assets",
            "bootstrap",
            "required_main_distributions",
            "reviewed_pth_import_sha256",
            "retained_wheels",
        }:
            hexvalue(spec[name])
        baseline_fields = {
            "units",
            "accepted_venv_inventory_sha256",
            "accepted_environment_sha256",
            "primary_cmdline_sha256",
            "route_policy_sha256",
            "timers" if host_role == "web" else "nft_sha256",
        }
        exact(spec["baseline"], baseline_fields)
        for k, v in spec["baseline"].items():
            if k not in {"units", "timers"}:
                hexvalue(v)
        exact(spec["baseline"]["units"], services(host_role))
        for u in spec["baseline"]["units"].values():
            exact(u, ("baseline", "command_sha256"))
            hexvalue(u["command_sha256"])
            exact(u["baseline"], ("properties_sha256", "unit_sha256"))
            for v in u["baseline"].values():
                hexvalue(v)
        if host_role == "web":
            exact(spec["baseline"]["timers"], timers())
            for t in spec["baseline"]["timers"].values():
                exact(t, ("properties_sha256", "unit_sha256"))
                for value in t.values():
                    hexvalue(value)
        require(
            type(spec["assets"]) is dict and set(spec["assets"]) <= {"avatars", "figures"},
            "asset_names",
        )
        require(
            type(spec["bootstrap"]) is dict and set(spec["bootstrap"]) <= {"pip", "setuptools"},
            "bootstrap_names",
        )
        require(
            type(spec["required_main_distributions"]) is list
            and all(type(x) is str for x in spec["required_main_distributions"]),
            "required_packages",
        )
        require(type(spec["reviewed_pth_import_sha256"]) is dict, "pth_map")
        for p, value in spec["reviewed_pth_import_sha256"].items():
            require(Path(p).name == p and p.endswith(".pth"), "pth_filename")
            hexvalue(value)
        for value in spec["assets"].values():
            hexvalue(value)
        require(
            type(spec["retained_wheels"]) is list and bool(spec["retained_wheels"]),
            "retained_wheels_required",
        )
        for wheel in spec["retained_wheels"]:
            exact(wheel, ("distribution", "path", "sha256"))
            hexvalue(wheel["sha256"])
        require(
            any(w["distribution"] == "dotmac-kernel" for w in spec["retained_wheels"]),
            "kernel_wheel_required",
        )
    require(m["roles"][role]["uid"] == pwd.getpwnam("dotmac").pw_uid, "dotmac_uid")


def approval(value, manifest_hash, m, phase, historical=False):
    exact(
        value,
        (
            "schema",
            "approval_id",
            "attempt",
            "approved_by",
            "approval_record_sha256",
            "approval_record_path",
            "approved_unix",
            "expires_unix",
            "manifest_sha256",
            "plan_sha256",
            "executor_sha256",
            "helpers",
            "candidate",
            "tree",
            "source",
            "venv",
            "previous",
            "recovery",
            "retention",
            "authorized_phases",
        ),
    )
    require(
        value["schema"] == "AcademyExecutionApproval.v1" and value["approved_by"] == "Michael",
        "genuine_root_approval_record_required",
    )
    hexvalue(value["approval_record_sha256"])
    require(
        digest(read_bytes(value["approval_record_path"], limit=2000000, private=True))
        == value["approval_record_sha256"],
        "actual_approval_record_hash",
    )
    require(
        type(value["approval_id"]) is str and re.fullmatch(r"[A-Za-z0-9-]{8,100}", value["approval_id"]),
        "approval_identity",
    )
    hexvalue(value["attempt"])
    require(
        type(value["approved_unix"]) is int
        and type(value["expires_unix"]) is int
        and value["approved_unix"] < value["expires_unix"] <= value["approved_unix"] + 3600
        and (historical or value["approved_unix"] <= int(time.time()) < value["expires_unix"]),
        "approval_window",
    )
    require(
        value["manifest_sha256"] == manifest_hash
        and value["plan_sha256"] == m["plan_sha256"]
        and value["executor_sha256"] == m["self_sha256"]
        and value["helpers"] == m["helpers"],
        "frozen_approval_bindings",
    )
    for k in (
        "candidate",
        "tree",
        "source",
        "venv",
        "previous",
        "recovery",
        "retention",
    ):
        require(value[k] == m[k], "approval_identity_drift")
    phases = value["authorized_phases"]
    require(
        type(phases) is list and len(phases) == len(set(phases)) and set(phases) <= set(PHASES) and phase in phases,
        "authorized_phase",
    )
    if phase in MIGRATION_PIPELINE:
        require(MIGRATION_PIPELINE <= set(phases), "same_approval_entire_fixed_pipeline")
    # No future observation hash occurs in approval. Root private custody, actual
    # approval record and independent human review establish authority, not JSON.


class Evidence:
    def __init__(self, path, m, a, approval_hash, manifest_hash):
        self.value, self.sha256 = load(path)
        self.used = {}
        self.m, self.a = m, a
        self.approval_hash, self.manifest_hash = approval_hash, manifest_hash
        exact(self.value, ("schema", "candidate", "tree", "attempt", "created_unix", "entries"))
        require(self.value["schema"] == "AcademyExecutionEvidenceIndex.v2", "evidence_index_schema")
        for k in ("candidate", "tree", "attempt"):
            require(self.value[k] == (a[k] if k == "attempt" else m[k]), "evidence_index_identity")
        stamp(self.value["created_unix"])
        require(type(self.value["entries"]) is dict and len(self.value["entries"]) <= 80, "evidence_index_entries")
        for name, item in self.value["entries"].items():
            require(
                re.fullmatch(r"[a-z][a-z0-9-]{1,80}", name) or name == "maintenance-lab-adopted_and_fenced",
                "evidence_name",
            )
            exact(item, ("path", "sha256", "producer", "producer_sha256", "role", "observed_unix"))
            hexvalue(item["sha256"])
            hexvalue(item["producer_sha256"])
            require(item["role"] in HOSTS and type(item["observed_unix"]) is int, "evidence_descriptor")
            require(
                item["producer"] in m["helpers"]
                or item["producer"] in {"candidate_execute.py", "candidate_maintenance.py"},
                "evidence_producer",
            )
            expected = (
                m["self_sha256"]
                if item["producer"] == "candidate_execute.py"
                else (
                    m["helpers"]["maintenance"]["sha256"]
                    if item["producer"] == "candidate_maintenance.py"
                    else m["helpers"][item["producer"]]
                )
            )
            require(item["producer_sha256"] == expected, "producer_hash")

    def get(self, name, producer, role, fresh=True):
        value = self._get_raw(name, producer, role, fresh=fresh)
        if producer == "external_census":
            require(not name.startswith("sources-"), "census_sources_require_raw_read")
            census_module(self.m).verify_receipt_sources(
                common_api(), self.m, self, name, value, self.used[name]["sha256"], fresh
            )
        return value

    def _get_raw(self, name, producer, role, fresh=True):
        require(name in self.value["entries"], "required_evidence_missing")
        item = self.value["entries"][name]
        require(item["producer"] == producer and item["role"] == role, "evidence_producer_role")
        if fresh:
            stamp(item["observed_unix"])
        raw = read_bytes(item["path"], limit=100000000, private=True)
        require(digest(raw) == item["sha256"], "evidence_bytes_drift")
        value = decode(raw)
        self.used[name] = {
            "sha256": item["sha256"],
            "producer_sha256": item["producer_sha256"],
            "role": role,
            "observed_unix": item["observed_unix"],
        }
        return value

    def phase(self, name, role, expected_phase, fresh=True):
        value = self.get(name, "candidate_execute.py", role, fresh=fresh)
        exact(
            value,
            (
                "schema",
                "status",
                "phase",
                "role",
                "candidate",
                "tree",
                "attempt",
                "approval_sha256",
                "manifest_sha256",
                "evidence_index_sha256",
                "intent_sha256",
                "started_unix",
                "completed_unix",
                "evidence",
                "observations",
                "process_groups",
                "deployment_ready",
            ),
        )
        require(
            value["schema"] == "AcademyExecutionReceipt.v2"
            and value["status"] == "observed"
            and value["phase"] == expected_phase
            and value["role"] == role
            and value["deployment_ready"] is False,
            "phase_receipt",
        )
        for key, want in (
            ("candidate", self.m["candidate"]),
            ("tree", self.m["tree"]),
            ("attempt", self.a["attempt"]),
            ("approval_sha256", self.approval_hash),
            ("manifest_sha256", self.manifest_hash),
        ):
            require(value[key] == want, "phase_receipt_identity")
        require(
            type(value["started_unix"]) is int
            and type(value["completed_unix"]) is int
            and 0 <= value["started_unix"] <= value["completed_unix"],
            "phase_receipt_chronology",
        )
        for field in ("evidence_index_sha256", "intent_sha256"):
            hexvalue(value[field])
        if fresh:
            stamp(value["completed_unix"])
        require(all(x.get("confirmed") is True for x in value["process_groups"]), "prior_process_cleanup")
        return value


def git_read(source, *args):
    owner = pwd.getpwnam("dotmac")
    allowed = args in (
        ("rev-parse", "HEAD"),
        ("rev-parse", "HEAD^{tree}"),
        ("status", "--porcelain", "--untracked-files=all"),
    )
    require(allowed, "git_read_argv")
    argv = [
        "/usr/bin/git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "--no-optional-locks",
        "-C",
        source,
        *args,
    ]
    code, out, _ = run_group(
        argv,
        clean_env(),
        30,
        user=owner.pw_uid,
        group=owner.pw_gid,
        extra_groups=[],
        umask=0o077,
        stdin=subprocess.DEVNULL,
    )
    require(code == 0 and len(out) < 1000000, "git_read_failed")
    return out.decode().strip()


def inventory(path, include_rows=False, strict=True, runtime=None):
    path = Path(path)
    rows = []
    for p in [path, *sorted(path.rglob("*"))]:
        if "__pycache__" in p.parts or p.suffix == ".pyc":
            continue
        require(len(rows) < 250000, "inventory_count")
        s = p.lstat()
        require(s.st_uid in {0, pwd.getpwnam("dotmac").pw_uid}, "inventory_owner")
        row = [str(p.relative_to(path)), s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
        if stat.S_ISLNK(s.st_mode):
            target = os.readlink(p)
            require(allowed_inventory_link(p, path, target, runtime), "inventory_unreviewed_link")
            row += ["link", target]
        elif stat.S_ISREG(s.st_mode):
            row += ["file", digest(read_bytes(p, strict=strict))]
        else:
            require(stat.S_ISDIR(s.st_mode) and not s.st_mode & 0o022, "inventory_directory_mode")
            row += ["dir"]
        rows.append(row)
    return {"sha256": digest(canonical(rows)), "entries": rows} if include_rows else digest(canonical(rows))


def stage_content(staged, m, role):
    """Validate both hosts' actual complete stage receipt content, not status."""
    exact(
        staged,
        (
            "schema",
            "status",
            "candidate",
            "tree",
            "role",
            "manifest_sha256",
            "source",
            "venv",
            "stage_cache",
            "deployment_ready",
            "started_unix",
            "observed_steps",
            "process_group_observations",
            "process_group_limit",
            "observed_live_before_sha256",
            "installed_inventory",
            "wheel_byte_parity",
            "observed_live_after_sha256",
            "completed_unix",
            "source_file_manifest",
            "venv_file_manifest",
            "stage_cache_file_manifest",
            "lock_sha256",
            "pyvenv_cfg_sha256",
            "interpreter_sha256",
            "poetry_tool_inventory_sha256",
            "expected_observed_live_sha256",
            "runtime_baseline_sha256",
            "baseline_helper_sha256",
            "unmet_prerequisites",
        ),
    )
    spec = m["roles"][role]
    runtime = baseline_runtime(m, role)
    require(
        staged["runtime_baseline_sha256"] == digest(canonical(runtime))
        and staged["baseline_helper_sha256"] == m["helpers"]["candidate_baseline.py"],
        "stage_baseline_helper_join",
    )
    require(
        staged["schema"] == "AcademyInactiveStageReceipt.v2"
        and staged["status"] == "inactive_stage_observed"
        and staged["role"] == role
        and staged["deployment_ready"] is False,
        "stage_complete_schema",
    )
    for key in ("candidate", "tree", "source", "venv"):
        require(staged[key] == m[key], "stage_complete_identity")
    require(staged["manifest_sha256"] == spec["staging_manifest_sha256"], "stage_complete_manifest")
    require(
        staged["stage_cache"] == "/srv/academy/tools/stage-" + m["candidate"]
        and staged["poetry_tool_inventory_sha256"] == spec["poetry_tool_inventory_sha256"],
        "stage_cache_and_tool_identity",
    )
    require(
        type(staged["completed_unix"]) is int
        and type(staged["started_unix"]) is int
        and staged["started_unix"] <= staged["completed_unix"] <= int(time.time()),
        "stage_timestamps",
    )
    require(
        staged["observed_steps"]
        == ["exact_source_and_poetry_check_lock", "new_venv_locked_install_and_metadata_inventory"],
        "stage_complete_steps",
    )
    require(
        staged["process_group_observations"]
        and all(x["confirmed"] is True for x in staged["process_group_observations"]),
        "stage_complete_cleanup",
    )
    hexvalue(staged["expected_observed_live_sha256"])
    require(staged["unmet_prerequisites"] == list(STAGE_HISTORICAL_LIMITS), "stage_historical_scope_limits")
    require(
        staged["observed_live_before_sha256"]
        == staged["observed_live_after_sha256"]
        == staged["expected_observed_live_sha256"],
        "stage_observed_runtime_preserved",
    )
    for label in ("source", "venv"):
        rows = staged[label + "_file_manifest"]
        exact(rows, ("sha256", "entries"))
        require(
            type(rows["entries"]) is list
            and len(rows["entries"]) <= 250000
            and digest(canonical(rows["entries"])) == rows["sha256"] == spec[label + "_inventory_sha256"],
            "stage_complete_inventory",
        )
    cache = staged["stage_cache_file_manifest"]
    exact(cache, ("sha256", "entries"))
    require(
        type(cache["entries"]) is list
        and len(cache["entries"]) <= 250000
        and digest(canonical(cache["entries"])) == cache["sha256"] == spec["stage_cache_inventory_sha256"],
        "stage_cache_inventory",
    )
    require(
        staged["lock_sha256"] == spec["lock_sha256"] and staged["interpreter_sha256"] == spec["python_sha256"],
        "stage_complete_lock_interpreter",
    )
    expected_wheels = {normalize(w["distribution"]): w["sha256"] for w in spec["retained_wheels"]}
    require(
        len(expected_wheels) == len(spec["retained_wheels"])
        and "dotmac-kernel" in expected_wheels
        and staged["wheel_byte_parity"] == expected_wheels,
        "stage_complete_wheel_parity",
    )
    pkgs = staged["installed_inventory"]
    exact(
        pkgs,
        ("distributions", "metadata_sha256", "pth_sha256", "pth_import_files_reviewed_by_hash", "pth_inspection_limit"),
    )
    require(
        type(pkgs["distributions"]) is dict
        and set(pkgs["distributions"]) == set(pkgs["metadata_sha256"])
        and set(spec["required_main_distributions"]) <= set(pkgs["distributions"]),
        "stage_complete_distribution_set",
    )
    locked = tomllib.loads(read_bytes(Path(SOURCE) / "poetry.lock").decode())
    allowed = {}
    for package in locked["package"]:
        if "main" in package.get("groups", []):
            allowed.setdefault(normalize(package["name"]), set()).add(package["version"])
    for name, version in spec["bootstrap"].items():
        allowed.setdefault(name, set()).add(version)
        require(pkgs["distributions"].get(name) == version, "stage_complete_bootstrap")
    require(
        all(version in allowed.get(name, set()) for name, version in pkgs["distributions"].items()),
        "stage_complete_locked_versions",
    )
    rows = staged["venv_file_manifest"]["entries"]
    filehashes = {row[0]: row[5] for row in rows if len(row) == 6 and row[4] == "file"}
    require(all(v in filehashes.values() for v in pkgs["metadata_sha256"].values()), "stage_complete_metadata_bytes")
    require(filehashes.get("pyvenv.cfg") == staged["pyvenv_cfg_sha256"], "stage_complete_venv_cfg")
    pth = {
        Path(name).name: value
        for name, value in filehashes.items()
        if name.startswith("lib/python3.12/site-packages/") and name.endswith(".pth")
    }
    require(pth == pkgs["pth_sha256"], "stage_complete_pth_inventory")
    for name in pkgs["pth_import_files_reviewed_by_hash"]:
        require(pth.get(name) == spec["reviewed_pth_import_sha256"].get(name), "stage_complete_pth_review")


def verify_stage(m, role, evidence):
    spec = m["roles"][role]
    runtime = baseline_runtime(m, role)
    for base in (Path(SOURCE) / "app", Path(SOURCE) / "alembic"):
        for parent, dirs, files in os.walk(base, followlinks=False):
            require(
                "__pycache__" not in dirs and not any(n.endswith((".pyc", ".pyo")) for n in files),
                "candidate_source_bytecode_refused",
            )
            require(not any((Path(parent) / name).is_symlink() for name in dirs), "candidate_source_directory_link")
    staged = evidence.get("stage-" + role, "candidate_stage.py", role, fresh=False)
    stage_content(staged, m, role)
    # candidate_stage receipts predate attempt approval; bind actual manifest,
    # completed provenance and recomputed bytes rather than a status string.
    require(
        staged["schema"] == "AcademyInactiveStageReceipt.v2" and staged["status"] == "inactive_stage_observed",
        "stage_receipt",
    )
    for key in ("candidate", "tree", "source", "venv"):
        require(staged[key] == m[key], "stage_identity")
    require(staged["role"] == role and staged["manifest_sha256"] == spec["staging_manifest_sha256"], "stage_manifest")
    require(
        staged["observed_steps"]
        == ["exact_source_and_poetry_check_lock", "new_venv_locked_install_and_metadata_inventory"],
        "stage_steps",
    )
    require(
        staged["process_group_observations"]
        and all(x["confirmed"] is True for x in staged["process_group_observations"]),
        "stage_process_cleanup",
    )
    for name, path in (("source", SOURCE), ("venv", VENV)):
        observed = inventory(path, include_rows=True, runtime=runtime)
        exact(staged[name + "_file_manifest"], ("sha256", "entries"))
        require(
            staged[name + "_file_manifest"] == observed and observed["sha256"] == spec[name + "_inventory_sha256"],
            "stage_inventory_drift",
        )
    require(
        git_read(SOURCE, "rev-parse", "HEAD") == m["candidate"]
        and git_read(SOURCE, "rev-parse", "HEAD^{tree}") == m["tree"]
        and not git_read(SOURCE, "status", "--porcelain", "--untracked-files=all"),
        "candidate_git",
    )
    for observed in runtime["units"].values():
        require(
            git_read(observed["source"], "rev-parse", "HEAD") == observed["head"]
            and git_read(observed["source"], "rev-parse", "HEAD^{tree}") == observed["tree"]
            and not git_read(observed["source"], "status", "--porcelain", "--untracked-files=all"),
            "observed_runtime_git",
        )
    for name, field in (("pyproject.toml", "pyproject_sha256"), ("poetry.lock", "lock_sha256")):
        require(digest(read_bytes(Path(SOURCE) / name)) == spec[field], "project_lock_drift")
    locked = tomllib.loads(read_bytes(Path(SOURCE) / "poetry.lock").decode())
    project = tomllib.loads(read_bytes(Path(SOURCE) / "pyproject.toml").decode())
    required = sorted(normalize(n) for n in project["tool"]["poetry"]["dependencies"] if n != "python")
    require(required == sorted(spec["required_main_distributions"]), "required_direct_dependencies")
    pkgs = packages(Path(VENV), Path(SOURCE), locked, required, spec["bootstrap"], spec["reviewed_pth_import_sha256"])
    require(pkgs == staged["installed_inventory"], "installed_metadata_pth_drift")
    wheels = parity(spec["retained_wheels"], Path(VENV) / "lib/python3.12/site-packages", locked)
    require(wheels == staged["wheel_byte_parity"] and "dotmac-kernel" in wheels, "wheel_parity")
    require(os.path.realpath(VENV + "/bin/python") == "/usr/bin/python3.12", "candidate_python_origin")
    require(
        digest(read_bytes("/usr/bin/python3.12")) == spec["python_sha256"] == staged["interpreter_sha256"],
        "interpreter_bytes",
    )
    require(digest(read_bytes(Path(VENV) / "pyvenv.cfg")) == staged["pyvenv_cfg_sha256"], "venv_cfg")
    env = Path(SOURCE) / ".env"
    require(env.is_symlink() and os.readlink(env) == runtime["environment"]["target"], "candidate_env_link")
    require(observed_environment(runtime) == spec["environment_sha256"], "environment_bytes")
    for name, upload in runtime["uploads"].items():
        link = Path(SOURCE) / "static" / name
        require(link.is_symlink() and os.readlink(link) == upload["target"], "candidate_asset_link")
        require(
            inventory(Path(upload["target"]), strict=False, runtime=runtime) == upload["inventory_sha256"],
            "retained_asset_drift",
        )
    return {
        "stage_sha256": evidence.used["stage-" + role]["sha256"],
        "source_inventory_sha256": spec["source_inventory_sha256"],
        "venv_inventory_sha256": spec["venv_inventory_sha256"],
        "installed_inventory_sha256": digest(canonical(pkgs)),
        "wheel_parity": wheels,
    }


def proc_bytes(path, limit=1000000):
    path = Path(path)
    require(path.is_absolute() and path.parts[1] == "proc" and ".." not in path.parts, "proc_read_path")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "proc_regular")
            raw = stream.read(limit + 1)
            require(len(raw) <= limit, "proc_read_bound")
            return raw
    finally:
        os.close(parent)


def proc_ticks(pid):
    require(type(pid) is int and pid > 1, "proc_pid")
    raw = proc_bytes(Path("/proc", str(pid), "stat"), 65536)
    require(len(raw) < 65536 and b") " in raw, "proc_stat")
    return raw.rsplit(b") ", 1)[1].split()[19].decode()


def exclusion(evidence, m, a, role, maintenance_status="fenced"):
    maintenance_observation(m, evidence, a, role, maintenance_status)
    maintenance_key = "maintenance-" + role + "-" + maintenance_status
    value = evidence.get("exclusion-" + role, "external_census", role)
    exact(
        value,
        (
            "schema",
            "candidate",
            "tree",
            "attempt",
            "hostname",
            "observed_unix",
            "observed_unix_started",
            "quiesce_receipts",
            "maintenance_observation_sha256",
            "resolved_pre_quiescence_findings",
            "authorities",
            "process_census_sha256",
            "session_census_sha256",
            "fencing_receipt_sha256",
            "hold_id",
            "owner_record_sha256",
            "gate_approval_sha256",
            "authority_scope_sha256",
            "coverage_complete",
            "unresolved_coverage",
        ),
    )
    require(value["schema"] == "AcademyRootSenderExclusion.v2", "sender_exclusion_schema")
    scope, scope_hash = census_scope(m)
    require(
        value["authority_scope_sha256"] == scope_hash
        and value["coverage_complete"] is True
        and value["unresolved_coverage"] == [],
        "exclusion_complete_frozen_scope",
    )
    for key in ("candidate", "tree"):
        require(value[key] == m[key], "sender_candidate")
    require(
        value["attempt"] == a["attempt"] and value["hostname"] == m["roles"][role]["hostname"], "sender_attempt_host"
    )
    stamp(value["observed_unix_started"])
    stamp(value["observed_unix"])
    require(value["observed_unix_started"] <= value["observed_unix"], "exclusion_observation_order")
    require(
        value["maintenance_observation_sha256"] == evidence.used[maintenance_key]["sha256"],
        "exclusion_actual_current_maintenance_observation",
    )
    exact(value["quiesce_receipts"], HOSTS)
    required_findings = {}
    stopped_at = []
    for host_role in HOSTS:
        receipt = evidence.phase("quiesce-" + host_role, host_role, "quiesce", fresh=False)
        hexvalue(value["quiesce_receipts"][host_role])
        require(
            value["quiesce_receipts"][host_role] == evidence.used["quiesce-" + host_role]["sha256"],
            "exclusion_actual_stop_receipt_chain",
        )
        completed = receipt["observations"]["stop_completed_unix"]
        require(
            type(completed) in {int, float} and value["observed_unix_started"] >= completed,
            "exclusion_snapshot_predates_successful_stop",
        )
        require(receipt["observations"]["global_sender_exclusion_proven"] is False, "quiesce_is_not_global_exclusion")
        stopped_at.append(completed)
        before = evidence.get("pre-quiescence-" + host_role, "external_census", host_role, fresh=False)
        require(
            evidence.used["pre-quiescence-" + host_role]["sha256"]
            == receipt["observations"]["pre_quiescence_inventory_sha256"],
            "exclusion_original_inventory_chain",
        )
        all_findings = [item for entries in before["authority_findings"].values() for item in entries] + before[
            "unresolved_coverage"
        ]
        for finding in all_findings:
            required_findings.setdefault(finding["authority_id_sha256"], set()).add(finding["evidence_sha256"])
    exact(value["resolved_pre_quiescence_findings"], required_findings)
    for authority, resolution in value["resolved_pre_quiescence_findings"].items():
        exact(
            resolution,
            (
                "finding_evidence_sha256",
                "resolution",
                "fence_mechanism",
                "observed_unix_started",
                "proof_path",
                "proof_sha256",
            ),
        )
        require(
            type(resolution["finding_evidence_sha256"]) is list
            and len(resolution["finding_evidence_sha256"]) == len(set(resolution["finding_evidence_sha256"]))
            and set(resolution["finding_evidence_sha256"]) == required_findings[authority],
            "all_prequiescence_findings_require_resolution",
        )
        require(resolution["resolution"] in {"proven_fenced", "proven_non_sender"}, "prequiescence_findings_unresolved")
        require(
            resolution["fence_mechanism"]
            in (
                {"not_a_sender"}
                if resolution["resolution"] == "proven_non_sender"
                else {"gate_exclusive_lease", "stopped_and_execution_fenced", "external_issuer_fenced"}
            ),
            "actual_resolution_mechanism_required",
        )
        stamp(resolution["observed_unix_started"])
        require(resolution["observed_unix_started"] >= max(stopped_at), "resolution_predates_both_actual_stops")
        raw = read_bytes(resolution["proof_path"], limit=2000000, private=True)
        require(digest(raw) == hexvalue(resolution["proof_sha256"]), "actual_authority_resolution_proof_bytes")
        proof = decode(raw)
        exact(
            proof,
            (
                "schema",
                "candidate",
                "tree",
                "attempt",
                "authority_id_sha256",
                "finding_evidence_sha256",
                "resolution",
                "fence_mechanism",
                "observed_unix_started",
                "process_or_provider_evidence_sha256",
            ),
        )
        require(
            proof["schema"] == "AcademySenderAuthorityResolution.v1"
            and proof["candidate"] == m["candidate"]
            and proof["tree"] == m["tree"]
            and proof["attempt"] == a["attempt"]
            and proof["authority_id_sha256"] == authority
            and all(
                proof[key] == resolution[key]
                for key in ("finding_evidence_sha256", "resolution", "fence_mechanism", "observed_unix_started")
            ),
            "actual_authority_resolution_identity",
        )
        hexvalue(proof["process_or_provider_evidence_sha256"])
    for key in (
        "process_census_sha256",
        "session_census_sha256",
        "fencing_receipt_sha256",
        "hold_id",
        "owner_record_sha256",
        "gate_approval_sha256",
    ):
        hexvalue(value[key])
    exact(value["authorities"], ("supported", "legacy", "manual", "external"))
    for name, authority in value["authorities"].items():
        require(type(authority) is dict and authority.get("state") in {"fenced", "absent"}, "authority_state")
        if authority["state"] == "absent":
            exact(
                authority,
                ("state", "inventory_sha256", "active_senders", "unaccounted_authorities", "absence_proof"),
            )
            require(
                name != "supported" and scope["authority_membership"][role][name] == [],
                "absence_requires_empty_non_supported_frozen_membership",
            )
            exact(authority["absence_proof"], ("path", "sha256"))
            raw = read_bytes(authority["absence_proof"]["path"], limit=2000000, private=True)
            require(digest(raw) == hexvalue(authority["absence_proof"]["sha256"]), "actual_absence_proof_bytes")
            # The shared source verifier validates these bytes against full current
            # domain coverage, both stops, the gate epoch and the frozen scope.
        else:
            exact(
                authority,
                (
                    "state",
                    "inventory_sha256",
                    "fence_sha256",
                    "active_senders",
                    "unaccounted_authorities",
                    "fence_mechanism",
                ),
            )
            hexvalue(authority["fence_sha256"])
        hexvalue(authority["inventory_sha256"])
        require(
            type(authority["active_senders"]) is int
            and authority["active_senders"] == 0
            and type(authority["unaccounted_authorities"]) is int
            and authority["unaccounted_authorities"] == 0,
            "sender_authority_not_excluded",
        )
        if authority["state"] == "absent":
            continue
        require(
            authority["fence_mechanism"]
            in {"gate_exclusive_lease", "stopped_and_execution_fenced", "external_issuer_fenced"},
            "sender_fence_mechanism",
        )
        if name == "supported":
            require(authority["fence_mechanism"] == "gate_exclusive_lease", "supported_gate_lease")
    # The actual root-custody census producer remains a separate prerequisite.
    # This validates its concrete per-authority facts, never creates a census.
    return value


def gate_ready(evidence, m, a, role):
    """Supported gate readiness only; never asserts sender authority exclusion."""
    if role == "lab":
        web = evidence.phase("quiesce-web", "web", "quiesce", fresh=False)
        prior = web["observations"]["gate"]
        proof = evidence.get("gate-web", "external_census", "web")
        exact(
            proof,
            (
                "schema",
                "candidate",
                "tree",
                "attempt",
                "hostname",
                "observed_unix_started",
                "hold_id",
                "owner_record_sha256",
                "gate_approval_sha256",
                "supervisor_pid",
                "supervisor_start_ticks",
                "lock_inode",
                "lock_kernel_row",
                "state_sha256",
            ),
        )
        require(
            proof["schema"] == "AcademyRootGateObservation.v1"
            and proof["candidate"] == m["candidate"]
            and proof["tree"] == m["tree"]
            and proof["attempt"] == a["attempt"]
            and proof["hostname"] == m["roles"]["web"]["hostname"]
            and proof["state_sha256"] == digest(b"HELD\n"),
            "remote_actual_gate_readiness",
        )
        stamp(proof["observed_unix_started"])
        require(
            proof["observed_unix_started"] >= web["observations"]["stop_completed_unix"],
            "remote_gate_observation_predates_web_stop",
        )
        for key in ("hold_id", "owner_record_sha256", "gate_approval_sha256"):
            hexvalue(proof[key])
        require(
            type(proof["supervisor_pid"]) is int
            and proof["supervisor_pid"] > 1
            and type(proof["supervisor_start_ticks"]) is str
            and proof["supervisor_start_ticks"].isdigit(),
            "remote_gate_supervisor",
        )
        require(
            type(proof["lock_inode"]) is list
            and len(proof["lock_inode"]) == 2
            and all(type(x) is int and x >= 0 for x in proof["lock_inode"]),
            "remote_gate_inode",
        )
        words = proof["lock_kernel_row"].split()
        inode = proof["lock_inode"]
        require(
            len(words) == 8
            and words[1:5] == ["FLOCK", "ADVISORY", "WRITE", str(proof["supervisor_pid"])]
            and words[5] == f"{os.major(inode[0]):02x}:{os.minor(inode[0]):02x}:{inode[1]}"
            and words[6:] == ["0", "EOF"],
            "remote_kernel_exclusive_lease",
        )
        require(
            prior["gate_held"] is True
            and all(
                proof[key] == prior[key]
                for key in (
                    "hold_id",
                    "owner_record_sha256",
                    "gate_approval_sha256",
                    "supervisor_pid",
                    "supervisor_start_ticks",
                    "lock_inode",
                )
            ),
            "fresh_remote_gate_matches_successful_web_quiescence",
        )
        return dict(
            gate_held=True,
            hold_id=proof["hold_id"],
            owner_record_sha256=proof["owner_record_sha256"],
            gate_approval_sha256=proof["gate_approval_sha256"],
            supervisor_pid=proof["supervisor_pid"],
            supervisor_start_ticks=proof["supervisor_start_ticks"],
            lock_inode=proof["lock_inode"],
            root_gate_observation_sha256=evidence.used["gate-web"]["sha256"],
            attempt=a["attempt"],
            global_sender_exclusion_proven=False,
        )
    owner_raw = read_bytes("/var/lib/dotmac-academy/mail-delivery/owner.json", limit=65536, root_file=True, mode=0o600)
    owner = decode(owner_raw)
    exact(
        owner,
        (
            "schema",
            "hold_id",
            "epoch",
            "candidate",
            "tree",
            "hostname",
            "approval_sha256",
            "script_sha256",
            "plan_sha256",
            "created_at",
        ),
    )
    hold = hexvalue(owner["hold_id"])
    require(owner["epoch"] == hold and owner["schema"] == "AcademyMailHoldOwner.v1", "gate_owner")
    control = Path("/run/academy-mail-hold") / m["candidate"] / m["roles"]["web"]["hostname"]
    claim = decode(
        read_bytes(
            "/var/lib/dotmac-academy/mail-delivery/supervisor-claim.json", limit=65536, root_file=True, mode=0o600
        )
    )
    heartbeat = decode(read_bytes(control / "heartbeat.json", limit=65536, root_file=True, mode=0o600))
    exact(
        claim,
        (
            "schema",
            "hold_id",
            "owner_record_sha256",
            "candidate",
            "tree",
            "hostname",
            "approval_sha256",
            "script_sha256",
            "plan_sha256",
            "supervisor_pid",
            "supervisor_start_ticks",
            "claimed_at",
        ),
    )
    exact(
        heartbeat,
        (
            "schema",
            "hold_ready_at",
            "hold_id",
            "owner_record_sha256",
            "status",
            "gate_held",
            "pid",
            "start_ticks",
            "hostname",
            "candidate",
            "tree",
            "approval_sha256",
            "script_sha256",
            "plan_sha256",
            "lock_inode",
            "state_sha256",
            "observed_at",
            "sender_inventory_authority",
        ),
    )
    require(
        claim["schema"] == "AcademyMailSupervisorClaim.v1" and heartbeat["schema"] == "AcademyMailHoldHeartbeat.v1",
        "gate_claim_heartbeat",
    )
    for value in (owner, claim, heartbeat):
        require(
            value["candidate"] == m["candidate"]
            and value["tree"] == m["tree"]
            and value["hostname"] == m["roles"]["web"]["hostname"]
            and value["script_sha256"] == m["helpers"]["mail_hold_operator.py"]
            and value["hold_id"] == hold
            and value["plan_sha256"] == m["gate_plan_sha256"],
            "gate_identity",
        )
    owner_hash = digest(owner_raw)
    require(
        claim["owner_record_sha256"] == heartbeat["owner_record_sha256"] == owner_hash
        and claim["approval_sha256"] == heartbeat["approval_sha256"] == owner["approval_sha256"],
        "gate_owner_provenance",
    )
    pid = heartbeat["pid"]
    require(
        claim["supervisor_pid"] == pid
        and str(claim["supervisor_start_ticks"]) == str(heartbeat["start_ticks"]) == proc_ticks(pid),
        "gate_supervisor_identity",
    )
    observed = datetime.fromisoformat(heartbeat["observed_at"].replace("Z", "+00:00")).timestamp()
    require(heartbeat["state_sha256"] == digest(b"HELD\n"), "heartbeat_held_state_bytes")
    require(
        0 <= time.time() - observed < 10 and heartbeat["gate_held"] is True and heartbeat["status"] == "held",
        "fresh_gate_held",
    )
    require(
        read_bytes("/var/lib/dotmac-academy/mail-delivery/state", limit=6, root_file=True, mode=0o644) == b"HELD\n",
        "live_gate_held",
    )
    lock = Path("/var/lib/dotmac-academy/mail-delivery/lock")
    parent = directory_fd(lock.parent, root_only=True)
    try:
        info = os.stat(lock.name, dir_fd=parent, follow_symlinks=False)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and [info.st_dev, info.st_ino] == heartbeat["lock_inode"],
            "gate_lock_inode",
        )
    finally:
        os.close(parent)
    lock_rows = proc_bytes(Path("/proc/locks"), 8000000)
    require(len(lock_rows) <= 8000000, "kernel_locks_bound")
    inode_key = f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino}"
    require(
        any(
            row.split()[1:6] == [b"FLOCK", b"ADVISORY", b"WRITE", str(pid).encode(), inode_key.encode()]
            for row in lock_rows.splitlines()
        ),
        "supervisor_actual_exclusive_lease",
    )
    # Supervisor heartbeat only proves supported senders; exclusion() separately
    # requires actual legacy/manual/external root-custody authority evidence.
    return {
        "gate_held": True,
        "hold_id": hold,
        "supervisor_pid": pid,
        "supervisor_start_ticks": str(heartbeat["start_ticks"]),
        "owner_record_sha256": owner_hash,
        "gate_approval_sha256": owner["approval_sha256"],
        "heartbeat_sha256": digest(canonical(heartbeat)),
        "lock_inode": [info.st_dev, info.st_ino],
        "attempt": a["attempt"],
        "global_sender_exclusion_proven": False,
    }


def gate(evidence, m, a, role):
    """Strict activation gate: readiness PLUS genuine post-both-stop exclusion."""
    proof = gate_ready(evidence, m, a, role)
    census = exclusion(evidence, m, a, role)
    require(
        all(census[key] == proof[key] for key in ("hold_id", "owner_record_sha256", "gate_approval_sha256")),
        "strict_gate_post_quiescence_exclusion_binding",
    )
    return {
        **proof,
        "global_sender_exclusion_proven": True,
        "exclusion_sha256": evidence.used["exclusion-" + role]["sha256"],
    }


def stopped(role, m):
    result = {}
    for unit in services(role) + (timers() if role == "web" else []):
        state = properties(unit, "MainPID,ActiveState,SubState")
        require(
            state["MainPID"] == "0" and state["ActiveState"] == "inactive" and state["SubState"] == "dead",
            "unit_not_stopped",
        )
        result[unit] = state
    prior_paths = baseline_module(m).forbidden_runtime_paths()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == os.getpid():
            continue
        try:
            before = proc_ticks(pid)
            cmdline = proc_bytes(entry / "cmdline")
            require(len(cmdline) < 1000000, "proc_argv_bound")
            uid = entry.stat().st_uid
            if uid == m["roles"][role]["uid"]:
                require(
                    not any(path.encode() in cmdline for path in (*prior_paths, SOURCE, VENV)),
                    "remaining_accepted_or_candidate_process",
                )
                require(
                    not any(x in cmdline for x in (b"app.cli", b"app.main", b"gunicorn", b"uvicorn")),
                    "unaccounted_dotmac_application_process",
                )
            require(before == proc_ticks(pid), "process_census_pid_reuse")
        except FileNotFoundError:
            continue
    return {"units": result, "process_census_observed_unix": int(time.time()), "matching_application_pids": []}


def preserved(role, m):
    spec = m["roles"][role]["baseline"]
    routes = digest(canonical(route_policy(read_command(["/usr/sbin/ip", "-j", "route", "show", "table", "all"]))))
    require(routes == spec["route_policy_sha256"], "route_drift")
    result = {"route_policy_sha256": routes}
    if role == "lab":
        guard = properties("academy-v2-console-guard", "ActiveState,SubState,Type,Result,ExecMainStatus,MainPID")
        require(
            guard
            == dict(
                ActiveState="active",
                SubState="exited",
                Type="oneshot",
                Result="success",
                ExecMainStatus="0",
                MainPID="0",
            ),
            "guard_drift",
        )
        nft = digest(read_command(["/usr/sbin/nft", "-s", "list", "ruleset"]).encode())
        require(nft == spec["nft_sha256"], "nft_drift")
        result.update(nft_sha256=nft, guard=guard)
    return result


def approval_current(a):
    require(
        type(a.get("approved_unix")) is int
        and type(a.get("expires_unix")) is int
        and a["approved_unix"] <= time.time() < a["expires_unix"],
        "approval_expired_before_quiesce_or_migration_mutation",
    )


def revalidate_ddl_authority(evidence, phase):
    """Reread original protected authority and frozen scope at the DDL boundary."""
    require(phase == "migrate-kernel0031", "fixed_ddl_phase")
    require(
        hasattr(evidence, "approval_path") and hasattr(evidence, "manifest_path"),
        "original_ddl_custody_required",
    )
    current, current_hash = load(evidence.approval_path)
    m, manifest_hash = load(evidence.manifest_path)
    require(
        current_hash == evidence.approval_hash and current == evidence.a,
        "protected_approval_bytes_changed",
    )
    require(
        manifest_hash == evidence.manifest_hash and m == evidence.m,
        "protected_manifest_bytes_changed",
    )
    approval(current, manifest_hash, m, phase)
    require(
        digest(read_bytes(Path(__file__).absolute(), limit=2000000, private=True)) == m["self_sha256"],
        "current_executor_binding",
    )
    require(
        digest(
            read_bytes(
                Path(evidence.manifest_path).parent / "execution-plan.json",
                limit=2000000,
                private=True,
            )
        )
        == m["plan_sha256"],
        "current_plan_binding",
    )
    helper_path = Path("/usr/local/lib/academy-deploy") / m["candidate"] / "candidate_migration_entry.py"
    require(
        digest(read_bytes(helper_path, limit=2000000, public_helper=True))
        == m["helpers"]["candidate_migration_entry.py"],
        "current_ddl_helper_binding",
    )


def stop_units(selected, a):
    require(selected == timers() or selected in (["academy-v2-web"], ["academy-v2-lab-worker"]), "fixed_stop_set")
    approval_current(a)
    code, _, _ = run_group(["/usr/bin/systemctl", "stop", *selected], clean_env(), 90, stdin=subprocess.DEVNULL)
    require(code == 0, "stop_failed")


def old_unit_inventory(unit, m, role):
    state = properties(unit, "MainPID,ActiveState,SubState")
    require(state["MainPID"].isdigit(), "preinventory_mainpid")
    pid = int(state["MainPID"])
    timer = unit in timers()
    result = dict(
        unit_state=state,
        start_ticks=None,
        argv_sha256=None,
        gate_awareness="timer_only" if timer else "legacy_gate_unaware",
        planned_action="stop_timer" if timer else ("stop_primary" if unit == services(role)[0] else "drain_only"),
    )
    if timer:
        require(pid == 0, "timer_cannot_own_sender_pid")
    elif pid:
        runtime_unit = baseline_runtime(m, role)["units"][unit]
        require(pid > 1, "preinventory_sender_pid")
        ticks = proc_ticks(pid)
        proc = Path("/proc") / str(pid)
        argv = proc_bytes(proc / "cmdline")
        actual_argv = argv.rstrip(b"\0").split(b"\0")
        if unit == "academy-v2-hr-report":
            command = configured_start(read_command(["/usr/bin/systemctl", "cat", unit]))
            render_override(unit, command, m["roles"][role]["baseline"]["units"][unit]["command_sha256"], runtime_unit)
            require(
                actual_argv == [arg.encode() for arg in shlex.split(command)]
                and os.readlink(proc / "exe") == os.path.realpath("/bin/sh"),
                "preinventory_actual_hr_wrapper",
            )
        else:
            require(
                actual_argv[0].decode()
                in [runtime_unit["venv"] + "/bin/" + name for name in ("python", "python3", "uvicorn", "gunicorn")]
                and os.readlink(proc / "exe") == os.path.realpath(runtime_unit["venv"] + "/bin/python"),
                "preinventory_actual_interpreter",
            )
        require(
            proc.stat().st_uid == m["roles"][role]["uid"] and os.readlink(proc / "cwd") == runtime_unit["source"],
            "preinventory_actual_legacy_process_identity",
        )
        require(
            proc_ticks(pid) == ticks and properties(unit, "MainPID,ActiveState,SubState") == state,
            "preinventory_pid_ticks_stable",
        )
        result.update(start_ticks=ticks, argv_sha256=digest(argv))
    return result


def pre_quiescence_inventory(evidence, m, a, role, baseline, ready, compare_live=True):
    value = evidence.get("pre-quiescence-" + role, "external_census", role)
    exact(
        value,
        (
            "schema",
            "candidate",
            "tree",
            "attempt",
            "hostname",
            "role",
            "execution_approval_sha256",
            "execution_manifest_sha256",
            "baseline_receipt_sha256",
            "observed_unix_started",
            "process_inventory_sha256",
            "session_inventory_sha256",
            "authority_inventory_sha256",
            "gate",
            "authorized_stop_targets",
            "units",
            "authority_findings",
            "unresolved_coverage",
            "authority_scope_sha256",
            "coverage_complete",
        ),
    )
    require(
        value["schema"] == "AcademyPreQuiescenceInventory.v2"
        and value["candidate"] == m["candidate"]
        and value["tree"] == m["tree"]
        and value["attempt"] == a["attempt"]
        and value["hostname"] == m["roles"][role]["hostname"]
        and value["role"] == role
        and value["execution_approval_sha256"] == evidence.approval_hash
        and value["execution_manifest_sha256"] == evidence.manifest_hash
        and value["baseline_receipt_sha256"] == evidence.used["baseline-" + role]["sha256"],
        "preinventory_actual_attempt_baseline_custody",
    )
    _, scope_hash = census_scope(m)
    require(
        value["authority_scope_sha256"] == scope_hash
        and value["coverage_complete"] is True
        and value["unresolved_coverage"] == [],
        "preinventory_complete_frozen_scope_required",
    )
    stamp(value["observed_unix_started"])
    for key in ("process_inventory_sha256", "session_inventory_sha256", "authority_inventory_sha256"):
        hexvalue(value[key])
    gate_keys = (
        "hold_id",
        "owner_record_sha256",
        "gate_approval_sha256",
        "supervisor_pid",
        "supervisor_start_ticks",
        "lock_inode",
    )
    exact(value["gate"], gate_keys)
    require(all(value["gate"][key] == ready[key] for key in gate_keys), "preinventory_gate_epoch_lease_binding")
    expected = (timers() if role == "web" else []) + [services(role)[0]]
    require(value["authorized_stop_targets"] == expected, "preinventory_fixed_authorized_stop_targets")
    exact(value["units"], services(role) + (timers() if role == "web" else []))
    for unit, observed in value["units"].items():
        exact(observed, ("unit_state", "start_ticks", "argv_sha256", "gate_awareness", "planned_action"))
        exact(observed["unit_state"], ("MainPID", "ActiveState", "SubState"))
        require(
            type(observed["unit_state"]["MainPID"]) is str and observed["unit_state"]["MainPID"].isdigit(),
            "preinventory_pid_format",
        )
        pid = int(observed["unit_state"]["MainPID"])
        if pid:
            require(
                type(observed["start_ticks"]) is str and observed["start_ticks"].isdigit(), "preinventory_start_ticks"
            )
            hexvalue(observed["argv_sha256"])
        else:
            require(
                observed["start_ticks"] is None and observed["argv_sha256"] is None,
                "preinventory_no_fabricated_pid_evidence",
            )
        expected_action = (
            "stop_timer" if unit in timers() else ("stop_primary" if unit == services(role)[0] else "drain_only")
        )
        require(
            observed["planned_action"] == expected_action
            and observed["gate_awareness"] == ("timer_only" if unit in timers() else "legacy_gate_unaware"),
            "preinventory_legacy_gate_unaware_drain_plan",
        )
        if compare_live:
            require(observed == old_unit_inventory(unit, m, role), "preinventory_actual_unit_pid_drift")
    primary = value["units"][services(role)[0]]
    require(
        int(primary["unit_state"]["MainPID"]) == baseline["observations"]["baseline"]["primary"]["pid"]
        and primary["start_ticks"] == baseline["observations"]["baseline"]["primary"]["start_ticks"],
        "preinventory_original_primary_identity",
    )
    exact(value["authority_findings"], ("legacy", "manual", "external"))
    for findings in [*value["authority_findings"].values(), value["unresolved_coverage"]]:
        require(type(findings) is list and len(findings) <= 1000, "preinventory_bounded_truthful_findings")
        for finding in findings:
            exact(finding, ("authority_id_sha256", "evidence_sha256", "observed_state", "disposition"))
            hexvalue(finding["authority_id_sha256"])
            hexvalue(finding["evidence_sha256"])
            require(
                finding["observed_state"] in {"active", "inactive", "unknown"}
                and finding["disposition"]
                in {"observed_only", "not_authorized_to_stop", "requires_post_stop_exclusion"},
                "preinventory_findings_are_not_fences",
            )
    # Findings may truthfully be active or unknown. This receipt authorizes no
    # extra actor stops and proves no global absence/fence/readiness predicate.
    return value


def verify_old_primary(role, m, baseline):
    actual = old_unit_inventory(services(role)[0], m, role)
    prior = baseline["observations"]["baseline"]["primary"]
    require(
        actual["unit_state"]["ActiveState"] == "active"
        and actual["unit_state"]["SubState"] == "running"
        and int(actual["unit_state"]["MainPID"]) == prior["pid"]
        and actual["start_ticks"] == prior["start_ticks"]
        and actual["argv_sha256"] == prior["argv_sha256"],
        "old_primary_changed_before_fixed_stop",
    )


def quiesce(role, m, a, evidence):
    baseline = evidence.phase("baseline-" + role, role, "baseline", fresh=False)
    approval_current(a)
    current = snapshot(role, m["roles"][role]["baseline"], baseline_runtime(m, role))
    require(current == baseline["observations"]["baseline"], "prequiesce_baseline_drift")
    ready = gate_ready(evidence, m, a, role)
    inventory = pre_quiescence_inventory(evidence, m, a, role, baseline, ready)
    pre_stop_idle = None
    if role == "web":
        # The old worker is still available to drain. Existing real runtime or
        # queued/claimed work aborts before any timer/web downtime.
        pre_stop_idle = fresh_idle(m, role, "before", a["attempt"])
        approval_current(a)
        gate_ready(evidence, m, a, role)
        verify_old_primary(role, m, baseline)
        stop_units(timers(), a)
        deadline = time.monotonic() + 60
        while True:
            states = [properties(u, "MainPID,ActiveState,SubState") for u in services(role)[1:]]
            if all(state == dict(MainPID="0", ActiveState="inactive", SubState="dead") for state in states):
                break
            require(time.monotonic() < deadline, "cli_drain_timeout_fix_forward_hold")
            time.sleep(1)
    ready = gate_ready(evidence, m, a, role)
    pre_quiescence_inventory(evidence, m, a, role, baseline, ready, compare_live=False)
    verify_old_primary(role, m, baseline)
    preserved(role, m)
    if role == "lab":
        maintenance_observation(m, evidence, a, role, "fenced")
        # Web is already quiesced; inspect globally while the old worker can
        # still drain. This readonly DB snapshot is not mail exclusion or a
        # claim that the host/worker has already stopped.
        pre_stop_idle = fresh_idle(m, role, "before", a["attempt"])
        approval_current(a)
        gate_ready(evidence, m, a, role)
        verify_old_primary(role, m, baseline)
    stop_units([services(role)[0]], a)
    result = stopped(role, m)
    result.update(
        preserved=preserved(role, m),
        gate=gate_ready(evidence, m, a, role),
        pre_stop_lab_idle=pre_stop_idle,
        original_active_timers=sorted(baseline["observations"]["baseline"].get("timers", {})),
        pre_quiescence_inventory_sha256=evidence.used["pre-quiescence-" + role]["sha256"],
        pre_quiescence_findings_sha256=digest(
            canonical(
                {
                    "authority_findings": inventory["authority_findings"],
                    "unresolved_coverage": inventory["unresolved_coverage"],
                }
            )
        ),
        global_sender_exclusion_proven=False,
        stop_completed_unix=time.time(),
    )
    return result


def common_input(m, role, helper):
    spec = m["roles"][role]
    return dict(
        candidate=m["candidate"],
        tree=m["tree"],
        source=SOURCE,
        venv=VENV,
        hostname=spec["hostname"],
        uid=spec["uid"],
        retained_source=baseline_module(m).primary_runtime(baseline_runtime(m, role))["source"],
        environment_file=retained_environment_target(m, role),
        helper_sha256=m["helpers"][helper],
    )


def helper_call(m, role, helper, value, timeout=120, authorization=None, ddl_authority=None):
    require(
        helper
        in {
            "candidate_db_readiness.py",
            "candidate_lab_idle.py",
            "candidate_migration_entry.py",
        },
        "helper_allowlist",
    )
    helper_path = Path("/usr/local/lib/academy-deploy") / m["candidate"] / helper
    require(
        digest(read_bytes(helper_path, limit=2000000, public_helper=True)) == m["helpers"][helper],
        "helper_provisioning_or_hash",
    )
    require(len(canonical(value)) <= 65536, "helper_input_bound")
    owner = pwd.getpwnam("dotmac")
    env = {"HOME": owner.pw_dir, "PATH": VENV + "/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
    # Popen performs credential demotion before exec; root never imports app/site.
    if helper == "candidate_migration_entry.py":
        require(
            type(authorization) is dict and ddl_authority is not None,
            "migration_actual_approval_required",
        )
        approval_current(authorization)
        timeout = min(timeout, authorization["expires_unix"] - time.time())
        require(timeout > 0, "migration_approval_deadline")
    launch_started_unix = int(time.time())
    code, out, _ = run_group(
        [VENV + "/bin/python", "-I", "-B", str(helper_path)],
        env,
        timeout,
        cwd=SOURCE,
        user=owner.pw_uid,
        group=owner.pw_gid,
        extra_groups=[],
        umask=0o077,
        input_bytes=canonical(value),
        ddl_authority=ddl_authority,
    )
    require(len(out) <= 2000000, "helper_output_bound")
    report = decode(out)
    require(
        code == 0 and type(report) is dict and report.get("ok") is True and report.get("unmet_predicates") == [],
        "helper_refused",
    )
    return {
        "input_sha256": digest(canonical(value)),
        "helper_sha256": m["helpers"][helper],
        "stdout_sha256": digest(out),
        "launch_started_unix": launch_started_unix,
        "report": report,
    }


def fresh_idle(m, role, mode, attempt):
    require(mode in {"before", "after"}, "fixed_idle_mode")
    value = common_input(m, role, "candidate_lab_idle.py")
    value.update(
        schema="AcademyCandidateLabIdleInputs.v2",
        mode=mode,
        observation_id=attempt,
        source_file_sha256=m["idle_source_pins"],
        env_sha256=m["roles"][role]["environment_sha256"],
        venv_cfg_sha256=digest(read_bytes(Path(VENV) / "pyvenv.cfg")),
        python_sha256=m["roles"][role]["python_sha256"],
        expected_revisions={
            "before": BASELINE_REVISIONS,
            "after": FINAL_REVISIONS,
        }[mode],
        require_zero=True,
        max_observation_seconds=120,
    )
    observed = helper_call(m, role, "candidate_lab_idle.py", value)
    r = observed["report"]
    require(
        r.get("schema") == 2
        and r.get("observer") == "academy_lab_idle"
        and r.get("database_idle") is True
        and r.get("environment_file") == value["environment_file"],
        "idle_observer",
    )
    require(
        r.get("session") == ["app_admin", "app_admin", "academy", "on", "on", "off"],
        "idle_readonly_session",
    )
    starts = [
        observed["launch_started_unix"],
        r.get("observed_unix_started"),
        r.get("database_unix_started"),
    ]
    require(all(type(value) in {int, float} for value in starts), "idle_start_times")
    require(
        0 <= time.time() - min(starts) < 300,
        "idle_freshness_from_earliest_snapshot_start",
    )
    require(
        r.get("revision_vector") == value["expected_revisions"]
        and r.get("row_security_active") == {"lab_operations": False, "lab_instances": False},
        "idle_full_revision_rls",
    )
    require(
        r["counts"]["open_operations_all_tenants"] == 0
        and r["counts"]["present_or_unknown_instances_all_tenants"] == 0,
        "idle_zero",
    )
    return observed


def both_stopped(evidence, role, m):
    for host_role in HOSTS:
        receipt = evidence.phase("quiesce-" + host_role, host_role, "quiesce", fresh=False)
        observed = evidence.get("stopped-" + host_role, "external_census", host_role)
        exact(
            observed,
            (
                "schema",
                "candidate",
                "tree",
                "attempt",
                "hostname",
                "observed_unix",
                "quiesce_receipt_sha256",
                "units",
                "application_pids",
                "process_census_sha256",
                "preserved",
            ),
        )
        require(
            observed["schema"] == "AcademyRootStoppedObservation.v1"
            and observed["candidate"] == m["candidate"]
            and observed["tree"] == m["tree"]
            and observed["attempt"] == evidence.a["attempt"]
            and observed["hostname"] == m["roles"][host_role]["hostname"],
            "stopped_observation_identity",
        )
        stamp(observed["observed_unix"])
        completed = receipt["observations"]["stop_completed_unix"]
        require(
            type(completed) in {int, float} and observed["observed_unix"] >= completed,
            "stopped_observation_predates_successful_stop",
        )
        require(
            observed["quiesce_receipt_sha256"] == evidence.used["quiesce-" + host_role]["sha256"],
            "stopped_original_intent_chain",
        )
        require(
            observed["application_pids"] == receipt["observations"]["matching_application_pids"] == [],
            "quiesce_processes",
        )
        hexvalue(observed["process_census_sha256"])
        require(
            set(observed["units"]) == set(services(host_role) + (timers() if host_role == "web" else [])),
            "quiesce_exact_units",
        )
        for state in observed["units"].values():
            require(state == dict(MainPID="0", ActiveState="inactive", SubState="dead"), "quiesce_unit_state")
        require(observed["preserved"] == receipt["observations"]["preserved"], "fresh_preserved_policy")
    stopped(role, m)
    preserved(role, m)


def migration_report(observed, m, step):
    exact(
        observed,
        (
            "input_sha256",
            "helper_sha256",
            "stdout_sha256",
            "launch_started_unix",
            "report",
        ),
    )
    require(
        observed["helper_sha256"] == m["helpers"]["candidate_migration_entry.py"],
        "migration_producer_hash",
    )
    r = observed["report"]
    require(step == "kernel0031", "only_fixed_kernel_step")
    target, before = "0031_rate_limit_buckets", BASELINE_REVISIONS
    require(
        r.get("schema") == "AcademyCandidateMigrationReport.v4"
        and r.get("environment_file") == retained_environment_target(m, "web")
        and r.get("ok") is True
        and r.get("unmet_predicates") == []
        and r.get("candidate") == m["candidate"]
        and r.get("tree") == m["tree"]
        and r.get("helper_sha256") == observed["helper_sha256"]
        and r.get("source_file_sha256") == m["migration_source_pins"]
        and r.get("migration_step") == step
        and r.get("target") == target
        and r.get("migration_invoked") is True
        and r.get("migration_cli_returned") is True
        and r.get("expected_before") == before
        and r.get("before_revision_vector") == before
        and r.get("kernel_migration") == m["kernel_migration"]
        and r.get("overall_readiness_claimed") is False,
        "canonical_fixed_step_migration_report",
    )


def catalog_report(observed, m, mode):
    exact(
        observed,
        (
            "input_sha256",
            "helper_sha256",
            "stdout_sha256",
            "launch_started_unix",
            "report",
        ),
    )
    require(
        observed["helper_sha256"] == m["helpers"]["candidate_db_readiness.py"],
        "catalog_producer_hash",
    )
    verify_catalog_readback(observed["report"], m, "web", mode)


def verify_catalog_readback(r, m, role, mode="after"):
    require(mode in {"before", "after"}, "fixed_catalog_mode")
    require(
        r.get("candidate") == m["candidate"]
        and r.get("environment_file") == retained_environment_target(m, role)
        and r.get("tree") == m["tree"]
        and r.get("hostname") == m["roles"][role]["hostname"]
        and r.get("source_file_sha256") == m["db_source_pins"],
        "catalog_exact_source_identity",
    )
    require(
        r.get("schema") == 4
        and r.get("ok") is True
        and r.get("unmet_predicates") == []
        and r.get("mode") == mode
        and r.get("migration_executed") is False
        and r.get("oidc_enabled") is False
        and r.get("oidc_client_secret_present") is False
        and r.get("overall_readiness_claimed") is False
        and r.get("revision_vector")
        == {
            "before": BASELINE_REVISIONS,
            "after": FINAL_REVISIONS,
        }[mode]
        and r.get("session") == [["app_admin", "academy", "on", "on", "off"]],
        "actual_full_composed_catalog_report",
    )
    if mode == "before":
        require(
            r.get("kernel_table") == [] and r.get("kernel_prerequisite_roles") == [["platform_api"]],
            "baseline_kernel_catalog_absent",
        )
    else:
        require(
            r.get("kernel_table") == [["r", "app_admin", False, False, False]]
            and r.get("kernel_row_count") == 0
            and all(
                key in r
                for key in (
                    "kernel_columns",
                    "kernel_policies",
                    "kernel_constraints",
                    "kernel_indexes",
                    "kernel_acl",
                    "kernel_column_acl",
                    "kernel_noninternal_triggers",
                    "kernel_access",
                )
            ),
            "actual_kernel_catalog_required",
        )
        require(
            r["kernel_columns"]
            == [
                [n, t, True, None, "", ""]
                for n, t in (
                    ("key_hash", "character varying(64)"),
                    ("window_start", "timestamp with time zone"),
                    ("hit_count", "integer"),
                    ("expires_at", "timestamp with time zone"),
                )
            ],
            "kernel_exact_columns",
        )
        require(
            r["kernel_policies"] == []
            and r["kernel_constraints"]
            == [
                [
                    "ck_rate_limit_buckets_hit_count",
                    "c",
                    "CHECK ((hit_count >= 1))",
                    True,
                    False,
                    False,
                ],
                [
                    "pk_rate_limit_buckets",
                    "p",
                    "PRIMARY KEY (key_hash, window_start)",
                    True,
                    False,
                    False,
                ],
            ],
            "kernel_exact_policy_constraints",
        )
        require(
            r["kernel_indexes"]
            == [
                [
                    "ix_rate_limit_buckets_expires_at",
                    "CREATE INDEX ix_rate_limit_buckets_expires_at ON public.rate_limit_buckets USING btree (expires_at)",
                    True,
                    True,
                ],
                [
                    "pk_rate_limit_buckets",
                    "CREATE UNIQUE INDEX pk_rate_limit_buckets ON public.rate_limit_buckets USING btree (key_hash, window_start)",
                    True,
                    True,
                ],
            ],
            "kernel_exact_indexes",
        )
        require(
            [row for row in r["kernel_acl"] if row[0] != "app_admin"]
            == [
                ["platform_api", "app_admin", privilege, False]
                for privilege in ("DELETE", "INSERT", "SELECT", "UPDATE")
            ]
            and all(row[1] == "app_admin" for row in r["kernel_acl"] if row[0] == "app_admin"),
            "kernel_exact_acl",
        )
        require(
            r["kernel_column_acl"] == []
            and r["kernel_noninternal_triggers"] == []
            and r["kernel_access"] == [[False, True, True, True, True, True, True, True, True, False]],
            "kernel_exact_access",
        )

    require(
        type(r.get("roles")) is list
        and len(r["roles"]) == 2
        and r["roles"][1][0] == "app_user"
        and not any(r["roles"][1][i] for i in (1, 2, 3, 5, 6))
        and r.get("app_user_memberships") == [],
        "catalog_no_app_user_bypass",
    )
    require(
        type(r.get("default_acl")) is list
        and all(
            row[3] == "app_admin"
            or (row[3] == "app_user" and row[4] in {"SELECT", "INSERT", "UPDATE", "DELETE"} and not row[5])
            for row in r["default_acl"]
        ),
        "catalog_exact_default_acl",
    )
    require(
        r.get("table") == [["r", "app_admin", True, True, False]] and r.get("target_row_count") == 0,
        "existing_oidc_catalog_owner_force_rls_empty",
    )
    require(
        r.get("migration_privileges") == [[True, True, True, True]],
        "catalog_migration_privileges",
    )
    require(
        r.get("columns")
        == [
            [name, kind, True, "now()" if name == "created_at" else None, "", ""]
            for name, kind in (
                ("id", "uuid"),
                ("tenant_id", "uuid"),
                ("state_hash", "character varying(64)"),
                ("provider_binding", "character varying(80)"),
                ("code_verifier", "text"),
                ("nonce", "text"),
                ("redirect_uri", "text"),
                ("return_to", "text"),
                ("issued_at", "bigint"),
                ("expires_at", "timestamp with time zone"),
                ("created_at", "timestamp with time zone"),
            )
        ],
        "oidc_exact_columns",
    )
    expression = "(tenant_id = public.app_current_tenant_id())"
    require(
        r.get("policies")
        == [
            [
                "academy_oidc_login_states_tenant_isolation",
                "*",
                True,
                "{0}",
                expression,
                expression,
            ]
        ],
        "oidc_exact_tenant_policy",
    )
    require(
        r.get("constraints")
        == [
            [
                "academy_oidc_login_states_pkey",
                "p",
                "PRIMARY KEY (id)",
                True,
                False,
                False,
            ],
            [
                "fk_academy_oidc_login_tenant",
                "f",
                "FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE",
                True,
                False,
                False,
            ],
            [
                "uq_academy_oidc_login_tenant_state",
                "u",
                "UNIQUE (tenant_id, state_hash)",
                True,
                False,
                False,
            ],
        ],
        "oidc_exact_constraints",
    )
    require(
        r.get("indexes")
        == [
            [
                "academy_oidc_login_states_pkey",
                "CREATE UNIQUE INDEX academy_oidc_login_states_pkey ON public.academy_oidc_login_states USING btree (id)",
                True,
                True,
            ],
            [
                "ix_academy_oidc_login_states_tenant_id",
                "CREATE INDEX ix_academy_oidc_login_states_tenant_id ON public.academy_oidc_login_states USING btree (tenant_id)",
                True,
                True,
            ],
            [
                "uq_academy_oidc_login_tenant_state",
                "CREATE UNIQUE INDEX uq_academy_oidc_login_tenant_state ON public.academy_oidc_login_states USING btree (tenant_id, state_hash)",
                True,
                True,
            ],
        ],
        "oidc_exact_indexes",
    )
    require(
        type(r.get("acl")) is list
        and [row for row in r["acl"] if row[0] != "app_admin"]
        == [["app_user", "app_admin", privilege, False] for privilege in ("DELETE", "INSERT", "SELECT", "UPDATE")]
        and all(row[1] == "app_admin" for row in r["acl"] if row[0] == "app_admin"),
        "oidc_exact_acl",
    )
    require(
        r.get("column_acl") == [] and r.get("noninternal_triggers") == [] and r.get("access") == [[True, False]],
        "oidc_no_extra_access",
    )


def migration_history(evidence):
    """Three genuine immutable stopped receipts; never current host/catalog proof."""
    require(hasattr(evidence, "execution_approval"), "original_execution_authority_reference_required")
    reference = evidence.execution_approval
    exact(reference, ("path", "sha256"))
    require(reference["sha256"] == evidence.approval_hash, "original_execution_authority_hash_binding")
    authority, authority_hash = load(reference["path"])
    require(authority_hash == evidence.approval_hash, "original_execution_authority_bytes")
    # Historical expiry allowance applies only here, never to live authority.
    approval(authority, evidence.manifest_hash, evidence.m, "migrate-kernel0031", historical=True)
    require(
        authority["attempt"] == evidence.value["attempt"] == evidence.a["attempt"],
        "original_execution_authority_attempt",
    )
    before = evidence.phase("db-before", "web", "db-before", fresh=False)
    kernel = evidence.phase("migrate-kernel0031", "web", "migrate-kernel0031", fresh=False)
    after = evidence.phase("db-after", "web", "db-after", fresh=False)
    catalog_report(before["observations"]["database"], evidence.m, "before")
    migration_report(kernel["observations"]["migration"], evidence.m, "kernel0031")
    catalog_report(after["observations"]["database"], evidence.m, "after")
    chain = [("db-before", before), ("migrate-kernel0031", kernel), ("db-after", after)]
    for index, (_, receipt) in enumerate(chain):
        require(
            type(receipt["started_unix"]) is int
            and type(receipt["completed_unix"]) is int
            and authority["approved_unix"]
            <= receipt["started_unix"]
            <= receipt["completed_unix"]
            <= authority["expires_unix"],
            "migration_history_same_original_approval_window",
        )
        observation = receipt["observations"]["migration" if index == 1 else "database"]
        require(
            type(observation["launch_started_unix"]) is int
            and receipt["started_unix"] <= observation["launch_started_unix"] <= receipt["completed_unix"],
            "migration_history_producer_launch_window",
        )
        for previous_name, previous in chain[:index]:
            require(
                receipt["started_unix"] >= previous["completed_unix"]
                and receipt["evidence"].get(previous_name) == evidence.used[previous_name],
                "migration_history_order_and_exact_receipt_join",
            )
    require(kernel["observations"].get("mandatory_next_phase") == "db-after", "fixed_pipeline_next_phase")
    return dict(catalog_before=before, kernel_migration=kernel, catalog_after=after)


def database_phase(phase, role, m, a, evidence):
    require(role == "web", "database_phases_web_only")
    require(
        hasattr(evidence, "phase_started_unix") and type(evidence.phase_started_unix) is int,
        "database_phase_start_custody",
    )
    both_stopped(evidence, role, m)
    verify_stage(m, role, evidence)
    exclusion(evidence, m, a, role)
    gate(evidence, m, a, role)
    require(phase in {"db-before", "migrate-kernel0031", "db-after"}, "fixed_database_phase")
    mode = "after" if phase == "db-after" else "before"
    idle = fresh_idle(m, role, mode, a["attempt"])
    if phase != "db-before":
        before = evidence.phase("db-before", "web", "db-before", fresh=phase == "migrate-kernel0031")
        catalog_report(before["observations"]["database"], m, "before")
        require(
            type(before["started_unix"]) is int
            and type(before["completed_unix"]) is int
            and type(before["observations"]["database"]["launch_started_unix"]) is int
            and before["started_unix"]
            <= before["observations"]["database"]["launch_started_unix"]
            <= before["completed_unix"]
            and a["approved_unix"]
            <= before["started_unix"]
            <= before["completed_unix"]
            <= evidence.phase_started_unix
            < a["expires_unix"],
            "baseline_original_approval_window",
        )
        if phase == "db-after":
            kernel = evidence.phase("migrate-kernel0031", "web", "migrate-kernel0031", fresh=False)
            migration_report(kernel["observations"]["migration"], m, "kernel0031")
            require(
                type(kernel["started_unix"]) is int
                and type(kernel["completed_unix"]) is int
                and type(kernel["observations"]["migration"]["launch_started_unix"]) is int
                and kernel["started_unix"]
                <= kernel["observations"]["migration"]["launch_started_unix"]
                <= kernel["completed_unix"]
                and before["completed_unix"]
                <= kernel["started_unix"]
                <= kernel["completed_unix"]
                <= evidence.phase_started_unix
                < a["expires_unix"]
                and kernel["evidence"].get("db-before") == evidence.used["db-before"]
                and kernel["observations"].get("mandatory_next_phase") == "db-after",
                "kernel_baseline_custody_join",
            )
    if phase == "migrate-kernel0031":
        stamp(before["observations"]["database"]["launch_started_unix"])
        value = common_input(m, role, "candidate_migration_entry.py")
        value.update(
            schema="AcademyCandidateMigrationInputs.v4",
            database="academy",
            migration_step="kernel0031",
            source_file_sha256=m["migration_source_pins"],
            kernel_migration=m["kernel_migration"],
            expected_before=BASELINE_REVISIONS,
            env_sha256=m["roles"][role]["environment_sha256"],
        )
        both_stopped(evidence, role, m)
        exclusion(evidence, m, a, role)
        gate(evidence, m, a, role)
        observed = helper_call(
            m,
            role,
            "candidate_migration_entry.py",
            value,
            timeout=600,
            authorization=a,
            ddl_authority=(evidence, phase),
        )
        migration_report(observed, m, "kernel0031")
        return {
            "migration": observed,
            "idle_before": idle,
            "gate": gate(evidence, m, a, role),
            "mandatory_next_phase": "db-after",
            "catalog_after_proven": False,
        }
    value = common_input(m, role, "candidate_db_readiness.py")
    value.update(
        schema="AcademyCandidateDBReadinessInputs.v4",
        env_sha256=m["roles"][role]["environment_sha256"],
        mode=mode,
        database="academy",
        source_file_sha256=m["db_source_pins"],
        expected_before=m["expected_before"],
        oidc_expect_empty=True,
    )
    database = helper_call(m, role, "candidate_db_readiness.py", value)
    catalog_report(database, m, mode)
    stamp(database["launch_started_unix"])
    return {
        "database": database,
        "idle_before": idle,
        "idle_after": fresh_idle(m, role, mode, a["attempt"]),
        "gate": gate(evidence, m, a, role),
        "preserved": preserved(role, m),
    }


def migration_intent_path(phase="migrate-kernel0031"):
    """One permanent web-host barrier for this database transition, across packets."""
    require(phase == "migrate-kernel0031", "fixed_migration_ledger")
    parent = directory_fd("/root", root_only=True, private=True)
    try:
        name = "academy-deployment-ledger"
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        ledger = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            info = os.fstat(ledger)
            require(
                info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                "migration_ledger_root0700",
            )
            os.fsync(ledger)
        finally:
            os.close(ledger)
        os.fsync(parent)
    finally:
        os.close(parent)
    return Path("/root/academy-deployment-ledger/academy-kernel0031-migration.json")


def main():
    global SOURCE, VENV
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--role", choices=HOSTS, required=True)
    for name in ("manifest", "approval", "evidence-index", "receipt"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require(
        sys.platform == "linux" and os.getuid() == os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site,
        "trusted_root_system_python_I_S",
    )
    require(socket.gethostname().split(".")[0] == HOSTS[args.role], "host_identity")
    host_execution_lock()
    m, manifest_hash = load(args.manifest)
    validate_manifest(m, args.role)
    SOURCE, VENV = m["source"], m["venv"]
    require(
        digest(read_bytes(Path(__file__).absolute(), limit=2000000, private=True)) == m["self_sha256"],
        "executor_hash",
    )
    require(
        digest(
            read_bytes(
                Path(args.manifest).parent / "execution-plan.json",
                limit=2000000,
                private=True,
            )
        )
        == m["plan_sha256"],
        "plan_hash",
    )
    a, approval_hash = load(args.approval)
    approval(a, manifest_hash, m, args.phase)
    evidence = Evidence(args.evidence_index, m, a, approval_hash, manifest_hash)
    evidence.approval_path, evidence.manifest_path = args.approval, args.manifest
    evidence.execution_approval = {"path": args.approval, "sha256": approval_hash}
    evidence.active_authority = {
        "kind": "execution",
        "phase": args.phase,
        "manifest": {"path": args.manifest, "sha256": manifest_hash},
        "approval": {"path": args.approval, "sha256": approval_hash},
    }
    evidence.validate_active_authority = lambda current, manifest, sha256, phase: approval(
        current, sha256, manifest, phase
    )
    if args.phase in UNSUPPORTED:
        print(
            json.dumps(
                {
                    "status": "unsupported_phase",
                    "phase": args.phase,
                    "reason": "effective_environment_candidate_process_acceptance_cleanup_release_contracts_pending",
                    "deployment_ready": False,
                }
            )
        )
        return 2
    receipt = Path(args.receipt)
    require(
        receipt.parent == Path(args.manifest).parent and re.fullmatch(r"[a-z0-9-]+\.json", receipt.name),
        "receipt_path",
    )
    if args.phase == "migrate-kernel0031":
        require(args.role == "web", "migration_web_only")
        intent_path = migration_intent_path(args.phase)
    elif args.phase in {"baseline", "db-before", "db-after"}:
        # Read-only observations can be refreshed with a new exclusive receipt.
        intent_path = receipt.parent / (receipt.stem + "-observation-intent.json")
    else:
        intent_path = receipt.parent / ("intent-" + a["attempt"] + "-" + args.role + "-" + args.phase + ".json")
    # The fixed database-transition ledger survives new packets, attempts and
    # source candidates. Never retry a prior migration intent automatically.
    intent = dict(
        schema="AcademyExecutionIntent.v1",
        phase=args.phase,
        role=args.role,
        candidate=m["candidate"],
        tree=m["tree"],
        attempt=a["attempt"],
        approval_sha256=approval_hash,
        manifest_sha256=manifest_hash,
        evidence_index_sha256=evidence.sha256,
        evidence=evidence.value["entries"],
        started_unix=int(time.time()),
        recovery=m["recovery"],
        retention=m["retention"],
    )
    # Reserve output first, then immutable intent, before any service/DB action.
    write_new(
        receipt,
        {
            "schema": "AcademyExecutionReservation.v1",
            "status": "started_or_interrupted_hold",
            "phase": args.phase,
            "attempt": a["attempt"],
            "candidate": m["candidate"],
            "intent": intent_path.name,
        },
    )
    write_new(intent_path, intent)
    state = dict(
        schema="AcademyExecutionReceipt.v2",
        status="failed_fix_forward_manual_hold",
        phase=args.phase,
        role=args.role,
        candidate=m["candidate"],
        tree=m["tree"],
        attempt=a["attempt"],
        approval_sha256=approval_hash,
        manifest_sha256=manifest_hash,
        evidence_index_sha256=evidence.sha256,
        intent_sha256=digest(canonical(intent) + b"\n"),
        started_unix=intent["started_unix"],
        completed_unix=0,
        evidence={},
        observations={},
        process_groups=[],
        deployment_ready=False,
    )
    evidence.phase_started_unix = state["started_unix"]
    # Final results use a separate exclusive file. The reservation and intent are
    # immutable; abrupt death cannot leave an apparently completed receipt.
    final_path = receipt.with_name(receipt.stem + "-result.json")
    try:
        if args.phase == "baseline":
            # Both staged receipts' provenance is mandatory before either role's
            # baseline; root separately transfers remote receipts under custody.
            for host_role in HOSTS:
                remote = evidence.get("stage-" + host_role, "candidate_stage.py", host_role, fresh=False)
                stage_content(remote, m, host_role)
                require(
                    remote["candidate"] == m["candidate"]
                    and remote["tree"] == m["tree"]
                    and remote["manifest_sha256"] == m["roles"][host_role]["staging_manifest_sha256"]
                    and remote["status"] == "inactive_stage_observed"
                    and remote["role"] == host_role,
                    "both_stage_identity",
                )
                require(
                    remote["source_file_manifest"]["sha256"] == m["roles"][host_role]["source_inventory_sha256"]
                    and digest(canonical(remote["source_file_manifest"]["entries"]))
                    == remote["source_file_manifest"]["sha256"]
                    and remote["venv_file_manifest"]["sha256"] == m["roles"][host_role]["venv_inventory_sha256"]
                    and digest(canonical(remote["venv_file_manifest"]["entries"]))
                    == remote["venv_file_manifest"]["sha256"],
                    "both_stage_inventory_provenance",
                )
            state["observations"] = {
                "staged": verify_stage(m, args.role, evidence),
                "baseline": snapshot(args.role, m["roles"][args.role]["baseline"], baseline_runtime(m, args.role)),
            }
        elif args.phase == "quiesce":
            state["observations"] = quiesce(args.role, m, a, evidence)
        else:
            state["observations"] = database_phase(args.phase, args.role, m, a, evidence)
        require(
            all(p["confirmed"] is True for p in PROCESS_GROUPS),
            "owned_process_cleanup_unconfirmed",
        )
        state["status"] = "observed"
    finally:
        for sig in INTERRUPTS:
            signal.signal(sig, signal.SIG_IGN)
        state.update(
            completed_unix=int(time.time()),
            evidence=evidence.used,
            process_groups=PROCESS_GROUPS,
        )
        if any(not p.get("confirmed") for p in PROCESS_GROUPS):
            state["status"] = "process_cleanup_unconfirmed_manual_hold"
        write_new(final_path, state)
    print(
        json.dumps(
            {
                "status": state["status"],
                "phase": args.phase,
                "receipt_sha256": digest(canonical(state) + b"\n"),
                "deployment_ready": False,
            }
        )
    )


if __name__ == "__main__":
    for interrupt in INTERRUPTS:
        signal.signal(interrupt, interrupt_stage)
    try:
        exit_code = main()
    except BaseException:
        print(
            '{"status":"refused_or_failed_paused_fix_forward","deployment_ready":false,"details":"preserve_intent_reservation_results_and_all_partial_state"}'
        )
        sys.exit(1)
    else:
        sys.exit(exit_code or 0)

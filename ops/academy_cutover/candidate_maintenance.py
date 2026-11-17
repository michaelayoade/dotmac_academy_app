"""Root-only named-unit maintenance authority; source preparation grants no authority.

Acyclic component validation and retained verification are read-only. Only the
standalone CLI acquires the shared host lock. No legacy daemon/job is killed,
restarted or resumed. Unfrozen or unsupported configurations refuse.
"""

# ruff: noqa: E501 -- fixed closed contracts and unit directives stay auditable.
import argparse
import hashlib
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
import types
from pathlib import Path

HOSTS = {"web": "vmi2490731", "lab": "academy-labs"}
NAMES = ("admin-report", "email-digest", "email-outbox", "erp-training-sync", "hr-report", "learner-digest", "reminders")
WEB = tuple(["academy-web.service", *("academy-" + n + ".service" for n in NAMES), *("academy-" + n + ".timer" for n in NAMES)])
LAB_LEGACY = ("academy-app.service", "academy-email-digest.service", "academy-lab-reconcile.service", "academy-lab-worker.service", "academy-reap-labs.service", "academy-email-digest.timer", "academy-lab-reconcile.timer", "academy-reap-labs.timer")
ADOPT = {"academy-v2-lab-reconcile.service": "lab-reconcile", "academy-v2-reap-labs.service": "reap-labs"}
RESUME = tuple(name.removesuffix(".service") + ".timer" for name in ADOPT)
TARGETS = {"web": WEB, "lab": (*LAB_LEGACY, *ADOPT, *RESUME)}
PROTECTED = {"academy-db-tunnel.service", "academy-lab-ipv6-guard.service", "academy-v2-db-tunnel.service", "academy-v2-console-guard.service", "academy-v2-web.service", "academy-v2-lab-worker.service", *("academy-v2-" + n + ".service" for n in NAMES), *("academy-v2-" + n + ".timer" for n in NAMES)}
STATUSES = ("fenced", "adopted_and_fenced", "resumed")
DEPS = ("Requires", "Requisite", "Wants", "BindsTo", "PartOf", "Conflicts", "OnSuccess", "OnFailure", "Triggers", "TriggeredBy", "PropagatesStopTo", "StopPropagatedFrom", "RequiredBy", "WantedBy", "RequisiteOf", "BoundBy", "ConsistsOf", "ConflictedBy", "JoinsNamespaceOf", "After", "Before")
BASE_DEPS = {"-.mount", "system.slice", "sysinit.target", "basic.target", "network.target", "network-online.target", "shutdown.target", "timers.target", "systemd-journald.socket", "time-set.target", "time-sync.target"}
EMPTY_DEPS = {"Requisite", "BindsTo", "PartOf", "OnSuccess", "OnFailure", "PropagatesStopTo", "StopPropagatedFrom", "RequisiteOf", "BoundBy", "ConsistsOf", "JoinsNamespaceOf"}
HOOKS = ("ExecCondition", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload")
EMPTY_SERVICE_SIGNATURES = dict.fromkeys(HOOKS, "a(sasbttttuii)") | {"EnvironmentFiles": "a(sb)"}
SERVICE_TARGETS = frozenset(unit for units in TARGETS.values() for unit in units if unit.endswith(".service"))
COMMON_CONFIG = ("Id", "Names", "LoadState", "FragmentPath", "SourcePath", "DropInPaths", "UnitFileState", "RefuseManualStart", "RefuseManualStop", "AllowIsolate", "StopWhenUnneeded", "FailureAction", "SuccessAction", "JobTimeoutAction", "StartLimitAction", *DEPS)
SERVICE_CONFIG = ("Type", "User", "Group", "WorkingDirectory", "RootDirectory", "RootImage", "DynamicUser", "PrivateUsers", "Environment", "EnvironmentFiles", "PassEnvironment", "UnsetEnvironment", "Restart", "RestartMode", "RestartForceExitStatus", "RestartPreventExitStatus", "PAMName", "SupplementaryGroups", "BindPaths", "BindReadOnlyPaths", "MountImages", "ExtensionImages", "ExtensionDirectories", "ExecStart", *HOOKS)
TIMER_CONFIG = ("Unit", "Persistent", "WakeSystem", "RandomizedDelayUSec", "AccuracyUSec")
STATE = ("MainPID", "ControlPID", "ControlGroup", "ActiveState", "SubState")
CONTRACT_SHA = "3d4d8ec55c10fdeee86f751dc90b5a81ce4ca5c43bc974edffca4b1350b475a0"
COMMANDS = []
SPAWNING = PENDING = False


class Refusal(Exception):
    pass


def require(ok, tag="maintenance_refused"):
    if not ok:
        raise Refusal(tag)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields), "strict_fields")


def hexvalue(value, length=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value), "hash_shape")


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "nonfinite_json"))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory(path, private=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute_directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in (None, *path.parts[1:]):
            if part is not None:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = following
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "root_directory_custody")
        if private:
            require(path.is_relative_to(Path("/root")) and stat.S_IMODE(info.st_mode) == 0o700, "root_private_parent")
        return fd
    except BaseException:
        os.close(fd)
        raise


def names(fd, cap=128):
    result = []
    with os.scandir(fd) as entries:
        for entry in entries:
            require(len(result) < cap, "directory_stream_bound")
            result.append(entry.name)
    return sorted(result)


def read_file(path, *, private=False, limit=2_000_000, mode=0o600, virtual=False):
    path = Path(path)
    parent = directory(path.parent, private=private)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and not before.st_mode & 0o022 and before.st_size <= limit, "root_regular_file")
            require(mode is None or stat.S_IMODE(before.st_mode) == mode, "exact_file_mode")
            blocks, size = [], 0
            while True:
                block = stream.read(min(65536, limit + 1 - size))
                if not block:
                    break
                size += len(block)
                require(size <= limit, "streaming_file_bound")
                blocks.append(block)
            require(virtual or (identity(before) == identity(os.fstat(stream.fileno())) and size == before.st_size), "file_changed")
            return b"".join(blocks), before
    finally:
        os.close(parent)


def load(pin):
    exact(pin, ("path", "sha256"))
    hexvalue(pin["sha256"])
    raw, _ = read_file(pin["path"], private=True)
    require(sha(raw) == pin["sha256"], "protected_pin_drift")
    return decode(raw)


def module(pin, basename):
    require(Path(pin["path"]).name == basename, "module_basename")
    raw, _ = read_file(pin["path"], private=True)
    require(sha(raw) == pin["sha256"], "module_hash")
    loaded = types.ModuleType("reviewed_" + basename.replace(".", "_"))
    loaded.__file__ = pin["path"]
    exec(compile(raw, pin["path"], "exec"), loaded.__dict__)  # noqa: S102 -- exact reviewed root-private source only
    return loaded


def own_path(m, unit, fence):
    require(unit in set(WEB) | set(TARGETS["lab"]) and unit not in PROTECTED, "protected_or_unknown_target")
    prefix = "zzzz-academy-maintenance-" if fence else "zzzy-academy-maintenance-"
    return Path("/etc/systemd/system") / (unit + ".d") / (prefix + m["candidate"] + ".conf")


def fence_bytes(unit):
    text = "[Unit]\nRefuseManualStart=yes\nOnFailure=\nOnSuccess=\nFailureAction=none\nSuccessAction=none\nJobTimeoutAction=none\nStartLimitAction=none\n"
    if unit.endswith(".service"):
        text += "[Service]\nExecCondition=\nExecStartPre=\nExecStart=\nExecStart=/usr/bin/false\nExecStartPost=\nExecStop=\nExecStopPost=\nExecReload=\nRestart=no\nRestartForceExitStatus=\nRestartPreventExitStatus=\nEnvironment=\nEnvironmentFile=\nPassEnvironment=\nUnsetEnvironment=\n"
    return text.encode()


def adoption_bytes(m, unit):
    require(unit in ADOPT, "adoption_target")
    return ("[Service]\nWorkingDirectory=" + m["source"] + "\nExecStart=\nExecStart=" + m["venv"] + "/bin/python -m app.cli " + ADOPT[unit] + "\n").encode()


def validate_dependencies(role, unit, dependencies):
    exact(dependencies, DEPS)
    pair = unit.removesuffix(".timer") + ".service" if unit.endswith(".timer") else unit.removesuffix(".service") + ".timer"
    for key, values in dependencies.items():
        require(type(values) is list and values == sorted(set(values)) and all(type(v) is str for v in values), "dependency_list")
        if key in EMPTY_DEPS:
            require(not values, "unsupported_dependency_relation")
        elif key in {"Triggers", "TriggeredBy"}:
            expected = [pair] if pair in TARGETS[role] and ((key == "Triggers") == unit.endswith(".timer")) else []
            require(values == expected or (not values and key == "TriggeredBy"), "unsupported_activation_relation")
        else:
            allowed = set(BASE_DEPS)
            if key in {"After", "Before"} and pair in TARGETS[role]:
                allowed.add(pair)
            if key == "After" and (role, unit) in {("web", "academy-web.service"), ("lab", "academy-lab-reconcile.service"), ("lab", "academy-lab-worker.service"), ("lab", "academy-v2-lab-reconcile.service")} :
                allowed.add("docker.service")
            # Explicitly classified infrastructure edge, NOT a non-sender proof.
            if role == "lab" and unit == "academy-app.service" and key in {"Wants", "After"}:
                allowed.add("docker.service")
            require(set(values) <= allowed, "unsupported_external_dependency")


def validate_component(common, execution_manifest):
    """Read-only; never recursively invoke common.validate_manifest or take flock."""
    m = execution_manifest
    exact(m["maintenance"], ("path", "sha256"))
    exact(m["helpers"]["maintenance"], ("path", "sha256"))
    component = load(m["maintenance"])
    exact(component, ("schema", "candidate", "tree", "source", "venv", "helper", "plan", "inert_program_sha256", "hosts"))
    require(component["schema"] == "AcademyMaintenanceInputs.v1", "component_schema")
    for key in ("candidate", "tree", "source", "venv"):
        require(component[key] == m[key], "component_candidate_identity")
    hexvalue(component["candidate"], 40)
    hexvalue(component["tree"], 40)
    require(component["source"] == "/srv/academy/releases/" + m["candidate"] and component["venv"] == "/srv/academy/venvs/" + m["candidate"], "component_new_paths")
    require(component["helper"] == m["helpers"]["maintenance"] and Path(component["helper"]["path"]).name == "candidate_maintenance.py", "component_helper_join")
    for field in ("helper", "plan"):
        exact(component[field], ("path", "sha256"))
        raw, _ = read_file(component[field]["path"], private=True)
        require(sha(raw) == component[field]["sha256"], "component_code_plan_pin")
    require(Path(component["plan"]["path"]).name == "maintenance-plan.json", "plan_basename")
    hexvalue(component["inert_program_sha256"])
    exact(component["hosts"], HOSTS)
    for role, host in component["hosts"].items():
        exact(host, ("hostname", "uid", "gid", "manager_environment_sha256", "units"))
        require(host["hostname"] == HOSTS[role] and host["uid"] == m["roles"][role]["uid"] and type(host["gid"]) is int and host["gid"] > 0, "component_host")
        hexvalue(host["manager_environment_sha256"])
        exact(host["units"], TARGETS[role])
        for unit, spec in host["units"].items():
            exact(spec, ("original_files", "enablement_links", "original_unit_text_sha256", "expected_config_sha256", "dependencies", "originally_active", "fence_sha256", "adoption_sha256", "observed_command_sha256", "environment_sha256"))
            require(unit not in PROTECTED and type(spec["originally_active"]) is bool, "absolute_target_scope")
            validate_dependencies(role, unit, spec["dependencies"])
            require(type(spec["original_files"]) is list and 1 <= len(spec["original_files"]) <= 16, "original_file_count")
            require(len({ref["path"] for ref in spec["original_files"]}) == len(spec["original_files"]), "duplicate_original_files")
            fragments = 0
            for ref in spec["original_files"]:
                exact(ref, ("path", "sha256", "dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns"))
                path = Path(ref["path"])
                fragment = path in {Path("/etc/systemd/system") / unit, Path("/usr/lib/systemd/system") / unit}
                fragments += int(fragment)
                require(all(type(ref[key]) is int and ref[key] >= 0 for key in ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")) and ref["size"] <= 2_000_000, "original_metadata_types")
                dropin = path.parent in {Path("/etc/systemd/system") / (unit + ".d"), Path("/usr/lib/systemd/system") / (unit + ".d")} and path.name.endswith(".conf")
                require((fragment or dropin) and path not in {own_path(m, unit, True), own_path(m, unit, False)} and ref["uid"] == 0 and ref["mode"] == 0o644 and ref["nlink"] == 1, "original_file_namespace")
                if dropin:
                    require(path.name < own_path(m, unit, unit not in ADOPT).name, "unsupported_dropin_precedence")
                hexvalue(ref["sha256"])
            require(fragments == 1, "exactly_one_fragment")
            if unit in RESUME:
                require(spec["originally_active"] is True and len(spec["enablement_links"]) == 1, "resume_only_originally_active_enabled_timers")
            require(type(spec["enablement_links"]) is list and len(spec["enablement_links"]) <= 1, "enablement_link_count")
            for ref in spec["enablement_links"]:
                exact(ref, ("path", "target", "dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns"))
                require(all(type(ref[key]) is int and ref[key] >= 0 for key in ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")), "link_metadata_types")
                require(unit.endswith(".timer") and Path(ref["path"]) == Path("/etc/systemd/system/timers.target.wants") / unit and ref["target"] == "/etc/systemd/system/" + unit and ref["uid"] == 0 and ref["mode"] == 0o777, "closed_enablement_link")
            exact(spec["expected_config_sha256"], ("original", *STATUSES))
            for value in (*spec["expected_config_sha256"].values(), spec["original_unit_text_sha256"], spec["observed_command_sha256"], spec["environment_sha256"]):
                hexvalue(value)
            require(spec["fence_sha256"] == sha(fence_bytes(unit)), "exact_inert_override")
            require(spec["adoption_sha256"] == (sha(adoption_bytes(m, unit)) if unit in ADOPT else None), "exact_candidate_override")
            if unit.endswith(".timer"):
                require(spec["observed_command_sha256"] == spec["environment_sha256"] == sha(b""), "timer_has_no_service_command_or_environment")
            if unit not in ADOPT:
                require(spec["expected_config_sha256"]["adopted_and_fenced"] == spec["expected_config_sha256"]["fenced"], "nonadopted_configuration")
            if unit not in {*ADOPT, *RESUME}:
                require(spec["expected_config_sha256"]["resumed"] == spec["expected_config_sha256"]["fenced"], "legacy_never_resumed")
    return component


def interrupted(_sig, _frame):
    global PENDING
    if SPAWNING:
        PENDING = True
    else:
        raise Refusal("interrupted")


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def cleanup(proc):
    handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
    result = {"pgid": proc.pid, "confirmed": False}
    try:
        for sig, seconds in ((signal.SIGTERM, 2), (signal.SIGKILL, 5)):
            if group_present(proc.pid):
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    pass
            until = time.monotonic() + seconds
            while time.monotonic() < until:
                proc.poll()
                if not group_present(proc.pid):
                    break
                time.sleep(0.02)
        proc.wait(timeout=2)
        result["confirmed"] = not group_present(proc.pid)
    except BaseException:
        result["confirmed"] = False
    finally:
        for pipe in (proc.stdout, proc.stderr):
            pipe.close()
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    return result


def empty_property_argv(unit, key):
    require(unit in SERVICE_TARGETS and key in EMPTY_SERVICE_SIGNATURES, "closed_empty_service_property")
    encoded = "".join(c if c.isascii() and c.isalnum() else "_" + format(ord(c), "02x") for c in unit)
    return ["/usr/bin/busctl", "--system", "--no-pager", "--timeout=10", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/" + encoded, "org.freedesktop.systemd1.Service", key]


def run(argv, timeout=30):
    """Stream bounds enforced before buffering; never expose child streams."""
    global SPAWNING, PENDING
    require(argv[0] == "/usr/bin/systemctl" or tuple(argv) in {tuple(empty_property_argv(unit, key)) for unit in SERVICE_TARGETS for key in EMPTY_SERVICE_SIGNATURES}, "closed_owned_command")
    proc = None
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    record = {"program": Path(argv[0]).name, "started_unix": time.time()}
    require(len(COMMANDS) < 1024, "owned_command_count_bound")
    COMMANDS.append(record)
    try:
        SPAWNING = True
        try:
            proc = subprocess.Popen(argv, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)  # noqa: S603 -- closed module-owned systemctl arguments
        finally:
            SPAWNING = False
        if PENDING:
            PENDING = False
            raise Refusal("interrupted_during_spawn")
        for stream, name in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            require(time.monotonic() < deadline, "systemctl_timeout")
            for key, _mask in selector.select(0.1):
                raw = os.read(key.fd, 65536)
                if not raw:
                    selector.unregister(key.fileobj)
                else:
                    target = buffers[key.data]
                    require(len(target) + len(raw) <= 2_000_000, "systemctl_stream_bound")
                    target.extend(raw)
        proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        require(proc.returncode == 0, "systemctl_failed_details_suppressed")
        return bytes(buffers["stdout"]).decode("utf-8")
    finally:
        selector.close()
        record.update(stdout_sha256=sha(buffers["stdout"]), stderr_sha256=sha(buffers["stderr"]), completed_unix=time.time())
        if proc is not None:
            record["cleanup"] = cleanup(proc)
            require(record["cleanup"]["confirmed"], "owned_command_cleanup_unconfirmed")
        else:
            record["cleanup"] = {"confirmed": False, "spawn_handle_unavailable": True}


def read_timeout(deadline):
    if deadline is None:
        return 30
    remaining = deadline - time.monotonic()
    require(remaining > 0, "natural_job_drain_unconfirmed")
    return min(30, remaining)


def read_command(argv, deadline=None):
    require(not PENDING, "interrupted")
    result = run(argv, timeout=read_timeout(deadline))
    read_timeout(deadline)
    return result


def show(unit, config=True, *, deadline=None):
    fields = (*COMMON_CONFIG, *(SERVICE_CONFIG if unit.endswith(".service") else TIMER_CONFIG)) if config else STATE
    text = read_command(["/usr/bin/systemctl", "show", unit, "--all", "--property=" + ",".join(fields)], deadline)
    values = {}
    for line in text.splitlines():
        require("=" in line, "systemctl_property_representation")
        key, value = line.split("=", 1)
        require(key in fields and key not in values, "systemctl_property_fields")
        values[key] = value
    required = set(fields) if config or unit.endswith(".service") else {"ActiveState", "SubState"}
    for key in sorted(required - set(values)):
        require(unit.endswith(".service") and key in EMPTY_SERVICE_SIGNATURES, "systemctl_missing_property")
        raw_empty = read_command(empty_property_argv(unit, key), deadline)
        require(raw_empty == EMPTY_SERVICE_SIGNATURES[key] + " 0\n", "typed_empty_service_property_required")
        values[key] = ""
    require(required <= set(values), "systemctl_missing_property")
    return values


def manager_environment(host, *, deadline=None):
    raw = read_command(["/usr/bin/systemctl", "show-environment"], deadline)
    require(sha(raw.encode()) == host["manager_environment_sha256"], "manager_environment_drift")
    allowed = {"PATH", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ", "HOME", "USER", "LOGNAME", "SHELL"}
    values = {}
    for line in raw.splitlines():
        parts = shlex.split(line, comments=False)
        require(len(parts) == 1 and "=" in parts[0], "manager_environment_representation")
        key, value = parts[0].split("=", 1)
        require(key in allowed and key not in values, "unsafe_manager_environment_key")
        if key == "PATH":
            for entry in value.split(":"):
                require(entry and Path(entry).is_absolute(), "manager_path")
                fd = directory(Path(entry).resolve(strict=True))
                os.close(fd)
        elif key in {"HOME", "SHELL"}:
            require(value in {"/root", "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}, "manager_home_shell")
        else:
            require(re.fullmatch(r"[A-Za-z0-9_.:/+@-]{0,128}", value), "manager_literal_environment")
        values[key] = value
    return sha(raw.encode())


def originals(spec):
    rows = []
    for ref in spec["original_files"]:
        raw, info = read_file(ref["path"], mode=0o644)
        actual = {key: value for key, value in zip(("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns"), identity(info), strict=True)}
        require(all(actual[key] == ref[key] for key in actual) and sha(raw) == ref["sha256"], "immutable_original_preimage")
        rows.append({"path": ref["path"], "sha256": sha(raw)})
    for ref in spec["enablement_links"]:
        path = Path(ref["path"])
        fd = directory(path.parent)
        try:
            info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            require(stat.S_ISLNK(info.st_mode) and identity(info) == tuple(ref[key] for key in ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")) and os.readlink(path.name, dir_fd=fd) == ref["target"], "immutable_enablement_link")
        finally:
            os.close(fd)
    return sha(canonical(rows))


def normalized_config(C, values):
    values = dict(values)
    for key in DEPS:
        values[key] = sorted(values[key].split())
    values["Names"] = sorted(values["Names"].split())
    values["DropInPaths"] = sorted(values["DropInPaths"].split())
    if "ExecStart" in values:
        values["ExecStart"] = C.stable_exec_start(values["ExecStart"])
    return sha(canonical(values))


def cgroup_empty(unit, state):
    require(state.get("MainPID", "0") == state.get("ControlPID", "0") == "0", "named_process_still_running")
    group = state.get("ControlGroup", "")
    if not group:
        return sha(b"empty_cgroup_path")
    require(group == "/system.slice/" + unit, "unsupported_cgroup_path")
    root = Path("/sys/fs/cgroup") / group.removeprefix("/")
    try:
        fd = directory(root)
    except FileNotFoundError:
        return sha(group.encode())
    visited, procs_seen = 0, 0
    def inspect(fd):
        nonlocal visited, procs_seen
        for name in names(fd, 128):
            visited += 1
            require(visited <= 2048, "cgroup_directory_bound")
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(not stat.S_ISLNK(info.st_mode), "cgroup_link_refused")
            if stat.S_ISDIR(info.st_mode):
                require(info.st_uid == 0 and not info.st_mode & 0o022, "nested_cgroup_custody")
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    inspect(child)
                finally:
                    os.close(child)
            elif name == "cgroup.procs":
                procs_seen += 1
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    require(stat.S_ISREG(os.fstat(child).st_mode) and os.fstat(child).st_uid == 0 and not os.fstat(child).st_mode & 0o022, "cgroup_procs_type")
                    raw = os.read(child, 65537)
                    require(len(raw) <= 65536 and not raw.strip(), "named_cgroup_populated")
                finally:
                    os.close(child)
    try:
        inspect(fd)
        require(procs_seen > 0, "missing_cgroup_procs")
    finally:
        os.close(fd)
    return sha(group.encode())


class SelectedJobsPresent(Refusal):
    """A strict proof refusal retains the exact selected rows for classification."""
    def __init__(self, jobs):
        super().__init__("named_pending_job_refused")
        self.jobs = tuple(tuple(row) for row in jobs)


class NamedUnitBusy(Refusal):
    """Never proof: only the resume wrapper may classify a permitted start race."""
    def __init__(self, unit, live, reason):
        super().__init__(reason)
        self.unit, self.live = unit, dict(live)


def selected_jobs(role, *, deadline=None):
    require(role in HOSTS, "selected_job_role")
    raw = read_command(["/usr/bin/systemctl", "list-jobs", "--no-pager", "--no-legend", "--plain"], deadline)
    selected, identifiers = [], set()
    for count, line in enumerate(raw.splitlines()):
        require(count < 4096, "pending_job_row_bound")
        fields = line.split()
        require(len(fields) == 4 and fields[0].isdigit() and fields[0] not in identifiers, "pending_job_representation")
        identifiers.add(fields[0])
        if fields[1] in TARGETS[role]:
            require(len(selected) < len(TARGETS[role]) and not any(row[1] == fields[1] for row in selected), "duplicate_named_pending_job")
            selected.append(fields)
    return selected


def pending_jobs(role, *, deadline=None):
    selected = selected_jobs(role, deadline=deadline)
    if selected:
        raise SelectedJobsPresent(selected)
    return sha(canonical(selected))


def own_files(m, role, unit, status):
    fence = status != "resumed" or unit not in {*ADOPT, *RESUME}
    adopt = role == "lab" and unit in ADOPT and status in {"adopted_and_fenced", "resumed"}
    expected = {own_path(m, unit, True): fence_bytes(unit)} if fence else {}
    if adopt:
        expected[own_path(m, unit, False)] = adoption_bytes(m, unit)
    for path in (own_path(m, unit, True), own_path(m, unit, False)):
        if path in expected:
            raw, _ = read_file(path, mode=0o644)
            require(raw == expected[path], "owned_override_drift")
        else:
            require(not path.exists() and not path.is_symlink(), "unexpected_owned_override")
    return expected


def current(C, m, component, role, status, *, timers_started=True, deadline=None):
    require(role in HOSTS and socket.gethostname() == HOSTS[role], "host_local_observation_only")
    require(status in STATUSES and (role == "lab" or status == "fenced"), "role_status")
    host = component["hosts"][role]
    owner = pwd.getpwnam("dotmac")
    require((owner.pw_uid, owner.pw_gid) == (host["uid"], host["gid"]), "actual_dotmac_identity")
    require(read_command(["/usr/bin/systemctl", "--version"], deadline).splitlines()[0].startswith("systemd 255 "), "systemd255_only")
    manager_environment(host, deadline=deadline)
    activation_links(component, role)
    binary, _ = read_file("/usr/bin/false", mode=0o755)
    require(sha(binary) == component["inert_program_sha256"], "inert_program_hash")
    jobs = pending_jobs(role, deadline=deadline)
    result, states = {}, {}
    for unit, spec in host["units"].items():
        original_sha = originals(spec)
        config = show(unit, deadline=deadline)
        require(config["Id"] == unit and config["Names"] == unit and config["LoadState"] == "loaded" and config["SourcePath"] == "", "unit_alias_generator_or_load_refused")
        require(config["RefuseManualStop"] == "no" and config["AllowIsolate"] == "no", "unsupported_unit_controls")
        dependencies = {key: sorted(config[key].split()) for key in DEPS}
        require(dependencies == spec["dependencies"], "effective_dependencies_drift")
        actual_owned = own_files(m, role, unit, status)
        originals_set = {ref["path"] for ref in spec["original_files"]}
        require(config["FragmentPath"] in originals_set and set(config["DropInPaths"].split()) == {path for path in originals_set if path.endswith(".conf")} | {str(path) for path in actual_owned}, "effective_config_file_coverage")
        conf_inventory(m, unit, originals_set | {str(path) for path in actual_owned})
        if unit in ADOPT and status in {"adopted_and_fenced", "resumed"}:
            require(config["WorkingDirectory"] == m["source"], "adopted_candidate_cwd")
        for path in config["DropInPaths"].split():
            require(Path(path).name <= own_path(m, unit, True).name, "override_precedence")
        if unit.endswith(".service"):
            require(not any(config[key] for key in ("PAMName", "SupplementaryGroups", "BindPaths", "BindReadOnlyPaths", "MountImages", "ExtensionImages", "ExtensionDirectories")) and config["RestartMode"] == "normal", "inert_namespace_or_credential_context")
            require(not any(config[name].strip() for name in HOOKS) and config["RootDirectory"] == config["RootImage"] == "" and config["DynamicUser"] == config["PrivateUsers"] == "no" and config["User"] == "dotmac" and config["Group"] in {"", "dotmac"}, "unsupported_service_execution_context")
            if status != "resumed" or unit not in ADOPT:
                require(config["Restart"] == "no" and config["RestartForceExitStatus"] == config["RestartPreventExitStatus"] == "" and config["Environment"] == config["EnvironmentFiles"] == config["PassEnvironment"] == config["UnsetEnvironment"] == "", "inert_execution_environment")
                command = C.configured_start(read_command(["/usr/bin/systemctl", "cat", unit], deadline))
                require(command == "/usr/bin/false", "effective_inert_execstart")
            else:
                command = C.configured_start(read_command(["/usr/bin/systemctl", "cat", unit], deadline))
                require(command == m["venv"] + "/bin/python -m app.cli " + ADOPT[unit] and config["WorkingDirectory"] == m["source"], "effective_candidate_cli")
                require(sha(config["Environment"].encode()) == spec["environment_sha256"] and config["PassEnvironment"] == config["UnsetEnvironment"] == "", "adopted_inline_environment")
                parsed = shlex.split(config["Environment"])
                require(len(parsed) == 1 and parsed[0].startswith("LAB_HOST_ROLE=") and config["EnvironmentFiles"] == C.retained_environment_target(m, role) + " (ignore_errors=no)", "candidate_job_environment")
        require(all(config[key] == "none" for key in ("FailureAction", "SuccessAction", "JobTimeoutAction", "StartLimitAction")), "unsupported_unit_actions")
        cfg_sha = normalized_config(C, config)
        require(cfg_sha == spec["expected_config_sha256"][status], "effective_configuration_not_frozen")
        require(config["RefuseManualStart"] == ("no" if status == "resumed" and unit in {*ADOPT, *RESUME} else "yes"), "effective_manual_start_control")
        live = show(unit, config=False, deadline=deadline)
        try:
            group_sha = cgroup_empty(unit, live)
        except Refusal as failure:
            if status == "resumed" and timers_started and unit in ADOPT and str(failure) in {"named_process_still_running", "named_cgroup_populated"}:
                raise NamedUnitBusy(unit, live, str(failure)) from None
            raise
        active = status == "resumed" and unit in RESUME and timers_started
        if (live["ActiveState"], live["SubState"]) != (("active", "waiting") if active else ("inactive", "dead")):
            if status == "resumed" and timers_started and unit in {*ADOPT, *RESUME}:
                raise NamedUnitBusy(unit, live, "named_unit_state")
            raise Refusal("named_unit_state")
        result[unit] = {"effective_config_sha256": cfg_sha, "original_files_sha256": original_sha, "owned_files_sha256": sha(canonical({str(path): sha(raw) for path, raw in actual_owned.items()})), "cgroup_path_sha256": group_sha, "main_pid": live.get("MainPID", "0"), "control_pid": live.get("ControlPID", "0"), "active_state": live["ActiveState"], "sub_state": live["SubState"]}
        states[unit] = [live["ActiveState"], live["SubState"]]
    read_timeout(deadline)
    return {"units": result, "configuration_sha256": sha(canonical({u: v["effective_config_sha256"] for u, v in result.items()})), "process_census_sha256": sha(canonical({u: [v["main_pid"], v["control_pid"], v["cgroup_path_sha256"]] for u, v in result.items()})), "pending_jobs_sha256": jobs, "timer_states_sha256": sha(canonical({u: s for u, s in states.items() if u.endswith(".timer")}))}


def bindings(C, m, evidence, approval, role, status):
    return {"candidate": m["candidate"], "tree": m["tree"], "role": role, "status": status, "attempt": approval["attempt"], "execution_manifest_sha256": evidence.manifest_hash, "component_sha256": m["maintenance"]["sha256"], "helper_sha256": m["helpers"]["maintenance"]["sha256"], "authority_record_sha256": approval["approval_record_sha256"]}


def validate_current_body(m, component, role, status, value):
    require(role in HOSTS and status in STATUSES and (role == "lab" or status == "fenced"), "observation_role_status")
    exact(value, ("units", "configuration_sha256", "process_census_sha256", "pending_jobs_sha256", "timer_states_sha256"))
    exact(value["units"], TARGETS[role])
    states = {}
    for unit, row in value["units"].items():
        exact(row, ("effective_config_sha256", "original_files_sha256", "owned_files_sha256", "cgroup_path_sha256", "main_pid", "control_pid", "active_state", "sub_state"))
        spec = component["hosts"][role]["units"][unit]
        expected_original = [{"path": ref["path"], "sha256": ref["sha256"]} for ref in spec["original_files"]]
        owned = {}
        if status != "resumed" or unit not in {*ADOPT, *RESUME}:
            owned[str(own_path(m, unit, True))] = sha(fence_bytes(unit))
        if unit in ADOPT and status in {"adopted_and_fenced", "resumed"}:
            owned[str(own_path(m, unit, False))] = sha(adoption_bytes(m, unit))
        require(row["effective_config_sha256"] == spec["expected_config_sha256"][status] and row["original_files_sha256"] == sha(canonical(expected_original)) and row["owned_files_sha256"] == sha(canonical(owned)), "retained_config_recipe_join")
        require(row["main_pid"] == row["control_pid"] == "0" and row["cgroup_path_sha256"] in {sha(b"empty_cgroup_path"), sha(("/system.slice/" + unit).encode())}, "retained_named_process_shape")
        require((row["active_state"], row["sub_state"]) == (("active", "waiting") if status == "resumed" and unit in RESUME else ("inactive", "dead")), "retained_named_unit_state")
        states[unit] = [row["active_state"], row["sub_state"]]
    require(value["configuration_sha256"] == sha(canonical({u: row["effective_config_sha256"] for u, row in value["units"].items()})) and value["process_census_sha256"] == sha(canonical({u: [row["main_pid"], row["control_pid"], row["cgroup_path_sha256"]] for u, row in value["units"].items()})) and value["pending_jobs_sha256"] == sha(canonical([])) and value["timer_states_sha256"] == sha(canonical({u: state for u, state in states.items() if u.endswith(".timer")})), "retained_current_body_hashes")


def validate_action_receipt(C, m, receipt, expected, approval, evidence):
    exact(receipt, ("schema", *expected, "action", "outcome", "started_unix", "completed_unix", "authority", "intent", "events", "commands", "observations", "partial_resume_cleanup", "refusal_tag", "deployment_ready"))
    require(receipt["schema"] == "AcademyMaintenanceReceipt.v1" and receipt["outcome"] == "observed" and receipt["deployment_ready"] is False and receipt["refusal_tag"] is None and receipt["partial_resume_cleanup"] is None and all(receipt[k] == v for k, v in expected.items()), "actual_action_receipt_identity")
    phase = {"fenced": "quiesce", "adopted_and_fenced": "promote", "resumed": "resume"}[expected["status"]]
    require(receipt["action"] == {"quiesce": "fence", "promote": "adopt", "resume": "resume"}[phase], "receipt_action_status")
    require(type(receipt["completed_unix"]) in {int, float}, "action_completion_timestamp")
    require(type(receipt["started_unix"]) in {int, float} and receipt["started_unix"] <= receipt["completed_unix"] <= time.time(), "actual_action_chronology")
    authority = receipt["authority"]
    exact(authority, ("kind", "manifest", "approval", "verifier"))
    original = load(authority["approval"])
    original_manifest = load(authority["manifest"])
    require(original["approval_record_sha256"] == approval["approval_record_sha256"] and original["attempt"] == approval["attempt"] and original["approved_unix"] <= receipt["started_unix"] <= receipt["completed_unix"] < original["expires_unix"], "original_genuine_authority_window")
    if phase == "quiesce":
        require(authority["kind"] == "execution" and authority["manifest"]["sha256"] == expected["execution_manifest_sha256"] and original_manifest == m and authority["verifier"]["sha256"] == m["self_sha256"] and authority["approval"]["sha256"] == evidence.approval_hash, "retained_execution_identity")
        require(Path(authority["verifier"]["path"]).name == "candidate_execute.py", "retained_executor_basename")
        verifier_bytes, _ = read_file(authority["verifier"]["path"], private=True)
        require(sha(verifier_bytes) == m["self_sha256"], "retained_executor_bytes")
        C.approval(original, authority["manifest"]["sha256"], m, "quiesce", historical=True)
    else:
        require(authority["kind"] == "promotion" and authority["manifest"]["sha256"] == evidence.promotion_manifest_hash and authority["approval"]["sha256"] == evidence.promotion_approval_hash and original_manifest == evidence.promoter and authority["verifier"]["sha256"] == original_manifest["self_sha256"], "retained_promotion_identity")
        promoter = module(authority["verifier"], "candidate_promote.py")
        promoter.COMMON = C
        # Deliberately requires the original promotion envelope STILL current;
        # no historical promotion bypass, rewrapping, or automatic extension.
        promoter.authorization(original, original_manifest, authority["manifest"]["sha256"], phase)
    intent = load(receipt["intent"])
    exact(intent, ("schema", "binding", "action", "started_unix"))
    require(intent["schema"] == "AcademyMaintenanceIntent.v1" and intent["binding"] == expected and intent["action"] == receipt["action"] and intent["started_unix"] == receipt["started_unix"], "actual_durable_intent_join")
    require(type(receipt["events"]) is list and 1 <= len(receipt["events"]) <= 128, "durable_action_events")
    operations = {}
    for sequence, pin in enumerate(receipt["events"]):
        event = load(pin)
        exact(event, ("operation", "target", "sequence", "unix", "attempt"))
        operations.setdefault(event["operation"], []).append(event["target"])
        require(event["sequence"] == sequence and event["attempt"] == expected["attempt"] and receipt["started_unix"] <= event["unix"] <= receipt["completed_unix"], "actual_journal_chronology")
    require(set(operations) <= {"systemctl-stop", "systemctl-start", "systemctl-daemon-reload", "create-fence", "create-adoption", "remove-fence"} and operations.get("systemctl-daemon-reload") == [None], "closed_successful_action_journal")
    role = expected["role"]
    require(not operations.get("systemctl-stop") or (phase == "quiesce" and len(set(operations["systemctl-stop"])) == len(operations["systemctl-stop"]) and all(u in TARGETS[role] and u.endswith(".timer") for u in operations["systemctl-stop"])), "journal_timer_stop_scope")
    required = {"create-fence": [str(own_path(m, u, True)) for u in TARGETS[role]]} if phase == "quiesce" else {"create-adoption": [str(own_path(m, u, False)) for u in ADOPT]} if phase == "promote" else {"remove-fence": [str(own_path(m, u, True)) for u in (*ADOPT, *RESUME)], "systemctl-start": list(RESUME)}
    for operation in ("create-fence", "create-adoption", "remove-fence", "systemctl-start"):
        require(sorted(operations.get(operation, [])) == sorted(required.get(operation, [])), "actual_complete_action_scope")
    require(type(receipt["commands"]) is list and receipt["commands"] and all(item["cleanup"]["confirmed"] is True for item in receipt["commands"]), "action_owned_command_cleanup")
    validate_current_body(m, validate_component(C, m), expected["role"], expected["status"], receipt["observations"]["after"])


def verify_retained(common, execution_manifest, evidence, approval, role, status):
    C, m = common, execution_manifest
    component = validate_component(C, m)
    value = evidence.get("maintenance-" + role + "-" + status, "candidate_maintenance.py", role)
    expected = bindings(C, m, evidence, approval, role, status)
    exact(value, ("schema", *expected, "retained_receipt", "observed_unix_started", "observed_unix_finished", "current", "deployment_ready"))
    require(value["schema"] == "AcademyMaintenanceObservation.v1" and value["deployment_ready"] is False and all(value[k] == v for k, v in expected.items()), "retained_observation_identity")
    C.stamp(value["observed_unix_started"])
    C.stamp(value["observed_unix_finished"])
    validate_current_body(m, component, role, status, value["current"])
    require(value["observed_unix_started"] <= value["observed_unix_finished"] <= time.time(), "observation_chronology")
    receipt = load(value["retained_receipt"])
    validate_action_receipt(C, m, receipt, expected, approval, evidence)
    require(receipt["completed_unix"] <= value["observed_unix_started"], "action_before_observation")
    return {"status": status, "observation_sha256": evidence.used["maintenance-" + role + "-" + status]["sha256"], "retained_receipt_sha256": value["retained_receipt"]["sha256"], "observed_unix_started": value["observed_unix_started"], "observed_unix_finished": value["observed_unix_finished"], "remote_current_state_proven": False}


def verify_observation(common, execution_manifest, evidence, approval, role, status, *, deadline=None):
    read_timeout(deadline)
    require(socket.gethostname() == HOSTS[role], "host_local_observation_only")
    proof = verify_retained(common, execution_manifest, evidence, approval, role, status)
    proof["current"] = current(common, execution_manifest, validate_component(common, execution_manifest), role, status, deadline=deadline)
    read_timeout(deadline)
    proof["host_local_current_state_proven"] = True
    return proof


def file_pin(path):
    raw, _ = read_file(path, private=True)
    return {"path": str(path), "sha256": sha(raw)}, decode(raw)


def activation_links(component, role):
    expected = {ref["path"]: ref["target"] for spec in component["hosts"][role]["units"].values() for ref in spec["enablement_links"]}
    observed, inspected = {}, 0
    selected = set(TARGETS[role])
    for base in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/usr/local/lib/systemd/system"):
        try:
            parent = directory(base)
        except FileNotFoundError:
            continue
        try:
            folders = [(parent, Path(base), False)]
            try:
                for name in names(parent, 512):
                    if name.endswith((".wants", ".requires", ".upholds")):
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                        folders.append((child, Path(base) / name, True))
                        info = os.fstat(child)
                        require(info.st_uid == 0 and not info.st_mode & 0o022, "activation_directory_custody")
                for fd, path, _close in folders:
                    for name in names(fd, 512):
                        inspected += 1
                        require(inspected <= 8192, "activation_inventory_bound")
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode):
                            target = os.readlink(name, dir_fd=fd)
                            if name in selected or Path(target).name in selected:
                                observed[str(path / name)] = target
                require(all(expected.get(path) == target for path, target in observed.items()), "unknown_unit_alias_or_activation_link")
            finally:
                for fd, _path, close in folders:
                    if close:
                        os.close(fd)
        finally:
            os.close(parent)
    require(observed == expected, "exact_activation_link_inventory")
    return sha(canonical(observed))


def conf_inventory(m, unit, expected):
    """Catch unloaded/unlisted drop-ins too; do not silently wait for reload."""
    for base in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/usr/local/lib/systemd/system", "/etc/systemd/system.control", "/run/systemd/system.control"):
        folder = Path(base) / (unit + ".d")
        try:
            fd = directory(folder)
        except FileNotFoundError:
            continue
        try:
            actual = {str(folder / name) for name in names(fd) if name.endswith(".conf")}
            require(actual == {path for path in expected if Path(path).parent == folder}, "unlisted_dropin_on_disk")
        finally:
            os.close(fd)


def original_identity_expected(component, role, unit):
    """Pure hash-only identity recipe; declaration alone is never an observation."""
    require(role in HOSTS and unit in component["hosts"][role]["units"], "original_identity_unit")
    spec = component["hosts"][role]["units"][unit]
    files = sorted(({"path_sha256": sha(ref["path"].encode()), "body_sha256": ref["sha256"]}
                    for ref in spec["original_files"]), key=lambda row: row["path_sha256"])
    return {"schema": "AcademyMaintenanceUnitIdentity.v1", "requested_sha256": sha(unit.encode()),
            "canonical_sha256": sha(unit.encode()), "names_sha256": [sha(unit.encode())],
            "original_files_sha256": sha(canonical([{"path": ref["path"], "sha256": ref["sha256"]}
                                                     for ref in spec["original_files"]])),
            "effective_config_sha256": spec["expected_config_sha256"]["original"],
            "configured_command_sha256": spec["observed_command_sha256"],
            "unit_text_sha256": spec["original_unit_text_sha256"],
            "dependencies": {key: sorted(sha(value.encode()) for value in spec["dependencies"][key]) for key in DEPS},
            "source_files": files}


def _original_identity(C, m, component, role, unit, *, deadline=None):
    """Observe exact protected originals and effective config, without action readiness."""
    read_timeout(deadline)
    require(role in HOSTS and unit in component["hosts"][role]["units"], "original_identity_unit")
    spec = component["hosts"][role]["units"][unit]
    original_sha = originals(spec)
    values = show(unit, deadline=deadline)
    require(values["Id"] == values["Names"] == unit and values["LoadState"] == "loaded" and not values["SourcePath"], "original_alias_generator")
    expected = {ref["path"] for ref in spec["original_files"]}
    require(values["FragmentPath"] in expected and set(values["DropInPaths"].split()) == {p for p in expected if p.endswith(".conf")}, "original_file_coverage")
    conf_inventory(m, unit, expected)
    require({key: sorted(values[key].split()) for key in DEPS} == spec["dependencies"], "original_dependencies_drift")
    require(normalized_config(C, values) == spec["expected_config_sha256"]["original"], "original_effective_configuration")
    unit_text = read_command(["/usr/bin/systemctl", "cat", unit], deadline)
    require(sha(unit_text.encode()) == spec["original_unit_text_sha256"], "original_unit_text_drift")
    if unit.endswith(".service"):
        require(not any(values[key] for key in ("PAMName", "SupplementaryGroups", "BindPaths", "BindReadOnlyPaths", "MountImages", "ExtensionImages", "ExtensionDirectories")) and values["RestartMode"] == "normal", "original_namespace_or_credential_context")
        require(not any(values[key] for key in HOOKS) and not values["RootDirectory"] and not values["RootImage"] and values["DynamicUser"] == values["PrivateUsers"] == "no" and values["User"] == "dotmac" and values["Group"] in {"", "dotmac"}, "original_execution_context_unsupported")
        command = C.configured_start(unit_text)
        require(sha(command.encode()) == spec["observed_command_sha256"], "original_configured_argv_drift")
        if unit in ADOPT:
            require(command == "/home/dotmac/projects/dotmac_academy_v2/.venv/bin/python -m app.cli " + ADOPT[unit] and values["WorkingDirectory"] == "/home/dotmac/projects/dotmac_academy_v2", "original_lab_cli_shape")
            require(values["EnvironmentFiles"] == C.retained_environment_target(m, role) + " (ignore_errors=no)" and sha(values["Environment"].encode()) == spec["environment_sha256"] and values["PassEnvironment"] == values["UnsetEnvironment"] == "", "original_lab_environment")
            inline = shlex.split(values["Environment"])
            require(len(inline) == 1 and inline[0].startswith("LAB_HOST_ROLE="), "original_lab_inline_environment")
    projection = original_identity_expected(component, role, unit)
    require(original_sha == projection["original_files_sha256"], "original_identity_files_join")
    read_timeout(deadline)
    return projection, values


def original_identity_projection(C, m, component, role, unit, *, deadline=None):
    """Read-only identity projection; no inactive/disabled/name-based sender inference."""
    projection, _values = _original_identity(C, m, component, role, unit, deadline=deadline)
    return projection


def preflight_original(C, m, component, role):
    host = component["hosts"][role]
    owner = pwd.getpwnam("dotmac")
    require((owner.pw_uid, owner.pw_gid) == (host["uid"], host["gid"]), "actual_dotmac_identity")
    require(run(["/usr/bin/systemctl", "--version"]).splitlines()[0].startswith("systemd 255 "), "systemd255_only")
    manager_environment(host)
    activation_links(component, role)
    binary, _ = read_file("/usr/bin/false", mode=0o755)
    require(sha(binary) == component["inert_program_sha256"], "inert_program_hash")
    pending_jobs(role)
    result, permitted = {}, []
    for unit, spec in host["units"].items():
        projection, values = _original_identity(C, m, component, role, unit)
        original_sha = projection["original_files_sha256"]
        for flag in (True, False):
            try:
                read_file(own_path(m, unit, flag), mode=0o644)
            except FileNotFoundError:
                pass
            else:
                raise Refusal("existing_owned_dropin_no_reuse")
        live = show(unit, config=False)
        if unit.endswith(".service"):
            require(values["Type"] == "oneshot" or live["ActiveState"] == "inactive", "active_legacy_daemon_hold")
        else:
            require((live["ActiveState"] == "active") is spec["originally_active"] and live["SubState"] in {"waiting", "dead"}, "original_timer_state_changed")
        require(values["RefuseManualStop"] == values["AllowIsolate"] == "no" and all(values[key] == "none" for key in ("FailureAction", "SuccessAction", "JobTimeoutAction", "StartLimitAction")), "unsupported_original_actions")
        if unit.endswith(".service") and values["Type"] == "oneshot":
            permitted.append(unit)
        result[unit] = original_sha
    return {"original_files_sha256": sha(canonical(result)), "permitted_oneshot_services": sorted(permitted)}


START_STATES = {("activating", "start"), ("active", "running")}


def drain_authority(ctx, deadline):
    read_timeout(deadline)
    ctx.check()
    read_timeout(deadline)


def frozen_drain_service(ctx, unit, configuration, deadline):
    """Accept a busy service only with exact pinned original/candidate config."""
    role, m = ctx.args.role, ctx.m
    require(unit in TARGETS[role] and unit.endswith(".service"), "drain_service_scope")
    require(configuration in {"original", "resumed"}, "drain_configuration_scope")
    if configuration == "resumed":
        require(role == "lab" and unit in ADOPT, "drain_candidate_scope")
    drain_authority(ctx, deadline)
    spec = ctx.component["hosts"][role]["units"][unit]
    originals(spec)
    values = show(unit, deadline=deadline)
    require(values["Type"] == "oneshot" and normalized_config(ctx.C, values) == spec["expected_config_sha256"][configuration], "drain_frozen_oneshot_configuration")
    expected = {ref["path"] for ref in spec["original_files"]}
    if configuration == "resumed":
        expected |= {str(path) for path in own_files(m, role, unit, "resumed")}
    else:
        for fence in (True, False):
            try:
                read_file(own_path(m, unit, fence), mode=0o644)
            except FileNotFoundError:
                pass
            else:
                raise Refusal("drain_unexpected_owned_override")
    require(values["Id"] == values["Names"] == unit and values["LoadState"] == "loaded" and not values["SourcePath"] and values["FragmentPath"] in expected and set(values["DropInPaths"].split()) == {path for path in expected if path.endswith(".conf")}, "drain_effective_file_coverage")
    conf_inventory(m, unit, expected)
    text = read_command(["/usr/bin/systemctl", "cat", unit], deadline)
    command = ctx.C.configured_start(text)
    if configuration == "original":
        require(sha(text.encode()) == spec["original_unit_text_sha256"] and sha(command.encode()) == spec["observed_command_sha256"], "drain_original_command_pin")
    else:
        require(command == m["venv"] + "/bin/python -m app.cli " + ADOPT[unit] and values["WorkingDirectory"] == m["source"], "drain_candidate_command_pin")
    drain_authority(ctx, deadline)


def start_jobs(ctx, jobs, permitted_services, configuration, deadline):
    for row in jobs:
        require(row[1] in permitted_services and row[2] == "start" and row[3] in {"running", "waiting"}, "unsupported_named_drain_job")
        frozen_drain_service(ctx, row[1], configuration, deadline)
    return {row[1] for row in jobs}


def permitted_start(ctx, unit, configuration, deadline, *, allow_settled=False):
    frozen_drain_service(ctx, unit, configuration, deadline)
    live = show(unit, config=False, deadline=deadline)
    state = (live["ActiveState"], live["SubState"])
    if allow_settled and state == ("inactive", "dead"):
        cgroup_empty(unit, live)
    else:
        require(state in START_STATES, "unsupported_named_drain_state")
    return live


def quiet(ctx, permitted_services, configuration, *, deadline):
    """Read-only natural drain; a quiet named-unit snapshot is NOT global idle."""
    role = ctx.args.role
    require(type(deadline) in {int, float} and 0 < deadline - time.monotonic() <= 60, "explicit_bounded_drain_deadline")
    require((configuration == "original" and ctx.args.action == "fence") or (configuration == "resumed" and ctx.args.action == "resume"), "drain_action_scope")
    require(type(permitted_services) is frozenset and permitted_services <= {u for u in TARGETS[role] if u.endswith(".service")}, "explicit_drain_service_scope")
    require(configuration == "original" or (configuration == "resumed" and role == "lab" and permitted_services == frozenset(ADOPT)), "explicit_drain_configuration")
    while True:
        drain_authority(ctx, deadline)
        jobs = selected_jobs(role, deadline=deadline)
        starting = start_jobs(ctx, jobs, permitted_services, configuration, deadline)
        unsettled = bool(jobs)
        for unit in TARGETS[role]:
            if not unit.endswith(".service"):
                continue
            live = show(unit, config=False, deadline=deadline)
            if (live["ActiveState"], live["SubState"]) != ("inactive", "dead"):
                require(unit in permitted_services, "unpermitted_named_service_active")
                require((live["ActiveState"], live["SubState"]) in START_STATES, "unsupported_named_drain_state")
                permitted_start(ctx, unit, configuration, deadline, allow_settled=True)
                unsettled = True
                continue
            try:
                cgroup_empty(unit, live)
            except Refusal as failure:
                if unit not in permitted_services or str(failure) not in {"named_process_still_running", "named_cgroup_populated"}:
                    raise
                # A start may race the inactive snapshot. Independently observe
                # the exact same approved oneshot actually starting; otherwise
                # preserve the original uncertainty instead of retrying blindly.
                permitted_start(ctx, unit, configuration, deadline, allow_settled=unit in starting)
                unsettled = True
        drain_authority(ctx, deadline)
        final_jobs = selected_jobs(role, deadline=deadline)
        start_jobs(ctx, final_jobs, permitted_services, configuration, deadline)
        drain_authority(ctx, deadline)
        if not unsettled and not final_jobs:
            return
        time.sleep(min(2, read_timeout(deadline)))


def classify_resume_transient(ctx, failure, deadline):
    """Explicit actual start evidence only; config/authority/unknown errors escape."""
    permitted = frozenset(ADOPT)
    if isinstance(failure, SelectedJobsPresent):
        require(bool(failure.jobs), "empty_selected_job_transient")
        start_jobs(ctx, failure.jobs, permitted, "resumed", deadline)
        return
    require(isinstance(failure, NamedUnitBusy), "unsupported_resume_transient")
    unit, live = failure.unit, failure.live
    if unit in ADOPT:
        if (live["ActiveState"], live["SubState"]) in START_STATES:
            frozen_drain_service(ctx, unit, "resumed", deadline)
        else:
            require((live["ActiveState"], live["SubState"]) == ("inactive", "dead") and str(failure) in {"named_process_still_running", "named_cgroup_populated"}, "unsupported_resume_service_transient")
            permitted_start(ctx, unit, "resumed", deadline)
    else:
        require(unit in RESUME and (live["ActiveState"], live["SubState"]) == ("active", "running"), "unsupported_resume_timer_transient")
        # A running timer is transient only with an independently observed
        # approved paired oneshot start, never a timer job or an unknown job.
        pair = unit.removesuffix(".timer") + ".service"
        jobs = selected_jobs("lab", deadline=deadline)
        active_jobs = start_jobs(ctx, jobs, permitted, "resumed", deadline)
        if pair not in active_jobs:
            permitted_start(ctx, pair, "resumed", deadline)


def resumed_snapshot(ctx, *, deadline):
    while True:
        quiet(ctx, frozenset(ADOPT), "resumed", deadline=deadline)
        drain_authority(ctx, deadline)
        try:
            snapshot = current(ctx.C, ctx.m, ctx.component, "lab", "resumed", deadline=deadline)
            drain_authority(ctx, deadline)
            return snapshot
        except (SelectedJobsPresent, NamedUnitBusy) as failure:
            classify_resume_transient(ctx, failure, deadline)
            drain_authority(ctx, deadline)
            # Read-only retry under the original deadline; never replay start,
            # stop, reload, override writes, or any other mutation.


class Context:
    """Only this standalone owner takes the host lock; API validators never do."""
    def __init__(self, args):
        self.args = args
        self.cm_pin, self.m = file_pin(args.execution_manifest)
        self.ea_pin, self.ea = file_pin(args.execution_approval)
        self.C = module({"path": args.common, "sha256": args.common_sha256}, "candidate_execute.py")
        require(args.common_sha256 == self.m["self_sha256"], "common_source_join")
        self.C.SOURCE, self.C.VENV = self.m["source"], self.m["venv"]
        self.C.validate_manifest(self.m, args.role)
        self.component = validate_component(self.C, self.m)
        python_bytes, _ = read_file("/usr/bin/python3.12", mode=0o755, limit=32_000_000)
        require(sha(python_bytes) == self.m["roles"][args.role]["python_sha256"], "actual_system_python_bytes")
        require(Path(__file__).name == "candidate_maintenance.py" and sha(read_file(__file__, private=True)[0]) == self.m["helpers"]["maintenance"]["sha256"], "running_helper_pin")
        self.pm = self.P = None
        self.a, self.authority_pin = self.ea, self.ea_pin
        self.manifest_pin = self.cm_pin
        self.C.approval(self.ea, self.cm_pin["sha256"], self.m, "quiesce", historical=args.action != "fence")
        if args.action in {"adopt", "resume"} or args.status in {"adopted_and_fenced", "resumed"}:
            require(args.role == "lab" and args.promotion_manifest and args.promotion_approval and args.promoter and args.promoter_sha256, "promotion_authority_required")
            self.pm_pin, self.pm = file_pin(args.promotion_manifest)
            self.pa_pin, self.a = file_pin(args.promotion_approval)
            self.P = module({"path": args.promoter, "sha256": args.promoter_sha256}, "candidate_promote.py")
            self.P.COMMON = self.C
            require(args.promoter_sha256 == self.pm["self_sha256"] and self.pm["execution_manifest"] == self.cm_pin and self.pm["execution_approval"] == self.ea_pin, "promotion_parent_join")
            self.P.validate_manifest(self.pm, args.role)
            self.authority_pin, self.manifest_pin = self.pa_pin, self.pm_pin
            self.evidence = self.P.Evidence(args.evidence_index, self.pm, self.m, self.a, self.pa_pin["sha256"], self.pm_pin["sha256"], self.cm_pin["sha256"])
        else:
            self.evidence = self.C.Evidence(args.evidence_index, self.m, self.ea, self.ea_pin["sha256"], self.cm_pin["sha256"])
        self.evidence.execution_manifest_hash = self.cm_pin["sha256"]
        self.evidence.active_authority = {
            "kind": "promotion" if self.P is not None else "execution",
            "phase": (
                "resume" if self.args.action == "resume" or self.args.status == "resumed" else "promote"
            ) if self.P is not None else "quiesce",
            "manifest": dict(self.manifest_pin),
            "approval": dict(self.authority_pin),
        }
        self.evidence.validate_active_authority = (
            self.P.authorization if self.P is not None else
            lambda current, manifest, sha256, phase: self.C.approval(current, sha256, manifest, phase)
        )
        self.events, self.started_timers, self.removed_fences = [], [], []
        self.result = None
        self.check()

    def check(self):
        require(load(self.cm_pin) == self.m and load(self.ea_pin) == self.ea, "execution_authority_bytes_changed")
        require(validate_component(self.C, self.m) == self.component, "component_changed")
        self.C.approval(self.ea, self.cm_pin["sha256"], self.m, "quiesce", historical=self.P is not None or self.args.action == "observe")
        if self.P is not None:
            require(load(self.pm_pin) == self.pm and load(self.pa_pin) == self.a, "promotion_authority_bytes_changed")
            self.P.authorization(self.a, self.pm, self.pm_pin["sha256"], "resume" if self.args.action == "resume" or self.args.status == "resumed" else "promote")
            require(self.a["approval_record_sha256"] == self.ea["approval_record_sha256"] and self.a["attempt"] == self.ea["attempt"], "same_genuine_human_record_required")
        require(socket.gethostname() == HOSTS[self.args.role], "fixed_host")

    def journal(self, operation, target):
        require(self.result is not None, "durable_intent_required")
        self.check()
        event = {"operation": operation, "target": target, "sequence": len(self.events), "unix": time.time(), "attempt": self.a["attempt"]}
        path = str(self.args.receipt) + ".event-" + str(len(self.events)) + ".json"
        pin = write_new(path, event)
        self.events.append(pin)
        self.check()

    def command(self, verb, unit=None):
        require(verb in {"stop", "start", "daemon-reload"} and (unit is None if verb == "daemon-reload" else unit in TARGETS[self.args.role]), "closed_mutation_command")
        if verb == "start":
            require(self.args.action == "resume" and unit in RESUME, "legacy_never_start")
        self.journal("systemctl-" + verb, unit)
        return run(["/usr/bin/systemctl", verb, *([unit] if unit else [])])


def write_new(path, value):
    raw = canonical(value) + b"\n"
    parent = directory(Path(path).parent, private=True)
    try:
        fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
        return {"path": str(path), "sha256": sha(raw)}
    finally:
        os.close(parent)


def dropin(ctx, unit, fence, remove=False):
    path = own_path(ctx.m, unit, fence)
    raw = fence_bytes(unit) if fence else adoption_bytes(ctx.m, unit)
    originals(ctx.component["hosts"][ctx.args.role]["units"][unit])
    ctx.journal("remove-fence" if remove else "create-fence" if fence else "create-adoption", str(path))
    base = directory(path.parent.parent)
    try:
        try:
            fd = os.open(path.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base)
        except FileNotFoundError:
            require(not remove, "missing_fence_parent")
            ctx.check()
            os.mkdir(path.parent.name, 0o755, dir_fd=base)
            fd = os.open(path.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base)
            os.fchmod(fd, 0o755)  # Only the just-created owned directory.
            os.fsync(fd)
            os.fsync(base)
        try:
            parent = os.fstat(fd)
            require(parent.st_uid == 0 and stat.S_IMODE(parent.st_mode) == 0o755, "dropin_directory_custody")
            ctx.check()
            if remove:
                actual, info = read_file(path, mode=0o644)
                require(actual == raw and identity(info) == identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), "remove_exact_own_fence_only")
                ctx.check()
                ctx.removed_fences.append(unit)  # Before unlink: interruption may follow the mutation.
                os.unlink(path.name, dir_fd=fd)
            else:
                output = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=fd)
                with os.fdopen(output, "wb") as stream:
                    os.fchmod(stream.fileno(), 0o644)
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(base)


def initial_lab_fence(ctx):
    C, m, e = ctx.C, ctx.m, ctx.evidence
    quiesce = e.phase("quiesce-web", "web", "quiesce", fresh=False)
    observed = e.get("stopped-web", "external_census", "web")
    exact(observed, ("schema", "candidate", "tree", "attempt", "hostname", "observed_unix", "quiesce_receipt_sha256", "units", "application_pids", "process_census_sha256", "preserved"))
    C.stamp(observed["observed_unix"])
    C.hexvalue(observed["process_census_sha256"])
    require(observed["observed_unix"] >= quiesce["observations"]["stop_completed_unix"], "web_observation_after_original_stop")
    require(observed["schema"] == "AcademyRootStoppedObservation.v1" and observed["candidate"] == m["candidate"] and observed["tree"] == m["tree"] and observed["attempt"] == ctx.a["attempt"] and observed["hostname"] == HOSTS["web"] and observed["quiesce_receipt_sha256"] == e.used["quiesce-web"]["sha256"] and not observed["application_pids"], "fresh_web_primary_stopped_before_lab_fence")
    require(quiesce["observations"]["matching_application_pids"] == [] and set(observed["units"]) == set(C.services("web") + C.timers()) and all(state == {"MainPID": "0", "ActiveState": "inactive", "SubState": "dead"} for state in observed["units"].values()) and observed["preserved"] == quiesce["observations"]["preserved"], "actual_web_quiescence")
    baseline = e.phase("baseline-lab", "lab", "baseline", fresh=False)
    C.verify_old_primary("lab", m, baseline)
    return C.fresh_idle(m, "lab", "before", ctx.a["attempt"])


def fence(ctx):
    role = ctx.args.role
    before = preflight_original(ctx.C, ctx.m, ctx.component, role)
    if role == "lab":
        before["global_idle"] = initial_lab_fence(ctx)
    for unit in TARGETS[role]:
        if unit.endswith(".timer") and show(unit, config=False)["ActiveState"] == "active":
            if role == "lab":
                ctx.C.verify_old_primary("lab", ctx.m, ctx.evidence.phase("baseline-lab", "lab", "baseline", fresh=False))
                ctx.C.fresh_idle(ctx.m, role, "before", ctx.a["attempt"])
            ctx.command("stop", unit)
    quiet(ctx, frozenset(before["permitted_oneshot_services"]), "original", deadline=time.monotonic() + 60)
    for unit in TARGETS[role]:
        dropin(ctx, unit, True)
    ctx.command("daemon-reload")
    return {"before": before, "after": current(ctx.C, ctx.m, ctx.component, role, "fenced")}


def adopt(ctx):
    C, m, e = ctx.C, ctx.m, ctx.evidence
    verify_observation(C, m, e, ctx.a, "lab", "fenced")
    C.both_stopped(e, "lab", m)
    C.verify_stage(m, "lab", e)
    C.exclusion(e, m, ctx.a, "lab", maintenance_status="fenced")
    catalog = ctx.P.catalog_after(e, m)
    idle = C.fresh_idle(m, "lab", "after", ctx.a["attempt"])
    gate = ctx.P.held_gate("lab", ctx.pm, m, ctx.a, e, maintenance_status="fenced")
    for unit in ADOPT:
        dropin(ctx, unit, False)
    ctx.command("daemon-reload")
    return {"catalog": catalog, "idle": idle, "held_gate": gate, "after": current(C, m, ctx.component, "lab", "adopted_and_fenced")}


def resume_guards(ctx):
    C, P, m, e = ctx.C, ctx.P, ctx.m, ctx.evidence
    require(hasattr(P, "verify_web_resume_custody"), "reviewed_web_resume_custody_api_required")
    released = P.verify_web_resume_custody(ctx.pm, m, ctx.a, e)
    catalog = P.catalog_after(e, m)
    primary = P.units("lab")[0]
    environment = P.validate_new_unit(primary, ctx.pm["roles"]["lab"]["units"][primary], ctx.pm, "lab")
    process = P.new_process("lab", ctx.pm, m, environment)
    C.preserved("lab", m)
    return {"actual_web_release": released, "catalog": catalog, "primary_process": process}


def resume(ctx):
    C, m = ctx.C, ctx.m
    verify_observation(C, m, ctx.evidence, ctx.a, "lab", "adopted_and_fenced")
    C.verify_stage(m, "lab", ctx.evidence)
    accepted = ctx.P.acceptance(ctx.pm, m, ctx.a, ctx.evidence, resumed=False)
    guards = resume_guards(ctx)
    for unit in (*ADOPT, *RESUME):
        resume_guards(ctx)
        dropin(ctx, unit, True, remove=True)
    ctx.command("daemon-reload")
    # Before starting, verify the exact resumed configuration while both timers
    # remain stopped. The same checker otherwise requires waiting timers.
    current(C, m, ctx.component, "lab", "resumed", timers_started=False)
    for unit in RESUME:
        resume_guards(ctx)
        ctx.started_timers.append(unit)
        ctx.command("start", unit)
    return {"acceptance": accepted, "guards": guards, "after": resumed_snapshot(ctx, deadline=time.monotonic() + 60)}


def compensate(ctx):
    """Safety actions affect only timers/fences owned by this one failed resume."""
    result = {"stopped_owned_timers": [], "refenced_owned_units": [], "uncertain": []}
    for unit in reversed(ctx.started_timers):
        try:
            ctx.command("stop", unit)
            result["stopped_owned_timers"].append(unit)
        except BaseException:
            result["uncertain"].append("stop:" + unit)
    try:
        quiet(ctx, frozenset(ADOPT), "resumed", deadline=time.monotonic() + 30)
    except BaseException:
        result["uncertain"].append("natural_drain")
    for unit in ctx.removed_fences:
        try:
            try:
                raw, _ = read_file(own_path(ctx.m, unit, True), mode=0o644)
            except FileNotFoundError:
                dropin(ctx, unit, True)
            else:
                require(raw == fence_bytes(unit), "partial_existing_fence_drift")
            result["refenced_owned_units"].append(unit)
        except BaseException:
            result["uncertain"].append("refence:" + unit)
    try:
        ctx.command("daemon-reload")
    except BaseException:
        result["uncertain"].append("reload")
    result["manual_hold"] = True
    return result


def observe(ctx):
    require(ctx.args.retained_receipt and ctx.args.retained_sha256 and ctx.args.status in STATUSES, "retained_action_receipt_required")
    status = ctx.args.status
    pin = {"path": ctx.args.retained_receipt, "sha256": ctx.args.retained_sha256}
    receipt = load(pin)
    expected = bindings(ctx.C, ctx.m, ctx.evidence, ctx.a, ctx.args.role, status)
    validate_action_receipt(ctx.C, ctx.m, receipt, expected, ctx.a, ctx.evidence)
    started = time.time()
    actual = current(ctx.C, ctx.m, ctx.component, ctx.args.role, status)
    return {"schema": "AcademyMaintenanceObservation.v1", **expected, "retained_receipt": pin, "observed_unix_started": started, "observed_unix_finished": time.time(), "current": actual, "deployment_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", required=True, choices=("fence", "adopt", "resume", "observe"))
    parser.add_argument("--role", required=True, choices=tuple(HOSTS))
    for name in ("common", "common-sha256", "execution-manifest", "execution-approval", "evidence-index", "receipt"):
        parser.add_argument("--" + name, required=True)
    for name in ("promotion-manifest", "promotion-approval", "promoter", "promoter-sha256", "retained-receipt", "retained-sha256"):
        parser.add_argument("--" + name)
    parser.add_argument("--status", choices=STATUSES)
    args = parser.parse_args()
    promotion_values = (args.promotion_manifest, args.promotion_approval, args.promoter, args.promoter_sha256)
    if args.action == "observe":
        require(args.status in STATUSES and args.retained_receipt and args.retained_sha256, "observe_arguments")
        require(all(promotion_values) if args.status != "fenced" else not any(promotion_values), "observe_authority_arguments")
    else:
        require(args.status is None and args.retained_receipt is None and args.retained_sha256 is None, "action_arguments")
        require(all(promotion_values) if args.action in {"adopt", "resume"} else not any(promotion_values), "action_authority_arguments")
    require(sys.platform == "linux" and os.getuid() == os.geteuid() == 0 and sys.version_info[:2] == (3, 12) and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode and Path(sys.executable) == Path("/usr/bin/python3.12"), "root_system_python312_I_S_B_required")
    require(socket.gethostname() == HOSTS[args.role], "fixed_host")
    require(args.action == "fence" or args.role == "lab" or args.action == "observe", "lab_only_adopt_resume")
    os.umask(0o077)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    ctx = Context(args)
    ctx.C.host_execution_lock()
    ctx.check()
    if args.action == "observe":
        result = observe(ctx)
        pin = write_new(args.receipt, result)
        print(json.dumps({"status": "observed", "role": args.role, "receipt_sha256": pin["sha256"], "deployment_ready": False}))
        return
    status = {"fence": "fenced", "adopt": "adopted_and_fenced", "resume": "resumed"}[args.action]
    started = time.time()
    ctx.result = {"schema": "AcademyMaintenanceReceipt.v1", **bindings(ctx.C, ctx.m, ctx.evidence, ctx.a, args.role, status), "action": args.action, "outcome": "failed_manual_hold", "started_unix": started, "completed_unix": None, "authority": {"kind": "promotion" if ctx.P else "execution", "manifest": ctx.manifest_pin, "approval": ctx.authority_pin, "verifier": {"path": args.promoter if ctx.P else args.common, "sha256": args.promoter_sha256 if ctx.P else args.common_sha256}}, "intent": None, "events": ctx.events, "commands": COMMANDS, "observations": {}, "partial_resume_cleanup": None, "refusal_tag": None, "deployment_ready": False}
    # OEXCL durable intent precedes any mutation. Reusing a receipt path is
    # never a retry/repair operation, even following partial failure.
    ctx.result["intent"] = write_new(str(args.receipt) + ".intent.json", {"schema": "AcademyMaintenanceIntent.v1", "binding": {k: ctx.result[k] for k in bindings(ctx.C, ctx.m, ctx.evidence, ctx.a, args.role, status)}, "action": args.action, "started_unix": started})
    # Reserve the final result name before side effects; update through this
    # one fd only. A crash leaves an explicit incomplete reserved receipt.
    ctx.check()
    parent = directory(Path(args.receipt).parent, private=True)
    fd = None
    try:
        fd = os.open(Path(args.receipt).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        os.write(fd, canonical({"schema": "AcademyMaintenanceIncomplete.v1", "deployment_ready": False}) + b"\n")
        os.fsync(fd)
        os.fsync(parent)
        try:
            ctx.result["observations"] = {"fence": fence, "adopt": adopt, "resume": resume}[args.action](ctx)
            ctx.check()
            ctx.result["outcome"] = "observed"
            ctx.result["completed_unix"] = time.time()
            validate_action_receipt(ctx.C, ctx.m, ctx.result, bindings(ctx.C, ctx.m, ctx.evidence, ctx.a, args.role, status), ctx.a, ctx.evidence)
        except BaseException as failure:
            ctx.result["refusal_tag"] = str(failure) if isinstance(failure, Refusal) and re.fullmatch(r"[a-z_]{1,100}", str(failure)) else "guard_or_runtime_refusal_details_suppressed"
            if args.action == "resume":
                ctx.result["partial_resume_cleanup"] = compensate(ctx)
            ctx.result["outcome"] = "failed_manual_hold"
        if ctx.result["outcome"] != "observed":
            ctx.result["completed_unix"] = time.time()
        raw = canonical(ctx.result) + b"\n"
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
        print(json.dumps({"status": ctx.result["outcome"], "role": args.role, "receipt_sha256": sha(raw), "deployment_ready": False}))
        require(ctx.result["outcome"] == "observed", "maintenance_manual_hold")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print('{"status":"refused_or_manual_hold","deployment_ready":false}')
        raise SystemExit(1) from None

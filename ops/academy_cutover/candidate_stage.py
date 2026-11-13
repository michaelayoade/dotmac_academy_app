"""Inactive-only stager. Explicit root invocation authorizes staging, never deployment.

Use trusted system Python -I -S. No service changes, DB, migrations or approval IO.
All Git/venv/Poetry execution runs as dotmac; root reads/hashes bytes only.
"""

import argparse
import email.parser
import hashlib
import json
import os
import pwd
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import tomllib
import types
import zipfile
from pathlib import Path

SHARED_RUNTIME = Path("/home/dotmac/projects/dotmac_academy_v2")
SOURCE_PARENT = Path("/srv/academy/releases")
VENV_PARENT = Path("/srv/academy/venvs")
TOOLS_PARENT = Path("/srv/academy/tools")
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
GIT = [
    "/usr/bin/git",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "credential.helper=",
    "-c",
    "protocol.file.allow=always",
]
CREDENTIALS = ("POETRY_HTTP_BASIC_FORGEJO_USERNAME", "POETRY_HTTP_BASIC_FORGEJO_PASSWORD")
PROCESS_GROUPS = []
SPAWNING = False
PENDING_INTERRUPT = False
INTERRUPTS = (signal.SIGINT, signal.SIGTERM)
BASELINE = None


class StageInterrupted(BaseException):
    """A controlled interruption, handled after owned process-group cleanup."""


class ProcessCleanupUnconfirmed(Exception):
    """Process group or captured pipes could not be confirmed complete."""


def interrupt_stage(_signum, _frame):
    global PENDING_INTERRUPT
    if SPAWNING:
        PENDING_INTERRUPT = True
        return
    raise StageInterrupted()


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def cleanup_group(proc):
    """Bounded TERM/KILL, direct-child reap and pipe drain; no escapee claim."""
    handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in INTERRUPTS}
    outcome = {
        "pgid": proc.pid,
        "confirmed": False,
        "term_sent": False,
        "kill_sent": False,
        "child_reaped": False,
        "pipes_drained": False,
    }
    try:
        for sig, key in ((signal.SIGTERM, "term_sent"), (signal.SIGKILL, "kill_sent")):
            try:
                os.killpg(proc.pid, sig)
                outcome[key] = True
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    proc.communicate(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
                    outcome["pipes_drained"] = True
                except subprocess.TimeoutExpired:
                    pass
                outcome["child_reaped"] = proc.poll() is not None
                if not group_present(proc.pid) and outcome["child_reaped"] and outcome["pipes_drained"]:
                    outcome["confirmed"] = True
                    return outcome
        # An escaped process holding a pipe or orphaned group zombie is a hold.
        return outcome
    except BaseException:
        # Cleanup itself may fail: still attempt whole-group KILL and bounded reap.
        outcome["cleanup_exception"] = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            outcome["kill_sent"] = True
        except BaseException:
            outcome["kill_retry_unconfirmed"] = True
        try:
            proc.communicate(timeout=1)
            outcome["pipes_drained"] = True
            outcome["child_reaped"] = proc.poll() is not None
            outcome["confirmed"] = not group_present(proc.pid) and outcome["child_reaped"]
        except BaseException:
            outcome["reap_or_drain_retry_unconfirmed"] = True
        return outcome
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        if not outcome["pipes_drained"]:
            for pipe in (proc.stdout, proc.stderr):
                if pipe:
                    pipe.close()


def run_group(argv, env, timeout, **kwargs):
    """Every command gets its own session; interrupt launch without inherited masks."""
    global SPAWNING, PENDING_INTERRUPT
    proc = None
    outcome_recorded = False
    try:
        SPAWNING = True
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed module-owned argv, no shell
                argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, **kwargs
            )
        finally:
            SPAWNING = False
        if PENDING_INTERRUPT:
            PENDING_INTERRUPT = False
            raise StageInterrupted()
        stdout, stderr = proc.communicate(timeout=timeout)
        if group_present(proc.pid):
            outcome = cleanup_group(proc)
        else:
            outcome = {
                "pgid": proc.pid,
                "confirmed": True,
                "term_sent": False,
                "kill_sent": False,
                "child_reaped": True,
                "pipes_drained": True,
            }
        PROCESS_GROUPS.append(outcome)
        outcome_recorded = True
        if not outcome["confirmed"]:
            raise ProcessCleanupUnconfirmed()
        return proc.returncode, stdout, stderr
    except BaseException:
        if proc is not None and not outcome_recorded:
            PROCESS_GROUPS.append(cleanup_group(proc))
        elif proc is None:
            PROCESS_GROUPS.append({"confirmed": False, "spawn_handle_unavailable": True})
        raise


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def file_identity(info):
    # Reading can change atime; content/authority change indicators must stay fixed.
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def chain(path, owners, private=False, missing=False):
    path = Path(path)
    require(path.is_absolute(), "absolute_path_required")
    for p in reversed([path, *path.parents][:-1]):
        if missing and not p.exists() and not p.is_symlink():
            continue
        s = p.lstat()
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid in owners and not s.st_mode & 0o022, "unsafe_path_chain")
    if private:
        require(
            path.parts[1] == "root"
            and path.stat().st_uid == 0
            and not path.stat().st_mode & 0o077
            and not path.parent.stat().st_mode & 0o077,
            "root_private_required",
        )
    return path


def no_links(path):
    require(not any(p.is_symlink() for p in [path, *path.parents]), "unexpected_read_symlink")
    return path


def directory_fd(path, strict=True):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "directory_path")
    retained_roots = (*(Path(p) for p in BASELINE.forbidden_runtime_paths()), SHARED_RUNTIME) if BASELINE else ()
    require(strict or any(path.is_relative_to(root) for root in retained_roots), "retained_path_scope")
    retained_ancestors = {
        Path("/home/dotmac/projects"),
        Path("/home/dotmac/.local"),
        Path("/home/dotmac/.local/share"),
        Path("/home/dotmac/.local/share/academy-v2-venvs"),
    }
    anchor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    owners = (0, pwd.getpwnam("dotmac").pw_uid)
    try:
        info = os.fstat(anchor)
        require(info.st_uid == 0 and not info.st_mode & 0o022, "unsafe_root_directory")
        opened = Path("/")
        for part in path.parts[1:]:
            opened /= part
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=anchor)
            os.close(anchor)
            anchor = following
            info = os.fstat(anchor)
            legacy = not strict and (
                opened in retained_ancestors or any(opened.is_relative_to(root) for root in retained_roots)
            )
            require(
                info.st_uid in owners and not info.st_mode & (0o002 if legacy else 0o022),
                "unsafe_opened_directory",
            )
        return anchor
    except Exception:
        os.close(anchor)
        raise


def read_bytes(path, limit=500000000, strict=True):
    """Bounded nofollow fd reads; explicit retained roots alone allow old group modes."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "read_path")
    anchor = directory_fd(path.parent, strict=strict)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=anchor)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "read_regular_bound")
            data = stream.read(limit + 1)
            require(len(data) <= limit, "read_growth_bound")
            return data
    finally:
        os.close(anchor)


def pinned(path, expected, private=False, owners=(0,)):
    p = chain(path, owners, private=private)
    require(p.is_file() and digest(read_bytes(p)) == expected, "pinned_file_drift")
    return p


def load_baseline(manifest_path, expected):
    """Load only the hash-pinned root-private sibling, never an import search path."""
    require(type(expected) is str and re.fullmatch("[0-9a-f]{64}", expected), "baseline_helper_pin")
    path = chain(manifest_path.parent / "candidate_baseline.py", (0,), private=True)
    parent = directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_uid == 0
                and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600
                and 0 < before.st_size <= 200000,
                "baseline_helper_file",
            )
            data = stream.read(200001)
            after = os.fstat(stream.fileno())
            require(
                file_identity(before) == file_identity(after) and len(data) == before.st_size, "baseline_helper_changed"
            )
    finally:
        os.close(parent)
    require(digest(data) == expected, "baseline_helper_hash")
    module = types.ModuleType("_academy_stage_baseline")
    exec(compile(data, str(path), "exec"), module.__dict__)  # noqa: S102 - reviewed hash-pinned stdlib-only bytes
    return module


def check_environment(runtime):
    descriptor = BASELINE.environment_file(runtime)
    path, target = Path(descriptor["path"]), Path(descriptor["target"])
    anchor = directory_fd(path.parent, strict=False)
    try:
        info = os.stat(path.name, dir_fd=anchor, follow_symlinks=False)
        if descriptor["link_target"] is None:
            require(stat.S_ISREG(info.st_mode), "runtime_environment_regular")
        else:
            require(
                stat.S_ISLNK(info.st_mode)
                and info.st_uid in (0, pwd.getpwnam("dotmac").pw_uid)
                and os.readlink(path.name, dir_fd=anchor) == descriptor["link_target"],
                "runtime_environment_link",
            )
    finally:
        os.close(anchor)
    anchor = directory_fd(target.parent, strict=False)
    try:
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=anchor)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
                == (descriptor["uid"], descriptor["gid"], descriptor["mode"])
                and before.st_size <= 2000000,
                "runtime_environment_authority",
            )
            data = stream.read(2000001)
            require(
                file_identity(os.fstat(stream.fileno())) == file_identity(before)
                and len(data) == before.st_size
                and digest(data) == descriptor["sha256"],
                "runtime_environment_drift",
            )
    finally:
        os.close(anchor)
    anchor = directory_fd(path.parent, strict=False)
    try:
        require(
            file_identity(os.stat(path.name, dir_fd=anchor, follow_symlinks=False)) == file_identity(info),
            "runtime_environment_path_changed",
        )
    finally:
        os.close(anchor)
    return descriptor


def check_assets(runtime):
    assets = BASELINE.upload_targets(runtime)
    roots = {Path(BASELINE.primary_runtime(runtime)["source"]), SHARED_RUNTIME}
    nginx = BASELINE.nginx_static_root(runtime)
    if nginx is not None:
        roots.add(Path(nginx))
    for name in ("avatars", "figures"):
        for root in roots:
            static = root / "static"
            anchor = directory_fd(static, strict=False)
            try:
                try:
                    info = os.stat(name, dir_fd=anchor, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                require(name in assets, "undeclared_runtime_asset")
                observed = static / name
                # Other closed observation roots may retain an identical real
                # copy. Equality preserves it; only the descriptor selects the
                # target linked by the candidate. No symlink alias is inferred.
                require(
                    stat.S_ISDIR(info.st_mode)
                    and inventory(no_links(observed), strict=False) == assets[name]["inventory_sha256"],
                    "runtime_asset_target",
                )
            finally:
                os.close(anchor)
    for item in assets.values():
        target = no_links(Path(item["target"]))
        require(target.is_dir() and inventory(target, strict=False) == item["inventory_sha256"], "runtime_asset_drift")
    return assets


def inventory(path, include_rows=False, strict=True):
    rows = []
    for p in [path, *sorted(path.rglob("*"))]:
        if "__pycache__" in p.parts or p.suffix == ".pyc":
            continue
        require(len(rows) < 250000, "inventory_count")
        s = p.lstat()
        row = [str(p.relative_to(path)), s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
        if stat.S_ISLNK(s.st_mode):
            row += ["link", os.readlink(p)]
        elif stat.S_ISREG(s.st_mode):
            require(s.st_size < 500000000, "inventory_file_size")
            row += ["file", digest(read_bytes(p, strict=strict))]
        else:
            require(stat.S_ISDIR(s.st_mode), "inventory_special_file")
            check = directory_fd(p, strict=strict)
            os.close(check)
            row += ["dir"]
        rows.append(row)
    return {"sha256": digest(canonical(rows)), "entries": rows} if include_rows else digest(canonical(rows))


def child(argv, env, owner, cwd=None, *, public_source=False):
    # Only this module constructs argv. No shell, supplied commands, root child,
    # complete inherited environment, or raw child output is permitted.
    require(
        argv[0] in ("/usr/bin/git", "/usr/bin/python3.12", env.get("STAGE_POETRY_TOOL")), "child_executable_refused"
    )
    require(type(public_source) is bool and (not public_source or argv[: len(GIT)] == GIT), "public_source_git_only")
    child_env = {k: v for k, v in env.items() if k != "STAGE_POETRY_TOOL"}
    code, stdout, stderr = run_group(
        argv,
        child_env,
        1800,
        cwd=cwd,
        user=owner.pw_uid,
        group=owner.pw_gid,
        extra_groups=[],
        umask=0o022 if public_source else 0o077,
    )
    require(code == 0, "unprivileged_child_failed")
    require(len(stdout) + len(stderr) < 16000000, "child_output_bound")
    return stdout


def live(role, runtime):
    # Root executes only the trusted systemctl read-only show binary.
    def show(unit, props):
        code, stdout, _stderr = run_group(
            ["/usr/bin/systemctl", "show", unit, "--property=" + props],
            {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            30,
        )
        require(code == 0 and len(stdout) < 100000, "live_read_failed")
        return dict(x.split("=", 1) for x in stdout.decode().splitlines())

    unit = "academy-v2-web" if role == "web" else "academy-v2-lab-worker"
    prior = BASELINE.primary_runtime(runtime)
    owner = pwd.getpwnam("dotmac")
    git_env = {
        "HOME": owner.pw_dir,
        "USER": "dotmac",
        "LOGNAME": "dotmac",
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    checked_sources = set()
    for item in runtime["units"].values():
        identity = (item["source"], item["head"], item["tree"])
        if identity in checked_sources:
            continue
        checked_sources.add(identity)
        for expression, expected in (("HEAD", item["head"]), ("HEAD^{tree}", item["tree"])):
            require(
                child([*GIT, "-C", item["source"], "rev-parse", expression], git_env, owner).decode().strip()
                == expected,
                "observed_runtime_git_identity",
            )
        require(
            not child(
                [*GIT, "-C", item["source"], "status", "--porcelain", "--untracked-files=all"], git_env, owner
            ).strip(),
            "observed_runtime_git_dirty",
        )
    vals = show(unit, "MainPID,ActiveState,SubState,WorkingDirectory,ExecStart,EnvironmentFiles")
    require(
        vals["ActiveState"] == "active"
        and vals["SubState"] == "running"
        and vals["WorkingDirectory"] == prior["source"],
        "observed_primary_required",
    )
    pid = int(vals["MainPID"])
    require(pid > 1, "primary_pid")
    proc = Path("/proc") / str(pid)
    environment = check_environment(runtime)
    require(
        vals["EnvironmentFiles"] == environment["path"] + " (ignore_errors=no)",
        "configured_environment_file_drift",
    )
    venv = prior["venv"]
    argv = (proc / "cmdline").read_bytes()
    require(
        os.readlink(proc / "cwd") == prior["source"]
        and os.readlink(proc / "exe") == os.path.realpath(venv + "/bin/python")
        and argv.split(b"\0")[0].decode() in [venv + "/bin/" + n for n in ("python", "python3", "uvicorn", "gunicorn")],
        "observed_process_identity",
    )
    value = {
        "unit": unit,
        "pid": pid,
        "cwd": prior["source"],
        "exe": os.readlink(proc / "exe"),
        "argv_sha256": digest(argv),
        "environment_file_sha256": environment["sha256"],
        "configured_environment_file": environment["path"],
    }
    if role == "web":
        value["timers"] = {
            name: show("academy-v2-" + name + ".timer", "ActiveState,UnitFileState,Unit") for name in NAMES
        }
        require(all(v["ActiveState"] == "active" for v in value["timers"].values()), "timers_not_active")
    return value


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
            b"/home/dotmac/projects/" not in raw
            and all(path.encode() not in raw for path in BASELINE.forbidden_runtime_paths()),
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
        with zipfile.ZipFile(path) as archive:
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


def main():
    global BASELINE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--role", required=True, choices=HOSTS)
    parser.add_argument("--receipt", required=True)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() == 0, "root_linux_required")
    manifest_path = chain(args.manifest, (0,), private=True)
    raw = read_bytes(manifest_path, limit=2000000)
    require(len(raw) < 2000000, "manifest_bound")
    m = json.loads(raw)
    require(
        m["schema"] == "AcademyInactiveStageInputs.v2"
        and re.fullmatch("[0-9a-f]{40}", m["candidate"])
        and re.fullmatch("[0-9a-f]{40}", m["tree"]),
        "manifest_schema",
    )
    require(socket.gethostname().split(".")[0] == HOSTS[args.role] == m["hostname"], "wrong_host")
    pinned(Path(__file__).absolute(), m["self_sha256"], private=True)
    pinned(manifest_path.parent / "staging-plan.json", m["plan_sha256"], private=True)
    owner = pwd.getpwnam("dotmac")
    require(owner.pw_uid > 0 and owner.pw_gid > 0 and owner.pw_dir == "/home/dotmac", "unprivileged_dotmac_identity")
    required_fields = {
        "schema",
        "candidate",
        "tree",
        "hostname",
        "self_sha256",
        "plan_sha256",
        "baseline_helper_sha256",
        "runtime_baseline",
        "observed_live_sha256",
        "python_sha256",
        "poetry_tool",
        "poetry_tool_sha256",
        "poetry_tool_inventory_sha256",
        "bundle_path",
        "bundle_sha256",
        "pyproject_path",
        "pyproject_sha256",
        "lock_path",
        "lock_sha256",
        "required_main_distributions",
        "bootstrap",
        "retained_wheels",
    }
    require(
        type(m) is dict and required_fields <= set(m) <= required_fields | {"reviewed_pth_import_sha256"},
        "manifest_strict_fields",
    )
    require(
        type(m["observed_live_sha256"]) is str and re.fullmatch("[0-9a-f]{64}", m["observed_live_sha256"]),
        "observed_live_pin",
    )
    BASELINE = load_baseline(manifest_path, m["baseline_helper_sha256"])
    runtime = BASELINE.validate_runtime(m["runtime_baseline"], args.role, owner.pw_uid)
    source, venv = SOURCE_PARENT / m["candidate"], VENV_PARENT / m["candidate"]
    stage_cache = TOOLS_PARENT / ("stage-" + m["candidate"])
    for path in (source, venv, stage_cache):
        chain(path, (0, owner.pw_uid), missing=True)
        require(not path.exists() and not path.is_symlink(), "candidate_must_be_absent")
    receipt = Path(args.receipt)
    require(receipt.parent == manifest_path.parent and re.fullmatch(r"[a-z0-9-]+\.json", receipt.name), "receipt_path")
    require(not receipt.exists() and not receipt.is_symlink(), "receipt_must_be_new")
    # Reserve durable evidence before any candidate object; failure preserves all files.
    receipt_parent_fd = directory_fd(receipt.parent)
    require(
        os.fstat(receipt_parent_fd).st_uid == 0 and not os.fstat(receipt_parent_fd).st_mode & 0o077,
        "receipt_parent_private",
    )
    receipt_fd = os.open(
        receipt.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=receipt_parent_fd
    )
    os.fsync(receipt_parent_fd)
    state = {
        "schema": "AcademyInactiveStageReceipt.v2",
        "runtime_baseline_sha256": digest(canonical(runtime)),
        "baseline_helper_sha256": m["baseline_helper_sha256"],
        "expected_observed_live_sha256": m["observed_live_sha256"],
        "observed_live_before_sha256": None,
        "observed_live_after_sha256": None,
        "status": "incomplete",
        "candidate": m["candidate"],
        "tree": m["tree"],
        "role": args.role,
        "manifest_sha256": digest(raw),
        "source": str(source),
        "venv": str(venv),
        "stage_cache": str(stage_cache),
        "deployment_ready": False,
        "started_unix": int(time.time()),
        "observed_steps": [],
    }

    def revalidate_parents():
        paths = [SOURCE_PARENT, VENV_PARENT, TOOLS_PARENT]
        paths.extend(p for p in (source, venv, stage_cache) if p.exists() or p.is_symlink())
        for path in paths:
            check = directory_fd(path)
            os.close(check)
        check = directory_fd(receipt.parent)
        try:
            info = os.fstat(check)
            require(info.st_uid == 0 and not info.st_mode & 0o077, "receipt_parent_private")
        finally:
            os.close(check)

    def save():
        state["process_group_observations"] = list(PROCESS_GROUPS)
        state["process_group_limit"] = "No containment claim for descendants escaping via setsid/setpgid."
        os.lseek(receipt_fd, 0, os.SEEK_SET)
        os.ftruncate(receipt_fd, 0)
        data = memoryview(canonical(state) + b"\n")
        while data:
            data = data[os.write(receipt_fd, data) :]
        os.fsync(receipt_fd)
        os.fsync(receipt_parent_fd)

    save()
    try:
        python = pinned("/usr/bin/python3.12", m["python_sha256"])
        tool = Path(m["poetry_tool"])
        require(tool.is_absolute() and tool.name == "poetry", "poetry_basename")
        tool = pinned(tool.resolve(strict=True), m["poetry_tool_sha256"], owners=(0, owner.pw_uid))
        tool_root = tool.parent.parent

        def check_tool_inventory():
            expected = m["poetry_tool_inventory_sha256"]
            require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "tool_inventory_hash_format")
            require(inventory(tool_root) == expected, "poetry_tool_inventory_drift")

        check_tool_inventory()
        bundle = pinned(m["bundle_path"], m["bundle_sha256"], private=True)
        project = pinned(m["pyproject_path"], m["pyproject_sha256"], private=True)
        lock = pinned(m["lock_path"], m["lock_sha256"], private=True)
        locked, config = tomllib.loads(lock.read_text()), tomllib.loads(project.read_text())
        direct = {normalize(x) for x in config["tool"]["poetry"]["dependencies"] if x != "python"}
        require(set(m["required_main_distributions"]) == direct, "required_direct_set")
        env = {
            "HOME": owner.pw_dir,
            "USER": "dotmac",
            "LOGNAME": "dotmac",
            "LANG": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "PYTHONNOUSERSITE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "STAGE_POETRY_TOOL": str(tool),
            "POETRY_VIRTUALENVS_CREATE": "false",
            "POETRY_NO_INTERACTION": "1",
            "POETRY_KEYRING_ENABLED": "false",
            "PIP_CONFIG_FILE": "/dev/null",
            "PIP_NO_INPUT": "1",
        }
        require(
            child([str(python), "-I", "-S", "-c", "import sys;print(sys.version_info[:2])"], env, owner).strip()
            == b"(3, 12)",
            "python_version",
        )
        require(child([str(tool), "--version"], env, owner).strip() == b"Poetry (version 2.4.1)", "poetry_version")
        before = live(args.role, runtime)
        state["observed_live_before_sha256"] = digest(canonical(before))
        save()
        require(state["observed_live_before_sha256"] == m["observed_live_sha256"], "observed_live_baseline")
        environment = check_environment(runtime)
        assets = check_assets(runtime)
        # Namespace bootstrap is separately reviewed coordinator work, never inferred.
        revalidate_parents()
        anchor = directory_fd(SOURCE_PARENT)
        transport = SOURCE_PARENT / ("stage-" + m["candidate"] + ".bundle")
        try:
            fd = os.open(transport.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=anchor)
            with os.fdopen(fd, "wb") as output:
                data = bundle.read_bytes()
                require(digest(data) == m["bundle_sha256"], "bundle_copy_drift")
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
                os.fchown(output.fileno(), owner.pw_uid, owner.pw_gid)
        finally:
            os.close(anchor)
        require(not source.exists() and not source.is_symlink(), "source_no_reuse")
        # Tracked source is public-safe. Nginx must traverse it and read its
        # static files; environment targets and installer/venv state stay private.
        child(
            [*GIT, "clone", "--no-checkout", "--no-hardlinks", "--", str(transport), str(source)],
            env,
            owner,
            public_source=True,
        )
        child([*GIT, "-C", str(source), "checkout", "--detach", m["candidate"]], env, owner, public_source=True)

        def git(*argv):
            return child([*GIT, "-C", str(source), *argv], env, owner).decode().strip()

        require(
            git("rev-parse", "HEAD") == m["candidate"] and git("rev-parse", "HEAD^{tree}") == m["tree"],
            "cloned_git_identity",
        )
        require(not git("status", "--porcelain", "--untracked-files=all"), "source_not_clean")
        require(
            digest(read_bytes(no_links(source / "pyproject.toml"))) == m["pyproject_sha256"]
            and digest(read_bytes(no_links(source / "poetry.lock"))) == m["lock_sha256"],
            "committed_lock_drift",
        )
        revalidate_parents()
        # Keep generated installer state outside the importable source tree.
        child(
            [
                str(python),
                "-I",
                "-S",
                "-c",
                "from pathlib import Path;import sys;Path(sys.argv[1]).mkdir(mode=0o700)",
                str(stage_cache),
            ],
            env,
            owner,
        )
        cache_parent = directory_fd(TOOLS_PARENT)
        try:
            cache_fd = os.open(stage_cache.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cache_parent)
            try:
                cache_info = os.fstat(cache_fd)
                require(
                    cache_info.st_uid == owner.pw_uid and stat.S_IMODE(cache_info.st_mode) == 0o700,
                    "cache_namespace_identity",
                )
                os.fsync(cache_fd)
            finally:
                os.close(cache_fd)
            os.fsync(cache_parent)
        finally:
            os.close(cache_parent)
        revalidate_parents()
        env["POETRY_CONFIG_DIR"] = str(stage_cache / "config")
        env["POETRY_CACHE_DIR"] = str(stage_cache / "cache")
        child([str(tool), "check", "--lock"], env, owner, source)
        state["observed_steps"].append("exact_source_and_poetry_check_lock")
        save()
        child(
            [
                str(python),
                "-I",
                "-S",
                "-c",
                "import pathlib,os,sys;p=sys.argv[1];pathlib.Path(p).mkdir(mode=0o700);"
                'os.execv(sys.executable,[sys.executable,"-I","-m","venv",p])',
                str(venv),
            ],
            env,
            owner,
        )
        env["VIRTUAL_ENV"], env["PATH"] = str(venv), str(venv / "bin") + ":/usr/bin:/bin"
        install_env = dict(env)
        # Revalidate the whole observed tool tree before giving its process
        # credentials; an entrypoint hash alone does not cover imported code.
        check_tool_inventory()
        for name in CREDENTIALS:
            require(name in os.environ, "forgejo_credentials_not_supplied")
            install_env[name] = os.environ[name]
        child([str(tool), "install", "--only", "main", "--no-root", "--no-interaction"], install_env, owner, source)
        del install_env
        check_tool_inventory()
        require(
            digest(read_bytes(no_links(source / "poetry.lock"))) == m["lock_sha256"]
            and digest(read_bytes(no_links(source / "pyproject.toml"))) == m["pyproject_sha256"],
            "installer_changed_lock",
        )
        require(Path(os.path.realpath(venv / "bin/python")) == python, "venv_interpreter_identity")
        for p in venv.rglob("*"):
            if p.is_symlink():
                target = p.resolve(strict=True)
                require(target == python or target.is_relative_to(venv), "venv_external_link")
        pkg = packages(venv, source, locked, direct, m["bootstrap"], m.get("reviewed_pth_import_sha256", {}))
        state["installed_inventory"] = pkg
        state["observed_steps"].append("new_venv_locked_install_and_metadata_inventory")
        save()
        state["wheel_byte_parity"] = parity(m["retained_wheels"], venv / "lib/python3.12/site-packages", locked)
        # Link only exact retained runtime assets, entirely as unprivileged dotmac.
        links = {".env": environment["target"], **{"static/" + n: item["target"] for n, item in assets.items()}}
        child(
            [
                str(python),
                "-I",
                "-S",
                "-c",
                "import pathlib,json,sys;p=pathlib.Path(sys.argv[1]);"
                "[(p/k).symlink_to(v) for k,v in json.loads(sys.argv[2]).items()]",
                str(source),
                json.dumps(links),
            ],
            env,
            owner,
        )
        require(
            not git("status", "--porcelain", "--untracked-files=no") and git("rev-parse", "HEAD") == m["candidate"],
            "poststage_source_drift",
        )
        require(not git("status", "--porcelain", "--untracked-files=all"), "poststage_untracked_source")
        revalidate_parents()
        after = live(args.role, runtime)
        state["observed_live_after_sha256"] = digest(canonical(after))
        require(after == before, "active_runtime_changed")
        require(check_environment(runtime) == environment, "poststage_environment_drift")
        require(check_assets(runtime) == assets, "poststage_asset_drift")
        for name, target in links.items():
            require((source / name).is_symlink() and os.readlink(source / name) == target, "candidate_runtime_link")
        for name in {"avatars", "figures"} - set(assets):
            require(
                not (source / "static" / name).exists() and not (source / "static" / name).is_symlink(),
                "candidate_undeclared_asset",
            )
        state.update(
            status="inactive_stage_observed",
            completed_unix=int(time.time()),
            source_file_manifest=inventory(source, include_rows=True),
            venv_file_manifest=inventory(venv, include_rows=True),
            stage_cache_file_manifest=inventory(stage_cache, include_rows=True),
            lock_sha256=m["lock_sha256"],
            pyvenv_cfg_sha256=digest(read_bytes(no_links(venv / "pyvenv.cfg"))),
            interpreter_sha256=digest(python.read_bytes()),
            poetry_tool_inventory_sha256=m["poetry_tool_inventory_sha256"],
            unmet_prerequisites=[
                "independent_artifact_provenance_and_offline_wheel_closure",
                "exact_final_candidate_ci_and_freeze",
                "database_revision_schema_acl_and_migration",
                "fresh_quiescence_gate_epoch_and_sender_exclusion",
                "exact_production_approval",
                "candidate_bound_acceptance_and_active_process_proof",
            ],
        )
        revalidate_parents()
        save()
        revalidate_parents()
        print(
            json.dumps(
                {
                    "status": state["status"],
                    "receipt_sha256": digest(canonical(state) + b"\n"),
                    "deployment_ready": False,
                }
            )
        )
    except BaseException:
        for sig in INTERRUPTS:
            signal.signal(sig, signal.SIG_IGN)
        state["status"] = "failed_preserved_for_review"
        try:
            revalidate_parents()
            state["failure_parent_chain_revalidated"] = True
        except BaseException:
            state["failure_parent_chain_revalidated"] = False
        if "before" in locals():
            try:
                failure_after = live(args.role, runtime)
                state["observed_live_after_sha256"] = digest(canonical(failure_after))
                state["failure_live_unchanged"] = failure_after == before
            except BaseException:
                state["failure_live_unchanged"] = "unobserved"
        if any(not item["confirmed"] for item in PROCESS_GROUPS):
            state["status"] = "process_cleanup_unconfirmed"
            state["manual_hold"] = True
        save()
        raise
    finally:
        os.close(receipt_fd)
        os.close(receipt_parent_fd)


if __name__ == "__main__":
    for interrupt in INTERRUPTS:
        signal.signal(interrupt, interrupt_stage)
    try:
        main()
    except BaseException:
        status = (
            "process_cleanup_unconfirmed" if any(not p["confirmed"] for p in PROCESS_GROUPS) else "refused_or_failed"
        )
        print(json.dumps({"status": status, "details": "preserved_private_receipt_if_reserved"}))
        sys.exit(1)

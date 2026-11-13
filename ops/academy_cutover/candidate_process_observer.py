"""Dotmac read-only process/config observer. Technical input creates no authority.

Fresh reconstruction uses actual /proc PID environment over exact pinned dotenv
bytes. It is not access to the target's in-memory settings or sys.path. Root's
promoter owns exact unit/argv/environment-file semantics, approval and custody.
"""

import hashlib
import io
import json
import os
import pwd
import re
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

HOSTS = {"vmi2490731", "academy-labs"}
RETAINED_SOURCES = (
    "/home/dotmac/projects/academy-v2-csp-stage-d12260b6996b18b27e04a784042f764bd583952d",
    "/home/dotmac/projects/academy-v2-release-7ef72b3d1c23a5bf4d3268a6cf21a3d46673db46",
)
ENVIRONMENT_FILES = (
    "/home/dotmac/projects/dotmac_academy_v2/.env",
    "/home/dotmac/projects/academy-v2-csp-stage-d12260b6996b18b27e04a784042f764bd583952d/.env",
    "/home/dotmac/projects/academy-v2-release-7ef72b3d1c23a5bf4d3268a6cf21a3d46673db46/.env",
)
LEGACY_ENV_DIRECTORIES = frozenset(
    (
        "/home/dotmac/projects",
        "/home/dotmac/projects/dotmac_academy_v2",
        "/home/dotmac/projects/academy-v2-csp-stage-d12260b6996b18b27e04a784042f764bd583952d",
        "/home/dotmac/projects/academy-v2-release-7ef72b3d1c23a5bf4d3268a6cf21a3d46673db46",
    )
)
SOURCE_FILES = {"app/config.py", "pyproject.toml", "poetry.lock"}
FIELDS = {
    "schema",
    "candidate",
    "tree",
    "source",
    "venv",
    "hostname",
    "uid",
    "pid",
    "start_ticks",
    "attempt",
    "helper_sha256",
    "source_file_sha256",
    "environment_file",
    "env_sha256",
    "python_sha256",
    "venv_cfg_sha256",
    "import_environment_sha256",
}


class Refusal(Exception):
    pass


def require(ok, name):
    if not ok:
        raise Refusal(name)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_field")
        result[key] = value
    return result


def no_constant(_value):
    raise Refusal("non_json_constant")


def directory_fd(path, owners, strict=True):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute_directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    current = Path("/")
    try:
        for part in (None, *path.parts[1:]):
            if part is not None:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                current /= part
            info = os.fstat(fd)
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid in owners
                and not info.st_mode & 0o002
                and (not info.st_mode & 0o020 or (not strict and str(current) in LEGACY_ENV_DIRECTORIES)),
                "unsafe_opened_directory",
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(path, owners, limit=5_000_000, strict=True, mode=None):
    path = Path(path)
    parent = directory_fd(path.parent, owners, strict)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_uid in owners
                and not before.st_mode & 0o022
                and before.st_size <= limit,
                "unsafe_regular_file",
            )
            require(mode is None or stat.S_IMODE(before.st_mode) == mode, "exact_file_mode")
            chunks, size = [], 0
            while True:
                chunk = os.read(fd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                require(size <= limit, "file_growth_bound")
                chunks.append(chunk)
            after = os.fstat(fd)
            require(
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "file_changed_during_read",
            )
            return b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


class OutputCapture:
    """Capture fd1/fd2 without raw retention; hash at most1MiB per stream."""

    def __init__(self):
        self.saved = {}
        self.threads = []
        self.stop = threading.Event()
        self.results = {}

    def start(self):
        for number, name in ((1, "stdout"), (2, "stderr")):
            self.saved[number] = os.dup(number)
            read_fd, write_fd = os.pipe()
            os.set_blocking(read_fd, False)
            os.dup2(write_fd, number)
            os.close(write_fd)
            result = {"bytes": 0, "sha256": None, "truncated": False, "drained": False}
            self.results[name] = result

            def drain(fd=read_fd, record=result):
                hasher, kept = hashlib.sha256(), 0
                stopped_at = None
                try:
                    while True:
                        try:
                            block = os.read(fd, 65536)
                        except BlockingIOError:
                            if self.stop.is_set():
                                stopped_at = stopped_at or time.monotonic()
                                if time.monotonic() - stopped_at > 1:
                                    break
                            time.sleep(0.01)
                            continue
                        if not block:
                            record["drained"] = True
                            break
                        record["bytes"] += len(block)
                        selected = block[: max(0, 1_048_576 - kept)]
                        hasher.update(selected)
                        kept += len(selected)
                        record["truncated"] = record["bytes"] > 1_048_576
                except BaseException:
                    record["capture_error"] = True
                finally:
                    record["sha256"] = hasher.hexdigest()
                    os.close(fd)

            thread = threading.Thread(target=drain, daemon=True)
            thread.start()
            self.threads.append(thread)

    def finish(self):
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except BaseException:
                # Never log a stream exception: it may contain captured material.
                self.results.setdefault("flush", {"drained": False, "capture_error": True})
        for number, saved in self.saved.items():
            os.dup2(saved, number)
            os.close(saved)
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=2)
        return self.results


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def git(m, action, rel=None):
    tails = {
        "head": ["rev-parse", "HEAD"],
        "tree": ["rev-parse", "HEAD^{tree}"],
        "clean": ["status", "--porcelain", "--untracked-files=no"],
    }
    if action == "file":
        require(rel in SOURCE_FILES, "git_file_allowlist")
        tail = ["show", "HEAD:" + rel]
    else:
        require(action in tails and rel is None, "git_action_allowlist")
        tail = tails[action]
    result = subprocess.run(  # noqa: S603 -- fixed action/file allowlist, no shell
        ["/usr/bin/git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *tail],
        cwd=m["source"],
        env={
            "HOME": "/nonexistent",
            "PATH": "/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=20,
        check=False,
    )
    require(result.returncode == 0, "git_readback_failed")
    return result.stdout


def check_source(m):
    require(git(m, "head").decode().strip() == m["candidate"], "candidate_head")
    require(git(m, "tree").decode().strip() == m["tree"], "candidate_tree")
    require(not git(m, "clean"), "tracked_source_dirty")
    for rel, expected in m["source_file_sha256"].items():
        data = read_file(Path(m["source"]) / rel, (0, m["uid"]))
        require(digest(data) == expected and git(m, "file", rel) == data, "source_file_pin")
    for base in (Path(m["source"]) / "app", Path(m["source"]) / "alembic"):
        for parent, dirs, files in os.walk(base, followlinks=False):
            require(
                "__pycache__" not in dirs and not any(n.endswith((".pyc", ".pyo")) for n in files),
                "source_bytecode_cache_refused",
            )
            require(not any((Path(parent) / name).is_symlink() for name in dirs), "source_directory_symlink")


def runtime_pins(m):
    python = Path("/usr/bin/python3.12")
    require(digest(read_file(python, (0,), limit=100_000_000)) == m["python_sha256"], "system_python_pin")
    cfg = read_file(Path(m["venv"]) / "pyvenv.cfg", (0, m["uid"]), limit=100_000)
    require(
        digest(cfg) == m["venv_cfg_sha256"] and b"include-system-site-packages = false" in cfg, "venv_configuration_pin"
    )
    require(Path(os.path.realpath(Path(m["venv"]) / "bin/python")) == python, "venv_interpreter_target")


def identity(m):
    require(type(m) is dict and set(m) == FIELDS and m["schema"] == "AcademyCandidateProcessInputs.v2", "input_schema")
    require(
        sys.platform == "linux" and len(sys.argv) == 1 and sys.flags.isolated == 1 and sys.dont_write_bytecode,
        "isolated_B_launch",
    )
    require(type(m["uid"]) is int and m["uid"] > 0 and os.getuid() == os.geteuid() == m["uid"], "dotmac_uid")
    user = pwd.getpwuid(os.getuid())
    require(user.pw_name == "dotmac" and user.pw_dir == "/home/dotmac", "dotmac_identity")
    require(
        type(m["hostname"]) is str and m["hostname"] in HOSTS and socket.gethostname() == m["hostname"],
        "actual_hostname",
    )
    for key in ("candidate", "tree"):
        require(type(m[key]) is str and re.fullmatch(r"[0-9a-f]{40}", m[key]), "git_identity_shape")
    for key in (
        "attempt",
        "helper_sha256",
        "env_sha256",
        "python_sha256",
        "venv_cfg_sha256",
        "import_environment_sha256",
    ):
        require(type(m[key]) is str and re.fullmatch(r"[0-9a-f]{64}", m[key]), "pin_shape")
    require(
        type(m["pid"]) is int
        and m["pid"] > 1
        and type(m["start_ticks"]) is str
        and re.fullmatch(r"[1-9][0-9]{0,24}", m["start_ticks"]),
        "pid_start_ticks_shape",
    )
    source = Path("/srv/academy/releases") / m["candidate"]
    venv = Path("/srv/academy/venvs") / m["candidate"]
    require(m["source"] == str(source) and m["venv"] == str(venv), "exact_new_runtime_paths")
    for path in (source, venv):
        fd = directory_fd(path, (0, m["uid"]))
        os.close(fd)
    require(
        Path.cwd() == source
        and sys.prefix == str(venv)
        and sys.base_prefix != sys.prefix
        and Path(sys.executable).absolute() == venv / "bin/python",
        "observer_runtime_identity",
    )
    helper = Path("/usr/local/lib/academy-deploy") / m["candidate"] / "candidate_process_observer.py"
    require(
        Path(__file__).absolute() == helper and digest(read_file(helper, (0,), mode=0o644)) == m["helper_sha256"],
        "root_public_helper_pin",
    )
    pins = m["source_file_sha256"]
    require(
        type(pins) is dict
        and set(pins) == SOURCE_FILES
        and all(type(v) is str and re.fullmatch(r"[0-9a-f]{64}", v) for v in pins.values()),
        "source_pin_set",
    )
    require(not any(n == "app" or n.startswith("app.") for n in sys.modules), "app_preimport_refused")
    check_source(m)
    runtime_pins(m)


def env_bytes(m):
    target = m["environment_file"]
    require(type(target) is str and target in ENVIRONMENT_FILES, "closed_environment_target")
    source_env = Path(m["source"]) / ".env"
    parent = directory_fd(source_env.parent, (0, m["uid"]))
    try:
        info = os.stat(".env", dir_fd=parent, follow_symlinks=False)
        require(
            stat.S_ISLNK(info.st_mode) and os.readlink(".env", dir_fd=parent) == target, "explicit_environment_link"
        )
        raw = read_file(Path(target), (0, m["uid"]), limit=2_000_000, strict=False, mode=0o600)
        require(digest(raw) == m["env_sha256"], "environment_file_pin")
        return raw
    finally:
        os.close(parent)


def proc_bytes(fd, name, uid, limit):
    require(name in {"stat", "status", "environ", "cmdline"}, "proc_file_allowlist")
    opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        info = os.fstat(opened)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid, "proc_file_owner")
        chunks, size = [], 0
        while True:
            chunk = os.read(opened, min(65536, limit + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            require(size <= limit, "proc_file_bound")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(opened)


def process_environment(raw):
    require(raw.endswith(b"\0"), "process_environment_termination")
    result = {}
    for entry in raw.split(b"\0")[:-1]:
        require(b"=" in entry, "process_environment_assignment")
        key, value = entry.split(b"=", 1)
        key, value = key.decode("utf-8"), value.decode("utf-8")
        require(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and key not in result, "process_environment_key_or_duplicate"
        )
        result[key] = value
    return result


def import_environment(values):
    selected = {
        k: digest(v.encode("utf-8"))
        for k, v in values.items()
        if k.startswith(("PYTHON", "LD_", "PG")) or k in {"VIRTUAL_ENV", "PATH"}
    }
    return digest(canonical(selected))


def validate_import_controls(values, m):
    require(values.get("PYTHONPATH") == m["source"], "actual_candidate_pythonpath")
    require(values.get("VIRTUAL_ENV") in (None, "", m["venv"]), "actual_candidate_virtual_env")
    require(values.get("PYTHONHOME") in (None, ""), "pythonhome_refused")
    for key in values:
        if key in {"PYTHONPATH", "PYTHONHOME"}:
            continue
        require(not key.startswith(("PYTHON", "LD_", "PG", "DYLD_")), "unsafe_actual_import_control")
    path = values.get("PATH")
    require(type(path) is str and path, "actual_path_required")
    for item in path.split(":"):
        part = Path(item)
        require(item and part.is_absolute() and ".." not in part.parts, "unsafe_actual_path_component")
        if item == m["venv"] + "/bin":
            fd = directory_fd(part, (0, m["uid"]))
        else:
            # Standard /bin and /sbin may be root-managed usr-merge aliases.
            # Resolve them, then require strictly root-owned final ancestry.
            fd = directory_fd(Path(os.path.realpath(part)), (0,))
        os.close(fd)


def observe_pid(m, expected_directory=None):
    pid = m["pid"]
    parent = directory_fd(Path("/proc"), (0,))
    try:
        fd = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        directory = (info.st_dev, info.st_ino)
        require(
            info.st_uid == m["uid"] and (expected_directory is None or directory == expected_directory),
            "pid_directory_identity",
        )
        raw_stat = proc_bytes(fd, "stat", m["uid"], 100_000)
        prefix, tail = raw_stat.rsplit(b")", 1)
        require(prefix.split(b" ", 1)[0] == str(pid).encode(), "stat_pid")
        fields = tail.split()
        require(
            len(fields) > 19 and fields[0] not in {b"Z", b"X", b"x"} and fields[19].decode() == m["start_ticks"],
            "pid_start_ticks_and_liveness",
        )
        status = proc_bytes(fd, "status", m["uid"], 100_000)
        uid_match = re.search(rb"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", status, re.M)
        require(uid_match is not None and all(int(v) == m["uid"] for v in uid_match.groups()), "pid_uid_vector")
        require(
            os.readlink("cwd", dir_fd=fd) == m["source"] and os.readlink("exe", dir_fd=fd) == "/usr/bin/python3.12",
            "pid_cwd_executable",
        )
        command = proc_bytes(fd, "cmdline", m["uid"], 200_000)
        require(command.endswith(b"\0"), "pid_command_termination")
        first = command.split(b"\0", 1)[0].decode("utf-8")
        require(
            first in {m["venv"] + "/bin/" + n for n in ("python", "python3", "python3.12", "uvicorn", "gunicorn")},
            "pid_new_venv_argv",
        )
        values = process_environment(proc_bytes(fd, "environ", m["uid"], 2_000_000))
        require(import_environment(values) == m["import_environment_sha256"], "actual_import_environment_pin")
        validate_import_controls(values, m)
        # Re-read the same opened proc instance after environment/argv reads.
        again = proc_bytes(fd, "stat", m["uid"], 100_000).rsplit(b")", 1)[1].split()
        require(
            len(again) > 19 and again[0] not in {b"Z", b"X", b"x"} and again[19].decode() == m["start_ticks"],
            "pid_changed_during_read",
        )
        os.kill(pid, 0)
        return values, directory, command
    finally:
        os.close(fd)


def settings_model(m, raw, process_values):
    os.environ.clear()
    os.environ.update(process_values)  # The target's actual initial process authority.
    sys.dont_write_bytecode = True
    sys.path.insert(0, m["source"])
    from dotenv import dotenv_values

    # Inspect the exact pinned file without interpolation, but do not promote
    # its literal values into process overrides. Canonical Settings owns the
    # target's normal dotenv interpolation/casefold/source precedence.
    parsed = dotenv_values(stream=io.StringIO(raw.decode("utf-8")), interpolate=False)
    require(
        any(k.casefold() == "migration_database_url" for k in (*parsed, *process_values)),
        "explicit_migration_url_authority",
    )
    from app.config import settings

    return settings


def readonly_revision(settings):
    import psycopg
    from sqlalchemy.engine import make_url

    raw_url = settings.migration_database_url
    require(type(raw_url) is str and bool(raw_url.strip()), "explicit_migration_url_string")
    url = make_url(raw_url)
    require(
        url.get_backend_name() == "postgresql"
        and url.username == "app_admin"
        and url.database == "academy"
        and not url.query,
        "fixed_readonly_postgresql_admin",
    )
    require(
        bool(url.host)
        and not any(c.isspace() or c in "/,@" for c in url.host)
        and bool(url.password)
        and (url.port is None or 0 < url.port < 65536),
        "explicit_host_password_port",
    )
    with psycopg.connect(
        host=url.host,
        port=url.port or 5432,
        dbname=url.database,
        user=url.username,
        password=url.password,
        connect_timeout=10,
        application_name="academy_process_observer",
        options=(
            "-c default_transaction_read_only=on -c statement_timeout=15000 "
            "-c lock_timeout=3000 -c search_path=pg_catalog"
        ),
    ) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")
            cursor.execute("SELECT current_user,current_database(),current_setting('transaction_read_only')")
            require(cursor.fetchone() == ("app_admin", "academy", "on"), "readonly_session_identity")
            cursor.execute("SELECT version_num FROM public.alembic_version ORDER BY version_num")
            revisions = [row[0] for row in cursor.fetchall()]
            require(revisions == ["0031_rate_limit_buckets", "a0011_oidc_login_states"], "exact_full_revision_vector")
        conn.rollback()
    return revisions


def main():
    report = {"schema": "AcademyCandidateProcessReport.v2", "ok": False, "unmet_predicates": []}
    capture = OutputCapture()
    started = int(time.time())
    try:
        capture.start()
        # No inherited launcher environment is a settings authority here.
        os.environ.clear()
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536, "stdin_bound")
        m = json.loads(raw, object_pairs_hook=unique_object, parse_constant=no_constant)
        identity(m)
        env_raw = env_bytes(m)
        process_before, proc_directory, command_before = observe_pid(m)
        settings = settings_model(m, env_raw, process_before)
        require(settings.oidc_enabled is False and not settings.oidc_client_secret, "actual_authority_oidc_dark")
        revisions = readonly_revision(settings)
        check_source(m)
        runtime_pins(m)
        require(env_bytes(m) == env_raw, "environment_file_changed")
        process_after, _, command_after = observe_pid(m, proc_directory)
        require(process_after == process_before and command_after == command_before, "pid_environment_or_argv_changed")
        # Reconstruct with the SAME actual process environment and canonical
        # default file policy, not manually merged/interpolated overrides.
        os.environ.clear()
        os.environ.update(process_after)
        from app.config import Settings

        after_settings = Settings()
        require(
            after_settings.oidc_enabled is False
            and not after_settings.oidc_client_secret
            and after_settings.migration_database_url == settings.migration_database_url,
            "effective_settings_changed",
        )
        require(env_bytes(m) == env_raw, "environment_changed_after_config_recheck")
        process_final, _, command_final = observe_pid(m, proc_directory)
        require(process_final == process_before and command_final == command_before, "pid_changed_after_config_recheck")
        report = {
            **m,
            "schema": "AcademyCandidateProcessReport.v2",
            "ok": True,
            "oidc_enabled": False,
            "oidc_client_secret_present": False,
            "revision_vector": revisions,
            "observed_unix_started": started,
            "observed_unix_finished": int(time.time()),
            "unmet_predicates": [],
        }
    except BaseException as exc:
        report = {
            "schema": "AcademyCandidateProcessReport.v2",
            "ok": False,
            "unmet_predicates": [str(exc) if isinstance(exc, Refusal) else "unexpected_error_details_suppressed"],
        }
    finally:
        captured = capture.finish()
    if any(not r["drained"] or r.get("capture_error") or r.get("truncated") for r in captured.values()):
        report = {
            "schema": "AcademyCandidateProcessReport.v2",
            "ok": False,
            "unmet_predicates": ["output_capture_incomplete"],
        }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except BaseException:
        # Even capture/finalization failure must not expose exception context.
        exit_code = 1
        try:
            os.write(
                1,
                b'{"schema":"AcademyCandidateProcessReport.v2","ok":false,'
                b'"unmet_predicates":["observer_entry_failed"]}\n',
            )
        except BaseException:
            exit_code = 1
    raise SystemExit(exit_code)

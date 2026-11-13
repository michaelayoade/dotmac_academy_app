"""Fixed-query, full-visibility, read-only lab observation; bounded JSON stdin.

Run only by root's separately reviewed clean-environment launcher as dotmac,
using the exact source cwd and venv/bin/python -I -B. Never stops a process,
executes a worker, destroys a runtime, or proves external host quiescence.
"""

# ruff: noqa: E501 -- fixed aggregate SQL remains directly auditable.

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
import time
from pathlib import Path

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

SOURCE_FILES = {
    "app/config.py",
    "app/models/lab.py",
    "app/services/lab_operations.py",
    "app/services/lab_lifecycle.py",
    "app/services/lab_jobs.py",
    "app/web/labs.py",
    "pyproject.toml",
    "poetry.lock",
}
FIELDS = {
    "schema",
    "environment_file",
    "mode",
    "observation_id",
    "candidate",
    "tree",
    "source",
    "venv",
    "hostname",
    "uid",
    "retained_source",
    "helper_sha256",
    "source_file_sha256",
    "env_sha256",
    "venv_cfg_sha256",
    "python_sha256",
    "expected_revisions",
    "require_zero",
    "max_observation_seconds",
}
REPORT = {
    "schema": 2,
    "observer": "academy_lab_idle",
    "ok": False,
    "runtime_mutation_executed": False,
    "host_process_quiescence_proven": False,
    "receipt_custody_or_freshness_proven": False,
    "unmet_predicates": [],
}


class Refusal(Exception):
    pass


def require(ok, name):
    if not ok:
        raise Refusal(name)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def git(*args):
    result = subprocess.run(  # noqa: S603 - literal read-only git subcommands at all call sites
        [
            "/usr/bin/git",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
        timeout=20,
    )
    require(result.returncode == 0, "git_readback_failed")
    return result.stdout


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
                and (not info.st_mode & 2)
                and (not info.st_mode & 16 or (not strict and str(current) in LEGACY_ENV_DIRECTORIES)),
                "unsafe_opened_directory",
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(path, owners, limit=5000000, strict=True, mode=None):
    path = Path(path)
    parent = directory_fd(path.parent, owners, strict)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_uid in owners
                and (not before.st_mode & 18)
                and (before.st_size <= limit),
                "unsafe_regular_file",
            )
            require(mode is None or stat.S_IMODE(before.st_mode) == mode, "exact_file_mode")
            chunks, size = ([], 0)
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


def environment_payload(m):
    target = m["environment_file"]
    require(type(target) is str and target in ENVIRONMENT_FILES, "closed_environment_target")
    require(type(m["env_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", m["env_sha256"]), "environment_hash_shape")
    parent = directory_fd(Path(m["source"]), (0, m["uid"]))
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


def identity(m):
    require(type(m) is dict and set(m) == FIELDS and m["schema"] == "AcademyCandidateLabIdleInputs.v2", "input_schema")
    require(m["mode"] in {"before", "intermediate", "after"}, "mode")
    require(
        isinstance(m["observation_id"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", m["observation_id"]),
        "observation_id",
    )
    require(type(m["uid"]) is int and m["uid"] > 0, "uid_input")
    require(
        os.getuid() == os.geteuid() == m["uid"] and pwd.getpwuid(os.getuid()).pw_name == "dotmac", "unprivileged_dotmac"
    )
    require(socket.gethostname() == m["hostname"], "hostname")
    require(not (set(os.environ) - {"HOME", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ"}), "minimal_launch_environment")
    for key in ("candidate", "tree"):
        require(isinstance(m[key], str) and re.fullmatch(r"[0-9a-f]{40}", m[key]), key + "_format")
    for key in ("source", "venv", "retained_source"):
        require(isinstance(m[key], str) and Path(m[key]).is_absolute(), key + "_absolute")
        require(str(Path(m[key]).resolve(strict=True)) == m[key], key + "_canonical")
    source, venv = Path(m["source"]), Path(m["venv"])
    require(Path.cwd() == source, "source_cwd")
    require(sys.prefix == str(venv) and sys.base_prefix != sys.prefix, "venv_prefix")
    require(Path(sys.executable).absolute() == venv / "bin/python", "venv_interpreter")
    require(sys.flags.isolated == 1 and sys.dont_write_bytecode, "isolated_no_bytecode_launch")
    for key in ("helper_sha256", "env_sha256", "venv_cfg_sha256", "python_sha256"):
        require(sha(m[key]), key + "_format")
    require(digest(Path(__file__).read_bytes()) == m["helper_sha256"], "helper_hash")
    require(digest((venv / "pyvenv.cfg").read_bytes()) == m["venv_cfg_sha256"], "venv_cfg_pin")
    require(digest(Path(sys.executable).read_bytes()) == m["python_sha256"], "interpreter_pin")
    require(git("rev-parse", "HEAD").decode().strip() == m["candidate"], "git_head")
    require(git("rev-parse", "HEAD^{tree}").decode().strip() == m["tree"], "git_tree")
    require(
        not git("status", "--porcelain", "--untracked-files=all", "--ignore-submodules=all"),
        "source_clean_including_untracked",
    )
    pins = m["source_file_sha256"]
    require(type(pins) is dict and set(pins) == SOURCE_FILES, "source_pin_set")
    for rel, expected in pins.items():
        path = source / rel
        require(path.resolve() == path and path.is_file(), "source_file_regular")
        require(sha(expected), "source_hash_format")
        data = path.read_bytes()
        require(digest(data) == expected and git("show", "HEAD:" + rel) == data, "source_file_pin")
    revisions = m["expected_revisions"]
    require(
        type(revisions) is list
        and bool(revisions)
        and all(isinstance(r, str) and re.fullmatch(r"[A-Za-z0-9_]{1,128}", r) for r in revisions),
        "full_revision_vector_shape",
    )
    require(len(revisions) == len(set(revisions)), "full_revision_vector_unique")
    require(type(m["require_zero"]) is bool, "zero_predicate_type")
    require(
        type(m["max_observation_seconds"]) is int and 1 <= m["max_observation_seconds"] <= 120,
        "bounded_observation_window",
    )
    env_payload = environment_payload(m)
    REPORT.update({key: m[key] for key in FIELDS if key != "schema"})
    REPORT["database"] = "academy"
    REPORT["observed_unix_started"] = time.time()
    return env_payload


def connect_settings(m, env_payload):
    os.environ.clear()
    os.environ.update(HOME=pwd.getpwuid(os.getuid()).pw_dir, PATH=m["venv"] + "/bin:/usr/bin:/bin")
    sys.dont_write_bytecode = True
    # Import dependencies from the pinned venv before introducing product code.
    import psycopg
    from dotenv import dotenv_values
    from sqlalchemy.engine import make_url

    values = dotenv_values(stream=io.StringIO(env_payload.decode("utf-8")), interpolate=False)
    require(bool(values.get("MIGRATION_DATABASE_URL")), "explicit_migration_url_no_fallback")
    os.environ.update(
        {
            key: value
            for key, value in values.items()
            if value is not None and not key.startswith(("PG", "PYTHON", "LD_", "DYLD_"))
        }
    )
    sys.path.insert(0, m["source"])
    from app.config import settings

    require(str(settings.migration_database_url) == values["MIGRATION_DATABASE_URL"], "exact_dotenv_migration_url")
    url = make_url(str(settings.migration_database_url))
    require(url.get_backend_name() == "postgresql" and url.username == "app_admin", "postgresql_app_admin")
    require(url.database == "academy" and not url.query, "academy_database_no_url_options")
    require(bool(url.host) and bool(url.password), "explicit_connection_identity")
    return psycopg.connect(
        host=url.host,
        port=url.port or 5432,
        dbname="academy",
        user="app_admin",
        password=url.password,
        connect_timeout=10,
        application_name="academy_lab_idle_observer",
        options="-c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=3000 -c search_path=pg_catalog",
    )


def readback(conn, m):
    with conn.cursor() as cur:
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        cur.execute("SET LOCAL row_security = off")
        cur.execute(
            "SELECT current_user, session_user, current_database(), current_setting('transaction_read_only'), current_setting('default_transaction_read_only'), current_setting('row_security')"
        )
        session = list(cur.fetchone())
        REPORT["session"] = session
        require(session == ["app_admin", "app_admin", "academy", "on", "on", "off"], "readonly_session_identity")
        cur.execute(
            "SELECT c.relname, c.relkind, pg_get_userbyid(c.relowner), c.relispartition FROM pg_class c WHERE c.oid IN ('public.lab_operations'::regclass, 'public.lab_instances'::regclass) ORDER BY c.relname"
        )
        tables = [list(row) for row in cur.fetchall()]
        REPORT["tables"] = tables
        require(
            tables == [["lab_instances", "r", "app_admin", False], ["lab_operations", "r", "app_admin", False]],
            "ordinary_source_tables_not_views",
        )
        cur.execute(
            "SELECT row_security_active('public.lab_operations'::regclass), row_security_active('public.lab_instances'::regclass)"
        )
        visibility = list(cur.fetchone())
        REPORT["row_security_active"] = dict(zip(("lab_operations", "lab_instances"), visibility, strict=True))
        require(visibility == [False, False], "full_visibility_both_lab_tables")
        cur.execute("SELECT version_num FROM public.alembic_version ORDER BY version_num")
        revisions = [row[0] for row in cur.fetchall()]
        REPORT["revision_vector"] = revisions
        require(revisions == sorted(m["expected_revisions"]), "exact_full_revision_vector")
        cur.execute(
            "WITH observed AS MATERIALIZED (SELECT clock_timestamp() AS at) SELECT at::text, EXTRACT(EPOCH FROM at)::double precision FROM observed"
        )
        REPORT["database_clock_started"], REPORT["database_unix_started"] = cur.fetchone()
        # Both aggregates use one repeatable-read snapshot and no tenant filter.
        # NULL/unrecognized state vocabulary is counted separately and refused.
        cur.execute("""
            WITH operations AS (
                SELECT count(*) AS total,
                    count(*) FILTER (WHERE state IN ('queued','claimed')) AS open,
                    count(*) FILTER (WHERE state IS NULL OR state NOT IN ('queued','claimed','succeeded','failed','cancelled')) AS unrecognized_state,
                    count(*) FILTER (WHERE kind IS NULL OR kind NOT IN ('deploy','destroy','check')) AS unrecognized_kind
                FROM public.lab_operations
            ), instances AS (
                SELECT count(*) AS total,
                    count(*) FILTER (WHERE runtime_presence IN ('present','unknown')) AS occupied,
                    count(*) FILTER (WHERE status IS NULL OR status NOT IN ('queued','provisioning','active','resetting','error','reaped')) AS unrecognized_status,
                    count(*) FILTER (WHERE runtime_presence IS NULL OR runtime_presence NOT IN ('absent','present','unknown')) AS unrecognized_presence,
                    count(*) FILTER (WHERE runtime_presence = 'present') AS present,
                    count(*) FILTER (WHERE runtime_presence = 'unknown') AS unknown
                FROM public.lab_instances
            ) SELECT operations.*, instances.* FROM operations CROSS JOIN instances
        """)
        counts = list(cur.fetchone())
        require(len(counts) == 10 and all(type(value) is int and value >= 0 for value in counts), "bounded_count_shape")
        keys = (
            "operations_total",
            "open_operations_all_tenants",
            "unrecognized_operation_state",
            "unrecognized_operation_kind",
            "instances_total",
            "present_or_unknown_instances_all_tenants",
            "unrecognized_instance_status",
            "unrecognized_runtime_presence",
            "present_instances",
            "unknown_instances",
        )
        REPORT["counts"] = dict(zip(keys, counts, strict=True))
        require(not any(counts[index] for index in (2, 3, 6, 7)), "recognized_state_vocabulary")
        cur.execute(
            "WITH observed AS MATERIALIZED (SELECT clock_timestamp() AS at) SELECT at::text, EXTRACT(EPOCH FROM at)::double precision FROM observed"
        )
        REPORT["database_clock_finished"], REPORT["database_unix_finished"] = cur.fetchone()
        REPORT["observed_unix_finished"] = time.time()
        require(
            0 <= REPORT["observed_unix_finished"] - REPORT["observed_unix_started"] <= m["max_observation_seconds"],
            "observation_window",
        )
        require(
            0 <= REPORT["database_unix_finished"] - REPORT["database_unix_started"] <= m["max_observation_seconds"],
            "database_observation_window",
        )
        REPORT["database_idle"] = counts[1] == counts[5] == 0
        require(
            not m["require_zero"] or REPORT["database_idle"],
            "requested_zero_open_operations_and_present_or_unknown_instances",
        )


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536, "input_size")
        manifest = json.loads(raw, object_pairs_hook=unique_object)
        env = identity(manifest)
        with connect_settings(manifest, env) as conn:
            readback(conn, manifest)
            conn.rollback()
        REPORT["ok"] = True
    except Refusal as exc:
        REPORT["unmet_predicates"].append(str(exc))
    except Exception:
        # Driver/config errors may contain DSNs: never emit messages/tracebacks.
        REPORT["unmet_predicates"].append("unexpected_error_details_suppressed")
    print(json.dumps(REPORT, sort_keys=True))
    return 0 if REPORT["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

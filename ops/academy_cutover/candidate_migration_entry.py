"""Dotmac-only fixed Kernel migration over an existing OIDC baseline. Technical pins are not deployment authority.

Root's separate executor owns genuine approval, fresh zero, one-shot intent,
process-group deadline/custody and mandatory after-catalog proof. JSON stdin
contains no URL, credential, approval assertion, command or migration target.
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

BASELINE = ["a0011_oidc_login_states"]
KERNEL = "0031_rate_limit_buckets"
MIGRATION_STEP = "kernel0031"
KERNEL_PATH = "dotmac_kernel/migrations/versions/20261109_0031_rate_limit_buckets.py"
KERNEL_SHA256 = "6abbbf72b7fefbc9c9a6ace62edbdc2edda6451967b2ab25216b9acc21dbdebd"
HOST = "vmi2490731"
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

# The Academy0011 pin identifies the existing catalog source, never a DDL target.
PINS = {
    "app/migration_cli.py": "06b51da435a8dcd4015c8f0be98f95dcd3c90d3f33470a784bb511cd5bd4ec2a",
    "app/migration_graph.py": "c8384053fd68344f4d34a9bc7a55741b8c15c2ee37e1f171e495c7ef177cb9b3",
    "app/config.py": "38aa06d526cc0d032e29e49b7b9d57e0204d0d141461b76284098fae3f0b8f50",
    "alembic/env.py": "61ab14bc06827aa2c13a649884acf9e266d4b68d84774cfd6195a9dec939ee80",
    "alembic.ini": "46494823e1b0f5507836186914c1596484a49ee4260e54f814713251822aaba6",
    "alembic/versions/a0011_oidc_login_states.py": "21a4b74fe49e4dab6864a4657d2824a6356db5f3315552af51beb787881beaf5",
}
FIELDS = {
    "schema",
    "candidate",
    "tree",
    "source",
    "venv",
    "hostname",
    "uid",
    "database",
    "retained_source",
    "helper_sha256",
    "source_file_sha256",
    "expected_before",
    "environment_file",
    "env_sha256",
    "migration_step",
    "kernel_migration",
}
REPORT = {
    "schema": "AcademyCandidateMigrationReport.v4",
    "ok": False,
    "migration_step": None,
    "target": None,
    "before_revision_vector": None,
    "migration_invoked": False,
    "migration_cli_returned": False,
    "overall_readiness_claimed": False,
    "mandatory_next_phase": "db-after",
    "catalog_after_proven": False,
    "unmet_predicates": [],
    "refusal_sha256": None,
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


def git(source, action, rel=None):
    fixed = {
        "head": ["rev-parse", "HEAD"],
        "tree": ["rev-parse", "HEAD^{tree}"],
        "clean": ["status", "--porcelain", "--untracked-files=no"],
    }
    if action == "file":
        require(rel in PINS, "git_file_allowlist")
        tail = ["show", "HEAD:" + rel]
    else:
        require(action in fixed and rel is None, "git_action_allowlist")
        tail = fixed[action]
    result = subprocess.run(  # noqa: S603 -- literal action allowlist, no shell
        ["/usr/bin/git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *tail],
        cwd=source,
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
    source = Path(m["source"])
    require(git(source, "head").decode().strip() == m["candidate"], "candidate_head")
    require(git(source, "tree").decode().strip() == m["tree"], "candidate_tree")
    require(not git(source, "clean"), "tracked_source_not_clean")
    for rel, expected in PINS.items():
        data = read_file(source / rel, (0, m["uid"]))
        require(digest(data) == expected and git(source, "file", rel) == data, "critical_source_pin")
    # -B prevents writes, not reads of pre-existing pyc; refuse those in source.
    for directory in (source / "app", source / "alembic"):
        for parent, dirs, files in os.walk(directory, followlinks=False):
            require(
                "__pycache__" not in dirs and not any(n.endswith((".pyc", ".pyo")) for n in files),
                "source_bytecode_cache_refused",
            )
            require(not any((Path(parent) / name).is_symlink() for name in dirs), "source_directory_link")


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
        require(digest(raw) == m["env_sha256"], "frozen_env_pin")
        return raw
    finally:
        os.close(parent)


def identity(m):
    require(type(m) is dict and set(m) == FIELDS, "input_schema")
    require(m["schema"] == "AcademyCandidateMigrationInputs.v4", "input_schema_version")
    require(
        sys.platform == "linux" and len(sys.argv) == 1 and sys.flags.isolated == 1 and sys.dont_write_bytecode,
        "isolated_B_no_arguments",
    )
    require(type(m["uid"]) is int and m["uid"] > 0 and os.getuid() == os.geteuid() == m["uid"], "unprivileged_uid")
    user = pwd.getpwuid(os.getuid())
    require(user.pw_name == "dotmac" and user.pw_dir == "/home/dotmac", "dotmac_identity")
    require(socket.gethostname().split(".")[0] == HOST == m["hostname"], "web_hostname")
    for key in ("candidate", "tree"):
        require(type(m[key]) is str and re.fullmatch(r"[0-9a-f]{40}", m[key]), "git_identity_shape")
    source = Path("/srv/academy/releases") / m["candidate"]
    venv = Path("/srv/academy/venvs") / m["candidate"]
    require(
        m["source"] == str(source)
        and m["venv"] == str(venv)
        and m["retained_source"] in RETAINED_SOURCES
        and m["database"] == "academy",
        "fixed_runtime_paths_database",
    )
    for path in (source, venv):
        fd = directory_fd(path, (0, m["uid"]))
        os.close(fd)
    require(
        Path.cwd() == source
        and sys.prefix == str(venv)
        and sys.base_prefix != sys.prefix
        and Path(sys.executable).absolute() == venv / "bin/python",
        "new_source_venv_identity",
    )
    helper = Path("/usr/local/lib/academy-deploy") / m["candidate"] / "candidate_migration_entry.py"
    require(Path(__file__).absolute() == helper, "root_public_helper_location")
    for key in ("helper_sha256", "env_sha256"):
        require(type(m[key]) is str and re.fullmatch(r"[0-9a-f]{64}", m[key]), "hash_shape")
    require(digest(read_file(helper, (0,), mode=0o644)) == m["helper_sha256"], "root_public_helper_pin")
    require(m["migration_step"] == MIGRATION_STEP, "fixed_kernel_migration_step")
    target, before = KERNEL, BASELINE
    require(m["source_file_sha256"] == PINS and m["expected_before"] == before, "frozen_sources_and_full_vector")
    require(not any(n == "app" or n.startswith("app.") for n in sys.modules), "app_preimport_refused")
    check_source(m)
    REPORT.update(
        candidate=m["candidate"],
        tree=m["tree"],
        hostname=HOST,
        environment_file=m["environment_file"],
        helper_sha256=m["helper_sha256"],
        source_file_sha256=PINS,
        expected_before=before,
        migration_step=m["migration_step"],
        target=target,
    )
    check_kernel_migration(m)
    return env_bytes(m)


def check_kernel_cache_free(package, owners):
    # -B prevents writes but still reads existing caches. Inspect without import
    # or following links, including directories not containing the pinned DDL.
    def inspect(fd):
        info = os.fstat(fd)
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid in owners and not info.st_mode & 0o022,
            "kernel_package_directory_custody",
        )
        for name in os.listdir(fd):
            require(
                name != "__pycache__" and not name.endswith((".pyc", ".pyo")),
                "installed_kernel_bytecode_cache_refused",
            )
            child_info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(not stat.S_ISLNK(child_info.st_mode), "kernel_package_symlink_refused")
            if stat.S_ISDIR(child_info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    inspect(child)
                finally:
                    os.close(child)
            else:
                require(
                    stat.S_ISREG(child_info.st_mode) and child_info.st_uid in owners and not child_info.st_mode & 0o022,
                    "kernel_package_regular_file_custody",
                )

    fd = directory_fd(package, owners)
    try:
        inspect(fd)
    finally:
        os.close(fd)


def check_kernel_migration(m):
    # Passive stdlib metadata only, after exact isolated interpreter/venv checks.
    from importlib import metadata

    contract = m["kernel_migration"]
    require(
        type(contract) is dict and set(contract) == {"distribution", "version", "relative_module_path", "sha256"},
        "kernel_contract_fields",
    )
    require(
        contract["distribution"] == "dotmac-kernel"
        and contract["relative_module_path"] == KERNEL_PATH
        and contract["sha256"] == KERNEL_SHA256,
        "kernel_fixed_source_contract",
    )
    version = contract["version"]
    require(
        type(version) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?", version),
        "kernel_frozen_published_version_shape",
    )
    venv = Path(m["venv"])
    site = venv / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    fd = directory_fd(site, (0, m["uid"]))
    os.close(fd)
    check_kernel_cache_free(site / "dotmac_kernel", (0, m["uid"]))
    # Validate fixed distribution metadata paths before metadata reads them.
    infos = [p for p in site.iterdir() if re.fullmatch(r"dotmac_kernel-[A-Za-z0-9_.]+\.dist-info", p.name)]
    require(len(infos) == 1, "kernel_unique_installed_distribution")
    info = infos[0]
    for name in ("METADATA", "RECORD"):
        read_file(info / name, (0, m["uid"]))
    dist = metadata.Distribution.at(info)
    require(
        re.sub(r"[-_.]+", "-", dist.metadata.get("Name", "")).lower() == "dotmac-kernel" and dist.version == version,
        "kernel_actual_installed_name_version",
    )
    files = list(dist.files or [])
    migration_files = [f for f in files if str(f) == KERNEL_PATH]
    metadata_files = [f for f in files if str(f) == info.name + "/METADATA"]
    require(len(migration_files) == len(metadata_files) == 1, "kernel_distribution_file_membership")
    for file in [*migration_files, *metadata_files]:
        located = Path(dist.locate_file(file))
        require(located == site / str(file) and located.is_relative_to(venv), "kernel_file_in_pinned_venv")
        data = read_file(located, (0, m["uid"]))
        if str(file) == KERNEL_PATH:
            require(digest(data) == KERNEL_SHA256, "installed_kernel_reviewed_ddl")
    REPORT["kernel_migration"] = dict(contract)


def configure(m, raw):
    os.environ.clear()
    base = {
        "HOME": "/home/dotmac",
        "PATH": m["venv"] + "/bin:/usr/bin:/bin",
        "USER": "dotmac",
        "LOGNAME": "dotmac",
        "LANG": "C.UTF-8",
    }
    os.environ.update(base)
    sys.dont_write_bytecode = True
    # This exact validated source is necessary for a --no-root venv; -I does
    # not add cwd. There is no caller-selectable additional import location.
    sys.path.insert(0, m["source"])
    from dotenv import dotenv_values

    values = dotenv_values(stream=io.StringIO(raw.decode("utf-8")), interpolate=False)
    unsafe_names = {
        "HOME",
        "PATH",
        "USER",
        "LOGNAME",
        "SHELL",
        "ENV",
        "BASH_ENV",
        "IFS",
        "CDPATH",
        "PERL5LIB",
        "RUBYOPT",
        "NODE_OPTIONS",
        "OPENSSL_CONF",
        "SSLKEYLOGFILE",
    }
    unsafe_prefixes = ("PG", "PYTHON", "LD_", "DYLD_", "GIT_", "PIP_", "POETRY_", "UV_", "BASH_FUNC_")
    os.environ.update(
        {
            k: v
            for k, v in values.items()
            if v is not None and k.upper() not in unsafe_names and not k.upper().startswith(unsafe_prefixes)
        }
    )
    os.environ.update(base)
    from sqlalchemy.engine import make_url

    from app.config import settings

    require(settings.oidc_enabled is False and not settings.oidc_client_secret, "oidc_dark_without_secret")
    raw_url = settings.migration_database_url
    require(
        type(raw_url) is str and bool(raw_url.strip()) and os.environ.get("MIGRATION_DATABASE_URL") == raw_url,
        "explicit_settings_migration_url",
    )
    url = make_url(raw_url)
    require(
        url.get_backend_name() == "postgresql"
        and url.username == "app_admin"
        and url.database == "academy"
        and not url.query,
        "fixed_postgresql_admin_database",
    )
    require(
        bool(url.host)
        and not any(c.isspace() or c in "/,@" for c in url.host)
        and bool(url.password)
        and (url.port is None or 0 < url.port < 65536),
        "explicit_host_password_port",
    )
    # Do NOT stringify a SQLAlchemy URL: its default string masks the password.
    # Canonical alembic/env.py reads this exact original validated string.
    os.environ["MIGRATION_DATABASE_URL"] = raw_url
    require(env_bytes(m) == raw, "env_changed_after_settings")
    return url, raw_url


def before_readonly(url, expected):
    import psycopg

    with psycopg.connect(
        host=url.host,
        port=url.port or 5432,
        dbname=url.database,
        user=url.username,
        password=url.password,
        connect_timeout=10,
        application_name="academy_fixed_migration_before",
        options=(
            "-c default_transaction_read_only=on -c statement_timeout=15000 "
            "-c lock_timeout=3000 -c search_path=pg_catalog"
        ),
    ) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")
            cursor.execute("SELECT current_user,current_database(),current_setting('transaction_read_only')")
            require(cursor.fetchone() == ("app_admin", "academy", "on"), "before_readonly_identity")
            cursor.execute("SELECT version_num FROM public.alembic_version ORDER BY version_num")
            revisions = [row[0] for row in cursor.fetchall()]
            REPORT["before_revision_vector"] = revisions
            require(revisions == expected, "before_exact_full_revision_vector")
        conn.rollback()


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


def main():
    capture = OutputCapture()
    try:
        capture.start()
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536, "stdin_bound")
        m = json.loads(raw, object_pairs_hook=unique_object, parse_constant=no_constant)
        frozen_env = identity(m)
        url, raw_url = configure(m, frozen_env)
        before_readonly(url, BASELINE)
        check_source(m)
        require(
            env_bytes(m) == frozen_env and os.environ.get("MIGRATION_DATABASE_URL") == raw_url,
            "last_migration_inputs_changed",
        )
        check_kernel_migration(m)
        from app.migration_cli import main as migration_main

        REPORT["migration_invoked"] = True
        # Sole literal target. Existing Academy0011 is never replayed.
        migration_main(["upgrade", "0031_rate_limit_buckets"])
        REPORT["migration_cli_returned"] = True
        require(
            env_bytes(m) == frozen_env and os.environ.get("MIGRATION_DATABASE_URL") == raw_url,
            "post_migration_environment_changed",
        )
        check_source(m)
        check_kernel_migration(m)
        REPORT["ok"] = True
    except BaseException as exc:
        reason = str(exc) if isinstance(exc, Refusal) else "unexpected_error_details_suppressed"
        REPORT["unmet_predicates"].append("refused")
        REPORT["refusal_sha256"] = digest(reason.encode("utf-8"))
    finally:
        REPORT["output_capture"] = capture.finish()
    if any(not item["drained"] or item.get("capture_error") for item in REPORT["output_capture"].values()):
        REPORT["ok"] = False
        REPORT["unmet_predicates"].append("output_capture_unconfirmed")
    print(json.dumps(REPORT, sort_keys=True))
    return 0 if REPORT["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

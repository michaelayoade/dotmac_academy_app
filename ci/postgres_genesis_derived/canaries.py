"""Hosted canaries for the reviewed derived image; real owner, real Docker, booleans only, no digest declared."""

from __future__ import annotations

import argparse
import ast
import ctypes
import hashlib
import importlib.util
import itertools
import json
import mmap
import os
import re
import secrets
import select
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

PREFIX = "ACADEMY_GENESIS_DERIVED_CANARY_JSON "
BINARY = "/usr/lib/postgresql/16/bin/postgres"
OWNER_SOURCE = "app/maintenance/retained_hosted_genesis.py"
LOCAL = "localhost/academy-genesis"
IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE, IN_CLOSE_NOWRITE, IN_OPEN = 0x2, 0x4, 0x8, 0x10, 0x20
IN_MOVED_FROM, IN_MOVED_TO, IN_CREATE, IN_DELETE = 0x40, 0x80, 0x100, 0x200
WITNESS_MASK = (
    IN_OPEN
    | IN_CLOSE_NOWRITE
    | IN_CLOSE_WRITE
    | IN_MODIFY
    | IN_ATTRIB
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
)
MUTATION_MASK = IN_CLOSE_WRITE | IN_MODIFY | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE
PID = "postmaster.pid"
HBA = "local all postgres scram-sha-256\nlocal all all reject\nhost all all all reject\n"
INITDB = "--auth-local=scram-sha-256 --auth-host=reject --locale=en_US.utf8 --encoding=UTF8"


class Refused(Exception):
    """No tool or server text escapes."""


def need(condition):
    if not condition:
        raise Refused


def sibling(name):
    path = Path(__file__).resolve().parent / (name + ".py")
    spec = importlib.util.spec_from_file_location("academy_derived_" + name, path)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def docker(*argv, timeout=120, merge=False, maximum=16777216):
    result = subprocess.run(  # noqa: S603 -- fixed Docker argv, no shell; stderr never emitted
        ["/usr/bin/docker", *argv],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merge else subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )
    need(len(result.stdout) <= maximum)
    return result.returncode, result.stdout


def docker_ok(*argv, **keywords):
    code, output = docker(*argv, **keywords)
    need(code == 0)
    return output


def owner_arguments(root):
    """The owner's exact server arguments, read from its committed source rather than retyped."""
    tree = ast.parse((root / OWNER_SOURCE).read_text())
    found = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Attribute)
        and node.targets[0].attr == "args"
        and isinstance(node.targets[0].value, ast.Name)
        and node.targets[0].value.id == "self"
        and isinstance(node.value, ast.Tuple)
    ]
    need(len(found) == 1)
    values = ast.literal_eval(found[0].value)
    need(type(values) is tuple and all(type(value) is str for value in values) and values[0] == "postgres")
    return values


class Witness:
    """Separate inotify fd; sees opens and nowrite closes that the owner's own mask omits."""

    def __init__(self, directory):
        libc = ctypes.CDLL(None, use_errno=True)
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        need(self.fd >= 0)
        need(libc.inotify_add_watch(self.fd, os.fsencode(directory), WITNESS_MASK) >= 0)
        self.events: list[tuple[float, int, bytes]] = []

    def poll(self, timeout):
        if self.fd < 0 or not select.select([self.fd], [], [], timeout)[0]:
            return
        data = os.read(self.fd, 65536)
        now = time.monotonic()
        offset = 0
        while offset + 16 <= len(data):
            _descriptor, mask, _cookie, length = struct.unpack_from("=iIII", data, offset)
            name = data[offset + 16 : offset + 16 + length].split(b"\0")[0]
            self.events.append((now, mask, name))
            offset += 16 + length

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def on(self, name, mask):
        return [stamp for stamp, value, label in self.events if label == name and value & mask]


def pair_times(witness):
    """Times of OPEN events on postmaster.pid that are followed by a CLOSE_NOWRITE."""
    closes = witness.on(PID.encode(), IN_CLOSE_NOWRITE)
    return [stamp for stamp in witness.on(PID.encode(), IN_OPEN) if any(close >= stamp for close in closes)]


def wait_for(witness, ready, bound):
    deadline = time.monotonic() + bound
    while time.monotonic() < deadline:
        witness.poll(0.5)
        if ready():
            return True
    return False


class Raw:
    """Harness-owned server using the owner's exact docker create argv, without any owner."""

    def __init__(self, image, arguments):
        self.image, self.arguments = image, arguments
        self.name = "academy-c58-" + secrets.token_hex(12)
        self.container: str | None = None
        self.home: Path | None = None

    def __enter__(self):
        try:
            return self.start()
        except BaseException:
            self.__exit__()
            raise

    def start(self):
        self.home = Path(tempfile.mkdtemp(prefix="academy-c58-raw-", dir="/tmp")).resolve(strict=True)
        for name in ("socket", "data", "control"):
            (self.home / name).mkdir(mode=0o700)
        self.secret = secrets.token_urlsafe(48)
        for name, text in (("hba", HBA), ("password", self.secret)):
            descriptor = os.open(self.home / "control" / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(text)
        self.container = (
            docker_ok(
                "create",
                "--name",
                self.name,
                "--pull=never",
                "--platform",
                "linux/amd64",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=32m",  # noqa: S108 -- private container tmpfs
                "--mount",
                f"type=bind,src={self.home / 'socket'},dst=/var/run/postgresql",
                "--mount",
                f"type=bind,src={self.home / 'data'},dst=/var/lib/postgresql/data",
                "--mount",
                f"type=bind,src={self.home / 'control'},dst=/academy-control,readonly",
                "--env",
                "POSTGRES_PASSWORD_FILE=/academy-control/password",
                "--env",
                "POSTGRES_DB=postgres",
                "--env",
                "POSTGRES_INITDB_ARGS=" + INITDB,
                self.image,
                *self.arguments,
            )
            .decode("ascii")
            .strip()
        )
        need(re.fullmatch(r"[a-f0-9]{64}", self.container) is not None)
        docker_ok("start", self.container)
        for _ in range(600):
            logs = self.logs()
            if b"PostgreSQL init process complete" in logs and logs.count(b"database system is ready to accept") >= 2:
                lines = (
                    (self.home / "data" / PID).read_bytes().split(b"\n") if (self.home / "data" / PID).exists() else []
                )
                if len(lines) >= 8 and lines[7] == b"ready":
                    return self
            time.sleep(0.1)
        raise Refused

    def logs(self):
        return docker_ok("logs", self.name, merge=True, maximum=16777216)

    def running(self):
        return docker_ok("inspect", "--format", "{{.State.Running}}", self.name).strip() == b"true"

    def __exit__(self, *_exc):
        docker("rm", "--force", "--volumes", self.name)
        if self.home is not None:
            shutil.rmtree(self.home, ignore_errors=True)
        return False


def wait_exit(raw, bound):
    deadline = time.monotonic() + bound
    while time.monotonic() < deadline:
        if not raw.running():
            return True
        time.sleep(1)
    return False


def home_of(holder):
    need(holder.home is not None)
    return holder.home


def raw_pid_case(image, arguments, kind):
    with Raw(image, arguments) as raw:
        path = home_of(raw) / "data" / PID
        original = path.read_bytes()
        lines = original.split(b"\n")
        pid = int(lines[0])
        if kind == "wrong":
            lines[0] = str(pid + 1).encode()
            changed = b"\n".join(lines)
            descriptor = os.open(path, os.O_WRONLY)
            os.pwrite(descriptor, changed, 0)
            os.ftruncate(descriptor, len(changed))
            os.close(descriptor)
        else:
            os.unlink(path)
        exited = wait_exit(raw, 75)
        logs = raw.logs()
    shutdown = b"performing immediate shutdown because data directory lock file is invalid" in logs
    if kind == "wrong":
        text = f'lock file "postmaster.pid" contains wrong PID: {pid + 1} instead of {pid}'.encode()
    else:
        text = b'could not open file "postmaster.pid": No such file or directory'
    return {"exited_within_75s": exited, "expected_log_line": text in logs, "immediate_shutdown_line": shutdown}


def raw_pg_config(image, arguments):
    import psycopg

    with Raw(image, arguments) as raw:
        home = home_of(raw)
        with psycopg.connect(
            host=str(home / "socket"), user="postgres", password=raw.secret, dbname="postgres", connect_timeout=5
        ) as connection:
            rows = connection.execute("SELECT name, setting FROM pg_config ORDER BY name").fetchall()
            version = connection.execute("SELECT version()").fetchone()[0]  # type: ignore[index]
            collation = connection.execute(
                "SELECT datcollversion FROM pg_database WHERE datname = 'postgres'"
            ).fetchone()[0]  # type: ignore[index]
    return [list(row) for row in rows], version, collation


def declaration(hosted, image):
    prefix = "academy_retained_environment_"

    def purpose(label):
        values = {
            "target_database": "c58_" + label + "_" + secrets.token_hex(6),
            "setup_session": "postgres",
            "service_image": image,
            "server_version_num": 160015,
            "encoding": "UTF8",
            "locale_provider": "c",
            "lc_collate": "en_US.utf8",
            "lc_ctype": "en_US.utf8",
            "icu_locale": None,
            "collation_version": "2.41",
            "actual_collation_version": "2.41",
            "extension_versions": (("plpgsql", "1.0"),),
        }
        return {prefix + key: value for key, value in values.items()}

    settings = {
        "image": image,
        "platform": "linux/amd64",
        "environment": purpose("environment"),
        "history": purpose("history"),
        "assembly": purpose("assembly"),
    }
    return hosted.declaration_from_settings(settings)


def refuses(hosted, owner):
    try:
        with owner.replay_connection():
            return False
    except hosted.HostedGenesisRefused:
        return True


def extract_layout(archive, destination, assemble):
    """Name-allowlisted extraction; every blob must hash to its own file name."""
    facts = assemble.archive_facts(archive)
    with tarfile.open(archive, "r") as source:
        for member in source:
            name = member.name.rstrip("/")
            if member.isdir():
                need(name in ("blobs", "blobs/sha256"))
                (destination / name).mkdir(exist_ok=True)
                continue
            need(member.isreg() and (name in ("oci-layout", "index.json") or assemble.BLOB.fullmatch(name) is not None))
            stream = source.extractfile(member)
            need(stream is not None)
            hashed = hashlib.sha256()
            with open(destination / name, "xb") as out:
                while chunk := stream.read(1048576):  # type: ignore[union-attr]
                    hashed.update(chunk)
                    out.write(chunk)
            if name.startswith("blobs/"):
                need(name.rsplit("/", 1)[1] == hashed.hexdigest())
    return facts


def http(url, method="GET"):
    request = urllib.request.Request(url, method=method)  # noqa: S310 -- fixed loopback URL
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, b""


def registry_pull(workspace, replica_archive, assemble, builder, base_layers, images):
    """Preflight, serve the reviewed layout read-only on loopback, pull, verify, and tear the server down."""
    report: dict[str, Any] = {}
    listing = subprocess.run(  # noqa: S603 -- fixed argv
        ["/usr/bin/ss", "-H", "-ltn"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=30
    ).stdout.decode()
    need(not any(re.search(r"[:\]]80$", line.split()[3]) for line in listing.splitlines() if len(line.split()) >= 4))
    hosts = subprocess.run(  # noqa: S603 -- fixed argv
        ["/usr/bin/getent", "ahosts", "localhost"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    ).stdout.decode()
    need("127.0.0.1" in hosts)
    recorded = {"localhost_ipv6_present": "::1" in hosts}
    cidrs = json.loads(docker_ok("info", "--format", "{{json .RegistryConfig.InsecureRegistryCIDRs}}"))
    need("127.0.0.0/8" in cidrs)
    layout = workspace / "layout"
    layout.mkdir(mode=0o755)
    for relative in ("blobs", "blobs/sha256"):
        (layout / relative).mkdir(exist_ok=True)
    facts = extract_layout(replica_archive, layout, assemble)
    manifest = facts["manifest_digest"]
    scripts = workspace / "registry-app"
    scripts.mkdir(mode=0o755)
    shutil.copyfile(Path(__file__).resolve().parent / "static_registry.py", scripts / "static_registry.py")
    name = "academy-c58-registry-" + secrets.token_hex(8)
    docker_ok(
        "run",
        "--detach",
        "--name",
        name,
        "--pull=never",
        "--network",
        "bridge",
        "--publish",
        "127.0.0.1:80:8080",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65534:65534",
        "--mount",
        f"type=bind,src={layout},dst=/srv,readonly",
        "--mount",
        f"type=bind,src={scripts},dst=/app,readonly",
        "--entrypoint",
        "/usr/bin/python3",
        builder,
        "-I",
        "/app/static_registry.py",
    )
    try:
        for _ in range(100):
            try:
                if http("http://127.0.0.1:80/v2/")[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.2)
        else:
            raise Refused
        status, served = http(f"http://127.0.0.1:80/v2/academy-genesis/manifests/{manifest}")
        report["manifest_bytes_equal_layout"] = (
            status == 200 and served == (layout / "blobs/sha256" / manifest.removeprefix("sha256:")).read_bytes()
        )
        report["unknown_path_404"] = http("http://127.0.0.1:80/v2/academy-genesis/manifests/latest")[0] == 404
        report["post_405"] = http("http://127.0.0.1:80/v2/", "POST")[0] == 405
        reference = f"{LOCAL}@{manifest}"
        images["derived"] = reference
        docker_ok("pull", "--platform", "linux/amd64", reference, timeout=900)
        identity = json.loads(
            docker_ok(
                "image",
                "inspect",
                "--format",
                '{"Id":{{json .Id}},"Repo":{{json .RepoDigests}},"Layers":{{json .RootFS.Layers}}}',
                reference,
            )
        )
        report["image_id_equals_config"] = identity["Id"] == facts["config_digest"]
        report["repo_digest_present"] = reference in identity["Repo"]
        report["rootfs_is_base_plus_new"] = identity["Layers"] == [*base_layers, facts["layer_diff_id"]]
    finally:
        docker("rm", "--force", "--volumes", name)
    return reference, report, recorded


def run_cases(arguments, common, assemble, lock, outputs, base_binary, root, workspace, images, state):
    sys.path.insert(0, str(root))
    from app.maintenance import retained_hosted_genesis as hosted

    results: dict[str, Any] = {}
    builder = lock["c56"]["builder_config_id"]
    # Registered before the load: a timed-out load may still have created the image.
    images["builder"] = builder
    state["builder_load_uncertain"] = True
    docker_ok("load", "--input", str(Path(arguments.c56) / "output/builder.docker.tar"), timeout=900)
    state["builder_load_uncertain"] = False
    need(json.loads(docker_ok("image", "inspect", "--format", "{{json .Id}}", builder)) == builder)
    docker_ok("pull", "--platform", "linux/amd64", common.BASE, timeout=900)
    base_info = json.loads(
        docker_ok("image", "inspect", "--format", '{"Id":{{json .Id}},"Layers":{{json .RootFS.Layers}}}', common.BASE)
    )
    need(base_info["Id"] == common.CONFIG and len(base_info["Layers"]) == 14)
    reference, registry, recorded = registry_pull(
        workspace, Path(arguments.derived) / "output" / common.ARCHIVE, assemble, builder, base_info["Layers"], images
    )
    results["registry"] = {"passed": all(registry.values()), **registry, "recorded": recorded}
    base_ref = common.BASE
    server_arguments = owner_arguments(root)

    def case(label, function):
        try:
            detail = function()
            passed = all(value is True for value in detail.values() if type(value) is bool)
            results[label] = {"passed": passed, **detail}
        except Exception as error:
            results[label] = {"passed": False, "error": type(error).__name__}

    def in_image(image, label, *command):
        name = "academy-c58-" + label + "-" + secrets.token_hex(6)
        return docker_ok(
            "run", "--rm", "--name", name, "--pull=never", "--platform", "linux/amd64", "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534",
            "--entrypoint", command[0], image, *command[1:],
        )  # fmt: skip

    def k0():
        versions = [in_image(i, "ver", BINARY, "--version") for i in (reference, base_ref)]
        digests = [in_image(i, "sha", "/usr/bin/sha256sum", BINARY).split()[0].decode() for i in (reference, base_ref)]
        stats = [
            in_image(i, "stat", "/usr/bin/stat", "-c", "%a %u %g %h", BINARY).decode().split()
            for i in (reference, base_ref)
        ]
        expected = [f"{base_binary['mode']:o}", str(base_binary["uid"]), str(base_binary["gid"])]
        return {
            "version_stdout_equal": versions[0] == versions[1] and bool(versions[0]),
            "derived_sha_equals_payload": digests[0] == outputs["postgres_sha256"],
            "base_sha_equals_preflight": digests[1] == base_binary["sha256"],
            "stat_equal": stats[0] == stats[1] and len(stats[0]) == 4,
            "base_stat_equals_preflight": stats[1][:3] == expected,
        }

    case("K0_identity", k0)
    derived_declaration = declaration(hosted, reference)
    base_declaration = declaration(hosted, base_ref)

    def lifecycle(owner, witness_seconds):
        witness = Witness(home_of(owner) / "data")
        try:
            if witness_seconds:
                wait_for(witness, lambda: len(pair_times(witness)) >= 3, witness_seconds)
        finally:
            witness.close()
        return witness

    def success_path(owner):
        with owner.replay_connection() as connection:
            connection.exec_driver_sql("SELECT 1")
            connection.commit()
        with owner.coordinator_connection() as connection:
            root_transaction = connection.begin()
            owner.bind_root(connection)
            owner.verify(connection, owner.expected)
            clean = owner.poisoned is False
            root_transaction.rollback()
        return clean

    def k1():
        with hosted.disposable_genesis(derived_declaration, purpose="environment") as owner:
            name, home = owner.name, home_of(owner)
            lifecycle(owner, 0)
            ok = success_path(owner)
            lines = (home / "data" / PID).read_bytes().split(b"\n")
        gone = docker_ok("ps", "--all", "--quiet", "--filter", f"name=^/{name}$").strip() == b""
        return {
            "owner_path_ok": ok,
            "pid_line_2": lines[1] == b"/var/lib/postgresql/data",
            "pid_line_8_ready": lines[7] == b"ready",
            "container_removed": gone,
            "home_removed": not home.exists(),
        }

    case("K1_startup_status_cleanup", k1)

    def k2():
        with hosted.disposable_genesis(derived_declaration, purpose="environment") as owner:
            witness = lifecycle(owner, 240)
            times = pair_times(witness)
            gaps = [later - earlier for earlier, later in itertools.pairwise(times)]
            quiet = not any(mask & MUTATION_MASK for _stamp, mask, _name in witness.events)
            ok = success_path(owner)
            return {
                "three_open_close_pairs": len(times) >= 3,
                "spacing_55_to_75": bool(gaps) and all(55 <= gap <= 75 for gap in gaps),
                "no_mutation_events": quiet,
                "owner_path_ok": ok,
            }

    case("K2_periodic_recheck_strict_owner", k2)

    def k2c():
        with hosted.disposable_genesis(base_declaration, purpose="environment") as owner:
            witness = Witness(home_of(owner) / "data")
            try:
                wait_for(witness, lambda: len(witness.on(PID.encode(), IN_OPEN)) >= 3, 240)
            finally:
                witness.close()
            raised = False
            try:
                with owner.replay_connection():
                    pass
            except hosted.HostedGenesisRefused as error:
                raised = str(error) == "Hosted resource watch refused"
            return {
                "three_opens": len(witness.on(PID.encode(), IN_OPEN)) >= 3,
                "close_write_seen": len(witness.on(PID.encode(), IN_CLOSE_WRITE)) >= 1,
                "no_close_nowrite": len(witness.on(PID.encode(), IN_CLOSE_NOWRITE)) == 0,
                "watch_refusal": raised,
                "watch_event_exact": owner._watch_event == (4, 13, IN_CLOSE_WRITE, False),
            }

    case("K2c_negative_control_base", k2c)

    def pid_pair(kind):
        pair = [raw_pid_case(i, server_arguments, kind) for i in (reference, base_ref)]
        return {
            "derived_all": all(pair[0].values()),
            "base_all": all(pair[1].values()),
            "same_booleans": pair[0] == pair[1],
        }

    case("K3_wrong_pid", lambda: pid_pair("wrong"))
    case("K4_missing_pid", lambda: pid_pair("missing"))

    def tamper(kind, event):
        with hosted.disposable_genesis(derived_declaration, purpose="environment") as owner:
            path = home_of(owner) / "data" / PID
            original = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
            if kind == "write":
                descriptor = os.open(path, os.O_WRONLY)
                os.pwrite(descriptor, original, 0)
                os.close(descriptor)
            elif kind == "chmod":
                os.chmod(path, 0o400)
                os.chmod(path, mode)
            elif kind == "rename":
                moved = path.with_name(PID + ".c58")
                os.rename(path, moved)
                os.rename(moved, path)
            else:
                descriptor = os.open(path, os.O_RDWR)
                mapped = mmap.mmap(descriptor, 0, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
                os.close(descriptor)
                first = mapped[0]
                mapped[0] = first ^ 0xFF
                mapped[0] = first
                mapped.flush()
                mapped.close()
            first_refusal = refuses(hosted, owner)
            second_refusal = refuses(hosted, owner)
            return {
                "first_call_refused": first_refusal,
                "sticky_second_call_refused": second_refusal,
                "watch_event_exact": owner._watch_event == (4, 13, event, False),
                "bytes_restored": path.read_bytes() == original and stat.S_IMODE(path.stat().st_mode) == mode,
            }

    case("K5_same_byte_write", lambda: tamper("write", IN_MODIFY))
    case("K6_chmod", lambda: tamper("chmod", IN_ATTRIB))
    case("K7_rename", lambda: tamper("rename", IN_MOVED_FROM))
    case("K8_mmap_write_then_repair", lambda: tamper("mmap", IN_CLOSE_WRITE))

    def k9():
        left = raw_pg_config(reference, server_arguments)
        right = raw_pg_config(base_ref, server_arguments)
        return {
            "pg_config_rows_equal": left[0] == right[0] and len(left[0]) > 10,
            "collation_version_2_41_both": left[2] == "2.41" and right[2] == "2.41",
            "row_count": len(left[0]),
            "pg_config_sha256": hashlib.sha256(json.dumps(left[0]).encode()).hexdigest(),
            "version_derived": left[1],
            "version_base": right[1],
            "version_strings_equal_review_item": left[1] == right[1],
        }

    case("K9_pg_config_equality", k9)
    return results


def cleanup(images, state):
    for image in images.values():
        docker("image", "rm", "--force", image)
    names = docker("ps", "--all", "--format", "{{.Names}}")[1].decode().split()
    leftovers = [name for name in names if name.startswith(("academy-genesis-", "academy-c58-"))]
    for name in leftovers:
        docker("rm", "--force", "--volumes", name)
    remaining = [
        name
        for name in docker("ps", "--all", "--format", "{{.Names}}")[1].decode().split()
        if name.startswith(("academy-genesis-", "academy-c58-"))
    ]
    directories = [str(p) for p in Path("/tmp").glob("academy-genesis-*")] + [  # noqa: S108
        str(p)
        for p in Path("/tmp").glob("academy-c58-*")  # noqa: S108
    ]
    gone = all(docker("image", "inspect", image)[0] != 0 for image in images.values())
    return {
        "passed": not leftovers
        and not remaining
        and not directories
        and gone
        and not state.get("builder_load_uncertain"),
        "leftover_containers": bool(leftovers) or bool(remaining),
        "leftover_directories": bool(directories),
        "images_removed": gone,
    }


def canary(arguments):
    common = sibling("build_derived")
    assemble = sibling("assemble_oci")
    compare = sibling("compare_ab")
    commit, ids, checked, contents, _environment = common.guards(common.OWNED[9])
    lock, receipt = common.checked_lock(contents)
    out = Path(arguments.out)
    need(not out.exists())
    out.mkdir(mode=0o755)
    root = Path.cwd()
    public: dict[str, Any] = {
        "status": "UNQUALIFIED_DERIVED_CANARIES_INCOMPLETE",
        "commit": commit,
        "run_id": ids["GITHUB_RUN_ID"],
        "run_attempt": ids["GITHUB_RUN_ATTEMPT"],
        "committed_sources": checked,
        "derived_runtime_image_digest": None,
        "admission_digest": None,
        "FRESH_CANONICAL_SHA256": None,
    }
    results: dict[str, Any] = {}
    images: dict[str, str] = {}
    state: dict[str, bool] = {}
    try:
        common.verify_c56(Path(arguments.c56), lock, receipt)
        outputs, replica = compare.read_side(arguments.derived, "a", common, assemble)
        need(replica["commit"] == commit and replica["run_id"] == ids["GITHUB_RUN_ID"])
        need(replica["committed_sources"] == checked)
        public["candidate_manifest_digest"] = outputs["manifest_digest"]
        base_binary = replica["base_binary"]
        with tempfile.TemporaryDirectory(prefix="academy-c58-harness-", dir="/tmp") as workspace:
            results = run_cases(
                arguments, common, assemble, lock, outputs, base_binary, root, Path(workspace), images, state
            )
    except Exception as error:
        public["failure"] = {"kind": "canary_harness_refused", "type": type(error).__name__}
    finally:
        public["K10_cleanup"] = cleanup(images, state)
    public["cases"] = results
    cases_ok = bool(results) and all(value.get("passed") is True for value in results.values())
    if cases_ok and public["K10_cleanup"]["passed"] and "failure" not in public:
        public["status"] = "UNQUALIFIED_DERIVED_CANARIES_PASSED"
    (out / "canary-receipt.json").write_text(json.dumps(public, sort_keys=True, indent=2) + "\n")
    encoded = json.dumps(public, ensure_ascii=True, separators=(",", ":"))
    need(len((PREFIX + encoded + "\n").encode()) <= 196608)
    print(PREFIX + encoded)
    return 0 if public["status"] == "UNQUALIFIED_DERIVED_CANARIES_PASSED" else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--c56", required=True)
    parser.add_argument("--derived", required=True)
    parser.add_argument("--out", required=True)
    return canary(parser.parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print(PREFIX + '{"status":"UNQUALIFIED_DERIVED_CANARIES_INCOMPLETE","phase":"hosted_guard_or_bounded_failure"}')
        raise SystemExit(1) from None

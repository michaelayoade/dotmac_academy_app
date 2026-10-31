"""Hosted derived build coordinator: bind the C56 artifact, build one payload, assemble one layer. Declares nothing."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

BASE = "postgres@sha256:b95b87e93ceb7594715d5c71fb6e09f6fc878851ab537735d617325eb9ba8b1b"
CONFIG = "sha256:74d436cb49d3398cf7b5d7b33635d43623d9e4da4b93c22db453f7d5d81181b1"
OWNED = (
    ".github/workflows/genesis-postgres-derived-build.yml",
    "ci/postgres_genesis_derived/derived-build-lock.json",
    "ci/postgres_genesis_derived/recheck-o-rdonly.diff",
    "ci/postgres_genesis_derived/academy-backend.mk",
    "ci/postgres_genesis_derived/build_derived.py",
    "ci/postgres_genesis_derived/in_builder_build.py",
    "ci/postgres_genesis_derived/assemble_oci.py",
    "ci/postgres_genesis_derived/compare_ab.py",
    "ci/postgres_genesis_derived/static_registry.py",
    "ci/postgres_genesis_derived/canaries.py",
    "tests/test_genesis_derived_static.py",
    "ci/postgres_genesis_derived/canaries-requirements.txt",
)
C56_OWNED = {
    "ci/postgres_genesis/prepare_build_inputs.py": "prepare_build_inputs.py",
    "ci/postgres_genesis/acquire_build_inputs.sh": "acquire_build_inputs.sh",
    "ci/postgres_genesis/inspect_build_source.py": "inspect_build_source.py",
    "ci/postgres_genesis/build-inputs-lock.json": "build-inputs-lock.json",
    ".github/workflows/genesis-postgres-build-inputs.yml": "genesis-postgres-build-inputs.yml",
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
CID = re.compile(rb"[0-9a-f]{64}\n?", re.ASCII)
PREFIX = "ACADEMY_GENESIS_DERIVED_BUILD_JSON "
CLAIM = (
    "Two isolated executions of the frozen recipe produced identical outputs; custom Genesis-only build; "
    "not a reproduction of the original PGDG binary."
)
HUB_HOSTS = (
    "auth.docker.io",
    "registry-1.docker.io",
    "production.cloudflare.docker.com",
    "production.cloudfront.docker.com",
)
ARTIFACT_DIR = "ci/postgres_genesis_derived/derived-artifacts"
ARCHIVE = "academy-genesis-postgres16-oci.tar"
BUILDER_TMPFS = {
    "/tmp": "rw,nosuid,nodev,size=512m",  # noqa: S108 -- container-private tmpfs
    "/var/lib/postgresql/data": "rw,nosuid,nodev,noexec,size=1m",
}
PHASES = frozenset(
    (
        "hosted_guard",
        "lock_binding",
        "c56_binding",
        "input_staging",
        "base_blob_fetch",
        "builder_load",
        "payload_build",
        "oci_assembly",
        "host_verification",
        "artifact_manifest",
        "complete",
    )
)


REVIEW_PLACEHOLDER = "PLACEHOLDER_S1_REVIEW_BYTES_NOT_YET_PROVIDED"
REFUSED_HOSTS: list[str] = []


class Refused(Exception):
    """No tool or remote exception text escapes."""


def need(condition):
    if not condition:
        raise Refused


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, environment, *, timeout=300, maximum=16777216):
    result = subprocess.run(  # noqa: S603 -- fixed Docker/git commands and validated owned identities
        argv,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )
    need(len(result.stdout) <= maximum and result.returncode == 0)
    return result.stdout


def read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum)
        data = stream.read(maximum + 1)
    need(len(data) == info.st_size)
    return data


def file_record(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    hashed = hashlib.sha256()
    total = 0
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum)
        while chunk := stream.read(1048576):
            total += len(chunk)
            need(total <= maximum)
            hashed.update(chunk)
    need(total == info.st_size)
    return {"sha256": hashed.hexdigest(), "bytes": total}


def sibling(name):
    path = Path(__file__).resolve().parent / (name + ".py")
    spec = importlib.util.spec_from_file_location("academy_derived_" + name, path)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def guards(entry):
    # No artifact directory, temporary home, Docker invocation or HTTP request precedes this gate.
    need(os.environ.get("CI") == "true" and os.environ.get("GITHUB_ACTIONS") == "true")
    need(os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64")
    need(platform.system() == "Linux" and platform.machine() == "x86_64")
    need(os.environ.get("GITHUB_REPOSITORY") == "michaelayoade/dotmac_academy_app")
    commit = os.environ.get("GITHUB_SHA", "")
    need(re.fullmatch(r"[0-9a-f]{40}", commit, flags=re.ASCII) is not None)
    need(
        not any(
            os.environ.get(key)
            for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_TLS")
        )
    )
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TZ") if key in os.environ}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    head = run(["git", "rev-parse", "HEAD"], environment)
    need(re.fullmatch(rb"[0-9a-f]{40}\n?", head) is not None and head.rstrip(b"\n").decode() == commit)
    need(Path(sys.argv[0]).resolve() == (Path.cwd() / entry).resolve())
    checked, contents = {}, {}
    for relative in OWNED:
        blob = run(["git", "cat-file", "blob", commit + ":" + relative], environment, maximum=16777216)
        actual = read(Path(relative), 16777216)
        need(actual == blob)
        checked[relative] = {"sha256": sha(actual), "bytes": len(actual)}
        contents[relative] = actual
    run_ids = {key: os.environ.get(key, "") for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    need(all(re.fullmatch(r"[1-9][0-9]{0,19}", value, flags=re.ASCII) is not None for value in run_ids.values()))
    return commit, run_ids, checked, contents, environment


def changelog_epoch(data):
    match = re.search(rb"(?m)^ -- .*?  (\S.*)$", data)
    need(match is not None)
    stamp = parsedate_to_datetime(match.group(1).decode("ascii"))  # type: ignore[union-attr]
    need(stamp.tzinfo is not None)
    return int(stamp.timestamp())


def checked_lock(contents):
    lock = json.loads(contents[OWNED[1]])
    need(lock["schema"] == "academy-genesis-derived-build-lock-v1")
    need(lock["status"] == "UNQUALIFIED_DERIVED_BUILD_RECIPE" and lock["compile_permitted"] is True)
    need(lock["base"] == BASE and lock["base_config"] == CONFIG and lock["platform"] == "linux/amd64")
    need(lock["repository"] == "michaelayoade/dotmac_academy_app")
    need(
        all(
            lock[name] is None
            for name in ("derived_runtime_image_digest", "admission_digest", "FRESH_CANONICAL_SHA256")
        )
    )
    c56 = lock["c56"]
    need(sha(c56["receipt_utf8"].encode()) == c56["receipt_sha256"])
    need(c56["receipt_sha256"] == "3860f12423e20778d3b3fbdc1c32803661acc2e3386795881d3c7888eda76e3b")
    # The S1 independent review bytes are a required pinned constant; the placeholder fails closed.
    need(type(c56["review_utf8"]) is str and type(c56["review_sha256"]) is str)
    need(c56["review_utf8"] != REVIEW_PLACEHOLDER and re.fullmatch(r"[0-9a-f]{64}", c56["review_sha256"]) is not None)
    need(sha(c56["review_utf8"].encode()) == c56["review_sha256"])
    need(type(json.loads(c56["review_utf8"])) is dict)
    receipt = json.loads(c56["receipt_utf8"])
    need(receipt["status"] == "UNQUALIFIED_BUILD_INPUTS_PREPARED" and receipt["cleanup_uncertain"] is False)
    need(receipt["run_id"] == str(c56["run_id"]) and receipt["run_attempt"] == str(c56["attempt"]))
    need(
        receipt["commit"] == c56["commit"] and receipt["artifact_manifest"]["sha256"] == c56["artifact_manifest_sha256"]
    )
    need(receipt["builder_archive"] == {"sha256": c56["builder_archive_sha256"], "bytes": c56["builder_archive_bytes"]})
    need(receipt["builder_config_id"] == c56["builder_config_id"])
    need(len(receipt["source_inventory"]["configure_argv"]) == 61)
    need(len(receipt["source_inventory"]["ordered_patches"]) == 11)
    need(type(lock["source_date_epoch"]) is int and lock["source_date_epoch"] > 0)
    guard = lock["patch_guard"]
    need(guard["diff_sha256"] == sha(contents[OWNED[2]]) and guard["diff_bytes"] == len(contents[OWNED[2]]))
    need(lock["backend_makefile"]["sha256"] == sha(contents[OWNED[3]]))
    return lock, receipt


def verify_c56(root, lock, receipt):
    """Fail-closed binding of the downloaded C56 artifact to the reviewed bytes."""
    c56 = lock["c56"]
    need(root.is_dir() and not root.is_symlink())
    raw = read(root / "artifact-manifest.json", 16777216)
    need(sha(raw) == c56["artifact_manifest_sha256"] and len(raw) == c56["artifact_manifest_bytes"])
    manifest = json.loads(raw)
    found = {}

    def refuse_walk(error):
        raise Refused from None

    for directory, directories, files in root.walk(on_error=refuse_walk):
        for name in directories:
            need(not (directory / name).is_symlink())
        for name in files:
            need(not (directory / name).is_symlink())
            found[(directory / name).relative_to(root).as_posix()] = directory / name
    # The C56 job writes preparation-result.json after the manifest, so it is present but not listed.
    need(set(found) == set(manifest) | {"artifact-manifest.json", "preparation-result.json"})
    for name, path in found.items():
        if name in manifest:
            need(file_record(path, 17179869184) == manifest[name])
    need(json.loads(read(root / "preparation-result.json", 1048576)) == receipt)
    need(
        manifest["output/builder.docker.tar"]
        == {"sha256": c56["builder_archive_sha256"], "bytes": c56["builder_archive_bytes"]}
    )
    for name, spec in lock["sources"].items():
        need(manifest["inputs/source/" + name] == {"sha256": spec["sha256"], "bytes": spec["bytes"]})
    need(manifest["base-manifest.json"]["sha256"] == lock["base_manifest_sha256"])
    need(manifest["output/source-inventory/tree-manifest.json"]["sha256"] == lock["tree_manifest_sha256"])
    for repository_path, name in C56_OWNED.items():
        need(manifest["inputs/" + name] == receipt["committed_sources"][repository_path])
    changelog = read(root / "output/source-inventory/public-files/debian__changelog", 4194304)
    need(changelog_epoch(changelog) == lock["source_date_epoch"])
    identity = json.loads(read(root / "base-identity.json", 1048576))
    need(identity["Id"] == CONFIG and len(identity["RootFS"]["Layers"]) == 14)
    return identity


IMAGE_TEMPLATE = (
    '{"Id":{{json .Id}},"RepoDigests":{{json .RepoDigests}},"Os":{{json .Os}},'
    '"Architecture":{{json .Architecture}},"RootFS":{{json .RootFS}},"Volumes":{{json .Config.Volumes}}}'
)
CONTAINER_TEMPLATE = (
    '{"Image":{{json .Image}},"User":{{json .Config.User}},"State":{'
    '"Status":{{json .State.Status}},"Running":{{json .State.Running}},"ExitCode":{{json .State.ExitCode}}},'
    '"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"NetworkMode":{{json .HostConfig.NetworkMode}},'
    '"Privileged":{{json .HostConfig.Privileged}},"PidMode":{{json .HostConfig.PidMode}},'
    '"IpcMode":{{json .HostConfig.IpcMode}},"CapAdd":{{json .HostConfig.CapAdd}},'
    '"CapDrop":{{json .HostConfig.CapDrop}},"SecurityOpt":{{json .HostConfig.SecurityOpt}},'
    '"Devices":{{json .HostConfig.Devices}},"Tmpfs":{{json .HostConfig.Tmpfs}},"Mounts":{{json .Mounts}}}'
)


def image_identity(docker, reference, environment):
    identity = json.loads(run([*docker, "image", "inspect", "--format", IMAGE_TEMPLATE, reference], environment))
    need(type(identity) is dict and DIGEST.fullmatch(identity["Id"]) is not None)
    need(identity["Os"] == "linux" and identity["Architecture"] == "amd64")
    need(identity["RootFS"]["Type"] == "layers" and type(identity["RootFS"]["Layers"]) is list)
    need(all(type(value) is str and DIGEST.fullmatch(value) is not None for value in identity["RootFS"]["Layers"]))
    need(identity["Volumes"] == {"/var/lib/postgresql/data": {}})
    return identity


def container_spec(image, binds, environment, workdir, entrypoint):
    """Single source for both the create argv and the inspect expectation."""
    argv = [
        "create",
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--ipc",
        "private",
        "--user",
        "65534:65534",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--cap-drop=ALL",
        "--workdir",
        workdir,
    ]
    for destination, (source, writable) in binds.items():
        argv += ["--mount", f"type=bind,src={source},dst={destination}" + ("" if writable else ",readonly")]
    for destination, options in BUILDER_TMPFS.items():
        argv += ["--tmpfs", f"{destination}:{options}"]
    for pair in environment:
        argv += ["--env", pair]
    argv += ["--entrypoint", "/usr/bin/python3", image, "-I", *entrypoint]
    return argv


def inspect_container(docker, container, image, binds, environment):
    actual = json.loads(run([*docker, "container", "inspect", "--format", CONTAINER_TEMPLATE, container], environment))
    need(actual["Image"] == image and actual["User"] == "65534:65534")
    need(actual["ReadonlyRootfs"] is True and actual["Privileged"] is False and actual["NetworkMode"] == "none")
    need(actual["PidMode"] == "" and actual["IpcMode"] == "private")
    need(actual["CapAdd"] in (None, []) and actual["Devices"] in (None, []) and actual["CapDrop"] == ["ALL"])
    need(actual["SecurityOpt"] == ["no-new-privileges"] and actual["Tmpfs"] == BUILDER_TMPFS)
    seen = set()
    for mount in actual["Mounts"]:
        destination = mount["Destination"]
        need(destination not in seen)
        seen.add(destination)
        if destination in binds:
            source, writable = binds[destination]
            need(mount["Type"] == "bind" and mount["RW"] is writable and mount["Source"] == str(source))
        else:
            # Docker versions can represent --tmpfs solely in HostConfig.Tmpfs.
            need(destination in BUILDER_TMPFS and mount["Type"] == "tmpfs" and mount["RW"] is True)
    need(set(binds) <= seen)
    return actual["State"]


def create_container(docker, image, binds, environment, workdir, entrypoint, command_environment, owned):
    argv = [*docker, *container_spec(image, binds, environment, workdir, entrypoint)]
    # Lost create stdout/timeout leaves an explicit uncertainty marker, never a false cleanup claim.
    owned.append(None)
    created = run(argv, command_environment)
    need(CID.fullmatch(created) is not None)
    container = created.strip().decode("ascii")
    owned[-1] = container
    state = inspect_container(docker, container, image, binds, command_environment)
    need(state["Running"] is False and state["Status"] in ("created", "exited"))
    return container


def hub_url(url):
    value = urllib.parse.urlsplit(url)
    if value.hostname not in HUB_HOSTS:
        host = value.hostname or ""
        REFUSED_HOSTS.append(host if re.fullmatch(r"[a-z0-9.-]{1,253}", host) else "invalid")
    need(value.scheme == "https" and value.hostname in HUB_HOSTS)
    need(value.username is None and value.password is None and value.port is None and not value.fragment)
    return url


class Redirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    max_repeats = 1

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, hub_url(newurl))
        if new is not None:
            # The signed CDN location must never receive the registry bearer token.
            new.remove_header("Authorization")
        return new


def hub_open(url, headers, timeout=60):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        Redirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    request = urllib.request.Request(hub_url(url), headers=headers)  # noqa: S310 -- scheme and host pinned above
    response = opener.open(request, timeout=timeout)
    hub_url(response.geturl())
    return response


def fetch_base_blobs(manifest, directory):
    """Anonymous, read-only fetch of the pinned base blobs by digest; every byte is size- and hash-checked."""
    for descriptor in [manifest["config"], *manifest["layers"]]:
        value = descriptor["digest"]
        need(DIGEST.fullmatch(value) is not None and type(descriptor["size"]) is int and descriptor["size"] > 0)
        scope = "repository:library/postgres:pull"
        token_url = "https://auth.docker.io/token?service=registry.docker.io&scope=" + urllib.parse.quote(
            scope, safe=""
        )
        with hub_open(token_url, {"Accept": "application/json"}) as response:
            token = json.loads(response.read(65536))["token"]
        need(type(token) is str and 0 < len(token) <= 16384)
        hashed = hashlib.sha256()
        total = 0
        deadline = time.monotonic() + 900
        target = directory / value.removeprefix("sha256:")
        with (
            hub_open(
                "https://registry-1.docker.io/v2/library/postgres/blobs/" + value, {"Authorization": "Bearer " + token}
            ) as response,
            open(target, "xb") as out,
        ):
            while True:
                need(time.monotonic() < deadline)
                chunk = response.read(min(1048576, descriptor["size"] + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                need(total <= descriptor["size"])
                hashed.update(chunk)
                out.write(chunk)
        need(total == descriptor["size"] and "sha256:" + hashed.hexdigest() == value)
        target.chmod(0o644)


def emit(public):
    encoded = json.dumps(public, ensure_ascii=True, separators=(",", ":"))
    need(len((PREFIX + encoded + "\n").encode()) <= 196608)
    print(PREFIX + encoded)


def build(arguments):
    commit, ids, checked, contents, environment = guards(OWNED[4])
    lock, receipt = checked_lock(contents)
    replica = arguments.replica
    need(replica in ("a", "b"))
    c56 = Path(arguments.c56).resolve()
    os.umask(0o022)
    root = Path.cwd() / ARTIFACT_DIR
    need(not root.exists())
    root.mkdir(mode=0o700)
    output = root / "output"
    output.mkdir(mode=0o755)
    output.chmod(0o777)
    public: dict[str, Any] = {
        "status": "UNQUALIFIED_DERIVED_BUILD_INCOMPLETE",
        "commit": commit,
        "run_id": ids["GITHUB_RUN_ID"],
        "run_attempt": ids["GITHUB_RUN_ATTEMPT"],
        "replica": replica,
        "committed_sources": checked,
        "phase": "lock_binding",
        "cleanup": "not_created",
        "cleanup_uncertain": False,
        "c56_binding_verified": False,
        "c56_review_bound": True,
        "payload_built": False,
        "oci_assembled": False,
        "derived_runtime_image_digest": None,
        "admission_digest": None,
        "FRESH_CANONICAL_SHA256": None,
    }
    containers: list[str | None] = []
    builder = None
    load_uncertain = False
    with tempfile.TemporaryDirectory(prefix="academy-derived-private-", ignore_cleanup_errors=True) as private_name:
        private = Path(private_name)
        config = private / "docker"
        config.mkdir(mode=0o700)
        (config / "config.json").write_text("{}\n")
        docker = ["docker", "--config", str(config)]
        inputs, work = private / "inputs", private / "build"
        inputs.mkdir(mode=0o755)
        work.mkdir(mode=0o755)
        work.chmod(0o777)
        try:
            public["phase"] = "c56_binding"
            identity = verify_c56(c56, lock, receipt)
            public["c56_binding_verified"] = True
            public["phase"] = "input_staging"
            for relative in OWNED[1:4] + OWNED[5:7]:
                (inputs / Path(relative).name).write_bytes(contents[relative])
            (inputs / "c56-receipt.json").write_text(lock["c56"]["receipt_utf8"])
            shutil.copytree(c56 / "inputs/source", inputs / "source")
            shutil.copyfile(c56 / "output/source-inventory/tree-manifest.json", inputs / "c56-tree-manifest.json")
            shutil.copyfile(c56 / "base-manifest.json", inputs / "base-manifest.json")
            shutil.copyfile(c56 / "base-identity.json", inputs / "base-identity.json")
            for path in (inputs / "source").iterdir():
                need(path.is_file() and not path.is_symlink())
            public["phase"] = "base_blob_fetch"
            base_manifest = json.loads(read(inputs / "base-manifest.json", 1048576))
            need(base_manifest["config"]["digest"] == CONFIG and len(base_manifest["layers"]) == 14)
            blobs = inputs / "base-blobs"
            blobs.mkdir(mode=0o755)
            fetch_base_blobs(base_manifest, blobs)
            public["phase"] = "builder_load"
            builder_id = lock["c56"]["builder_config_id"]
            # Registered before the load: a timed-out load may still have created the image.
            builder = builder_id
            load_uncertain = True
            run([*docker, "load", "--input", str(c56 / "output/builder.docker.tar")], environment, timeout=900)
            load_uncertain = False
            loaded = image_identity(docker, builder_id, environment)
            need(loaded["Id"] == builder_id and loaded["RootFS"]["Layers"][:14] == identity["RootFS"]["Layers"])
            epoch = str(lock["source_date_epoch"])
            shared = ["LC_ALL=C", "TZ=UTC", "SOURCE_DATE_EPOCH=" + epoch]
            public["phase"] = "payload_build"
            build_binds = {"/inputs": (inputs, False), "/out": (output, True), "/build": (work, True)}
            first = create_container(
                docker,
                builder_id,
                build_binds,
                [*shared, "HOME=/build/home", "TMPDIR=/build/tmp"],
                "/build",
                ["/inputs/in_builder_build.py", "build"],
                environment,
                containers,
            )
            run([*docker, "start", "--attach", first], environment, timeout=3600)
            state = inspect_container(docker, first, builder_id, build_binds, environment)
            need(state["Status"] == "exited" and state["ExitCode"] == 0)
            need(read(output / "phase.txt", 64) == b"complete\n")
            public["payload_built"] = True
            public["phase"] = "oci_assembly"
            assemble_binds = {"/inputs": (inputs, False), "/out": (output, True)}
            second = create_container(
                docker,
                builder_id,
                assemble_binds,
                [*shared, "HOME=/tmp"],
                "/out",
                ["/inputs/assemble_oci.py", "assemble"],
                environment,
                containers,
            )
            run([*docker, "start", "--attach", second], environment, timeout=1800)
            state = inspect_container(docker, second, builder_id, assemble_binds, environment)
            need(state["Status"] == "exited" and state["ExitCode"] == 0)
            public["oci_assembled"] = True
            public["phase"] = "host_verification"
            public.update(host_verification(output, lock))
        except Exception:
            try:
                value = read(output / "phase.txt", 64).decode("ascii").strip()
                public["builder_phase"] = value if re.fullmatch(r"[a-z_]{1,40}", value) else "unavailable"
            except Exception:
                public["builder_phase"] = "unavailable"
            public["failure"] = {
                "kind": "phase_failed" if public["phase"] in PHASES else "unknown_phase",
                "refused_hostname": REFUSED_HOSTS[0] if REFUSED_HOSTS else None,
            }
        finally:
            for container in reversed(containers):
                if container is None:
                    public["cleanup_uncertain"] = True
                    continue
                try:
                    run([*docker, "rm", "--force", "--volumes", container], environment)
                except Exception:
                    public["cleanup_uncertain"] = True
            if builder is not None:
                try:
                    run([*docker, "image", "rm", builder], environment)
                except Exception:
                    public["cleanup_uncertain"] = True
            if load_uncertain:
                public["cleanup_uncertain"] = True
            public["cleanup"] = (
                "uncertain"
                if public["cleanup_uncertain"]
                else "owned_resources_removed"
                if containers or builder is not None
                else "not_created"
            )
    if Path(private_name).exists():
        public["cleanup_uncertain"] = True
        public["cleanup"] = "uncertain"
    complete = public.get("outputs") is not None and "failure" not in public and not public["cleanup_uncertain"]
    if complete:
        public["phase"] = "artifact_manifest"
        try:
            manifest = {}

            def refuse_walk(error):
                raise Refused from None

            for directory, directories, files in root.walk(on_error=refuse_walk):
                for name in directories:
                    need(not (directory / name).is_symlink())
                for name in sorted(files):
                    path = directory / name
                    need(not path.is_symlink())
                    manifest[path.relative_to(root).as_posix()] = file_record(path, 17179869184)
            (root / "artifact-manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            public["artifact_manifest"] = file_record(root / "artifact-manifest.json", 16777216)
            public.update(status="UNQUALIFIED_DERIVED_PAYLOAD_BUILT", phase="complete", claim=CLAIM)
        except Exception:
            public["failure"] = {"kind": "artifact_manifest_failed"}
    (root / "build-receipt.json").write_text(json.dumps(public, sort_keys=True, indent=2) + "\n")
    emit(public)
    return 0 if public["status"] == "UNQUALIFIED_DERIVED_PAYLOAD_BUILT" else 1


def host_verification(output, lock):
    """Recompute every equality item on the host from bytes, independent of in-container claims."""
    assemble = sibling("assemble_oci")
    facts = json.loads(read(output / "build-facts.json", 16777216))
    assembled = json.loads(read(output / "assemble-facts.json", 16777216))
    unstripped = file_record(output / "postgres.unstripped", 536870912)
    stripped = file_record(output / "postgres", 536870912)
    archive = file_record(output / ARCHIVE, 17179869184)
    again = assemble.archive_facts(output / ARCHIVE)
    need(facts["postgres_unstripped"] == unstripped and facts["postgres"] == stripped)
    need(assembled["archive"]["sha256"] == archive["sha256"] and assembled["archive"]["bytes"] == archive["bytes"])
    need(assembled["elf"]["derived"]["sha256"] == stripped["sha256"])
    need(
        again["manifest_digest"] == assembled["manifest"]["digest"]
        and again["config_digest"] == assembled["config"]["digest"]
    )
    need(
        again["layer_blob_digest"] == assembled["layer"]["blob_digest"]
        and again["layer_diff_id"] == assembled["layer"]["diff_id"]
    )
    need(
        facts["patch"]["patched_sha256"] == lock["patch_guard"]["out_sha256"]
        and facts["tree_manifest_sha256"] == lock["tree_manifest_sha256"]
    )
    outputs = {
        "postgres_unstripped_sha256": unstripped["sha256"],
        "postgres_sha256": stripped["sha256"],
        "layer_diff_id": again["layer_diff_id"],
        "layer_blob_digest": again["layer_blob_digest"],
        "config_digest": again["config_digest"],
        "manifest_digest": again["manifest_digest"],
        "archive_sha256": archive["sha256"],
    }
    return {
        "outputs": outputs,
        "candidate_manifest_digest": again["manifest_digest"],
        "source_date_epoch": facts["source_date_epoch"],
        "patch": facts["patch"],
        "elf_gates": assembled["elf"]["gates"],
        "elf_records": {
            side: {key: assembled["elf"][side][key] for key in ("build_id", "version_banner", "section_names", "bytes")}
            for side in ("base", "derived")
        },
        "base_binary": assembled["base"]["binary"],
        "dropped_base_manifest_annotation_keys": assembled["base"]["dropped_manifest_annotation_keys"],
        "section_hashes": facts["sections"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("build",))
    parser.add_argument("--replica", required=True)
    parser.add_argument("--c56", required=True)
    return build(parser.parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print(PREFIX + '{"status":"UNQUALIFIED_DERIVED_BUILD_INCOMPLETE","phase":"hosted_guard_or_bounded_failure"}')
        raise SystemExit(1) from None

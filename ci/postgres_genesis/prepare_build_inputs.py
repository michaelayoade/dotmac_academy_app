"""Hosted scratch acquisition only: freeze inputs, never compile or admit a runtime."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shlex
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BASE = "postgres@sha256:b95b87e93ceb7594715d5c71fb6e09f6fc878851ab537735d617325eb9ba8b1b"
CONFIG = "sha256:74d436cb49d3398cf7b5d7b33635d43623d9e4da4b93c22db453f7d5d81181b1"
OWNED = (
    "ci/postgres_genesis/prepare_build_inputs.py",
    "ci/postgres_genesis/acquire_build_inputs.sh",
    "ci/postgres_genesis/inspect_build_source.py",
    "ci/postgres_genesis/build-inputs-lock.json",
    ".github/workflows/genesis-postgres-build-inputs.yml",
)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
CID = re.compile(rb"[0-9a-f]{64}\n?", re.ASCII)
PREFIX = "ACADEMY_GENESIS_BUILD_INPUTS_JSON "
PHASES = frozenset(
    (
        "source_download",
        "base_association",
        "acquisition",
        "base_preflight",
        "apt_configuration",
        "inherited_source_kind",
        "inherited_source_copy",
        "inherited_source_validation",
        "inherited_hook_kind",
        "inherited_hook_validation",
        "inherited_hook_copy",
        "debian_keyring_copy",
        "pgdg_keyring_copy",
        "explicit_config_creation",
        "explicit_config_capture",
        "debian_key_home",
        "pgdg_key_home",
        "debian_key_import",
        "pgdg_key_import",
        "debian_fingerprint_listing",
        "pgdg_fingerprint_listing",
        "debian_fingerprint_nonempty",
        "pgdg_fingerprint_nonempty",
        "pgdg_fingerprint_match",
        "apt_update",
        "metadata_signer",
        "metadata_index_hash",
        "bootstrap_simulate",
        "bootstrap_download",
        "bootstrap_install",
        "source_dependency_binding",
        "dependencies_simulate",
        "dependencies_download",
        "dependencies_install",
        "dependency_archive_authentication",
        "closure_verification",
        "toolchain_inventory",
        "acquisition_complete",
        "builder_freeze",
        "offline_source_inventory",
        "source_extract",
        "source_format",
        "source_dependencies",
        "source_series",
        "source_tree_manifest",
        "source_public_inspection",
        "artifact_manifest",
        "complete",
    )
)
ANCHORS = ("libc6-dev", "gcc-14", "g++-14", "llvm-19-dev", "clang-19")
DIAGNOSTIC_ENUMS = {
    "source_file_class": frozenset(("sources_list", "debian_sources", "pgdg_list", "other_sources", "other_list")),
    "file_kind": frozenset(("regular", "symlink", "directory", "other", "missing")),
    "source_validation": frozenset(("success", "failure")),
    "source_rejected_field": frozenset(
        ("types", "uris", "suites", "components", "signed_by", "architectures", "enabled", "deb_line", "other")
    ),
    "hook_file_class": frozenset(
        ("docker_clean", "docker_gzip_indexes", "docker_no_languages", "docker_autoremove_suggests", "debconf", "other")
    ),
    "hook_validation": frozenset(("success", "failure")),
    "hook_rejection": frozenset(
        ("custom_cache_reference", "unauthenticated_option_token", "insecure_option_token", "valid_until_false_token")
    ),
    "key_context": frozenset(("debian", "pgdg")),
    "key_format": frozenset(("armored_public_key", "binary_or_other")),
    "import_outcome": frozenset(("success", "nonzero")),
    "fingerprint_list_outcome": frozenset(("success", "nonzero")),
    "gpg_status_token": frozenset(("IMPORT_OK", "IMPORT_RES", "IMPORT_PROBLEM", "NODATA", "FAILURE", "ERROR")),
    "gpg_failure_operation": frozenset(
        (
            "import",
            "import_keys",
            "keydb_search",
            "keydb_get_keyblock",
            "keydb_new",
            "add_keyblock_resource",
            "keybox_open",
            "other",
        )
    ),
    "gpg_error_operation": frozenset(
        (
            "import",
            "import_keys",
            "keydb_search",
            "keydb_get_keyblock",
            "keydb_new",
            "add_keyblock_resource",
            "keybox_open",
            "other",
        )
    ),
}
DIAGNOSTIC_BOOLEANS = frozenset(
    (
        "known_uri_match",
        "known_suite_match",
        "known_signed_by_match",
        "leading_whitespace",
        "trailing_whitespace",
        "carriage_return",
        "primary_count_capped",
        "pinned_fingerprint_match",
    )
)
DIAGNOSTIC_COUNTS = {
    "primary_count": 64,
    "import_exit_code": 255,
    "fingerprint_list_exit_code": 255,
    "gpg_import_problem_reason": 4294967295,
    "gpg_nodata_reason": 4294967295,
    "gpg_failure_code": 4294967295,
    "gpg_error_code": 4294967295,
}


class Refused(Exception):
    """No tool or remote exception text escapes."""


def need(condition):
    if not condition:
        raise Refused


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, environment, *, timeout=300, maximum=16777216):
    result = subprocess.run(  # noqa: S603 -- fixed source commands and validated owned resource identities
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


def guards():
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
            for key in (
                "DOCKER_HOST",
                "DOCKER_CONTEXT",
                "DOCKER_TLS_VERIFY",
                "DOCKER_CERT_PATH",
                "DOCKER_TLS",
            )
        )
    )
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TZ") if key in os.environ}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    head = run(["git", "rev-parse", "HEAD"], environment)
    need(re.fullmatch(rb"[0-9a-f]{40}\n?", head) is not None and head.rstrip(b"\n").decode() == commit)
    need(Path(__file__).resolve() == (Path.cwd() / OWNED[0]).resolve())
    checked, contents = {}, {}
    for relative in OWNED:
        blob = run(["git", "cat-file", "blob", commit + ":" + relative], environment)
        actual = read(Path(relative), 524288)
        need(actual == blob)
        checked[relative] = {"sha256": sha(actual), "bytes": len(actual)}
        contents[relative] = actual
    run_ids = {key: os.environ.get(key, "") for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    need(all(re.fullmatch(r"[1-9][0-9]{0,19}", value, flags=re.ASCII) is not None for value in run_ids.values()))
    return commit, run_ids, checked, contents, environment


def checked_lock(data):
    lock = json.loads(data)
    need(lock["status"] == "UNQUALIFIED_BUILD_INPUTS" and lock["compile_permitted"] is False)
    need(lock["base"] == BASE and lock["base_config"] == CONFIG and lock["platform"] == "linux/amd64")
    need(lock["repository"] == "michaelayoade/dotmac_academy_app")
    need(
        all(
            lock[name] is None
            for name in ("derived_runtime_image_digest", "admission_digest", "FRESH_CANONICAL_SHA256")
        )
    )
    binding = lock["source_binding"]
    for name in ("receipt", "review"):
        need(type(binding[name + "_utf8"]) is str)
        need(sha(binding[name + "_utf8"].encode()) == binding[name + "_sha256"])
    need(binding["receipt_sha256"] == "de676514309617617690af861da21f21d71ee57d151bbe512297cb6034c7bc82")
    need(binding["review_sha256"] == "6734b38c5038f8a09bed38f1f9c350b8babfda7e6c00703becb3b4eff417ccd7")
    receipt = json.loads(binding["receipt_utf8"])
    review = json.loads(binding["review_utf8"])
    need(review["binding_assessment"]["supports_later_source_hash_binding"] is True)
    need(review["evidence_sha256"] == binding["receipt_sha256"])
    configure_text = receipt["projection"]["image"]["metadata"]["pg-config-configure.txt"]["text_capture"]["text"]
    need(lock["configure_argv"] == shlex.split(configure_text))
    source_records = receipt["projection"]["source_repository"]["checked_sources"]
    need(set(lock["sources"]) == set(source_records) and len(source_records) == 3)
    for name, spec in lock["sources"].items():
        need(Path(name).name == name and "/" not in name)
        need(
            {"sha256": spec["sha256"], "bytes": spec["bytes"]}
            == {
                "sha256": source_records[name]["sha256"],
                "bytes": source_records[name]["bytes"],
            }
        )
        need(source_records[name]["captured_bytes_match"] is True)
        need(type(spec["bytes"]) is int and 0 < spec["bytes"] <= 67108864)
    return lock


def safe_url(url):
    value = urllib.parse.urlsplit(url)
    need(value.scheme == "https" and value.hostname in ("apt.postgresql.org", "ftp.postgresql.org"))
    need(value.username is None and value.password is None and value.port is None)
    need(not value.query and not value.fragment)
    return url


class Redirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    max_repeats = 1

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, safe_url(newurl))


def download(path, spec):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        Redirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    data = bytearray()
    deadline = time.monotonic() + 180
    with opener.open(safe_url(spec["url"]), timeout=30) as response:
        safe_url(response.geturl())
        while True:
            need(time.monotonic() < deadline)
            chunk = response.read(min(65536, spec["bytes"] + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            need(len(data) <= spec["bytes"])
    need(len(data) == spec["bytes"] and sha(data) == spec["sha256"])
    path.write_bytes(data)


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


def inspect_container(docker, container, image, inputs, output, offline, environment):
    actual = json.loads(run([*docker, "container", "inspect", "--format", CONTAINER_TEMPLATE, container], environment))
    need(actual["Image"] == image and actual["User"] == ("65534:65534" if offline else "0:0"))
    need(actual["ReadonlyRootfs"] is offline and actual["Privileged"] is False)
    need(actual["NetworkMode"] == ("none" if offline else "bridge"))
    need(actual["PidMode"] == "" and actual["IpcMode"] == "private")
    need(actual["CapAdd"] in (None, []) and actual["Devices"] in (None, []))
    need(actual["CapDrop"] == ["ALL"] if offline else actual["CapDrop"] in (None, []))
    need(actual["SecurityOpt"] == ["no-new-privileges"])
    need(actual["Tmpfs"] == {"/var/lib/postgresql/data": "rw,nosuid,nodev,noexec,size=1m"})
    mounts = actual["Mounts"]
    need(type(mounts) is list and len(mounts) in (2, 3))
    seen = set()
    for mount in mounts:
        target = mount["Destination"]
        need(target not in seen)
        seen.add(target)
        if target in ("/inputs", "/out"):
            need(mount["Type"] == "bind" and mount["RW"] is (target == "/out"))
            need(mount["Source"] == str(inputs if target == "/inputs" else output))
        else:
            need(target == "/var/lib/postgresql/data" and mount["Type"] == "tmpfs" and mount["RW"] is True)
    # Docker versions can represent --tmpfs solely in HostConfig.Tmpfs.
    need(seen in ({"/inputs", "/out"}, {"/inputs", "/out", "/var/lib/postgresql/data"}))
    need(actual["State"]["Running"] is False and actual["State"]["Status"] in ("created", "exited"))
    return actual["State"]


def create_container(docker, image, inputs, output, offline, environment, owned):
    argv = [
        *docker,
        "create",
        "--platform",
        "linux/amd64",
        "--network",
        "none" if offline else "bridge",
        "--ipc",
        "private",
        "--user",
        "65534:65534" if offline else "0:0",
        "--security-opt=no-new-privileges",
        "--mount",
        f"type=bind,src={inputs},dst=/inputs,readonly",
        "--mount",
        f"type=bind,src={output},dst=/out",
        "--tmpfs",
        "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=1m",
        "--env",
        "LC_ALL=C",
        "--env",
        "TZ=UTC",
    ]
    if offline:
        argv.extend(
            [
                "--read-only",
                "--cap-drop=ALL",
                "--entrypoint",
                "/usr/bin/python3",
                image,
                "/inputs/inspect_build_source.py",
                "source",
            ]
        )
    else:
        argv.extend(
            [
                "--env",
                "DEBIAN_FRONTEND=noninteractive",
                "--entrypoint",
                "/bin/bash",
                image,
                "/inputs/acquire_build_inputs.sh",
            ]
        )
    # Lost create stdout/timeout leaves an explicit uncertainty marker, never a false cleanup claim.
    owned.append(None)
    created = run(argv, environment)
    need(CID.fullmatch(created) is not None)
    container = created.strip().decode("ascii")
    owned[-1] = container
    inspect_container(docker, container, image, inputs, output, offline, environment)
    return container


def json_file(path, maximum=16777216):
    return json.loads(read(path, maximum))


def failure_details(output):
    # Fixed public diagnostics; full public APT transactions stay in the artifact only.
    detail: dict[str, Any] = {"kind": "phase_failed", "mentioned_compatibility_anchors": []}
    try:
        data = b"\n".join(read(path, 16777216) for path in sorted((output / "transactions").glob("*.txt")))
        for name in ANCHORS:
            if name.encode() in data:
                detail["mentioned_compatibility_anchors"].append(name)
        if b"held broken packages" in data or b"held packages" in data or b"unmet dependencies" in data:
            detail["kind"] = "held_dependency_conflict"
        elif b"was not found" in data or b"Unable to locate package" in data:
            detail["kind"] = "missing_package_or_version"
        elif b"NO_PUBKEY" in data or b"not signed" in data or b"signature" in data:
            detail["kind"] = "repository_authentication_failed"
        text = data.decode("utf-8", errors="replace")
        tokens = set()
        for pattern in (
            r"E: Unable to locate package ([a-z0-9][a-z0-9+.-]{0,95})",
            r"E: Version '[A-Za-z0-9.+:~_-]{1,96}' for '([a-z0-9][a-z0-9+.-]{0,95})' was not found",
            r"(?m)^ ([a-z0-9][a-z0-9+.-]{0,95})(?::amd64)? : (?:Depends|PreDepends|Conflicts):",
            r"(?:Depends|PreDepends|Conflicts): ([a-z0-9][a-z0-9+.-]{0,95})(?::amd64)?(?: |$)",
        ):
            tokens.update(re.findall(pattern, text))
        detail["solver_package_names"] = sorted(tokens)[:32]
        detail["solver_package_names_omitted"] = len(tokens) > 32
    except Exception:
        detail["kind"] = "diagnostics_unavailable"
    return detail


def preparation_diagnostics(output):
    try:
        data = read(output / "configuration-diagnostics.tsv", 65536)
        lines = data.decode("ascii", errors="strict").splitlines()
        need(len(lines) <= 512)
        records = []
        for line in lines:
            parts = line.split("\t")
            need(len(parts) == 2)
            name, value = parts
            checked: str | bool | int
            if name in DIAGNOSTIC_ENUMS:
                need(value in DIAGNOSTIC_ENUMS[name])
                checked = value
            elif name in DIAGNOSTIC_BOOLEANS:
                need(value in ("true", "false"))
                checked = value == "true"
            else:
                need(
                    name in DIAGNOSTIC_COUNTS and re.fullmatch(r"0|[1-9][0-9]{0,9}", value, flags=re.ASCII) is not None
                )
                checked = int(value)
                need(0 <= checked <= DIAGNOSTIC_COUNTS[name])
            records.append({"name": name, "value": checked})
        return {"available": True, "records": records}
    except Exception:
        return {"available": False, "reason": "unavailable_or_invalid_diagnostics"}


def public_source_inventory(output, lock):
    path = output / "source-inventory/source-public.json"
    source = json_file(path, 1048576)
    need(source["vendor"] == "Debian" and source["series"] in ("debian/patches/series", "debian/patches/debian.series"))
    need(source["applied_patches_match"] is True and source["configure_argv"] == lock["configure_argv"])
    need(type(source["series_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", source["series_sha256"]) is not None)
    patches = []
    need(type(source["ordered_patches"]) is list and len(source["ordered_patches"]) <= 512)
    for patch in source["ordered_patches"]:
        name = patch["name"]
        need(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.+/-]{1,256}", name) is not None)
        need(not name.startswith("/") and ".." not in name.split("/"))
        need(type(patch["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", patch["sha256"]) is not None)
        need(type(patch["bytes"]) is int and 0 <= patch["bytes"] <= 16777216)
        patches.append({"name": name, "sha256": patch["sha256"], "bytes": patch["bytes"]})

    def excerpt(value, limit):
        need(type(value) is dict and type(value["text_excerpt"]) is str and len(value["text_excerpt"]) <= limit)
        text = value["text_excerpt"]
        need(all(character in "\t\r\n" or ord(character) >= 32 for character in text))
        need(re.search(r"[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text) is None)
        need(type(value["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None)
        need(type(value["bytes"]) is int and 0 <= value["bytes"] <= 4194304)
        need(type(value["omitted"]) is bool and type(value["contact_lines_omitted"]) is bool)
        return {key: value[key] for key in ("sha256", "bytes", "text_excerpt", "omitted", "contact_lines_omitted")}

    dependencies = {}
    for name in (
        "Build-Depends",
        "Build-Depends-Arch",
        "Build-Depends-Indep",
        "Build-Conflicts",
        "Build-Conflicts-Arch",
        "Build-Conflicts-Indep",
    ):
        value = source["dependency_fields"][name]
        need(type(value) is str and len(value) <= 16384 and "@" not in value)
        need(all(character in "\t\r\n" or 32 <= ord(character) < 127 for character in value))
        dependencies[name] = value
    common = {}
    for name, value in source["common_dev_makefiles"].items():
        need(
            type(name) is str
            and re.fullmatch(r"/usr/share/postgresql-common/[A-Za-z0-9_.+/-]{1,240}\.(?:mk|make)", name) is not None
        )
        need(".." not in name.split("/"))
        common[name] = excerpt(value, 12288)
    includes = source["include_directives"]
    need(type(includes) is list and len(includes) <= 64)
    need(
        all(
            type(line) is str
            and len(line) <= 2048
            and "@" not in line
            and all(32 <= ord(c) < 127 or c == "\t" for c in line)
            for line in includes
        )
    )
    function = excerpt(source["RecheckDataDirLockFile"], 32768)
    function["source_file_sha256"] = source["RecheckDataDirLockFile"]["source_file_sha256"]
    need(
        type(function["source_file_sha256"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", function["source_file_sha256"]) is not None
    )
    return {
        "vendor": "Debian",
        "series": source["series"],
        "series_sha256": source["series_sha256"],
        "ordered_patches": patches,
        "applied_patches_match": True,
        "configure_argv": lock["configure_argv"],
        "dependency_fields": dependencies,
        "debian_rules": excerpt(source["debian_rules"], 32768),
        "include_directives": includes,
        "common_dev_makefiles": common,
        "RecheckDataDirLockFile": function,
        "full_source_public_capture": file_record(path, 1048576),
        "projection_budget_omitted": False,
        "omitted_common_dev_makefile_count": 0,
        "omitted_include_directive_count": 0,
        "omitted_ordered_patch_count": 0,
        "packaging_preprocessing_requires_review_before_build": True,
    }


def public_builder_inputs(output):
    versions = {}
    wanted = {
        "libc6",
        "libc6-dev",
        "gcc-14-base",
        "gcc-14",
        "g++-14",
        "libllvm19",
        "llvm-19-dev",
        "clang-19",
        "postgresql-common-dev",
    }
    for line in read(output / "builder-bom.tsv", 16777216).decode("ascii").splitlines():
        parts = line.split("\t")
        need(len(parts) == 3)
        name = parts[0].removesuffix(":amd64")
        if name in wanted:
            need(re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,96}", parts[1]) is not None)
            need(parts[2] in ("all", "amd64"))
            versions[name] = {"version": parts[1], "architecture": parts[2]}
    need(set(versions) == wanted)
    hashes = {}
    tools = ("gcc-14", "g++-14", "clang-19", "llvm-config-19", "ld", "as", "strip", "make", "dpkg-source")
    for line in read(output / "tools/executable-hashes.txt", 8192).decode("ascii").splitlines():
        checksum, path = line.split()
        need(re.fullmatch(r"[0-9a-f]{64}", checksum) is not None and path.startswith("/usr/bin/"))
        tool = path.removeprefix("/usr/bin/")
        need(tool in tools and tool not in hashes)
        text_path = output / "transactions" / ("tool-" + tool + ".txt")
        text = read(text_path, 16777216).decode("utf-8", errors="strict").splitlines()[0]
        need(len(text) <= 240 and "@" not in text and all(32 <= ord(c) < 127 for c in text))
        hashes[tool] = {
            "executable_sha256": checksum,
            "version_first_line": text,
            "version_capture": file_record(text_path, 16777216),
        }
    need(set(hashes) == set(tools))
    need(read(output / "transactions/gcc-target.txt", 128).strip() == b"x86_64-linux-gnu")
    authentication = json_file(output / "repository-authentication.json")
    need(authentication["status"] == "verified_current_repository_integrity")
    releases = []
    expected_suites = {"trixie", "trixie-updates", "trixie-security", "trixie-pgdg"}
    for record in authentication["releases"].values():
        need(record["suite"] in expected_suites and record["keyring"] in ("debian", "pgdg"))
        need(
            type(record["release_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", record["release_sha256"]) is not None
        )
        signatures = []
        need(type(record["signatures"]) is list and 1 <= len(record["signatures"]) <= 8)
        for signature in record["signatures"]:
            need(
                all(
                    type(signature[name]) is str and re.fullmatch(r"[0-9A-F]{40}", signature[name]) is not None
                    for name in ("signer_fingerprint", "primary_fingerprint")
                )
            )
            signatures.append({name: signature[name] for name in ("signer_fingerprint", "primary_fingerprint")})
        releases.append(
            {
                "suite": record["suite"],
                "keyring": record["keyring"],
                "signatures": signatures,
                "release_sha256": record["release_sha256"],
            }
        )
    need({record["suite"] for record in releases} == expected_suites and len(releases) == 4)
    return {
        "versions": versions,
        "tools": hashes,
        "compiler_target": "x86_64-linux-gnu",
        "signed_releases": releases,
        "debian_keyring": file_record(output / "apt/keys/debian-archive-keyring.pgp", 4194304),
        "pgdg_keyring": file_record(output / "apt/keys/postgres.gpg.asc", 1048576),
        "repository_authentication_capture": file_record(output / "repository-authentication.json", 16777216),
        "dependency_closure_capture": file_record(output / "dependency-closure.json", 16777216),
    }


def main():
    commit, ids, checked, contents, environment = guards()
    lock = checked_lock(contents[OWNED[3]])
    os.umask(0o022)
    root = Path.cwd() / "ci/postgres_genesis/build-input-artifacts"
    need(not root.exists())
    root.mkdir(mode=0o700)
    inputs, output = root / "inputs", root / "output"
    inputs.mkdir(mode=0o755)
    output.mkdir(mode=0o755)
    (inputs / "source").mkdir(mode=0o755)
    for relative in OWNED:
        (inputs / Path(relative).name).write_bytes(contents[relative])
    for name in ("receipt", "review"):
        (inputs / ("c55-" + name + ".json")).write_text(lock["source_binding"][name + "_utf8"])
    public = {
        "status": "UNQUALIFIED_BUILD_INPUTS_INCOMPLETE",
        "commit": commit,
        "run_id": ids["GITHUB_RUN_ID"],
        "run_attempt": ids["GITHUB_RUN_ATTEMPT"],
        "committed_sources": checked,
        "phase": "source_download",
        "cleanup": "not_created",
        "cleanup_uncertain": False,
        "source_binding_verified": False,
        "base_packages_unchanged": False,
        "delta_complete": False,
        "offline_source_inventoried": False,
        "compile_performed": False,
        "derived_runtime_image_digest": None,
        "admission_digest": None,
        "FRESH_CANONICAL_SHA256": None,
    }
    containers: list[str | None] = []
    builder = None
    builder_identity_uncertain = False
    completed = False
    with tempfile.TemporaryDirectory(prefix="academy-builder-private-") as private:
        config = Path(private) / "docker"
        config.mkdir(mode=0o700)
        (config / "config.json").write_text("{}\n")
        docker = ["docker", "--config", str(config)]
        try:
            for name, spec in lock["sources"].items():
                download(inputs / "source" / name, spec)
            public["source_binding_verified"] = True
            public["phase"] = "base_association"
            manifest_raw = run([*docker, "buildx", "imagetools", "inspect", "--raw", BASE], environment)
            manifest = json.loads(manifest_raw)
            need(
                type(manifest) is dict and type(manifest.get("schemaVersion")) is int and manifest["schemaVersion"] == 2
            )
            need(
                manifest.get("mediaType")
                in (
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
            )
            need(
                manifest["config"]["digest"] == CONFIG
                and type(manifest["layers"]) is list
                and len(manifest["layers"]) == 14
            )
            need(
                all(
                    type(layer) is dict and DIGEST.fullmatch(layer["digest"]) is not None
                    for layer in manifest["layers"]
                )
            )
            (root / "base-manifest.json").write_bytes(manifest_raw)
            run([*docker, "pull", "--platform", "linux/amd64", BASE], environment, timeout=600)
            base = image_identity(docker, BASE, environment)
            need(base["Id"] == CONFIG and len(base["RootFS"]["Layers"]) == 14)
            need(any(value in base["RepoDigests"] for value in (BASE, "docker.io/library/" + BASE)))
            (root / "base-identity.json").write_text(json.dumps(base, sort_keys=True) + "\n")
            public["phase"] = "acquisition"
            need(not any(output.iterdir()))
            acquisition = create_container(docker, CONFIG, inputs, output, False, environment, containers)
            run([*docker, "start", "--attach", acquisition], environment, timeout=2700)
            state = inspect_container(docker, acquisition, CONFIG, inputs, output, False, environment)
            need(state["Status"] == "exited" and state["ExitCode"] == 0)
            need(read(output / "acquisition-outcome.txt", 32) == b"success\n")
            closure = json_file(output / "dependency-closure.json")
            need(closure["base_packages_unchanged"] is True and closure["delta_complete"] is True)
            need(type(closure["delta_count"]) is int and 0 < closure["delta_count"] <= 2000)
            public.update(base_packages_unchanged=True, delta_complete=True, delta_count=closure["delta_count"])
            public["builder_inputs"] = public_builder_inputs(output)
            public["phase"] = "builder_freeze"
            builder_identity_uncertain = True
            committed = run([*docker, "commit", acquisition], environment, timeout=600).strip().decode("ascii")
            need(DIGEST.fullmatch(committed) is not None)
            builder = committed
            builder_identity_uncertain = False
            identity = image_identity(docker, builder, environment)
            need(identity["Id"] == builder and identity["RootFS"]["Layers"][:14] == base["RootFS"]["Layers"])
            need(len(identity["RootFS"]["Layers"]) > 14)
            (output / "builder-identity.json").write_text(json.dumps(identity, sort_keys=True) + "\n")
            archive = output / "builder.docker.tar"
            run([*docker, "image", "save", "--output", str(archive), builder], environment, timeout=600)
            public["builder_archive"] = file_record(archive, 17179869184)
            public["builder_config_id"] = builder
            public["phase"] = "offline_source_inventory"
            inventory = output / "source-inventory"
            inventory.mkdir(mode=0o777)
            inventory.chmod(0o777)
            offline = create_container(docker, builder, inputs, output, True, environment, containers)
            run([*docker, "start", "--attach", offline], environment, timeout=600)
            state = inspect_container(docker, offline, builder, inputs, output, True, environment)
            need(state["Status"] == "exited" and state["ExitCode"] == 0)
            source = json_file(inventory / "source-result.json")
            need(
                source["status"] == "AUTHENTICATED_PGDG_SOURCE_INVENTORIED" and source["applied_patches_match"] is True
            )
            need(source["custom_patch_applied"] is False and source["configure_or_compilation_performed"] is False)
            public["offline_source_inventoried"] = True
            public["source_inventory"] = public_source_inventory(output, lock)
            completed = True
        except Exception:
            if public["phase"] == "acquisition":
                try:
                    phase = read(output / "phase.txt", 128).decode("ascii").strip()
                    if phase in PHASES:
                        public["phase"] = phase
                    if phase in (
                        "source_dependency_binding",
                        "dependency_archive_authentication",
                        "closure_verification",
                    ):
                        detail_phase = read(output / "check-phase.txt", 128).decode("ascii").strip()
                        if detail_phase in PHASES:
                            public["phase"] = detail_phase
                except Exception:
                    public["phase"] = "acquisition"
            elif public["phase"] == "offline_source_inventory":
                try:
                    detail_phase = read(output / "source-inventory/phase.txt", 128).decode("ascii").strip()
                    if detail_phase in PHASES:
                        public["phase"] = detail_phase
                except Exception:
                    public["phase"] = "offline_source_inventory"
            public["failure"] = failure_details(output)
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
            if builder_identity_uncertain:
                public["cleanup_uncertain"] = True
            if public["cleanup_uncertain"]:
                public["cleanup"] = "uncertain"
            elif containers or builder is not None:
                public["cleanup"] = "owned_resources_removed"
            else:
                public["cleanup"] = "not_created"
    public["preparation_diagnostics"] = preparation_diagnostics(output)
    if completed and not public["cleanup_uncertain"]:
        public["phase"] = "artifact_manifest"
        try:
            manifest = {}

            def refuse_walk(error):
                raise Refused from None

            # Unreadable directories and symlinks of any kind fail closed instead of being skipped.
            for directory, directories, files in root.walk(on_error=refuse_walk):
                for name in directories:
                    need(not (directory / name).is_symlink())
                for name in sorted(files):
                    path = directory / name
                    need(not path.is_symlink())
                    manifest[path.relative_to(root).as_posix()] = file_record(path, 17179869184)
            (root / "artifact-manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            public["artifact_manifest"] = file_record(root / "artifact-manifest.json", 16777216)
            public.update(status="UNQUALIFIED_BUILD_INPUTS_PREPARED", phase="complete")
        except Exception:
            public["failure"] = {"kind": "artifact_manifest_failed"}
    encoded = json.dumps(public, ensure_ascii=True, separators=(",", ":"))
    if "source_inventory" in public:
        source_view = public["source_inventory"]
        for name in sorted(source_view["common_dev_makefiles"], reverse=True):
            if len((PREFIX + encoded + "\n").encode()) <= 196608:
                break
            record = source_view["common_dev_makefiles"][name]
            record.update(text_excerpt="", omitted=True)
            source_view["projection_budget_omitted"] = True
            encoded = json.dumps(public, ensure_ascii=True, separators=(",", ":"))
        # Preserve named function/rules/configure/dependency fields before optional metadata.
        for field, counter in (
            ("common_dev_makefiles", "omitted_common_dev_makefile_count"),
            ("include_directives", "omitted_include_directive_count"),
            ("ordered_patches", "omitted_ordered_patch_count"),
        ):
            while len((PREFIX + encoded + "\n").encode()) > 196608 and source_view[field]:
                if type(source_view[field]) is dict:
                    source_view[field].pop(sorted(source_view[field])[-1])
                else:
                    source_view[field].pop()
                source_view[counter] += 1
                source_view["projection_budget_omitted"] = True
                encoded = json.dumps(public, ensure_ascii=True, separators=(",", ":"))
    need(len((PREFIX + encoded + "\n").encode()) <= 196608)
    (root / "preparation-result.json").write_text(json.dumps(public, sort_keys=True, indent=2) + "\n")
    print(PREFIX + encoded)
    return 0 if public["status"] == "UNQUALIFIED_BUILD_INPUTS_PREPARED" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print(PREFIX + '{"status":"UNQUALIFIED_BUILD_INPUTS_INCOMPLETE","phase":"hosted_guard_or_bounded_failure"}')
        raise SystemExit(1) from None

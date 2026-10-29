"""Hosted-only public inventory. Never build, push, run a server or admit an image."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BASE = "postgres@sha256:b95b87e93ceb7594715d5c71fb6e09f6fc878851ab537735d617325eb9ba8b1b"
UPSTREAM_SHA = "c1575341fa7bd40f5274ea465b34390f4dc64cdd0770af327005caaeb9f6b7ed"
KEY_FINGERPRINT = "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"
SOURCE_URLS = {
    "pgdg.dsc": "https://apt.postgresql.org/pub/repos/apt/pool/main/p/postgresql-16/postgresql-16_16.15-1.pgdg13%2B2.dsc",
    "pgdg.debian.tar.xz": "https://apt.postgresql.org/pub/repos/apt/pool/main/p/postgresql-16/postgresql-16_16.15-1.pgdg13%2B2.debian.tar.xz",
    "postgresql-16.15.tar.bz2": "https://ftp.postgresql.org/pub/source/v16.15/postgresql-16.15.tar.bz2",
    "pgdg-repository-key.asc": "https://www.postgresql.org/media/keys/ACCC4CF8.asc",
}
HOSTS = frozenset({"apt.postgresql.org", "ftp.postgresql.org", "www.postgresql.org"})
HEX40 = re.compile(r"[0-9a-f]{40}", re.ASCII)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
FINGERPRINT = re.compile(r"[0-9A-F]{40}", re.ASCII)
MAX_COMMAND_OUTPUT = 16 * 1024 * 1024


class Refused(Exception):
    """Fixed private control failure; never forward tool/HTTP exception text."""


def require(condition):
    if not condition:
        raise Refused


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_url(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in HOSTS)
    require(parsed.username is None and parsed.password is None and parsed.port is None)
    require(not parsed.query and not parsed.fragment)
    return url


class FixedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    max_repeats = 1

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, safe_url(newurl))


def command(ordinal, argv, environment, failures, *, timeout=120, status_only=False, exit_codes=None):
    try:
        result = subprocess.run(  # noqa: S603 -- only fixed source argument lists; no shell/credential inputs
            argv,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        require(len(result.stdout) <= MAX_COMMAND_OUTPUT)
        if exit_codes is not None:
            exit_codes.append(result.returncode)
        if result.returncode:
            failures.append({"command": ordinal, "reason": "nonzero_exit"})
            return result.stdout if status_only else None
        return result.stdout
    except Exception:
        failures.append({"command": ordinal, "reason": "unavailable_or_bounded_failure"})
        return None


def capture(directory, name, data):
    require(type(data) is bytes)
    (directory / name).write_bytes(data)
    return {"file": name, "bytes": len(data), "capture_sha256": sha(data)}


def acquire(directory, name, spec):
    # ProxyHandler({}) bypasses environment proxies; normal TLS verification stays on.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        FixedRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    deadline = time.monotonic() + 120
    data = bytearray()
    with opener.open(safe_url(spec["url"]), timeout=30) as response:
        final_url = safe_url(response.geturl())
        while True:
            require(time.monotonic() < deadline)
            chunk = response.read(min(65536, spec["maximum_bytes"] + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            require(len(data) <= spec["maximum_bytes"])
    observed = capture(directory, name, bytes(data))
    observed.update(url=spec["url"], final_url=final_url, expected_sha256=spec["expected_sha256"])
    expected = spec["expected_sha256"]
    observed["expected_hash_matches"] = None if expected is None else sha(data) == expected
    return observed


EXPECTED_VOLUMES: dict[str, dict[str, Any]] = {"/var/lib/postgresql/data": {}}


def metadata_container(directory, docker, environment, failures, ordinal, filename, entrypoint, arguments, config):
    """Own one metadata-only container; never start before validating its mounts."""
    record: dict[str, Any] = {"missing": True, "cleanup": "not_created", "cleanup_uncertain": False}
    created = command(
        ordinal,
        [
            *docker,
            "create",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            "65534:65534",
            "--entrypoint",
            entrypoint,
            BASE,
            *arguments,
        ],
        environment,
        failures,
    )
    if created is None or re.fullmatch(rb"[0-9a-f]{64}\n?", created) is None:
        record.update(cleanup="created_identity_unavailable", cleanup_uncertain=True)
        return record
    container = created.strip().decode("ascii")
    try:
        template = (
            '{"Image":{{json .Image}},"User":{{json .Config.User}},'
            '"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"NetworkMode":{{json .HostConfig.NetworkMode}},'
            '"Privileged":{{json .HostConfig.Privileged}},"CapDrop":{{json .HostConfig.CapDrop}},'
            '"SecurityOpt":{{json .HostConfig.SecurityOpt}},"Mounts":['
            "{{range $i,$m:=.Mounts}}{{if $i}},{{end}}"
            '{"Type":{{json $m.Type}},"Destination":{{json $m.Destination}},"RW":{{json $m.RW}}}{{end}}]}'
        )
        inspected = command(
            ordinal + 1, [*docker, "container", "inspect", "--format", template, container], environment, failures
        )
        require(inspected is not None)
        actual = json.loads(inspected)
        require(actual["Image"] == config and actual["User"] == "65534:65534")
        require(actual["ReadonlyRootfs"] is True and actual["Privileged"] is False and actual["NetworkMode"] == "none")
        require(actual["CapDrop"] == ["ALL"] and actual["SecurityOpt"] == ["no-new-privileges"])
        mounts = actual["Mounts"]
        require(type(mounts) is list and len(mounts) == 1)
        require(
            all(
                m["Type"] == "volume" and m["Destination"] in EXPECTED_VOLUMES and type(m["RW"]) is bool for m in mounts
            )
        )
        require({m["Destination"] for m in mounts} == set(EXPECTED_VOLUMES))
        # Only public target/type/RW fields persist; no host source path or ID.
        record["mounts"] = mounts
        output = command(ordinal + 2, [*docker, "start", "--attach", container], environment, failures)
        if output is not None:
            record.update(capture(directory, filename, output), missing=False)
    except Exception:
        failures.append({"command": ordinal + 1, "reason": "metadata_container_refused_before_or_during_start"})
    finally:
        removed = command(ordinal + 3, [*docker, "rm", "--force", "--volumes", container], environment, failures)
        record["cleanup"] = "owned_container_and_anonymous_volumes_removed" if removed is not None else "uncertain"
        record["cleanup_uncertain"] = removed is None
    return record


def image_inventory(directory, docker, environment, failures):
    result: dict[str, Any] = {"base_reference": BASE, "platform": "linux/amd64", "association_verified": False}
    raw = command(10, [*docker, "buildx", "imagetools", "inspect", "--raw", BASE], environment, failures)
    if raw is None:
        return result
    result["index_capture"] = capture(directory, "base-index.json", raw)
    try:
        index = json.loads(raw)
        candidates = [
            m
            for m in index["manifests"]
            if m.get("platform", {}).get("os") == "linux" and m.get("platform", {}).get("architecture") == "amd64"
        ]
        require(len(candidates) == 1 and DIGEST.fullmatch(candidates[0]["digest"]) is not None)
        child = "postgres@" + candidates[0]["digest"]
        result["observed_child_reference"] = child
        child_raw = command(11, [*docker, "buildx", "imagetools", "inspect", "--raw", child], environment, failures)
        require(child_raw is not None)
        result["child_capture"] = capture(directory, "amd64-child-manifest.json", child_raw)
        config = json.loads(child_raw)["config"]["digest"]
        require(DIGEST.fullmatch(config) is not None)
        result["observed_config_reference"] = config
        pulled = command(12, [*docker, "pull", "--platform", "linux/amd64", BASE], environment, failures, timeout=300)
        require(pulled is not None)
        # Explicit public identity fields only: no host GraphDriver paths, image
        # environment, arbitrary host configuration or credentials are captured.
        template = (
            '{"Id":{{json .Id}},"RepoDigests":{{json .RepoDigests}},"Os":{{json .Os}},'
            '"Architecture":{{json .Architecture}},"RootFS":{{json .RootFS}},"Volumes":{{json .Config.Volumes}}}'
        )
        inspected = command(13, [*docker, "image", "inspect", "--format", template, BASE], environment, failures)
        require(inspected is not None)
        identity = json.loads(inspected)
        require(identity["Id"] == config and identity["Os"] == "linux" and identity["Architecture"] == "amd64")
        require(
            any(
                reference in identity["RepoDigests"]
                for reference in (BASE, "docker.io/library/" + BASE, child, "docker.io/library/" + child)
            )
        )
        require(identity["Volumes"] == EXPECTED_VOLUMES)
        result["inspect_capture"] = capture(directory, "image-identity.json", inspected)
        result["association_verified"] = True
        for ordinal, name, entrypoint, arguments in (
            (14, "package-bom.tsv", "dpkg-query", ["-W", "-f", "${binary:Package}\t${Version}\t${Architecture}\n"]),
            (15, "postgres-version.txt", "postgres", ["--version"]),
            (16, "pg-config-configure.txt", "pg_config", ["--configure"]),
        ):
            result[name] = metadata_container(
                directory, docker, environment, failures, ordinal * 10, name, entrypoint, arguments, config
            )
            if result[name]["cleanup_uncertain"]:
                result["cleanup_uncertain"] = True
                break
    except Exception:
        failures.append({"command": 19, "reason": "image_association_unavailable"})
    # Capture SHA hashes tool stdout bytes; they are deliberately separate from
    # registry OCI digest references (CLI stdout may append a newline).
    return result


def signature_inventory(directory, environment, failures, home):
    result: dict[str, Any] = {
        "repository_key_fingerprint_expected": KEY_FINGERPRINT,
        "signature_outcome": "unavailable",
        "signer_fingerprint": None,
        "repository_key_identity_matches": False,
    }
    key, dsc = directory / "pgdg-repository-key.asc", directory / "pgdg.dsc"
    if not key.is_file() or not dsc.is_file():
        return result
    gpg = [
        "gpg",
        "--no-options",
        "--homedir",
        str(home),
        "--batch",
        "--no-tty",
        "--no-auto-key-retrieve",
        "--no-autostart",
        "--auto-key-locate",
        "clear",
    ]
    imported = command(30, [*gpg, "--import", str(key)], environment, failures)
    if imported is None:
        return result
    listing = command(31, [*gpg, "--with-colons", "--fingerprint", "--list-keys"], environment, failures)
    if listing is not None:
        fingerprints = [
            line.split(":")[9]
            for line in listing.decode("ascii", errors="strict").splitlines()
            if line.startswith("fpr:") and len(line.split(":")) > 9
        ]
        result["observed_key_fingerprints"] = [f for f in fingerprints if FINGERPRINT.fullmatch(f)]
        result["repository_key_identity_matches"] = KEY_FINGERPRINT in result["observed_key_fingerprints"]
    # Keep status stdout private until parsed. Never retain UID lines or stderr.
    exit_codes: list[int] = []
    status = command(
        32,
        [*gpg, "--status-fd", "1", "--verify", str(dsc)],
        environment,
        failures,
        status_only=True,
        exit_codes=exit_codes,
    )
    if status is None:
        result["signature_outcome"] = "not_verified_with_fetched_key"
        return result
    signers = [
        line.split()[2]
        for line in status.decode("ascii", errors="strict").splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) >= 3
    ]
    keyids = [
        line.split()[2]
        for line in status.decode("ascii", errors="strict").splitlines()
        if line.startswith(("[GNUPG:] ERRSIG ", "[GNUPG:] NO_PUBKEY ")) and len(line.split()) >= 3
    ]
    result["unverified_signer_keyids"] = sorted({key for key in keyids if re.fullmatch("[0-9A-F]{16}", key)})
    result["signature_outcome"] = "not_verified_with_fetched_key"
    if exit_codes == [0] and len(signers) == 1 and FINGERPRINT.fullmatch(signers[0]):
        result["signer_fingerprint"] = signers[0]
        result["signature_outcome"] = "valid_under_fetched_key_only"
    return result


COMMITTED_PATHS = (
    "ci/postgres_genesis/inventory.py",
    "ci/postgres_genesis/source-candidate.json",
    ".github/workflows/genesis-postgres-inventory.yml",
)


def committed_sources(commit, environment, failures):
    checked, contents = {}, {}
    require(Path(__file__).resolve() == (Path.cwd() / COMMITTED_PATHS[0]).resolve())
    for ordinal, relative in enumerate(COMMITTED_PATHS, 60):
        # All path suffixes are fixed source literals, not workflow/caller data.
        reference = commit + ":" + relative
        blob = command(ordinal, ["git", "cat-file", "blob", reference], environment, failures)
        require(blob is not None)
        oid = command(ordinal + 10, ["git", "rev-parse", "--verify", reference], environment, failures)
        require(oid is not None and re.fullmatch(rb"[0-9a-f]{40}\n?", oid) is not None)
        actual = Path(relative).read_bytes()
        require(actual == blob)  # Exact bytes; hashes are evidence, not this gate.
        checked[relative] = {
            "git_blob_oid": oid.rstrip(b"\n").decode("ascii"),
            "blob_content_sha256": sha(blob),
            "file_sha256": sha(actual),
        }
        contents[relative] = actual
    return checked, contents


def main():
    # No file creation, Docker invocation or HTTP request before hosted guards.
    require(os.environ.get("CI") == "true" and os.environ.get("GITHUB_ACTIONS") == "true")
    require(os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64")
    require(platform.system() == "Linux" and platform.machine() == "x86_64")
    require(os.environ.get("GITHUB_REPOSITORY") == "michaelayoade/dotmac_academy_app")
    commit = os.environ.get("GITHUB_SHA", "")
    require(HEX40.fullmatch(commit) is not None)
    require(
        not any(
            os.environ.get(k)
            for k in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_TLS")
        )
    )
    environment = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "TZ") if k in os.environ}
    failures: list[dict[str, Any]] = []
    head = command(1, ["git", "rev-parse", "HEAD"], environment, failures)
    require(head is not None and re.fullmatch(rb"[0-9a-f]{40}\n?", head) is not None)
    require(head.rstrip(b"\n").decode("ascii") == commit)
    require(re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get("GITHUB_RUN_ID", "")) is not None)
    require(re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get("GITHUB_RUN_ATTEMPT", "")) is not None)
    checked_sources, source_bytes = committed_sources(commit, environment, failures)
    os.umask(0o077)
    source = Path(__file__).resolve().with_name("source-candidate.json")
    candidate = json.loads(source_bytes[COMMITTED_PATHS[1]])
    require(
        candidate["status"] == "UNQUALIFIED"
        and candidate["base_image"] == BASE
        and candidate["platform"] == "linux/amd64"
    )
    require(all(candidate[name] is None for name in ("derived_image_digest", "admission_digest", "build_recipe")))
    require(set(candidate["sources"]) == set(SOURCE_URLS))
    for name, spec in candidate["sources"].items():
        require(
            spec["url"] == SOURCE_URLS[name]
            and type(spec["maximum_bytes"]) is int
            and 0 < spec["maximum_bytes"] <= 67108864
        )
        require(spec["expected_sha256"] == (UPSTREAM_SHA if name == "postgresql-16.15.tar.bz2" else None))
    directory = source.with_name("artifacts")
    require(not directory.exists())
    directory.mkdir(mode=0o700)
    report = {
        "status": "UNQUALIFIED",
        "repository": "michaelayoade/dotmac_academy_app",
        "commit": commit,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "script_sha256": checked_sources[COMMITTED_PATHS[0]]["file_sha256"],
        "source_candidate_sha256": checked_sources[COMMITTED_PATHS[1]]["file_sha256"],
        "committed_sources": checked_sources,
        "build_performed": False,
        "admission_digest": None,
        "derived_image_digest": None,
        "sources": {},
        "failures": failures,
        "trust_gaps": candidate["trust_gaps"],
    }
    report["input_source_candidate"] = capture(directory, "source-candidate.json", source_bytes[COMMITTED_PATHS[1]])
    with tempfile.TemporaryDirectory(prefix="academy-public-inventory-") as private:
        docker_config = Path(private) / "docker"
        docker_config.mkdir(mode=0o700)
        (docker_config / "config.json").write_text("{}\n")
        environment["DOCKER_CONFIG"] = str(docker_config)
        docker = ["docker", "--config", str(docker_config)]
        gpg_home = Path(private) / "gnupg"
        gpg_home.mkdir(mode=0o700)
        versions = {}
        for ordinal, tool, argv in (
            (2, "git", ["git", "--version"]),
            (3, "docker", [*docker, "--version"]),
            (4, "buildx", [*docker, "buildx", "version"]),
            (5, "gpg", ["gpg", "--no-options", "--homedir", str(gpg_home), "--batch", "--no-autostart", "--version"]),
        ):
            output = command(ordinal, argv, environment, failures)
            lines = [] if output is None else output.decode("ascii", errors="replace").splitlines()
            versions[tool] = lines[0][:200] if lines else None
        report["tool_versions"] = versions
        report["image"] = image_inventory(directory, docker, environment, failures)
        for ordinal, (name, spec) in enumerate(candidate["sources"].items(), 40):
            try:
                report["sources"][name] = acquire(directory, name, spec)
                if report["sources"][name]["expected_hash_matches"] is False:
                    failures.append({"command": ordinal, "reason": "expected_public_digest_mismatch"})
            except Exception:
                failures.append({"command": ordinal, "reason": "public_source_unavailable_or_invalid"})
                report["sources"][name] = {"missing": True, "expected_sha256": spec["expected_sha256"]}
        try:
            report["signature"] = signature_inventory(directory, environment, failures, gpg_home)
        except Exception:
            failures.append({"command": 39, "reason": "signature_inventory_unavailable"})
            report["signature"] = {"signature_outcome": "unavailable"}
    report["output_files"] = {
        p.name: {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())}
        for p in sorted(directory.iterdir())
        if p.is_file()
    }
    report["output_files_excludes"] = ["inventory.json", "inventory.sha256"]
    inventory_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    (directory / "inventory.json").write_bytes(inventory_bytes)
    (directory / "inventory.sha256").write_text(sha(inventory_bytes) + "  inventory.json\n")
    print(json.dumps({"status": "UNQUALIFIED", "failure_count": len(failures), "build_performed": False}))
    fatal = report["image"].get("cleanup_uncertain", False) or any(
        item["reason"] == "expected_public_digest_mismatch" for item in failures
    )
    return 1 if fatal else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print('{"status":"UNQUALIFIED","error":"inventory_refused"}')
        raise SystemExit(1) from None

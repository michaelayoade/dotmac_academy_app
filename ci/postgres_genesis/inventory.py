"""Hosted-only public inventory. Never build, push, run a server or admit an image."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import ssl
import stat
import subprocess
import tempfile
import time
import unicodedata
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
        require(type(index) is dict)
        if index.get("mediaType") in IMAGE_MANIFEST_MEDIA_TYPES:
            require(type(index.get("schemaVersion")) is int and index["schemaVersion"] == 2)
            require("manifests" not in index and type(index.get("layers")) is list)
            child, child_raw = BASE, raw
        else:
            candidates = [
                m
                for m in index["manifests"]
                if m.get("platform", {}).get("os") == "linux" and m.get("platform", {}).get("architecture") == "amd64"
            ]
            require(len(candidates) == 1 and DIGEST.fullmatch(candidates[0]["digest"]) is not None)
            child = "postgres@" + candidates[0]["digest"]
            child_raw = command(11, [*docker, "buildx", "imagetools", "inspect", "--raw", child], environment, failures)
        result["observed_child_reference"] = child
        require(child_raw is not None)
        result["child_capture"] = capture(directory, "amd64-child-manifest.json", child_raw)
        manifest = json.loads(child_raw)
        require(type(manifest) is dict and type(manifest.get("config")) is dict)
        config = manifest["config"].get("digest")
        require(type(config) is str and DIGEST.fullmatch(config) is not None)
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
        "status_stdout_available": False,
        "recognized_status_tokens": [],
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
    result["status_stdout_available"] = True
    # Only fixed token names escape; arguments can contain UIDs or other text.
    result["recognized_status_tokens"] = sorted(
        {
            parts[1].decode("ascii")
            for line in status.splitlines()
            if len(parts := line.split()) >= 2 and parts[0] == b"[GNUPG:]" and parts[1] in GPG_STATUS_TOKENS
        }
    )
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


PUBLIC_PREFIX = "ACADEMY_GENESIS_PUBLIC_JSON "
PUBLIC_LIMIT = 196608
PUBLIC_CAPTURE_LIMIT = 131072
PUBLIC_METADATA_FILES = ("package-bom.tsv", "postgres-version.txt", "pg-config-configure.txt")
PUBLIC_READABLE_FILES = (*PUBLIC_METADATA_FILES, "pgdg.dsc", "base-index.json")
PUBLIC_FAILURE_ORDINALS = frozenset(
    (
        1,
        2,
        3,
        4,
        5,
        10,
        11,
        12,
        13,
        19,
        30,
        31,
        32,
        39,
        40,
        41,
        42,
        43,
        60,
        61,
        62,
        70,
        71,
        72,
        140,
        141,
        142,
        143,
        150,
        151,
        152,
        153,
        160,
        161,
        162,
        163,
    )
)
PUBLIC_FAILURE_REASONS = frozenset(
    (
        "nonzero_exit",
        "unavailable_or_bounded_failure",
        "metadata_container_refused_before_or_during_start",
        "image_association_unavailable",
        "public_source_unavailable_or_invalid",
        "expected_public_digest_mismatch",
        "signature_inventory_unavailable",
    )
)
PUBLIC_TRUST_GAPS = (
    "DSC signer not established; repository key identity does not imply DSC signer identity.",
    "Unknown DSC/debian expected hashes remain null; observed hashes are candidates only.",
    "Binary-to-source relation and reproducibility unproven; no patch/build/admission is performed.",
    "Source-only proposed O_RDONLY change has not been implemented, built, qualified or pinned.",
)
DSC_BASENAMES = frozenset(
    (
        "postgresql-16_16.15.orig.tar.bz2",
        "postgresql-16_16.15.orig.tar.bz2.asc",
        "postgresql-16_16.15-1.pgdg13+2.debian.tar.xz",
    )
)
IMAGE_MANIFEST_MEDIA_TYPES = frozenset(
    (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)
MANIFEST_MEDIA_TYPES = IMAGE_MANIFEST_MEDIA_TYPES | frozenset(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )
)
GPG_STATUS_TOKENS = frozenset(
    (
        b"NEWSIG",
        b"GOODSIG",
        b"VALIDSIG",
        b"BADSIG",
        b"ERRSIG",
        b"NO_PUBKEY",
        b"NODATA",
        b"BADARMOR",
        b"UNEXPECTED",
        b"FAILURE",
        b"ERROR",
        b"EXPSIG",
        b"EXPKEYSIG",
        b"REVKEYSIG",
        b"KEYEXPIRED",
        b"SIGEXPIRED",
        b"KEYREVOKED",
    )
)


def public_hash(value, *, length=64):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value, flags=re.ASCII) is not None)
    return value


def public_owned_bytes(directory, name, record):
    # Only five fixed public captures are readable here, never arbitrary paths.
    require(name in PUBLIC_READABLE_FILES and type(record) is dict)
    require(record.get("missing", False) is False and record.get("file") == name)
    size = record.get("bytes")
    require(type(size) is int and 0 <= size <= PUBLIC_CAPTURE_LIMIT)
    expected = public_hash(record.get("capture_sha256"))
    descriptor = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size == size)
        data = stream.read(PUBLIC_CAPTURE_LIMIT + 1)
    require(len(data) == size and sha(data) == expected)
    return data


def public_text(data):
    text = data.decode("utf-8", errors="strict")
    require(all(character in "\t\n\r" or unicodedata.category(character) != "Cc" for character in text))
    return text


def public_dsc(directory, record):
    envelope = "unavailable"
    try:
        text = public_text(public_owned_bytes(directory, "pgdg.dsc", record)).replace("\r\n", "\n")
        markers = (
            "-----BEGIN PGP SIGNED MESSAGE-----",
            "-----BEGIN PGP SIGNATURE-----",
            "-----END PGP SIGNATURE-----",
        )
        envelope = (
            "no_cleartext_signature"
            if not any(marker in text for marker in markers)
            else "malformed_cleartext_signature"
        )
        if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"):
            require(all(text.count(marker) == 1 for marker in markers))
            _, separator, text = text.partition("\n\n")
            require(bool(separator))
            text, separator, signature = text.partition("\n-----BEGIN PGP SIGNATURE-----\n")
            require(bool(separator))
            _, separator, trailing = signature.partition("\n-----END PGP SIGNATURE-----")
            require(bool(separator) and not trailing.strip())
            envelope = "cleartext_signature"
        fields: dict[str, list[str]] = {}
        current = None
        for line in text.splitlines():
            if not line:
                continue
            if line.startswith((" ", "\t")):
                if current in ("Source", "Version"):
                    raise Refused
                if current == "Checksums-Sha256":
                    fields["Checksums-Sha256"].append(line.strip())
                continue
            match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9-]*):[ \t]*(.*)", line)
            if match is None:
                raise Refused
            current, value = match.groups()
            if current in ("Source", "Version", "Checksums-Sha256"):
                require(current not in fields)
                fields[current] = [value] if value else []
        require(fields.get("Source") == ["postgresql-16"] and fields.get("Version") == ["16.15-1.pgdg13+2"])
        rows, seen = [], set()
        require(2 <= len(fields.get("Checksums-Sha256", ())) <= 3)
        for line in fields["Checksums-Sha256"]:
            parts = line.split()
            require(len(parts) == 3)
            digest, count, name = parts
            public_hash(digest)
            require(re.fullmatch(r"0|[1-9][0-9]{0,8}", count, flags=re.ASCII) is not None)
            require(0 <= int(count) <= 67108864 and name in DSC_BASENAMES and name not in seen)
            seen.add(name)
            rows.append({"name": name, "sha256": digest, "bytes": int(count)})
        require({"postgresql-16_16.15.orig.tar.bz2", "postgresql-16_16.15-1.pgdg13+2.debian.tar.xz"} <= seen)
        return {
            "available": True,
            "Source": "postgresql-16",
            "Version": "16.15-1.pgdg13+2",
            "Checksums-Sha256": rows,
            "signature_envelope": envelope,
            "signature_trust_inferred": False,
        }
    except Exception:
        return {"available": False, "signature_envelope": envelope, "signature_trust_inferred": False}


def public_manifest_shape(directory, record):
    try:
        document = json.loads(public_owned_bytes(directory, "base-index.json", record))
        require(
            type(document) is dict and type(document.get("schemaVersion")) is int and document["schemaVersion"] == 2
        )
        media_type = document.get("mediaType")
        require(type(media_type) is str and media_type in MANIFEST_MEDIA_TYPES)
        shape = {
            "available": True,
            "schemaVersion": 2,
            "mediaType": media_type,
            "has_manifests": "manifests" in document,
            "has_config": "config" in document,
        }
        if "manifests" in document:
            require(type(document["manifests"]) is list and len(document["manifests"]) <= 1024)
        if "layers" in document:
            require(type(document["layers"]) is list and len(document["layers"]) <= 1024)
            shape["layer_count"] = len(document["layers"])
        if "config" in document:
            require(type(document["config"]) is dict)
            if "digest" in document["config"]:
                value = document["config"]["digest"]
                require(type(value) is str and DIGEST.fullmatch(value) is not None)
                shape["config_digest"] = value
        return shape
    except Exception:
        return {"available": False}


def public_inventory_projection(directory, report):
    require(report["status"] == "UNQUALIFIED" and report["build_performed"] is False)
    require(report["derived_image_digest"] is None and report["admission_digest"] is None)
    commit = report["commit"]
    require(type(commit) is str and HEX40.fullmatch(commit) is not None)
    run = {name: report[name] for name in ("run_id", "run_attempt")}
    require(all(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None for value in run.values()))
    checked = {}
    for name in COMMITTED_PATHS:
        record = report["committed_sources"][name]
        checked[name] = {
            "git_blob_oid": public_hash(record["git_blob_oid"], length=40),
            "blob_content_sha256": public_hash(record["blob_content_sha256"]),
            "file_sha256": public_hash(record["file_sha256"]),
        }
    image = report["image"]
    require(image["base_reference"] == BASE and image["platform"] == "linux/amd64")
    require(type(image["association_verified"]) is bool)
    image_view = {
        "base_reference": BASE,
        "platform": "linux/amd64",
        "association_verified": image["association_verified"],
    }
    for field, prefix in (("observed_child_reference", "postgres@"), ("observed_config_reference", "")):
        value = image.get(field)
        require(
            value is None
            or (type(value) is str and value.startswith(prefix) and DIGEST.fullmatch(value[len(prefix) :]) is not None)
        )
        image_view[field] = value
    metadata = {}
    for name in PUBLIC_METADATA_FILES:
        record = image.get(name)
        if record is None:
            metadata[name] = {"missing": True, "cleanup": "not_attempted", "mounts": []}
            continue
        require(type(record["missing"]) is bool and type(record["cleanup_uncertain"]) is bool)
        require(
            type(record["cleanup"]) is str
            and record["cleanup"]
            in (
                "not_created",
                "created_identity_unavailable",
                "owned_container_and_anonymous_volumes_removed",
                "uncertain",
            )
        )
        mounts = record.get("mounts", [])
        require(type(mounts) is list and len(mounts) <= 1)
        clean_mounts = []
        for mount in mounts:
            require(
                type(mount["Type"]) is str
                and mount["Type"] == "volume"
                and type(mount["Destination"]) is str
                and mount["Destination"] in EXPECTED_VOLUMES
                and type(mount["RW"]) is bool
            )
            clean_mounts.append({"type": "volume", "target": mount["Destination"], "RW": mount["RW"]})
        metadata[name] = {
            "missing": record["missing"],
            "cleanup": record["cleanup"],
            "cleanup_uncertain": record["cleanup_uncertain"],
            "mounts": clean_mounts,
        }
    image_view["metadata"] = metadata
    image_view["base_capture_shape"] = public_manifest_shape(directory, image.get("index_capture"))
    sources = {}
    for name, url in SOURCE_URLS.items():
        record = report["sources"].get(name, {})
        expected = UPSTREAM_SHA if name == "postgresql-16.15.tar.bz2" else None
        actual = record.get("capture_sha256")
        if actual is not None:
            public_hash(actual)
        size = record.get("bytes")
        require(size is None or (type(size) is int and 0 <= size <= 67108864))
        require(record.get("expected_sha256") == expected)
        require(record.get("url", url) == url)
        sources[name] = {
            "url": url,
            "actual_sha256": actual,
            "expected_sha256": expected,
            "bytes": size,
            "known_hash_match": None if expected is None or actual is None else actual == expected,
            "missing": record.get("missing", False),
        }
        require(type(sources[name]["missing"]) is bool)
    signature = report.get("signature", {})
    outcome = signature.get("signature_outcome", "unavailable")
    require(
        type(outcome) is str
        and outcome in ("unavailable", "not_verified_with_fetched_key", "valid_under_fetched_key_only")
    )
    signer = signature.get("signer_fingerprint")
    require(signer is None or (type(signer) is str and FINGERPRINT.fullmatch(signer) is not None))
    fingerprints, keyids = signature.get("observed_key_fingerprints", []), signature.get("unverified_signer_keyids", [])
    require(type(fingerprints) is list and len(fingerprints) <= 16 and type(keyids) is list and len(keyids) <= 16)
    require(all(type(value) is str and FINGERPRINT.fullmatch(value) is not None for value in fingerprints))
    require(all(type(value) is str and re.fullmatch(r"[0-9A-F]{16}", value) is not None for value in keyids))
    repository_match = signature.get("repository_key_identity_matches", False)
    require(type(repository_match) is bool)
    status_available = signature.get("status_stdout_available", False)
    status_tokens = signature.get("recognized_status_tokens", [])
    require(
        type(status_available) is bool and type(status_tokens) is list and len(status_tokens) <= len(GPG_STATUS_TOKENS)
    )
    require(all(type(value) is str and value.encode("ascii") in GPG_STATUS_TOKENS for value in status_tokens))
    failures = report["failures"]
    require(type(failures) is list and len(failures) <= 128)
    clean_failures = []
    for failure in failures:
        ordinal, reason = failure["command"], failure["reason"]
        require(
            type(ordinal) is int
            and ordinal in PUBLIC_FAILURE_ORDINALS
            and type(reason) is str
            and reason in PUBLIC_FAILURE_REASONS
        )
        clean_failures.append({"command": ordinal, "reason": reason})
    result = {
        "status": "UNQUALIFIED",
        "commit": commit,
        **run,
        "committed_sources": checked,
        "image": image_view,
        "sources": sources,
        "signature": {
            "signature_outcome": outcome,
            "signer_fingerprint": signer,
            "observed_key_fingerprints": fingerprints,
            "unverified_signer_keyids": keyids,
            "repository_key_fingerprint_expected": KEY_FINGERPRINT,
            "repository_key_identity_matches": repository_match,
            "status_stdout_available": status_available,
            "recognized_status_tokens": status_tokens,
        },
        "DSC": public_dsc(directory, report["sources"].get("pgdg.dsc")),
        "failures": clean_failures,
        "trust_gaps": PUBLIC_TRUST_GAPS,
        "build_performed": False,
        "build_recipe": None,
        "derived_image_digest": None,
        "admission_digest": None,
    }
    require(
        len((PUBLIC_PREFIX + json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n").encode())
        <= PUBLIC_LIMIT
    )
    for name in PUBLIC_METADATA_FILES:
        record = image.get(name)
        text_view: dict[str, Any] = {"available": False}
        try:
            require(image["association_verified"] is True and type(record) is dict and record.get("missing") is False)
            data = public_owned_bytes(directory, name, record)
            text_view = {"available": True, "bytes": len(data), "sha256": sha(data), "text": public_text(data)}
        except Exception:
            text_view = {"available": False, "reason": "unavailable_or_invalid_capture"}
        metadata[name]["text_capture"] = text_view
        if (
            len((PUBLIC_PREFIX + json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n").encode())
            > PUBLIC_LIMIT
        ):
            metadata[name]["text_capture"] = {"available": False, "reason": "projection_budget"}
    return result


def emit_public_inventory_projection(directory, report):
    try:
        view = public_inventory_projection(directory, report)
        encoded = json.dumps(view, ensure_ascii=True, separators=(",", ":"))
        require(len((PUBLIC_PREFIX + encoded + "\n").encode()) <= PUBLIC_LIMIT)
    except Exception:
        encoded = '{"status":"UNQUALIFIED","public_projection":"unavailable"}'
    print(PUBLIC_PREFIX + encoded)


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
    emit_public_inventory_projection(directory, report)
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

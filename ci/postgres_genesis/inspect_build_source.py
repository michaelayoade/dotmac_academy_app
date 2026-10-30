"""Fixed hosted preparation checks; never configure, compile, or execute source."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

INPUT = Path("/inputs")
OUTPUT = Path("/out")
HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
FPR = re.compile(r"[0-9A-F]{40}", re.ASCII)
REPOSITORIES = {
    "http://deb.debian.org/debian/dists/trixie/": ("trixie", "debian"),
    "http://deb.debian.org/debian/dists/trixie-updates/": ("trixie-updates", "debian"),
    "http://deb.debian.org/debian-security/dists/trixie-security/": ("trixie-security", "debian"),
    "http://apt.postgresql.org/pub/repos/apt/dists/trixie-pgdg/": ("trixie-pgdg", "pgdg"),
}
BAD_STATUS = frozenset(
    (
        b"EXPSIG",
        b"EXPKEYSIG",
        b"REVKEYSIG",
        b"KEYEXPIRED",
        b"SIGEXPIRED",
        b"KEYREVOKED",
        b"BADSIG",
        b"ERRSIG",
        b"NO_PUBKEY",
        b"NODATA",
        b"BADARMOR",
        b"UNEXPECTED",
        b"FAILURE",
        b"ERROR",
    )
)


class Refused(Exception):
    """No external text in diagnostics."""


def need(condition):
    if not condition:
        raise Refused


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum)
        data = stream.read(maximum + 1)
    need(len(data) == info.st_size)
    return data


def save(name, value):
    (OUTPUT / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def phase(name, *, source=False):
    relative = "source-inventory/phase.txt" if source else "check-phase.txt"
    (OUTPUT / relative).write_text(name + "\n")


def run(argv, *, maximum=16 * 1024 * 1024):
    result = subprocess.run(  # noqa: S603 -- fixed tool paths and checked public paths only
        argv,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=300,
        check=False,
    )
    need(result.returncode == 0 and len(result.stdout) <= maximum)
    return result.stdout


def fields(text):
    result: dict[str, str] = {}
    current = None
    for line in text.splitlines():
        need(bool(line))
        if line.startswith((" ", "\t")):
            if current is None:
                raise Refused
            result[current] += "\n" + line.strip()
        else:
            match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9-]*):[ \t]*(.*)", line)
            if match is None:
                raise Refused
            current, value = match.groups()
            need(current not in result)
            result[current] = value
    return result


def paragraphs(data):
    return [fields(p) for p in data.decode("utf-8", errors="strict").strip("\n").split("\n\n") if p]


def sha_rows(text):
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        need(len(parts) == 3)
        checksum, count, name = parts
        need(HEX.fullmatch(checksum) is not None and re.fullmatch(r"0|[1-9][0-9]{0,10}", count) is not None)
        need(name not in result and len(name) <= 512)
        result[name] = {"sha256": checksum, "bytes": int(count)}
    return result


def lock_and_sources():
    lock = json.loads(read(INPUT / "build-inputs-lock.json", 262144))
    need(lock["status"] == "UNQUALIFIED_BUILD_INPUTS" and lock["compile_permitted"] is False)
    for name, spec in lock["sources"].items():
        need(re.fullmatch(r"postgresql-16_[A-Za-z0-9.+-]+\.(?:dsc|tar\.bz2|debian\.tar\.xz)", name) is not None)
        data = read(INPUT / "source" / name, 67108864)
        need(len(data) == spec["bytes"] and digest(data) == spec["sha256"])
    return lock


def trusted_primary_fingerprints(home):
    listing = run(
        [
            "/usr/bin/gpg",
            "--no-options",
            "--homedir",
            str(home),
            "--batch",
            "--no-autostart",
            "--with-colons",
            "--fingerprint",
            "--list-keys",
        ]
    )
    values = []
    primary = False
    for line in listing.decode("utf-8", errors="strict").splitlines():
        parts = line.split(":")
        if parts[0] == "pub":
            primary = True
        elif parts[0] == "sub":
            primary = False
        elif parts[0] == "fpr" and primary:
            need(len(parts) > 9 and FPR.fullmatch(parts[9]) is not None)
            values.append(parts[9])
            primary = False
    need(bool(values) and len(values) <= 64)
    return sorted(set(values))


def release_inventory(lock):
    releases = {}
    for uri, (suite, key) in REPOSITORIES.items():
        filename = uri.removeprefix("http://").replace("/", "_") + "InRelease"
        path = OUTPUT / "apt" / "lists" / filename
        original = read(path, 4194304)
        home = Path("/tmp/academy-gpg-" + key)  # noqa: S108 -- created mode0700 in the owned disposable container
        trusted = trusted_primary_fingerprints(home)
        if key == "pgdg":
            need(trusted == [lock["pgdg_fingerprint"]])
        status = run(
            [
                "/usr/bin/gpg",
                "--no-options",
                "--homedir",
                str(home),
                "--batch",
                "--no-tty",
                "--no-auto-key-retrieve",
                "--no-autostart",
                "--auto-key-locate",
                "clear",
                "--status-fd",
                "1",
                "--verify",
                str(path),
            ]
        )
        need(original == read(path, 4194304))
        tokens = [line.split() for line in status.splitlines() if line.startswith(b"[GNUPG:] ")]
        need(not any(len(p) >= 2 and p[1] in BAD_STATUS for p in tokens))
        valid = [p for p in tokens if len(p) >= 2 and p[1] == b"VALIDSIG"]
        need(1 <= len(valid) <= 8 and (key != "pgdg" or len(valid) == 1))
        signers = []
        for row in valid:
            need(len(row) in (11, 12) and row[9] in (b"8", b"9", b"10") and row[10] == b"01")
            signer = row[2].decode("ascii", errors="strict")
            primary = row[11].decode("ascii", errors="strict") if len(row) == 12 else signer
            need(FPR.fullmatch(signer) is not None and primary in trusted)
            signers.append({"signer_fingerprint": signer, "primary_fingerprint": primary})
        text = original.decode("utf-8", errors="strict").replace("\r\n", "\n")
        need(text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"))
        _, separator, text = text.partition("\n\n")
        need(bool(separator))
        text, separator, _ = text.partition("\n-----BEGIN PGP SIGNATURE-----\n")
        need(bool(separator))
        need(all(not line.startswith("-") or line.startswith("- ") for line in text.splitlines()))
        release = fields("\n".join(line[2:] if line.startswith("- ") else line for line in text.splitlines()))
        if key == "pgdg":
            need(release.get("Origin") == "apt.postgresql.org" and release.get("Suite") == suite)
        else:
            need(release.get("Origin") == "Debian" and release.get("Codename") == suite)
            suffix = suite.removeprefix("trixie")
            need(release.get("Suite") in (suite, "stable" + suffix, "oldstable" + suffix))
        date = parsedate_to_datetime(release["Date"])
        now = datetime.now(UTC)
        need(date.tzinfo is not None and (date - now).total_seconds() <= 300)
        expiry = None
        if "Valid-Until" in release:
            expiry = parsedate_to_datetime(release["Valid-Until"])
            need(expiry.tzinfo is not None and expiry >= date and expiry > now)
        if key == "pgdg":
            need((now - date).total_seconds() <= 7 * 86400)
        releases[uri] = {
            "suite": suite,
            "keyring": key,
            "trusted_primary_fingerprints": trusted,
            "signatures": signers,
            "release_sha256": digest(original),
            "release_bytes": len(original),
            "date": date.astimezone(UTC).isoformat(),
            "valid_until": None if expiry is None else expiry.astimezone(UTC).isoformat(),
            "rows": sha_rows(release["SHA256"]),
        }
    return releases


def authenticated_indexes(releases):
    targets = paragraphs(read(OUTPUT / "apt" / "indextargets.txt", 16777216))
    indexes = []
    for target in targets:
        identifier = target.get("Identifier")
        if identifier not in ("Packages", "Sources"):
            continue
        need(target.get("Trusted") == "yes")
        uri = target["URI"]
        matches = [base for base in REPOSITORIES if uri.startswith(base)]
        need(len(matches) == 1)
        base = matches[0]
        relative = uri[len(base) :]
        need(relative == target["MetaKey"] and ".." not in relative.split("/"))
        filename = Path(target["Filename"])
        need(filename.parent == Path("/var/lib/apt/lists") and filename.name not in (".", ".."))
        path = OUTPUT / "apt" / "lists" / filename.name
        raw = read(path, 536870912)
        # apt-helper handles APT's optional local compression without altering retained bytes.
        data = run(["/usr/lib/apt/apt-helper", "cat-file", str(path)], maximum=536870912)
        need(releases[base]["rows"].get(relative) == {"sha256": digest(data), "bytes": len(data)})
        indexes.append(
            {
                "identifier": identifier,
                "repository": base,
                "path": relative,
                "capture": filename.name,
                "capture_sha256": digest(raw),
                "capture_bytes": len(raw),
                "sha256": digest(data),
                "bytes": len(data),
                "data": data,
            }
        )
    need(any(i["identifier"] == "Sources" for i in indexes))
    need(all(any(i["identifier"] == "Packages" and i["repository"] == base for i in indexes) for base in REPOSITORIES))
    return indexes


def metadata():
    lock = lock_and_sources()
    phase("metadata_signer")
    releases = release_inventory(lock)
    phase("metadata_index_hash")
    indexes = authenticated_indexes(releases)
    phase("source_dependency_binding")
    matches = []
    for index in indexes:
        if index["identifier"] == "Sources" and index["repository"].startswith("http://apt.postgresql.org/"):
            for row in paragraphs(index["data"]):
                if row.get("Package") == "postgresql-16" and row.get("Version") == lock["source_version"]:
                    matches.append(row)
    need(len(matches) == 1 and matches[0].get("Directory") == "pool/main/p/postgresql-16")
    rows = sha_rows(matches[0]["Checksums-Sha256"])
    expected = {name: {"sha256": spec["sha256"], "bytes": spec["bytes"]} for name, spec in lock["sources"].items()}
    need(set(expected) <= set(rows) <= set(expected) | {"postgresql-16_16.15.orig.tar.bz2.asc"})
    need(all(rows[name] == value for name, value in expected.items()))
    dsc = fields(read(INPUT / "source" / "postgresql-16_16.15-1.pgdg13+2.dsc", 1048576).decode().strip("\n"))
    for name in (
        "Build-Depends",
        "Build-Depends-Arch",
        "Build-Depends-Indep",
        "Build-Conflicts",
        "Build-Conflicts-Arch",
        "Build-Conflicts-Indep",
    ):
        need(" ".join(matches[0].get(name, "").split()) == " ".join(dsc.get(name, "").split()))
    save(
        "repository-authentication.json",
        {
            "status": "verified_current_repository_integrity",
            "releases": {
                uri: {key: value for key, value in row.items() if key != "rows"} for uri, row in releases.items()
            },
            "indexes": [{key: value for key, value in row.items() if key != "data"} for row in indexes],
            "source_hash_binding_matches": True,
            "dependency_fields_match_authenticated_dsc": True,
        },
    )
    return indexes


def bom(name):
    result = {}
    for line in read(OUTPUT / name, 16777216).decode("ascii").splitlines():
        parts = line.split("\t")
        need(len(parts) == 3 and parts[0] not in result and parts[2] in ("amd64", "all"))
        result[parts[0]] = parts[1:]
    return result


def closure(final):
    indexes = metadata()
    phase("closure_verification" if final else "dependency_archive_authentication")
    packages: dict[tuple[Any, Any, Any], list[tuple[dict[str, str], dict[str, Any]]]] = {}
    for index in indexes:
        if index["identifier"] != "Packages":
            continue
        for row in paragraphs(index["data"]):
            key = (row.get("Package"), row.get("Version"), row.get("Architecture"))
            packages.setdefault(key, []).append((row, index))
    records = []
    seen = set()
    total = 0
    base = bom("base-bom.tsv")
    for path in sorted((OUTPUT / "debs").glob("*.deb")):
        data = read(path, 1073741824)
        total += len(data)
        need(total <= 8589934592)
        row = fields(run(["/usr/bin/dpkg-deb", "--field", str(path)]).decode("utf-8").strip("\n"))
        key = (row["Package"], row["Version"], row["Architecture"])
        need(key not in seen and key[2] in ("amd64", "all"))
        need(key[0] not in base and key[0] + ":amd64" not in base)
        seen.add(key)
        candidates = [
            (r, i)
            for r, i in packages.get(key, [])
            if r.get("SHA256") == digest(data) and r.get("Size") == str(len(data))
        ]
        need(bool(candidates))
        chosen, index = candidates[0]
        need(bool(chosen.get("Filename")) and chosen["Filename"].startswith("pool/"))
        records.append(
            {
                "file": path.name,
                "package": key[0],
                "version": key[1],
                "architecture": key[2],
                "source": chosen.get("Source", key[0]),
                "sha256": digest(data),
                "bytes": len(data),
                "repository": index["repository"],
                "index_path": index["path"],
                "index_sha256": index["sha256"],
                "repository_filename": chosen["Filename"],
            }
        )
    need(bool(records))
    if final:
        builder = bom("builder-bom.tsv")
        need(all(builder.get(name) == value for name, value in base.items()))
        delta = {
            (name.removesuffix(":amd64"), value[0], value[1]) for name, value in builder.items() if name not in base
        }
        need(delta == seen)
        save(
            "dependency-closure.json",
            {
                "base_packages_unchanged": True,
                "delta_complete": True,
                "delta": records,
                "delta_count": len(records),
                "deb_total_bytes": total,
            },
        )


def source_inventory():
    lock = lock_and_sources()
    phase("source_extract", source=True)
    temporary = OUTPUT / "source-inventory" / "tmp"
    home = OUTPUT / "source-inventory" / "home"
    temporary.mkdir()
    home.mkdir()
    root = OUTPUT / "source-inventory" / "postgresql-16.15"
    need(not root.exists())
    log = OUTPUT / "source-inventory" / "dpkg-source.txt"
    result = subprocess.run(  # noqa: S603 -- fixed extraction invocation, authenticated input bytes
        ["/usr/bin/dpkg-source", "--extract", "/inputs/source/postgresql-16_16.15-1.pgdg13+2.dsc", str(root)],
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "TZ": "UTC",
            "TMPDIR": str(temporary),
            "HOME": str(home),
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=False,
    )
    need(len(result.stdout) <= 16777216)
    log.write_bytes(result.stdout)
    need(result.returncode == 0)
    lock_and_sources()
    phase("source_format", source=True)
    need(read(root / "debian/source/format", 128).strip() == b"3.0 (quilt)")
    vendor = run(["/usr/bin/dpkg-vendor", "--query", "Vendor"]).decode("ascii").strip()
    need(vendor == "Debian")
    phase("source_dependencies", source=True)
    run(["/usr/bin/dpkg-checkbuilddeps", str(root / "debian/control")])
    phase("source_series", source=True)
    series = root / "debian/patches/debian.series"
    if not series.exists():
        series = root / "debian/patches/series"
    series_data = read(series, 1048576)
    patches = []
    for line in series_data.decode("utf-8").splitlines():
        tokens = shlex.split(line, comments=True)
        if not tokens:
            continue
        name = tokens[0]
        path = root / "debian/patches" / name
        need(not Path(name).is_absolute() and ".." not in Path(name).parts and path.is_file())
        data = read(path, 16777216)
        patches.append({"name": name, "sha256": digest(data), "bytes": len(data), "options": tokens[1:]})
    applied = read(root / ".pc/applied-patches", 1048576).decode("utf-8").splitlines()
    need(applied == [p["name"] for p in patches])
    phase("source_tree_manifest", source=True)
    manifest = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        name = path.relative_to(root).as_posix()
        row = {"path": name, "mode": stat.S_IMODE(info.st_mode)}
        if stat.S_ISREG(info.st_mode):
            data = read(path, 134217728)
            row.update(type="file", bytes=len(data), sha256=digest(data))
        elif stat.S_ISDIR(info.st_mode):
            row.update(type="directory")
        elif stat.S_ISLNK(info.st_mode):
            need(path.resolve().is_relative_to(root.resolve()))
            row.update(type="symlink", target=os.readlink(path))
        else:
            raise Refused
        manifest.append(row)
    save("source-inventory/tree-manifest.json", manifest)
    public = OUTPUT / "source-inventory" / "public-files"
    public.mkdir()
    phase("source_public_inspection", source=True)
    files = {}
    for name in ("debian/rules", "debian/control", "debian/changelog", "src/backend/utils/init/miscinit.c"):
        data = read(root / name, 4194304)
        (public / name.replace("/", "__")).write_bytes(data)
        files[name] = {"sha256": digest(data), "bytes": len(data)}
    common = run(["/usr/bin/dpkg-query", "-L", "postgresql-common-dev"]).decode("utf-8").splitlines()
    common_files = {}
    for name in common:
        path = Path(name)
        need(path.is_absolute() and ".." not in path.parts)
        if path.is_symlink() or not path.is_file():
            continue
        data = read(path, 4194304)
        (public / ("common-dev__" + name.lstrip("/").replace("/", "__"))).write_bytes(data)
        common_files[name] = {"sha256": digest(data), "bytes": len(data)}
    need(bool(common_files))

    # Connector-readable source inspection, with raw public files retained separately.
    # Contacts are never forwarded even when they occur in authenticated source comments.
    def excerpt(data, limit=16384):
        text = data.decode("utf-8", errors="strict")
        lines = text.splitlines(keepends=True)
        kept = [
            line
            for line in lines
            if re.search(r"[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", line) is None
            and re.search(r"\b(?:Maintainer|Uploaders|Authors?|Contact|Copyright)\b", line, flags=re.IGNORECASE) is None
        ]
        filtered = "".join(kept)
        need(all(character in "\t\n\r" or ord(character) >= 32 for character in filtered))
        return {
            "sha256": digest(data),
            "bytes": len(data),
            "text_excerpt": filtered[:limit],
            "omitted": len(filtered) > limit or len(kept) != len(lines),
            "contact_lines_omitted": len(kept) != len(lines),
        }

    miscinit = read(root / "src/backend/utils/init/miscinit.c", 4194304)
    match = re.search(rb"(?m)^RecheckDataDirLockFile\(void\)\n\{", miscinit)
    if match is None:
        raise Refused
    start = match.start()
    stop = miscinit.find(b"\n}\n", match.end())
    need(stop > start and stop + 3 - start <= 32768)
    function = miscinit[start : stop + 3]
    rules = read(root / "debian/rules", 4194304)
    includes = []
    common_excerpts = {}
    # These are the actual installed package files, not invented include locations.
    for name in common_files:
        if name.endswith((".mk", ".make")):
            data = read(Path(name), 4194304)
            common_excerpts[name] = excerpt(data, 12288)
    for line in rules.decode("utf-8").splitlines():
        if re.match(r"^[ \t]*(?:-?include|sinclude)[ \t]+", line):
            need(len(line) <= 2048 and "@" not in line)
            includes.append(line)
    control = dsc_dependency_fields(lock)
    save(
        "source-inventory/source-public.json",
        {
            "vendor": "Debian",
            "series": series.relative_to(root).as_posix(),
            "series_sha256": digest(series_data),
            "ordered_patches": patches,
            "applied_patches_match": True,
            "configure_argv": lock["configure_argv"],
            "dependency_fields": control,
            "debian_rules": excerpt(rules, 32768),
            "include_directives": includes,
            "common_dev_makefiles": common_excerpts,
            "RecheckDataDirLockFile": {**excerpt(function, 32768), "source_file_sha256": digest(miscinit)},
            "packaging_preprocessing_requires_review_before_build": True,
        },
    )
    save(
        "source-inventory/source-result.json",
        {
            "status": "AUTHENTICATED_PGDG_SOURCE_INVENTORIED",
            "source_version": lock["source_version"],
            "format": "3.0 (quilt)",
            "vendor": "Debian",
            "series": series.relative_to(root).as_posix(),
            "series_sha256": digest(series_data),
            "ordered_patches": patches,
            "applied_patches_match": True,
            "public_files": files,
            "common_dev_files": common_files,
            "configure_argv": lock["configure_argv"],
            "custom_patch_applied": False,
            "configure_or_compilation_performed": False,
            "packaging_preprocessing_requires_review_before_build": True,
        },
    )
    # Retain original archives and a normalized manifest, avoiding a second mutable source tree.
    shutil.rmtree(root)


def dsc_dependency_fields(lock):
    source = fields(read(INPUT / "source" / "postgresql-16_16.15-1.pgdg13+2.dsc", 1048576).decode().strip("\n"))
    need(source.get("Source") == lock["source_package"] and source.get("Version") == lock["source_version"])
    return {
        name: source.get(name, "")
        for name in (
            "Build-Depends",
            "Build-Depends-Arch",
            "Build-Depends-Indep",
            "Build-Conflicts",
            "Build-Conflicts-Arch",
            "Build-Conflicts-Indep",
        )
    }


def main():
    need(len(sys.argv) == 2 and sys.argv[1] in ("metadata", "downloads", "closure", "source"))
    need(INPUT.is_dir() and OUTPUT.is_dir())
    if sys.argv[1] == "metadata":
        metadata()
    elif sys.argv[1] in ("downloads", "closure"):
        closure(sys.argv[1] == "closure")
    else:
        source_inventory()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # The coordinator exposes only its fixed current phase, never this exception.
        raise SystemExit(1) from None

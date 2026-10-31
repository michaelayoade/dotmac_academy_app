"""Networkless OCI assembly: one added layer over the 14 unchanged base blobs; never talks to a registry."""

from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

INPUT = Path("/inputs")
OUTPUT = Path("/out")
TARGET = "usr/lib/postgresql/16/bin/postgres"
ANCESTORS = ("usr", "usr/lib", "usr/lib/postgresql", "usr/lib/postgresql/16", "usr/lib/postgresql/16/bin")
ARCHIVE = "academy-genesis-postgres16-oci.tar"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
DIGEST = re.compile(r"sha256:([0-9a-f]{64})", re.ASCII)
BLOB = re.compile(r"blobs/sha256/([0-9a-f]{64})", re.ASCII)
MANIFEST_KEYS = frozenset(("schemaVersion", "mediaType", "config", "layers", "annotations"))
CREATED_BY = "academy-genesis C58: replace /usr/lib/postgresql/16/bin/postgres"
COMMENT = (
    "Custom Genesis-only build of PGDG postgresql-16 16.15-1.pgdg13+2 with RecheckDataDirLockFile open O_RDONLY; "
    "not an official PGDG binary"
)
TOOL_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"}


class Refused(Exception):
    """No tool or file text escapes."""


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


def file_digest(path):
    hashed = hashlib.sha256()
    total = 0
    with open(path, "rb") as stream:
        while chunk := stream.read(1048576):
            hashed.update(chunk)
            total += len(chunk)
    return hashed.hexdigest(), total


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class Tee:
    """Hash everything a consumer reads."""

    def __init__(self, stream):
        self.stream = stream
        self.hash = hashlib.sha256()
        self.total = 0

    def read(self, size=-1):
        data = self.stream.read(size)
        self.hash.update(data)
        self.total += len(data)
        return data


def normal(name):
    value = posixpath.normpath(name)
    need(not value.startswith("/") and value != ".." and not value.startswith("../"))
    return value


def preflight(layers, diff_ids, blobs):
    """Stream all base layers in order and prove the replaced path is one clean regular file."""
    record: dict[str, Any] = {}
    payload = b""
    count = 0
    directories: set[str] = set()
    for index, layer in enumerate(layers):
        match = DIGEST.fullmatch(layer["digest"])
        need(match is not None)
        with open(blobs / match.group(1), "rb") as raw:  # type: ignore[union-attr]
            tee = Tee(gzip.GzipFile(fileobj=raw))
            with tarfile.open(fileobj=tee, mode="r|") as archive:  # type: ignore[call-overload]
                for member in archive:
                    name = normal(member.name)
                    parent, base = posixpath.dirname(name), posixpath.basename(name)
                    if base == ".wh..wh..opq":
                        need(count == 0 or not (parent == "" or TARGET.startswith(parent + "/")))
                        continue
                    if base.startswith(".wh."):
                        hidden = posixpath.join(parent, base[4:])
                        need(count == 0 or not (TARGET == hidden or TARGET.startswith(hidden + "/")))
                        continue
                    if member.islnk():
                        need(normal(member.linkname) != TARGET)
                    need(not name.startswith(TARGET + "/"))
                    if name in ANCESTORS:
                        need(member.isdir())
                        directories.add(name)
                    if name == TARGET:
                        need(member.isreg() and not member.issparse())
                        need(not any(key.startswith("SCHILY.xattr.") for key in member.pax_headers))
                        stream = archive.extractfile(member)
                        need(stream is not None)
                        payload = stream.read()
                        need(len(payload) == member.size)
                        count += 1
                        record = {
                            "layer_index": index,
                            "mode": stat.S_IMODE(member.mode),
                            "uid": member.uid,
                            "gid": member.gid,
                            "uname": member.uname,
                            "gname": member.gname,
                            "mtime": int(member.mtime),
                            "bytes": len(payload),
                            "sha256": digest(payload),
                        }
            while tee.read(1048576):
                pass
            need("sha256:" + tee.hash.hexdigest() == diff_ids[index])
    need(count == 1 and set(ANCESTORS) <= directories)
    return record, payload


def build_layer(payload, binary, epoch):
    info = tarfile.TarInfo(TARGET)
    info.type = tarfile.REGTYPE
    info.size = len(payload)
    info.mode, info.uid, info.gid = binary["mode"], binary["uid"], binary["gid"]
    info.uname, info.gname, info.mtime = binary["uname"], binary["gname"], epoch
    buffer = io.BytesIO()
    with tarfile.TarFile(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def tool(argv):
    result = subprocess.run(  # noqa: S603 -- fixed binutils paths on files this step produced
        argv,
        env=TOOL_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=300,
        check=False,
    )
    need(result.returncode == 0 and len(result.stdout) <= 16777216)
    return result.stdout.decode("utf-8", errors="strict")


def elf_facts(path):
    header = tool(["/usr/bin/readelf", "-h", "-W", path])
    program = tool(["/usr/bin/readelf", "-l", "-W", path])
    dynamic = tool(["/usr/bin/readelf", "-d", "-W", path])
    needs_text = tool(["/usr/bin/readelf", "-V", "-W", path])
    sections = tool(["/usr/bin/readelf", "-S", "-W", path])
    notes = tool(["/usr/bin/readelf", "-n", "-W", path])
    symbols = tool(["/usr/bin/nm", "-D", "--defined-only", path])
    klass = re.search(r"Class:\s+(\S+)", header)
    kind = re.search(r"Type:\s+(\S+)", header)
    machine = re.search(r"Machine:\s+(.+)", header)
    need(klass is not None and kind is not None and machine is not None)
    needs: set[tuple[str, str]] = set()
    lines = needs_text.splitlines()
    for position, line in enumerate(lines):
        if line.startswith("Version needs section"):
            current = ""
            for follow in lines[position + 1 :]:
                if not follow.startswith(" "):
                    break
                library = re.search(r"File:\s+(\S+)", follow)
                if library is not None:
                    current = library.group(1)
                name = re.search(r"Name:\s+(\S+)", follow)
                if name is not None:
                    needs.add((current, name.group(1)))
    build_id = re.search(r"Build ID:\s+([0-9a-f]+)", notes)
    data = read(path, 536870912)
    banner = re.search(rb"PostgreSQL 16[ -~]{0,240}", data)
    return {
        "class": klass.group(1),  # type: ignore[union-attr]
        "type": kind.group(1),  # type: ignore[union-attr]
        "machine": machine.group(1).strip(),  # type: ignore[union-attr]
        "interpreter": re.findall(r"Requesting program interpreter:\s+(\S+?)\]", program),
        "needed": re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", dynamic),
        "defined_dynamic_symbols": sorted({line.split()[-1] for line in symbols.splitlines() if line.strip()}),
        "version_needs": sorted(needs),
        "section_names": re.findall(r"(?m)^\s*\[\s*\d+\]\s+(\.\S+)\s", sections),
        "build_id": None if build_id is None else build_id.group(1),
        "version_banner": None if banner is None else banner.group(0).decode("ascii"),
        "sha256": digest(data),
        "bytes": len(data),
    }


def elf_gates(base, derived):
    gates = {
        "elf64_x86_64_dyn": all(
            fact["class"] == "ELF64" and fact["type"] == "DYN" and "X86-64" in fact["machine"]
            for fact in (base, derived)
        ),
        "interpreter_equal": base["interpreter"] == derived["interpreter"] and len(base["interpreter"]) == 1,
        "needed_equal_in_order": base["needed"] == derived["needed"] and bool(base["needed"]),
        "defined_dynamic_symbols_equal": base["defined_dynamic_symbols"] == derived["defined_dynamic_symbols"]
        and bool(base["defined_dynamic_symbols"]),
        "version_needs_equal": base["version_needs"] == derived["version_needs"] and bool(base["version_needs"]),
    }
    need(all(gates.values()))
    return gates


def archive_facts(path):
    """Re-derive every identity from archive bytes alone; used by assembly, compare and canaries."""
    seen: dict[str, bytes | None] = {}
    sizes: dict[str, int] = {}
    with tarfile.open(path, "r") as archive:
        for member in archive:
            name = member.name.rstrip("/")
            need(name not in seen and member.uid == 0 and member.gid == 0 and not member.uname and not member.gname)
            if member.isdir():
                need(name in ("blobs", "blobs/sha256"))
                seen[name] = None
            else:
                need(member.isreg() and (name in ("oci-layout", "index.json") or BLOB.fullmatch(name) is not None))
                stream = archive.extractfile(member)
                need(stream is not None)
                hashed = hashlib.sha256()
                data = b""
                while chunk := stream.read(1048576):  # type: ignore[union-attr]
                    hashed.update(chunk)
                    if name in ("oci-layout", "index.json") or member.size <= 4194304:
                        data += chunk
                if BLOB.fullmatch(name) is not None:
                    need(BLOB.fullmatch(name).group(1) == hashed.hexdigest())  # type: ignore[union-attr]
                seen[name] = data
                sizes[name] = member.size
    need(json.loads(seen["oci-layout"] or b"") == {"imageLayoutVersion": "1.0.0"})
    index = json.loads(seen["index.json"] or b"")
    need(len(index["manifests"]) == 1 and "annotations" not in index and "annotations" not in index["manifests"][0])
    descriptor = index["manifests"][0]
    manifest_name = "blobs/sha256/" + descriptor["digest"].removeprefix("sha256:")
    manifest_bytes = seen[manifest_name]
    need(manifest_bytes is not None and descriptor["size"] == len(manifest_bytes))
    manifest = json.loads(manifest_bytes or b"")
    config_name = "blobs/sha256/" + manifest["config"]["digest"].removeprefix("sha256:")
    config_bytes = seen[config_name]
    need(config_bytes is not None and manifest["config"]["size"] == len(config_bytes))
    config = json.loads(config_bytes or b"")
    layers = manifest["layers"]
    need(len(layers) == len(config["rootfs"]["diff_ids"]) and len(layers) >= 2)
    new = layers[-1]
    new_name = "blobs/sha256/" + new["digest"].removeprefix("sha256:")
    need(sizes[new_name] == new["size"] and new["mediaType"] == OCI_LAYER)
    with tarfile.open(path, "r") as archive:
        stream = archive.extractfile(new_name)
        need(stream is not None)
        layer_blob = stream.read()  # type: ignore[union-attr]
    need(len(layer_blob) == new["size"] and "sha256:" + digest(layer_blob) == new["digest"])
    tar_bytes = gzip.decompress(layer_blob)
    need("sha256:" + digest(tar_bytes) == config["rootfs"]["diff_ids"][-1])
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as layer:
        members = layer.getmembers()
        need(len(members) == 1 and members[0].name == TARGET and members[0].isreg())
    need(set(seen) - {"blobs", "blobs/sha256", "oci-layout", "index.json"} >= {config_name, manifest_name, new_name})
    return {
        "manifest_digest": descriptor["digest"],
        "manifest_media_type": descriptor["mediaType"],
        "config_digest": manifest["config"]["digest"],
        "layer_blob_digest": new["digest"],
        "layer_diff_id": config["rootfs"]["diff_ids"][-1],
        "layer_count": len(layers),
        "blob_count": len([name for name in seen if BLOB.fullmatch(name) is not None]),
    }


def assemble():
    lock = json.loads(read(INPUT / "derived-build-lock.json", 4194304))
    epoch = lock["source_date_epoch"]
    need(type(epoch) is int)
    blobs = INPUT / "base-blobs"
    manifest_raw = read(INPUT / "base-manifest.json", 1048576)
    need(digest(manifest_raw) == lock["base_manifest_sha256"])
    base = json.loads(manifest_raw)
    need(type(base) is dict and set(base) <= MANIFEST_KEYS and base["schemaVersion"] == 2)
    need(base["mediaType"] == OCI_MANIFEST and base["config"]["mediaType"] == OCI_CONFIG)
    need(base["config"]["digest"] == lock["base_config"] and len(base["layers"]) == 14)
    need(all(layer["mediaType"] == OCI_LAYER and DIGEST.fullmatch(layer["digest"]) for layer in base["layers"]))
    dropped = sorted(base.get("annotations", {}))
    # Every base blob is hash- and size-checked again here, independent of the host fetch.
    for descriptor in [base["config"], *base["layers"]]:
        name = descriptor["digest"].removeprefix("sha256:")
        actual, total = file_digest(blobs / name)
        need(actual == name and total == descriptor["size"])
    config_bytes = read(blobs / base["config"]["digest"].removeprefix("sha256:"), 4194304)
    base_config = json.loads(config_bytes)
    need(len(base_config["rootfs"]["diff_ids"]) == 14 and type(base_config["history"]) is list)
    binary, payload_original = preflight(base["layers"], base_config["rootfs"]["diff_ids"], blobs)
    (OUTPUT / "base-postgres.original").write_bytes(payload_original)
    payload = read(OUTPUT / "postgres", 536870912)
    base_elf = elf_facts(str(OUTPUT / "base-postgres.original"))
    derived_elf = elf_facts(str(OUTPUT / "postgres"))
    need(base_elf["sha256"] == binary["sha256"] and derived_elf["sha256"] == digest(payload))
    gates = elf_gates(base_elf, derived_elf)

    tar_bytes = build_layer(payload, binary, epoch)
    layer_blob = gzip.compress(tar_bytes, compresslevel=9, mtime=0)
    diff_id = "sha256:" + digest(tar_bytes)
    layer_digest = "sha256:" + digest(layer_blob)
    stamp = datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    config = copy.deepcopy(base_config)
    config["created"] = stamp
    config["history"] = [*base_config["history"], {"created": stamp, "created_by": CREATED_BY, "comment": COMMENT}]
    config["rootfs"]["diff_ids"] = [*base_config["rootfs"]["diff_ids"], diff_id]
    untouched = ("created", "history", "rootfs")
    need(
        {k: v for k, v in config.items() if k not in untouched}
        == {k: v for k, v in base_config.items() if k not in untouched}
    )
    need(config["config"] == base_config["config"] and config["history"][:-1] == base_config["history"])
    need(
        {k: v for k, v in config["rootfs"].items() if k != "diff_ids"}
        == {k: v for k, v in base_config["rootfs"].items() if k != "diff_ids"}
    )
    new_config = compact(config)
    config_digest = "sha256:" + digest(new_config)
    manifest = compact(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {"mediaType": OCI_CONFIG, "digest": config_digest, "size": len(new_config)},
            "layers": [*base["layers"], {"mediaType": OCI_LAYER, "digest": layer_digest, "size": len(layer_blob)}],
        }
    )
    manifest_digest = "sha256:" + digest(manifest)
    index = compact(
        {
            "schemaVersion": 2,
            "manifests": [{"mediaType": OCI_MANIFEST, "digest": manifest_digest, "size": len(manifest)}],
        }
    )
    layout = compact({"imageLayoutVersion": "1.0.0"})
    memory = {
        config_digest.removeprefix("sha256:"): new_config,
        layer_digest.removeprefix("sha256:"): layer_blob,
        manifest_digest.removeprefix("sha256:"): manifest,
    }
    files = {name: blobs / name for name in (layer["digest"].removeprefix("sha256:") for layer in base["layers"])}
    need(not set(memory) & set(files))
    entries = sorted(["blobs/sha256/" + name for name in {*memory, *files}] + ["index.json", "oci-layout"])
    path = OUTPUT / ARCHIVE
    need(not path.exists())
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for directory in ("blobs", "blobs/sha256"):
            info = tarfile.TarInfo(directory)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, epoch
            archive.addfile(info)
        for name in entries:
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.mtime = tarfile.REGTYPE, 0o644, epoch
            short = name.removeprefix("blobs/sha256/")
            if name == "index.json":
                info.size = len(index)
                archive.addfile(info, io.BytesIO(index))
            elif name == "oci-layout":
                info.size = len(layout)
                archive.addfile(info, io.BytesIO(layout))
            elif short in memory:
                info.size = len(memory[short])
                archive.addfile(info, io.BytesIO(memory[short]))
            else:
                info.size = files[short].stat().st_size
                with open(files[short], "rb") as stream:
                    archive.addfile(info, stream)
    checked = archive_facts(path)
    need(checked["manifest_digest"] == manifest_digest and checked["config_digest"] == config_digest)
    need(checked["layer_blob_digest"] == layer_digest and checked["layer_diff_id"] == diff_id)
    need(checked["layer_count"] == 15 and checked["blob_count"] == 17)
    archive_sha, archive_bytes = file_digest(path)
    result = {
        "base": {
            "manifest_sha256": digest(manifest_raw),
            "config_digest": base["config"]["digest"],
            "layer_count": 14,
            "dropped_manifest_annotation_keys": dropped,
            "binary": binary,
        },
        "layer": {
            "diff_id": diff_id,
            "blob_digest": layer_digest,
            "blob_bytes": len(layer_blob),
            "tar_bytes": len(tar_bytes),
        },
        "config": {"digest": config_digest, "bytes": len(new_config)},
        "manifest": {"digest": manifest_digest, "bytes": len(manifest)},
        "archive": {"sha256": archive_sha, "bytes": archive_bytes, "name": ARCHIVE},
        "elf": {"base": base_elf, "derived": derived_elf, "gates": gates},
    }
    (OUTPUT / "assemble-facts.json").write_bytes((json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
    for directory, _directories, names in os.walk(OUTPUT):
        for name in names:
            if not os.path.islink(os.path.join(directory, name)):
                os.chmod(os.path.join(directory, name), 0o666)  # noqa: S103 -- host-removable bind-mount output


def main():
    need(len(sys.argv) == 2 and sys.argv[1] == "assemble" and INPUT.is_dir() and OUTPUT.is_dir())
    assemble()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(1) from None

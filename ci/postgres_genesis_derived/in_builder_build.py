"""Networkless builder step: extract, guard-patch one byte range, run the packaging path, compile the backend only."""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

INPUT = Path("/inputs")
OUTPUT = Path("/out")
BUILD = Path("/build")
ROOT = BUILD / "postgresql-16"
DSC = "postgresql-16_16.15-1.pgdg13+2.dsc"
MISCINIT = "src/backend/utils/init/miscinit.c"
PREFIX_MAP = "-ffile-prefix-map=/build/postgresql-16=."
HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
PHASES = (
    "lock_binding",
    "source_extract",
    "source_format",
    "source_series",
    "source_tree_manifest",
    "patch_guard_refused",
    "patch_application",
    "changelog_epoch",
    "dh_sequence",
    "autotools_update",
    "autoreconf",
    "configure",
    "configure_gates",
    "backend_compile",
    "strip",
    "facts",
    "complete",
)


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


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def save(name, value):
    (OUTPUT / name).write_bytes(encode(value))


def phase(name):
    (OUTPUT / "phase.txt").write_text(name + "\n")


def child_environment(epoch):
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": str(BUILD / "home"),
        "TMPDIR": str(BUILD / "tmp"),
        "SOURCE_DATE_EPOCH": str(epoch),
    }


def run(argv, environment, *, cwd=None, log=None, timeout=900, maximum=268435456):
    result = subprocess.run(  # noqa: S603 -- fixed tool paths, authenticated inputs, no shell
        argv,
        env=environment,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if log is not None:
        (OUTPUT / "logs" / (log + ".txt")).write_bytes(result.stdout[:maximum])
    need(result.returncode == 0 and len(result.stdout) <= maximum)
    return result.stdout


def tree_manifest(root):
    # Same algorithm as the C56 inventory (inspect_build_source.py), so the bytes are comparable.
    manifest = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        name = path.relative_to(root).as_posix()
        row: dict[str, Any] = {"path": name, "mode": stat.S_IMODE(info.st_mode)}
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
    return manifest


def guarded_substitute(data, spec):
    """Function-scoped byte substitution; every offset, length and digest is pinned (packet decision_1)."""
    need(type(data) is bytes and len(data) == spec["length"] and digest(data) == spec["sha256"])
    header, old, new = (spec[name].encode("ascii") for name in ("header", "old", "new"))
    need(data.count(header) == 1)
    start = data.index(header) + 1
    need(start == spec["header_start"])
    found = data.find(b"\n}\n", start)
    need(found >= 0)
    end = found + 3
    need(end == spec["span_end"])
    span = data[start:end]
    need(len(span) == spec["span_length"] and digest(span) == spec["span_sha256"])
    need(data.count(old) == spec["total_occurrences"] and span.count(old) == 1 and span.count(b"O_RDWR") == 1)
    need(data.index(old, start) == spec["old_index"])
    out = data[:start] + span.replace(old, new, 1) + data[end:]
    need(len(out) == spec["out_length"] and digest(out) == spec["out_sha256"])
    patched = out[start : end + len(new) - len(old)]
    need(len(patched) == spec["patched_span_length"] and digest(patched) == spec["patched_span_sha256"])
    need(out.count(old) == 1 and out.count(new) == 1)
    return out


def unified_diff_bytes(before, after, path):
    return "".join(
        difflib.unified_diff(
            before.decode().splitlines(True),
            after.decode().splitlines(True),
            "a/" + path,
            "b/" + path,
            n=3,
        )
    ).encode()


def elf_sections(data):
    need(data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1)
    (offset,) = struct.unpack_from("<Q", data, 0x28)
    entry_size, count, string_index = struct.unpack_from("<HHH", data, 0x3A)
    need(entry_size == 64 and 0 < count <= 256 and string_index < count)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + index * entry_size) for index in range(count)]
    names = data[headers[string_index][4] : headers[string_index][4] + headers[string_index][5]]
    rows = []
    for name_offset, kind, _flags, _address, position, size, *_rest in headers:
        end = names.index(b"\0", name_offset)
        content = b"" if kind == 8 else data[position : position + size]
        rows.append(
            {"name": names[name_offset:end].decode("ascii"), "type": kind, "bytes": size, "sha256": digest(content)}
        )
    return rows


def dh_commands(text):
    commands = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "debian/rules":
            need(len(parts) >= 2)
            commands.append(parts[1])
        else:
            commands.append(parts[0])
    return commands


def makefile_value(text, name):
    values = re.findall(r"(?m)^" + re.escape(name) + r"[ \t]*=[ \t]*(.*)$", text)
    need(len(values) == 1)
    return values[0]


def header_configure_args(header):
    # PG16 keeps the saved configure arguments only in pg_config.h; decode the one C string strictly.
    values = re.findall(r'(?m)^#define CONFIGURE_ARGS "((?:[^"\\\n]|\\.)*)"$', header)
    need(len(values) == 1)
    need(re.fullmatch(r'(?:[^\\]|\\[\\"])*', values[0]) is not None)
    return re.sub(r"\\(.)", r"\1", values[0])


def configure_gate_diagnostics(header, makefile, expected):
    # Diagnostics only: public build flags/paths from the generated build tree; the gates below are unchanged.
    report: dict[str, Any] = {}
    try:
        tokens = shlex.split(header_configure_args(header))
    except (Refused, ValueError):
        report["configure_args"] = "unavailable"
    else:
        report["argv_length"] = len(tokens)
        report["expected_length"] = len(expected)
        mismatches = [i for i in range(max(len(tokens), len(expected))) if tokens[i : i + 1] != expected[i : i + 1]]
        report["mismatch_count"] = len(mismatches)
        report["mismatches"] = [
            {
                "index": i,
                "observed": tokens[i] if i < len(tokens) else None,
                "expected": expected[i] if i < len(expected) else None,
            }
            for i in mismatches[:8]
        ]
    lines = re.findall(r"(?m)^CFLAGS[ \t]*=[ \t]*(.*)$", makefile)
    report["CFLAGS_line_count"] = len(lines)
    if len(lines) == 1:
        try:
            report["prefix_map_tokens"] = [
                token for token in shlex.split(lines[0]) if token.startswith("-f") and "prefix-map" in token
            ]
        except ValueError:
            report["CFLAGS_split"] = "failed"
    return report


def finish_permissions():
    # The host account must be able to remove everything this uid created in the owned bind mounts.
    for base in (BUILD, OUTPUT):
        for directory, directories, files in os.walk(base):
            for name in directories:
                if not os.path.islink(os.path.join(directory, name)):
                    os.chmod(os.path.join(directory, name), 0o777)  # noqa: S103 -- host-removable bind-mount leftovers
            for name in files:
                if not os.path.islink(os.path.join(directory, name)):
                    os.chmod(
                        os.path.join(directory, name),
                        0o666 if os.path.getsize(os.path.join(directory, name)) else 0o644,
                    )


def build():
    os.umask(0o022)
    (OUTPUT / "logs").mkdir(exist_ok=True)
    phase("lock_binding")
    lock = json.loads(read(INPUT / "derived-build-lock.json", 4194304))
    receipt = json.loads(read(INPUT / "c56-receipt.json", 1048576))
    epoch = lock["source_date_epoch"]
    need(type(epoch) is int and os.environ.get("SOURCE_DATE_EPOCH") == str(epoch))
    need(os.getuid() == 65534 and os.getgid() == 65534 and not Path("/etc/dpkg/buildflags.conf").exists())
    need(not ROOT.exists() and not any(BUILD.iterdir()))
    for name, spec in lock["sources"].items():
        data = read(INPUT / "source" / name, 67108864)
        need(len(data) == spec["bytes"] and digest(data) == spec["sha256"])
    committed = read(INPUT / "recheck-o-rdonly.diff", 65536)
    need(
        digest(committed) == lock["patch_guard"]["diff_sha256"] and len(committed) == lock["patch_guard"]["diff_bytes"]
    )
    makefile = read(INPUT / "academy-backend.mk", 4096)
    need(digest(makefile) == lock["backend_makefile"]["sha256"])
    (BUILD / "tmp").mkdir(mode=0o700)
    (BUILD / "home").mkdir(mode=0o700)
    environment = child_environment(epoch)

    phase("source_extract")
    run(["/usr/bin/dpkg-source", "--extract", "/inputs/source/" + DSC, str(ROOT)], environment, log="dpkg-source")
    phase("source_format")
    need(read(ROOT / "debian/source/format", 128).strip() == b"3.0 (quilt)")
    phase("source_series")
    series = read(ROOT / "debian/patches/series", 1048576)
    need(digest(series) == receipt["source_inventory"]["series_sha256"])
    names = [patch["name"] for patch in receipt["source_inventory"]["ordered_patches"]]
    need(len(names) == 11 and read(ROOT / ".pc/applied-patches", 1048576).decode().splitlines() == names)
    for patch in receipt["source_inventory"]["ordered_patches"]:
        data = read(ROOT / "debian/patches" / patch["name"], 16777216)
        need(len(data) == patch["bytes"] and digest(data) == patch["sha256"])

    phase("source_tree_manifest")
    before = tree_manifest(ROOT)
    reference = read(INPUT / "c56-tree-manifest.json", 134217728)
    need(encode(before) == reference)

    phase("patch_guard_refused")
    target = ROOT / MISCINIT
    original = read(target, 4194304)
    patched = guarded_substitute(original, lock["patch_guard"])
    need(unified_diff_bytes(original, patched, MISCINIT) == committed)
    phase("patch_application")
    descriptor = os.open(target, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(patched)
    need(read(target, 4194304) == patched)
    after = tree_manifest(ROOT)
    need(len(after) == len(before) and [row["path"] for row in after] == [row["path"] for row in before])
    changed = [(old, new) for old, new in zip(before, after, strict=True) if old != new]
    need(len(changed) == 1 and changed[0][0]["path"] == MISCINIT)
    need({key for key in changed[0][0] if changed[0][0][key] != changed[0][1][key]} == {"sha256", "bytes"})

    phase("changelog_epoch")
    stamp = run(["/usr/bin/dpkg-parsechangelog", "-l", "debian/changelog", "-STimestamp"], environment, cwd=ROOT)
    need(stamp.strip() == str(epoch).encode())

    phase("dh_sequence")
    sequence = run(["/usr/bin/dh", "build-arch", "--no-act"], environment, cwd=ROOT, log="dh-sequence")
    (OUTPUT / "dh-sequence.txt").write_bytes(sequence)
    commands = dh_commands(sequence.decode("utf-8", errors="strict"))
    stops = [i for i, name in enumerate(commands) if name in ("dh_auto_build", "override_dh_auto_build-arch")]
    need(bool(stops))
    leading = [name for name in commands[: stops[0]] if name != "dh_testdir"]
    need(leading == ["dh_update_autotools_config", "dh_autoreconf", "override_dh_auto_configure"])

    phase("autotools_update")
    run(["/usr/bin/dh_update_autotools_config", "-a"], environment, cwd=ROOT, log="dh_update_autotools_config")
    phase("autoreconf")
    run(["/usr/bin/dh_autoreconf", "-a"], environment, cwd=ROOT, log="dh_autoreconf", timeout=1800)
    phase("configure")
    run(
        ["/usr/bin/make", "-f", "debian/rules", "override_dh_auto_configure"],
        environment,
        cwd=ROOT,
        log="configure",
        timeout=1800,
    )

    phase("configure_gates")
    text = read(ROOT / "build/src/Makefile.global", 4194304).decode("utf-8", errors="strict")
    header = read(ROOT / "build/src/include/pg_config.h", 4194304).decode("utf-8", errors="strict")
    expected = receipt["source_inventory"]["configure_argv"]
    save("configure-gates.json", configure_gate_diagnostics(header, text, expected))
    need(shlex.split(header_configure_args(header)) == expected)
    tokens = shlex.split(makefile_value(text, "CFLAGS"))
    maps = [token for token in tokens if token.startswith("-f") and "prefix-map" in token]
    need(maps == [PREFIX_MAP])

    phase("backend_compile")
    run(
        ["/usr/bin/make", "-f", "debian/rules", "-f", "/inputs/academy-backend.mk", "academy-backend"],
        environment,
        cwd=ROOT,
        log="backend",
        timeout=3600,
    )
    built = ROOT / "build/src/backend/postgres"
    unstripped = read(built, 536870912)
    need(unstripped[:4] == b"\x7fELF")
    (OUTPUT / "postgres.unstripped").write_bytes(unstripped)
    phase("strip")
    run(
        [
            "/usr/bin/strip",
            "--remove-section=.comment",
            "--remove-section=.note",
            "-o",
            str(OUTPUT / "postgres"),
            str(OUTPUT / "postgres.unstripped"),
        ],
        environment,
        log="strip",
    )
    stripped = read(OUTPUT / "postgres", 536870912)
    need(stripped[:4] == b"\x7fELF")

    phase("facts")
    save(
        "build-facts.json",
        {
            "tree_manifest_sha256": digest(reference),
            "patched_tree_manifest_sha256": digest(encode(after)),
            "patch": {
                "path": MISCINIT,
                "source_sha256": digest(original),
                "patched_sha256": digest(patched),
                "diff_sha256": digest(committed),
            },
            "source_date_epoch": epoch,
            "dh_sequence_commands": commands,
            "configure_argv_count": len(receipt["source_inventory"]["configure_argv"]),
            "cflags_prefix_map_single": True,
            "makefile_global_sha256": digest(text.encode()),
            "postgres_unstripped": {"sha256": digest(unstripped), "bytes": len(unstripped)},
            "postgres": {"sha256": digest(stripped), "bytes": len(stripped)},
            "sections": {"unstripped": elf_sections(unstripped), "stripped": elf_sections(stripped)},
        },
    )
    phase("complete")


def main():
    need(len(sys.argv) == 2 and sys.argv[1] == "build")
    need(INPUT.is_dir() and OUTPUT.is_dir() and BUILD.is_dir())
    try:
        build()
    finally:
        with contextlib.suppress(Exception):
            finish_permissions()
            shutil.rmtree(BUILD / "tmp", ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # The coordinator reads only the fixed phase name, never this exception.
        raise SystemExit(1) from None

"""Pure static checks for the C58 derived build files; nothing here builds, runs Docker or touches a database."""

import gzip
import hashlib
import importlib.util
import io
import json
import re
import shlex
import tarfile
import urllib.request
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DERIVED = ROOT / "ci/postgres_genesis_derived"
WORKFLOW = ROOT / ".github/workflows/genesis-postgres-derived-build.yml"


def load(name):
    spec = importlib.util.spec_from_file_location("c58_test_" + name, DERIVED / (name + ".py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILD = load("in_builder_build")
COORD = load("build_derived")
ASSEMBLE = load("assemble_oci")
CAN = load("canaries")
LOCK = json.loads((DERIVED / "derived-build-lock.json").read_text())
GUARD = LOCK["patch_guard"]
OLD = GUARD["old"].encode()
NEW = GUARD["new"].encode()
HEADER = GUARD["header"].encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def synthetic(outside_before=1, inside=1, outside_after=0, repeat_header=False):
    """A miscinit-shaped file: the target line before the function (AddToDataDirLockFile) and inside it."""
    parts = [b"prefix\n"] + [b"void add(void)\n{\n" + OLD + b"}\n"] * outside_before
    function = HEADER[1:] + (b"\tint fd;\n" + OLD) * inside + b"\treturn;\n}\n"
    parts.append(b"\n" + function if not repeat_header else b"\n" + function + HEADER + b"}\n")
    parts += [b"tail\n" + OLD] * outside_after
    return b"".join(parts)


def spec_for(data, total=2):
    start = data.index(HEADER) + 1
    end = data.find(b"\n}\n", start) + 3
    span = data[start:end]
    out = data[:start] + span.replace(OLD, NEW, 1) + data[end:]
    patched = out[start : end + len(NEW) - len(OLD)]
    return {
        "length": len(data),
        "sha256": sha(data),
        "header": GUARD["header"],
        "header_start": start,
        "span_end": end,
        "span_length": len(span),
        "span_sha256": sha(span),
        "old": GUARD["old"],
        "new": GUARD["new"],
        "total_occurrences": total,
        "old_index": data.find(OLD, start),
        "out_length": len(out),
        "out_sha256": sha(out),
        "patched_span_length": len(patched),
        "patched_span_sha256": sha(patched),
    }


def test_guard_replaces_only_the_recheck_function_occurrence():
    data = synthetic()
    out = BUILD.guarded_substitute(data, spec_for(data))
    assert out.count(OLD) == 1 and out.count(NEW) == 1
    assert out.index(OLD) < out.index(HEADER) < out.index(NEW)
    assert len(out) == len(data) + 2


@pytest.mark.parametrize(
    "data",
    (
        synthetic(outside_before=0, inside=1),  # one occurrence in total
        synthetic(outside_before=0, inside=0),  # none
        synthetic(outside_before=1, inside=1, outside_after=1),  # three
        synthetic(outside_before=1, inside=2),  # two inside the function
        synthetic(outside_before=2, inside=0),  # none inside the function
        synthetic(repeat_header=True),  # header twice
    ),
)
def test_guard_refuses_wrong_occurrence_counts(data):
    with pytest.raises(BUILD.Refused):
        BUILD.guarded_substitute(data, spec_for(data))


@pytest.mark.parametrize(
    "key,delta",
    (("header_start", 1), ("span_end", 1), ("old_index", 1), ("length", 1), ("out_length", 1), ("span_length", 1)),
)
def test_guard_refuses_wrong_offsets(key, delta):
    data = synthetic()
    spec = spec_for(data)
    spec[key] += delta
    with pytest.raises(BUILD.Refused):
        BUILD.guarded_substitute(data, spec)


@pytest.mark.parametrize("key", ("sha256", "span_sha256", "out_sha256", "patched_span_sha256"))
def test_guard_refuses_wrong_hash(key):
    data = synthetic()
    spec = spec_for(data)
    spec[key] = "0" * 64
    with pytest.raises(BUILD.Refused):
        BUILD.guarded_substitute(data, spec)


def test_guard_refuses_changed_bytes_under_unchanged_spec():
    data = synthetic()
    spec = spec_for(data)
    with pytest.raises(BUILD.Refused):
        BUILD.guarded_substitute(data + b"x", spec)


def test_lock_guard_constants_are_self_consistent():
    assert GUARD["out_length"] - GUARD["length"] == 2
    assert GUARD["patched_span_length"] - GUARD["span_length"] == 2
    assert GUARD["span_end"] - GUARD["header_start"] == GUARD["span_length"]
    assert GUARD["header_start"] < GUARD["old_index"] < GUARD["span_end"]
    assert GUARD["total_occurrences"] == 2
    assert GUARD["out_sha256"] == "354d87983b76c7e7cb6c67d877a18e4058c8700ef358cf66694610e0921dfa87"
    assert OLD.replace(b"O_RDWR", b"O_RDONLY") == NEW


def test_committed_diff_and_makefile_match_the_lock():
    diff = (DERIVED / "recheck-o-rdonly.diff").read_bytes()
    assert sha(diff) == GUARD["diff_sha256"] == "9c9a6e7cd9e85777b8186cf2ba99adde166e89dd92090f3db0add830a7f5b4c9"
    assert len(diff) == GUARD["diff_bytes"] == 286
    makefile = (DERIVED / "academy-backend.mk").read_bytes()
    assert (
        makefile == b".PHONY: academy-backend\nacademy-backend:\n"
        b"\tMAKELEVEL=0 $(MAKE) -C build/src/backend generated-headers\n"
        b"\tMAKELEVEL=0 $(MAKE) -j4 -C build/src/backend all\n"
    )
    assert sha(makefile) == LOCK["backend_makefile"]["sha256"]


def test_lock_binds_the_c56_receipt_and_stays_unqualified():
    c56 = LOCK["c56"]
    assert sha(c56["receipt_utf8"].encode()) == c56["receipt_sha256"]
    receipt = json.loads(c56["receipt_utf8"])
    assert receipt["run_id"] == str(c56["run_id"]) and receipt["commit"] == c56["commit"]
    assert receipt["artifact_manifest"]["sha256"] == c56["artifact_manifest_sha256"]
    assert len(receipt["source_inventory"]["configure_argv"]) == 61
    assert LOCK["status"] == "UNQUALIFIED_DERIVED_BUILD_RECIPE"
    assert all(
        LOCK[name] is None for name in ("derived_runtime_image_digest", "admission_digest", "FRESH_CANONICAL_SHA256")
    )
    earlier = json.loads((ROOT / "ci/postgres_genesis/build-inputs-lock.json").read_text())
    assert LOCK["sources"] == {k: {"sha256": v["sha256"], "bytes": v["bytes"]} for k, v in earlier["sources"].items()}
    assert LOCK["base"] == earlier["base"] and LOCK["base_config"] == earlier["base_config"]


def test_source_date_epoch_matches_the_changelog_trailer():
    trailer = b"x\n\n -- PostgreSQL on Debian and Ubuntu <pgsql-pkg-debian@lists.postgresql.org>  Tue, 11 Aug 2026 23:37:50 +0200\n"
    assert COORD.changelog_epoch(trailer) == LOCK["source_date_epoch"] == 1786484270


def test_dh_sequence_normalisation_and_makefile_values():
    text = "dh_testdir\ndh_update_autotools_config -a\ndh_autoreconf -a\ndebian/rules override_dh_auto_configure\ndh_auto_build -a\n"
    assert BUILD.dh_commands(text) == [
        "dh_testdir",
        "dh_update_autotools_config",
        "dh_autoreconf",
        "override_dh_auto_configure",
        "dh_auto_build",
    ]
    assert BUILD.makefile_value("CFLAGS = -O2 -g\nCFLAGS_SL = -fPIC\n", "CFLAGS") == "-O2 -g"
    with pytest.raises(BUILD.Refused):
        BUILD.makefile_value("CFLAGS = a\nCFLAGS = b\n", "CFLAGS")


def test_owned_tuple_matches_files_and_workflow_triggers():
    text = WORKFLOW.read_text()
    triggers = set(re.findall(r"(?m)^      - '([^']+)'$", text))
    assert triggers == set(COORD.OWNED)
    assert all((ROOT / relative).is_file() for relative in COORD.OWNED)
    assert len(set(COORD.OWNED)) == len(COORD.OWNED) == 12
    assert not any(path.startswith("ci/postgres_genesis/") for path in COORD.OWNED)


def test_workflow_pins_permissions_and_scope():
    text = WORKFLOW.read_text()
    parsed = yaml.safe_load(text)
    assert type(parsed) is dict and parsed.get("jobs")
    assert "actions/setup-python" not in text
    uses = re.findall(r"(?m)^\s+- uses: (\S+)", text)
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", value) for value in uses)
    assert sorted(set(uses)) == [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ]
    assert text.count("actions: read") == 2 + 1  # two job grants plus the one explanatory comment
    assert re.search(r"(?m)^permissions:\n  contents: read\n", text)
    for forbidden in (
        "secrets.",
        "workflow_dispatch",
        "pull_request",
        "id-token",
        ": write",
        "--privileged",
        "docker.sock",
    ):
        assert forbidden not in text
    assert text.count("retention-days: 90") == text.count("actions/upload-artifact@") == 3
    assert "retention-days: 30" not in text
    build_job = text[text.index("\n  build:") : text.index("\n  compare:")]
    compare_job = text[text.index("\n  compare:") : text.index("\n  canaries:")]
    canary_job = text[text.index("\n  canaries:") :]
    assert "actions: read" in build_job and "actions: read" in canary_job
    assert "actions: read" not in compare_job and "permissions" not in compare_job


def test_registry_hosts_and_redirect_strip_the_bearer_token():
    assert COORD.HUB_HOSTS == (
        "auth.docker.io",
        "registry-1.docker.io",
        "production.cloudflare.docker.com",
        "production.cloudfront.docker.com",
    )
    for good in (
        "https://auth.docker.io/token?service=registry.docker.io",
        "https://production.cloudflare.docker.com/registry-v2/x?sig=1",
        "https://production.cloudfront.docker.com/registry-v2/x?sig=1",
    ):
        assert COORD.hub_url(good) == good
    for bad in (
        "http://auth.docker.io/token",
        "https://evil.example/token",
        "https://auth.docker.io:444/token",
        "https://user@auth.docker.io/token",
        "https://registry-1.docker.io.evil.example/x",
    ):
        with pytest.raises(COORD.Refused):
            COORD.hub_url(bad)
    request = urllib.request.Request("https://registry-1.docker.io/v2/x", headers={"Authorization": "Bearer t"})
    redirected = COORD.Redirect().redirect_request(
        request, None, 307, "Temporary Redirect", {}, "https://production.cloudflare.docker.com/y?sig=1"
    )
    assert redirected is not None and not redirected.has_header("Authorization")
    with pytest.raises(COORD.Refused):
        COORD.Redirect().redirect_request(request, None, 307, "Temporary Redirect", {}, "https://evil.example/y")


def test_container_spec_is_hardened():
    argv = COORD.container_spec(
        "sha256:" + "a" * 64, {"/inputs": ("/x", False), "/out": ("/y", True)}, ["LC_ALL=C"], "/out", ["s.py"]
    )
    text = " ".join(argv)
    for required in ("--network none", "--read-only", "--cap-drop=ALL", "--user 65534:65534", "no-new-privileges"):
        assert required in text
    for forbidden in ("--privileged", "--network host", "docker.sock", "--cap-add", "--pid"):
        assert forbidden not in text
    assert "dst=/inputs,readonly" in text and "dst=/out --" in text + " --"


def make_layer(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            info.mtime = 0
            if kind == "dir":
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(info)
            elif kind == "file":
                info.type, info.mode, info.size = tarfile.REGTYPE, 0o755, len(payload)
                archive.addfile(info, io.BytesIO(payload))
            elif kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, payload
                archive.addfile(info)
            elif kind == "hardlink":
                info.type, info.linkname = tarfile.LNKTYPE, payload
                archive.addfile(info)
    raw = buffer.getvalue()
    return gzip.compress(raw, mtime=0), "sha256:" + sha(raw)


DIRS = [(path, "dir", b"") for path in ASSEMBLE.ANCESTORS]
TARGET = ASSEMBLE.TARGET


def preflight(tmp_path, layers):
    blobs, descriptors, diff_ids = tmp_path, [], []
    for blob, diff_id in (make_layer(entries) for entries in layers):
        name = sha(blob)
        (blobs / name).write_bytes(blob)
        descriptors.append({"digest": "sha256:" + name})
        diff_ids.append(diff_id)
    return ASSEMBLE.preflight(descriptors, diff_ids, blobs)


def test_preflight_accepts_exactly_one_regular_file(tmp_path):
    record, payload = preflight(tmp_path, [[*DIRS, (TARGET, "file", b"\x7fELFbase")], [("other", "file", b"x")]])
    assert payload == b"\x7fELFbase" and record["layer_index"] == 0 and record["mode"] == 0o755
    assert record["sha256"] == sha(payload)


@pytest.mark.parametrize(
    "layers",
    (
        [[*DIRS, (TARGET, "file", b"a")], [(TARGET, "file", b"b")]],  # replaced in a later layer
        [DIRS],  # absent
        [[*DIRS, (TARGET, "file", b"a")], [("usr/lib/postgresql/16/bin/.wh.postgres", "file", b"")]],
        [[*DIRS, (TARGET, "file", b"a")], [("usr/lib/postgresql/16/bin/.wh..wh..opq", "file", b"")]],
        [[*DIRS, (TARGET, "file", b"a")], [("usr/lib/postgresql/.wh.16", "file", b"")]],
        [[*DIRS, (TARGET, "file", b"a")], [("link", "hardlink", TARGET)]],
        [[*DIRS, (TARGET, "symlink", "elsewhere")]],
        [
            DIRS[:3]
            + [
                ("usr/lib/postgresql/16", "symlink", "../x"),
                ("usr/lib/postgresql/16/bin", "dir", b""),
                (TARGET, "file", b"a"),
            ]
        ],
    ),
)
def test_preflight_refuses_unclean_bases(tmp_path, layers):
    with pytest.raises(ASSEMBLE.Refused):
        preflight(tmp_path, layers)


def test_preflight_refuses_a_diff_id_mismatch(tmp_path):
    blob, _ = make_layer([*DIRS, (TARGET, "file", b"a")])
    (tmp_path / sha(blob)).write_bytes(blob)
    with pytest.raises(ASSEMBLE.Refused):
        ASSEMBLE.preflight([{"digest": "sha256:" + sha(blob)}], ["sha256:" + "0" * 64], tmp_path)


def test_new_layer_is_one_deterministic_member():
    binary = {"mode": 0o755, "uid": 0, "gid": 0, "uname": "root", "gname": "root"}
    first = ASSEMBLE.build_layer(b"\x7fELFnew", binary, 1786484270)
    assert first == ASSEMBLE.build_layer(b"\x7fELFnew", binary, 1786484270)
    with tarfile.open(fileobj=io.BytesIO(first), mode="r") as archive:
        members = archive.getmembers()
    assert [m.name for m in members] == [TARGET] and members[0].isreg() and members[0].mtime == 1786484270
    assert gzip.compress(first, compresslevel=9, mtime=0) == gzip.compress(first, compresslevel=9, mtime=0)


def test_static_registry_serves_only_the_indexed_manifest(tmp_path):
    registry = load("static_registry")
    blobs = tmp_path / "blobs/sha256"
    blobs.mkdir(parents=True)
    config, layer = b'{"c":1}', b"layer"
    manifest = json.dumps(
        {
            "config": {"digest": "sha256:" + sha(config)},
            "layers": [{"digest": "sha256:" + sha(layer)}],
        }
    ).encode()
    for data in (config, layer, manifest):
        (blobs / sha(data)).write_bytes(data)
    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + sha(manifest),
                "size": len(manifest),
            }
        ],
    }
    (tmp_path / "index.json").write_text(json.dumps(index))
    descriptor, data, allowed = registry.load(tmp_path)
    assert data == manifest and descriptor["digest"] == "sha256:" + sha(manifest)
    assert allowed == {"sha256:" + sha(config), "sha256:" + sha(layer)}
    index["manifests"][0]["size"] += 1  # type: ignore[index]
    (tmp_path / "index.json").write_text(json.dumps(index))
    with pytest.raises(registry.Refused):
        registry.load(tmp_path)


def test_canary_requirements_are_hash_pinned_to_poetry_lock():
    text = (DERIVED / "canaries-requirements.txt").read_text()
    pins = re.findall(r"(?m)^([A-Za-z-]+)==(\S+) \\$", text)
    assert pins == [
        ("SQLAlchemy", "2.0.51"),
        ("psycopg", "3.3.4"),
        ("psycopg-binary", "3.3.4"),
        ("greenlet", "3.5.4"),
        ("typing-extensions", "4.16.0"),
    ]
    hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", text)
    assert len(hashes) == 6
    lock = (ROOT / "poetry.lock").read_text()
    assert all(value in lock for value in hashes)
    workflow = WORKFLOW.read_text()
    assert (
        "--require-hashes --no-deps --only-binary=:all: -r ci/postgres_genesis_derived/canaries-requirements.txt"
        in workflow
    )
    assert '"$RUNNER_TEMP/venv/bin/python" -I ci/postgres_genesis_derived/canaries.py' in workflow
    assert "poetry" not in workflow.lower() and "ci/postgres_genesis_derived/canaries-requirements.txt'" in workflow


def lock_contents(mutate):
    lock = json.loads((DERIVED / "derived-build-lock.json").read_text())
    mutate(lock)
    return {
        COORD.OWNED[1]: json.dumps(lock).encode(),
        COORD.OWNED[2]: (DERIVED / "recheck-o-rdonly.diff").read_bytes(),
        COORD.OWNED[3]: (DERIVED / "academy-backend.mk").read_bytes(),
    }


def test_review_placeholder_fails_closed_and_real_bytes_are_checked():
    pinned = COORD.checked_lock(lock_contents(lambda lock: None))[0]["c56"]
    assert pinned["review_sha256"] == "8952fb1aed96cbc8709db15d7dd6ac8b4a1b2bd832f88da82d7008c9dbc0799f"
    assert sha(pinned["review_utf8"].encode()) == pinned["review_sha256"]

    def placeholder(lock):
        lock["c56"]["review_utf8"] = COORD.REVIEW_PLACEHOLDER
        lock["c56"]["review_sha256"] = sha(COORD.REVIEW_PLACEHOLDER.encode())

    with pytest.raises(COORD.Refused):
        COORD.checked_lock(lock_contents(placeholder))
    review = json.dumps({"verdict": "ok"})

    def pin(lock):
        lock["c56"]["review_utf8"], lock["c56"]["review_sha256"] = review, sha(review.encode())

    assert COORD.checked_lock(lock_contents(pin))[0]["c56"]["review_utf8"] == review

    def wrong(lock):
        pin(lock)
        lock["c56"]["review_sha256"] = "1" * 64

    def absent(lock):
        lock["c56"]["review_utf8"] = lock["c56"]["review_sha256"] = None

    for mutate in (wrong, absent):
        with pytest.raises(COORD.Refused):
            COORD.checked_lock(lock_contents(mutate))


def test_refused_hostname_is_recorded_without_url_or_query():
    COORD.REFUSED_HOSTS.clear()
    with pytest.raises(COORD.Refused):
        COORD.hub_url("https://cdn.example.net/blob?sig=secret")
    assert COORD.REFUSED_HOSTS == ["cdn.example.net"]
    COORD.REFUSED_HOSTS.clear()


def test_configure_args_come_from_pg_config_header_strictly():
    expected = json.loads(LOCK["c56"]["receipt_utf8"])["source_inventory"]["configure_argv"]
    quoted = " " + " ".join("'" + value + "'" for value in expected)
    literal = quoted.replace("\\", "\\\\").replace('"', '\\"')
    header = '/* generated */\n#define CONFIGURE_ARGS "' + literal + '"\n#define OTHER 1\n'
    assert shlex.split(BUILD.header_configure_args(header)) == expected
    assert BUILD.configure_gate_diagnostics(header, "CFLAGS = -g\n", expected)["mismatch_count"] == 0
    for bad in ("", header + header, '#define CONFIGURE_ARGS "a\\nb"\n', '#define CONFIGURE_ARGS "a\\x41"\n'):
        with pytest.raises(BUILD.Refused):
            BUILD.header_configure_args(bad)


def test_pidfile_ready_status_is_the_padded_eight_byte_constant():
    assert CAN.PM_STATUS_READY == b"ready   " and len(CAN.PM_STATUS_READY) == 8
    source = (DERIVED / "canaries.py").read_text()
    assert '== b"ready"' not in source and source.count("PM_STATUS_READY") >= 3


def test_labelled_refusals_carry_fixed_labels_only():
    with pytest.raises(CAN.Refused) as default:
        CAN.need(False)
    assert str(default.value) == "unlabelled"
    with pytest.raises(CAN.Refused) as labelled:
        CAN.need(False, "some_label")
    assert str(labelled.value) == "some_label"
    assert CAN.start_label(1, 2, 0) == "raw_start_timeout init=1 ready2=2 line8=0"


def test_same_booleans_ignores_integer_fields():
    left = {"exited_within_75s": True, "exit_seconds": 61, "expected_log_line": True}
    right = {"exited_within_75s": True, "exit_seconds": 64, "expected_log_line": True}
    assert CAN.same_booleans(left, right)
    assert not CAN.same_booleans(left, {**right, "expected_log_line": False})


def test_wait_exit_returns_elapsed_whole_seconds():
    class Stopped:
        def running(self):
            return False

    assert CAN.wait_exit(Stopped(), 75) == 0

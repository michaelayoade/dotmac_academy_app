"""Hosted A/B comparison of two isolated replica artifacts; every equality item is recomputed from bytes."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
from typing import Any

PREFIX = "ACADEMY_GENESIS_DERIVED_COMPARE_JSON "
ARCHIVE = "academy-genesis-postgres16-oci.tar"
ITEMS = (
    "postgres_unstripped_sha256",
    "postgres_sha256",
    "layer_diff_id",
    "layer_blob_digest",
    "config_digest",
    "manifest_digest",
    "archive_sha256",
)


class Refused(Exception):
    """No file text escapes."""


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


def read_side(root, replica, common, assemble):
    root = Path(root)
    need(root.is_dir() and not root.is_symlink())
    raw = common.read(root / "artifact-manifest.json", 16777216)
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
    # build-receipt.json is written after the manifest, so it is present but not listed.
    need(set(found) == set(manifest) | {"artifact-manifest.json", "build-receipt.json"})
    for name, path in found.items():
        if name in manifest:
            need(common.file_record(path, 17179869184) == manifest[name])
    receipt = json.loads(common.read(root / "build-receipt.json", 1048576))
    need(receipt["status"] == "UNQUALIFIED_DERIVED_PAYLOAD_BUILT" and receipt["replica"] == replica)
    need(receipt["cleanup"] == "owned_resources_removed" and receipt["cleanup_uncertain"] is False)
    need(receipt["artifact_manifest"] == common.file_record(root / "artifact-manifest.json", 16777216))
    output = root / "output"
    archive = assemble.archive_facts(output / ARCHIVE)
    recomputed = {
        "postgres_unstripped_sha256": common.file_record(output / "postgres.unstripped", 536870912)["sha256"],
        "postgres_sha256": common.file_record(output / "postgres", 536870912)["sha256"],
        "layer_diff_id": archive["layer_diff_id"],
        "layer_blob_digest": archive["layer_blob_digest"],
        "config_digest": archive["config_digest"],
        "manifest_digest": archive["manifest_digest"],
        "archive_sha256": common.file_record(output / ARCHIVE, 17179869184)["sha256"],
    }
    need(recomputed == receipt["outputs"])
    return recomputed, receipt


def compare(arguments):
    common = sibling("build_derived")
    assemble = sibling("assemble_oci")
    commit, ids, checked, _contents, _environment = common.guards(common.OWNED[7])
    out = Path(arguments.out)
    need(not out.exists())
    out.mkdir(mode=0o755)
    public: dict[str, Any] = {
        "status": "UNQUALIFIED_DERIVED_AB_INCOMPLETE",
        "commit": commit,
        "run_id": ids["GITHUB_RUN_ID"],
        "run_attempt": ids["GITHUB_RUN_ATTEMPT"],
        "committed_sources": checked,
        "derived_runtime_image_digest": None,
        "admission_digest": None,
        "FRESH_CANONICAL_SHA256": None,
    }
    try:
        left, left_receipt = read_side(arguments.a, "a", common, assemble)
        right, right_receipt = read_side(arguments.b, "b", common, assemble)
        for receipt in (left_receipt, right_receipt):
            need(receipt["commit"] == commit and receipt["run_id"] == ids["GITHUB_RUN_ID"])
            need(receipt["committed_sources"] == checked)
        mismatched = [name for name in ITEMS if left[name] != right[name]]
        for name in (
            "patch",
            "elf_gates",
            "elf_records",
            "base_binary",
            "source_date_epoch",
            "candidate_manifest_digest",
        ):
            if left_receipt[name] != right_receipt[name]:
                mismatched.append(name)
        public["items"] = {
            name: {"a": left[name], "b": right[name], "equal": left[name] == right[name]} for name in ITEMS
        }
        if mismatched:
            public["status"] = "UNQUALIFIED_DERIVED_AB_MISMATCH"
            public["mismatched_items"] = mismatched
            # Bounded diagnosis: per-section tables of both replicas, stripped and unstripped.
            public["section_hashes"] = {"a": left_receipt["section_hashes"], "b": right_receipt["section_hashes"]}
        else:
            public["status"] = "UNQUALIFIED_DERIVED_AB_IDENTICAL"
            public["candidate_manifest_digest"] = left["manifest_digest"]
            public["claim"] = common.CLAIM
    except Exception:
        public["failure"] = {"kind": "compare_refused"}
    (out / "compare-receipt.json").write_text(json.dumps(public, sort_keys=True, indent=2) + "\n")
    encoded = json.dumps(public, ensure_ascii=True, separators=(",", ":"))
    need(len((PREFIX + encoded + "\n").encode()) <= 196608)
    print(PREFIX + encoded)
    return 0 if public["status"] == "UNQUALIFIED_DERIVED_AB_IDENTICAL" else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--a", required=True)
    parser.add_argument("--b", required=True)
    parser.add_argument("--out", required=True)
    need(os.environ.get("CI") == "true")
    return compare(parser.parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print(PREFIX + '{"status":"UNQUALIFIED_DERIVED_AB_INCOMPLETE","phase":"hosted_guard_or_bounded_failure"}')
        raise SystemExit(1) from None

"""Hosted-only historical authority joins using synthetic protected documents."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

SPEC = importlib.util.spec_from_file_location(
    "synthetic_promotion_history", Path(__file__).parents[1] / "candidate_promote.py"
)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
HUMAN = b"synthetic exact candidate approval record"
HASH = "a" * 64


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@pytest.fixture
def history(monkeypatch):
    files = {}

    def store(path, value):
        files[path] = copy.deepcopy(value)
        return {"path": path, "sha256": digest(value)}

    parent = {"candidate": "b" * 40, "tree": "c" * 40}
    original = {
        "attempt": HASH, "approval_record_path": "/synthetic/human",
        "approval_record_sha256": hashlib.sha256(HUMAN).hexdigest(),
    }
    parent_ref = store("/synthetic/execution", parent)
    original_ref = store("/synthetic/original", original)
    manifest = {
        "plan_sha256": HASH, "self_sha256": HASH, "common_sha256": HASH,
        "producers": {"synthetic": HASH}, "execution_approval_sha256": original_ref["sha256"],
        "candidate": parent["candidate"], "tree": parent["tree"], "source": "/synthetic/source",
        "venv": "/synthetic/venv", "previous": {"synthetic": "previous"},
        "recovery": {"synthetic": "recovery"}, "retention": "until explicit deletion approval",
        "execution_manifest": parent_ref, "execution_approval": original_ref,
    }
    manifest_ref = store("/synthetic/manifest", manifest)
    old = {
        "schema": "AcademyPromotionApproval.v1", "approved_by": "Michael",
        "approval_id": "synthetic-old-approval", **original,
        "approved_unix": 100, "expires_unix": 200,
        "manifest_sha256": manifest_ref["sha256"], "promoter_sha256": HASH,
        **{key: copy.deepcopy(manifest[key]) for key in (
            "plan_sha256", "common_sha256", "producers", "execution_approval_sha256",
            "candidate", "tree", "source", "venv", "previous", "recovery", "retention",
        )}, "authorized_phases": ["promote"],
    }
    current = dict(old, approval_id="synthetic-current-approval", approved_unix=250, expires_unix=350)
    current_ref = store("/synthetic/current", current)
    evidence = object.__new__(P.Evidence)
    evidence.active_authority = {
        "kind": "promotion", "phase": "promote", "manifest": manifest_ref, "approval": current_ref,
    }
    evidence.promoter, evidence.m, evidence.a = copy.deepcopy(manifest), copy.deepcopy(parent), copy.deepcopy(current)
    evidence.promotion_manifest_hash = manifest_ref["sha256"]
    evidence.promotion_approval_hash = current_ref["sha256"]
    evidence.manifest_hash, evidence.approval_hash = parent_ref["sha256"], original_ref["sha256"]
    evidence.execution_approval = original_ref
    common = SimpleNamespace(approval=Mock())
    monkeypatch.setattr(P, "COMMON", common)
    monkeypatch.setattr(P.time, "time", lambda: 300)
    monkeypatch.setattr(P, "root_read", lambda path: HUMAN if path == "/synthetic/human" else b"wrong record")
    monkeypatch.setattr(P, "load", lambda path: (copy.deepcopy(files[path]), digest(files[path])))
    return SimpleNamespace(
        files=files, store=store, old=old, current=current, manifest=manifest,
        manifest_hash=manifest_ref["sha256"], evidence=evidence, common=common,
    )


def validate(h, started=110, finished=120, phase="promote"):
    h.evidence.validate_historical_promotion(h.old, h.manifest, h.manifest_hash, phase, started, finished)


def test_expired_original_window_uses_separately_current_authority(history):
    validate(history)
    history.common.approval.assert_called_once_with(
        history.files["/synthetic/original"], history.evidence.manifest_hash,
        history.files["/synthetic/execution"], "quiesce", historical=True,
    )


@pytest.mark.parametrize("started,finished,reason", [
    (99, 110, "historical_approval_window"),
    (110, 200, "historical_approval_window"),
    (120, 110, "historical_observation_interval"),
    (110, 301, "historical_observation_interval"),
    (True, 120, "historical_observation_interval"),
    (110, 120.0, "historical_observation_interval"),
    (-1, 120, "historical_observation_interval"),
])
def test_original_observation_interval_is_not_refreshed(history, started, finished, reason):
    with pytest.raises(ValueError, match=reason):
        validate(history, started, finished)


@pytest.mark.parametrize("field,value,reason", [
    ("approved_unix", True, "historical_approval_window"),
    ("expires_unix", 3701, "historical_approval_window"),
    ("expires_unix", 100, "historical_approval_window"),
    ("approval_record_path", "/synthetic/another-human", "actual_approval_record"),
    ("attempt", "d" * 64, "historical_same_actual_human_record_attempt"),
    ("authorized_phases", ["resume"], "authorized_phase"),
    ("manifest_sha256", "d" * 64, "approval_hash_bindings"),
])
def test_historical_envelope_bindings_remain_strict(history, field, value, reason):
    history.old[field] = value
    with pytest.raises(ValueError, match=reason):
        validate(history)


def test_cross_phase_history_refused(history):
    with pytest.raises(ValueError, match="historical_same_promotion_phase"):
        validate(history, phase="resume")


@pytest.mark.parametrize("path,field,value,reason", [
    ("/synthetic/manifest", "source", "/synthetic/changed", "historical_identical_promotion_manifest"),
    ("/synthetic/current", "expires_unix", 300, "historical_current_promotion_approval"),
    ("/synthetic/execution", "tree", "d" * 40, "historical_original_execution_parent"),
    ("/synthetic/original", "attempt", "d" * 64, "historical_original_execution_parent"),
])
def test_protected_document_drift_is_not_accepted(history, path, field, value, reason):
    history.files[path][field] = value
    with pytest.raises(ValueError, match=reason):
        validate(history)


@pytest.mark.parametrize("approved,expires", [(200, 300), (301, 350), (True, 350), (250, 3851)])
def test_current_authority_must_be_live_even_when_history_is_valid(history, approved, expires):
    current = dict(history.current, approved_unix=approved, expires_unix=expires)
    ref = history.store("/synthetic/current", current)
    history.evidence.a = current
    history.evidence.active_authority["approval"] = ref
    history.evidence.promotion_approval_hash = ref["sha256"]
    with pytest.raises(ValueError, match="approval_window"):
        validate(history)


def test_identical_manifest_bytes_at_another_protected_path(history):
    ref = history.store("/synthetic/manifest-alias", history.manifest)
    history.evidence.active_authority["manifest"] = ref
    validate(history)

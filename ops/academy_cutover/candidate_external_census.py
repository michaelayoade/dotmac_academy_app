"""Root-private source census preparation; no application imports or DB connections.

Only local supported-gate and selected stopped-unit observations are implemented.
They are NOT a full sender census. Every eight-domain census and remote observation
adapter remains explicitly unavailable; no caller-provided observed dictionary is
accepted. Source bundles never create authority or refresh historical facts.
"""

import os
import socket
import time
from pathlib import Path

DOMAINS = (
    "installed/loaded system units and activation paths",
    "relevant user managers and accounts/namespaces",
    "running processes",
    "cron/anacron/at scheduling",
    "container daemons/workloads/start mechanisms",
    "database sessions AND principals/capabilities",
    "manual execution paths",
    "external mail issuers/outbox consumers",
)
BUCKETS = ("supported", "legacy", "manual", "external")
BUNDLE_FIELDS = (
    "schema",
    "receipt_name",
    "receipt_sha256",
    "candidate",
    "tree",
    "attempt",
    "role",
    "hostname",
    "producer_sha256",
    "execution_manifest_sha256",
    "execution_approval_sha256",
    "authority_scope_sha256",
    "active_authority",
    "observed_unix_started",
    "observed_unix_finished",
    "gate_epoch",
    "sources",
)


def _pin(C, ref):
    C.exact(ref, ("path", "sha256"))
    C.hexvalue(ref["sha256"])
    raw = C.read_bytes(ref["path"], limit=10_000_000, private=True, root_file=True, mode=0o600)
    C.require(C.digest(raw) == ref["sha256"], "census_protected_source_hash")
    return raw


def _json(C, ref):
    return C.decode(_pin(C, ref))


def _refs(C, refs):
    C.require(type(refs) is list and 0 < len(refs) <= 1000, "census_source_refs")
    seen = set()
    for ref in refs:
        _pin(C, ref)
        C.require(ref["path"] not in seen, "census_duplicate_source")
        seen.add(ref["path"])


def load_scope(C, m):
    """Validate frozen declared scope and actual operator bytes; returns actual pin.

    Validation establishes a declaration only. It cannot mark observation adapters
    implemented, classify unknown objects, or establish completed current coverage.
    """
    # The manifest pins freeze BYTES, not an inline freeze object. Reopen and
    # validate this provenance independently of any consumer's prior validation.
    frozen = _json(C, m["freeze"])
    C.exact(
        frozen,
        (
            "schema",
            "candidate",
            "tree",
            "ci_evidence_sha256",
            "source_review_sha256",
            "dependency_review_sha256",
            "recovery_review_sha256",
            "acceptance_harnesses_sha256",
            "executor_independent_review_sha256",
            "authority_scope",
        ),
    )
    C.require(
        frozen["schema"] == "AcademyExecutionFreeze.v2" and all(frozen[k] == m[k] for k in ("candidate", "tree")),
        "census_actual_freeze_identity",
    )
    for field in set(frozen) - {"schema", "candidate", "tree", "authority_scope"}:
        C.hexvalue(frozen[field])
    ref = frozen["authority_scope"]
    value = _json(C, ref)
    C.exact(
        value,
        (
            "schema",
            "candidate",
            "tree",
            "hosts",
            "operator_scope_record",
            "domains",
            "authority_membership",
            "classification_policy",
            "discovery_refs",
            "coverage_complete",
            "unresolved_coverage",
        ),
    )
    C.require(value["schema"] == "AcademyAuthorityScope.v1", "census_scope_schema")
    C.require(all(value[k] == m[k] for k in ("candidate", "tree")), "census_scope_candidate")
    C.exact(value["hosts"], ("web", "lab"))
    C.require(value["hosts"] == {r: m["roles"][r]["hostname"] for r in ("web", "lab")}, "census_scope_hosts")
    C.require(
        value["classification_policy"] == "positive_evidence_every_object_no_marker_absence_is_not_non_sender",
        "census_positive_classification_policy",
    )
    operator = value["operator_scope_record"]
    C.exact(operator, ("schema", "response", "candidate", "tree", "hosts", "manual_scope", "external_scope"))
    C.require(operator["schema"] == "AcademyOperatorSenderScope.v1", "census_operator_schema")
    C.require(all(operator[k] == value[k] for k in ("candidate", "tree", "hosts")), "census_operator_identity")
    response = _pin(C, operator["response"])
    C.require(response.strip() and len(response) <= 2_000_000, "census_operator_actual_response_required")
    for field in ("manual_scope", "external_scope"):
        item = operator[field]
        C.exact(item, ("status", "authority_ids", "response_sha256"))
        C.require(
            item["status"] == "answered" and item["response_sha256"] == C.digest(response), "census_operator_unanswered"
        )
        _ids(C, item["authority_ids"])
    C.exact(value["authority_membership"], ("web", "lab"))
    for buckets in value["authority_membership"].values():
        C.exact(buckets, BUCKETS)
        seen = set()
        for bucket, ids in buckets.items():
            _ids(C, ids)
            C.require(not seen.intersection(ids), "census_scope_disjoint_authorities")
            seen.update(ids)
            C.require(bucket != "supported" or ids, "census_supported_never_absent")
        for bucket in ("manual", "external"):
            C.require(
                set(buckets[bucket]) <= set(operator[bucket + "_scope"]["authority_ids"]), "census_operator_membership"
            )
    C.exact(value["domains"], DOMAINS)
    for domain in DOMAINS:
        item = value["domains"][domain]
        C.exact(item, ("hosts", "discovery_refs"))
        C.require(item["hosts"] == ["lab", "web"], "census_domain_both_hosts")
        _refs(C, item["discovery_refs"])
    _refs(C, value["discovery_refs"])
    C.require(type(value["coverage_complete"]) is bool, "census_scope_coverage_boolean")
    C.require(
        type(value["unresolved_coverage"]) is list and len(value["unresolved_coverage"]) <= 1000, "census_scope_gaps"
    )
    for gap in value["unresolved_coverage"]:
        C.exact(gap, ("domain", "role", "reason"))
        C.require(
            gap["domain"] in DOMAINS
            and gap["role"] in ("web", "lab")
            and type(gap["reason"]) is str
            and 0 < len(gap["reason"]) <= 1000,
            "census_scope_gap",
        )
    C.require(not value["coverage_complete"] or not value["unresolved_coverage"], "census_complete_has_no_gaps")
    return value, ref["sha256"]


def _ids(C, ids):
    C.require(type(ids) is list and len(ids) <= 1000 and ids == sorted(set(ids)), "census_sorted_unique_ids")
    for authority in ids:
        C.hexvalue(authority)


def _authority(C, m, evidence, active):
    """Independently reopen exact authority bytes before using existing validator."""
    C.exact(active, ("kind", "phase", "manifest", "approval"))
    C.require(active["kind"] in ("execution", "promotion"), "census_active_authority_kind")
    manifest = _json(C, active["manifest"])
    approval = _json(C, active["approval"])
    C.require(callable(getattr(evidence, "validate_active_authority", None)), "census_authority_validator_required")
    evidence.validate_active_authority(approval, manifest, active["manifest"]["sha256"], active["phase"])
    C.require(manifest["candidate"] == m["candidate"] and manifest["tree"] == m["tree"], "census_authority_candidate")
    C.require(approval["attempt"] == evidence.a["attempt"], "census_authority_attempt")
    if active["kind"] == "execution":
        C.require(
            manifest == m
            and active["manifest"]["sha256"] == evidence.manifest_hash
            and active["approval"]["sha256"] == evidence.approval_hash,
            "census_original_execution_authority",
        )
        original = approval
    else:
        original_ref = evidence.execution_approval
        original = _json(C, original_ref)
        C.require(
            original_ref["sha256"] == evidence.approval_hash
            and manifest["execution_manifest"]["sha256"] == evidence.manifest_hash
            and manifest["execution_approval"] == original_ref
            and _json(C, manifest["execution_manifest"]) == m,
            "census_promotion_original_execution_parent",
        )
        # Historical execution envelope may be expired. Validate its original
        # exact human record and technical binding without demanding it be current.
        C.approval(original, evidence.manifest_hash, m, "quiesce", historical=True)
    C.require(
        original["attempt"] == approval["attempt"]
        and original["approval_record_sha256"] == approval["approval_record_sha256"]
        and original["approval_record_path"] == approval["approval_record_path"],
        "census_same_actual_human_record_attempt",
    )
    return original


def _local(C, m, role):
    C.require(role in ("web", "lab") and os.geteuid() == 0, "census_root_role")
    C.require(socket.gethostname() == m["roles"][role]["hostname"], "census_remote_observation_adapter_unimplemented")


def _context(ctx):
    C = ctx["common"]
    C.exact(ctx, ("common", "manifest", "approval", "evidence", "role", "active_authority", "output"))
    m, evidence, role = ctx["manifest"], ctx["evidence"], ctx["role"]
    C.require(m == evidence.m and ctx["approval"] == evidence.a, "census_context_is_plumbing_only")
    C.require(ctx["active_authority"] == evidence.active_authority, "census_active_context")
    _local(C, m, role)
    _authority(C, m, evidence, ctx["active_authority"])
    # Verify own actual protected bytes instead of trusting a digest-shaped pin.
    helper = Path(__file__)
    C.require(helper.name == "candidate_external_census.py", "census_fixed_helper")
    own = C.read_bytes(helper, limit=2_000_000, private=True, root_file=True, mode=0o600)
    C.require(C.digest(own) == m["helpers"]["external_census"], "census_producer_actual_bytes")
    scope, scope_hash = load_scope(C, m)
    return C, m, evidence, role, scope, scope_hash


def _gap(C):
    C.require(False, "census_coverage_gap_unimplemented_adapters: " + "; ".join(DOMAINS))


def observe_pre_quiescence(ctx):
    """No completed inventory until all objects in all domains have real adapters."""
    C, *_ = _context(ctx)
    _gap(C)


def observe_exclusion(ctx, maintenance_status):
    """Neither idle authorities nor selected unit stops establish global absence."""
    C, m, evidence, role, *_ = _context(ctx)
    C.require(maintenance_status in ("fenced", "adopted_and_fenced", "resumed"), "census_maintenance_status")
    C.maintenance_observation(m, evidence, evidence.a, role, maintenance_status)
    _gap(C)


def _gate(C, m, evidence, role):
    C.require(role == "web", "census_gate_web_only")
    ready = C.gate_ready(evidence, m, evidence.a, role)
    inode, pid = ready["lock_inode"], ready["supervisor_pid"]
    key = f"{os.major(inode[0]):02x}:{os.minor(inode[0]):02x}:{inode[1]}".encode()
    rows = C.proc_bytes(Path("/proc/locks"), 8_000_000).splitlines()
    matches = [r for r in rows if r.split()[1:6] == [b"FLOCK", b"ADVISORY", b"WRITE", str(pid).encode(), key]]
    C.require(len(matches) == 1, "census_exact_gate_kernel_lease")
    return {
        k: ready[k]
        for k in (
            "hold_id",
            "owner_record_sha256",
            "gate_approval_sha256",
            "supervisor_pid",
            "supervisor_start_ticks",
            "lock_inode",
        )
    } | {"lock_kernel_row": matches[0].decode("ascii"), "state_sha256": C.digest(b"HELD\n")}


def _stopped(C, m, evidence, role):
    prior = evidence.phase("quiesce-" + role, role, "quiesce", fresh=False)
    stopped = C.stopped(role, m)
    return {
        "units": stopped["units"],
        "application_pids": stopped["matching_application_pids"],
        "preserved": C.preserved(role, m),
        "quiesce_receipt_sha256": evidence.used["quiesce-" + role]["sha256"],
        "stop_completed_unix": prior["observations"]["stop_completed_unix"],
        "gate_epoch": C.gate_ready(evidence, m, evidence.a, role)["hold_id"],
    }


def _write(ctx, parts, name, receipt, facts, started):
    C, m, evidence, role, _, scope_hash = parts
    finished = int(time.time())
    C.require(started <= finished, "census_observation_clock")
    output = Path(ctx["output"])
    # Existing common API walks every directory without symlinks and requires
    # private root custody. No caller-selected loader, provider or command exists.
    fd = C.directory_fd(output, root_only=True, private=True)
    os.close(fd)
    source = {
        "schema": "AcademyLocalCensusSource.v1",
        "adapter": name.split("-")[0],
        "candidate": m["candidate"],
        "tree": m["tree"],
        "attempt": evidence.a["attempt"],
        "role": role,
        "hostname": m["roles"][role]["hostname"],
        "producer_sha256": m["helpers"]["external_census"],
        "observed_unix_started": started,
        "observed_unix_finished": finished,
        "facts": facts,
    }
    source_path = output / ("raw-" + name + ".json")
    receipt_path = output / (name + ".json")
    bundle_path = output / ("sources-" + name + ".json")
    C.write_new(source_path, source)
    source_raw = C.read_bytes(source_path, private=True, root_file=True, mode=0o600)
    # Receipt precedes its binding bundle; neither receipt nor raw source contains
    # the bundle digest. The coordinator alone later constructs an evidence index.
    C.write_new(receipt_path, receipt)
    receipt_raw = C.read_bytes(receipt_path, private=True, root_file=True, mode=0o600)
    bundle = {
        "schema": "AcademyCensusSourceBundle.v1",
        "receipt_name": name,
        "receipt_sha256": C.digest(receipt_raw),
        "candidate": m["candidate"],
        "tree": m["tree"],
        "attempt": evidence.a["attempt"],
        "role": role,
        "hostname": m["roles"][role]["hostname"],
        "producer_sha256": m["helpers"]["external_census"],
        "execution_manifest_sha256": evidence.manifest_hash,
        "execution_approval_sha256": evidence.approval_hash,
        "authority_scope_sha256": scope_hash,
        "active_authority": ctx["active_authority"],
        "observed_unix_started": started,
        "observed_unix_finished": finished,
        "gate_epoch": facts.get("hold_id", facts.get("gate_epoch")),
        "sources": {"local_observation": {"path": str(source_path), "sha256": C.digest(source_raw)}},
    }
    C.write_new(bundle_path, bundle)
    return receipt


def observe_gate_web(ctx):
    parts = _context(ctx)
    C, m, evidence, role, *_ = parts
    started = int(time.time())
    facts = _gate(C, m, evidence, role)
    receipt = {
        "schema": "AcademyRootGateObservation.v1",
        "candidate": m["candidate"],
        "tree": m["tree"],
        "attempt": evidence.a["attempt"],
        "hostname": m["roles"][role]["hostname"],
        "observed_unix_started": started,
        **facts,
    }
    return _write(ctx, parts, "gate-web", receipt, facts, started)


def observe_stopped(ctx):
    parts = _context(ctx)
    C, m, evidence, role, *_ = parts
    started = int(time.time())
    facts = _stopped(C, m, evidence, role)
    C.require(started >= facts["stop_completed_unix"], "census_snapshot_predates_original_stop")
    receipt = {
        "schema": "AcademyRootStoppedObservation.v1",
        "candidate": m["candidate"],
        "tree": m["tree"],
        "attempt": evidence.a["attempt"],
        "hostname": m["roles"][role]["hostname"],
        "observed_unix": started,
        **{k: facts[k] for k in ("units", "application_pids", "preserved", "quiesce_receipt_sha256")},
        "process_census_sha256": C.digest(C.canonical(facts)),
    }
    return _write(ctx, parts, "stopped-" + role, receipt, facts, started)


def verify_receipt_sources(C, m, evidence, name, receipt, receipt_sha256, fresh):
    """Shared public-get verifier; private raw reads prevent receipt recursion.

    Protected custody alone does not turn authored JSON into current observations:
    implemented adapters must reproduce facts locally. Remote facts are refused.
    """
    C.require(
        name
        in (
            "gate-web",
            "stopped-web",
            "stopped-lab",
            "pre-quiescence-web",
            "pre-quiescence-lab",
            "exclusion-web",
            "exclusion-lab",
        ),
        "census_receipt_name",
    )
    role = "web" if name == "gate-web" else name.rsplit("-", 1)[1]
    bundle = evidence._get_raw("sources-" + name, "external_census", role, fresh=fresh)
    C.exact(bundle, BUNDLE_FIELDS)
    _, scope_hash = load_scope(C, m)
    C.require(
        bundle["schema"] == "AcademyCensusSourceBundle.v1"
        and bundle["receipt_name"] == name
        and bundle["receipt_sha256"] == receipt_sha256,
        "census_receipt_bundle_binding",
    )
    for field, expected in (
        ("candidate", m["candidate"]),
        ("tree", m["tree"]),
        ("attempt", evidence.a["attempt"]),
        ("role", role),
        ("hostname", m["roles"][role]["hostname"]),
        ("producer_sha256", m["helpers"]["external_census"]),
        ("execution_manifest_sha256", evidence.manifest_hash),
        ("execution_approval_sha256", evidence.approval_hash),
        ("authority_scope_sha256", scope_hash),
    ):
        C.require(bundle[field] == expected, "census_bundle_identity_" + field)
    # Validate CURRENT authority separately; original receipt retains historical
    # authority without requiring a prior execution envelope to remain current.
    _authority(C, m, evidence, evidence.active_authority)
    historical = bundle["active_authority"]
    C.exact(historical, ("kind", "phase", "manifest", "approval"))
    for ref in (historical["manifest"], historical["approval"]):
        _pin(C, ref)
    historical_manifest = _json(C, historical["manifest"])
    historical_approval = _json(C, historical["approval"])
    started, finished = bundle["observed_unix_started"], bundle["observed_unix_finished"]
    C.require(
        type(started) is int and type(finished) is int and 0 <= started <= finished <= time.time(),
        "census_source_interval",
    )
    if historical["kind"] == "execution":
        C.require(
            historical_manifest == m
            and historical["manifest"]["sha256"] == evidence.manifest_hash
            and historical["approval"]["sha256"] == evidence.approval_hash,
            "census_historical_original_execution",
        )
        C.approval(historical_approval, evidence.manifest_hash, m, historical["phase"], historical=True)
    else:
        C.require(
            historical["kind"] == "promotion"
            and callable(getattr(evidence, "validate_historical_promotion", None)),
            "census_historical_promotion_validator_required",
        )
        evidence.validate_historical_promotion(
            historical_approval,
            historical_manifest,
            historical["manifest"]["sha256"],
            historical["phase"],
            started,
            finished,
        )
    current_approval = _json(C, evidence.active_authority["approval"])
    C.require(
        historical_approval["attempt"] == current_approval["attempt"]
        and all(
            historical_approval[k] == current_approval[k] for k in ("approval_record_path", "approval_record_sha256")
        ),
        "census_historical_same_human_record",
    )
    C.require(
        historical_approval["approved_unix"] <= started <= finished < historical_approval["expires_unix"],
        "census_original_observation_authority_window",
    )
    C.require(evidence.used["sources-" + name]["observed_unix"] == finished, "census_source_descriptor_underlying_time")
    C.require(
        evidence.used[name]["observed_unix"] == receipt.get("observed_unix", receipt.get("observed_unix_started")),
        "census_receipt_descriptor_underlying_time",
    )
    if fresh:
        C.stamp(started)
        C.stamp(finished)
    if name.startswith(("pre-quiescence-", "exclusion-")):
        _gap(C)
    _local(C, m, role)
    C.exact(bundle["sources"], ("local_observation",))
    source = _json(C, bundle["sources"]["local_observation"])
    C.exact(
        source,
        (
            "schema",
            "adapter",
            "candidate",
            "tree",
            "attempt",
            "role",
            "hostname",
            "producer_sha256",
            "observed_unix_started",
            "observed_unix_finished",
            "facts",
        ),
    )
    C.require(
        source["schema"] == "AcademyLocalCensusSource.v1" and source["adapter"] == name.split("-")[0],
        "census_source_adapter",
    )
    for field in (
        "candidate",
        "tree",
        "attempt",
        "role",
        "hostname",
        "producer_sha256",
        "observed_unix_started",
        "observed_unix_finished",
    ):
        C.require(source[field] == bundle[field], "census_underlying_source_identity")
    facts = source["facts"]
    if name == "gate-web":
        C.require(facts == _gate(C, m, evidence, role), "census_actual_gate_source_drift")
        C.require(bundle["gate_epoch"] == facts["hold_id"], "census_actual_gate_epoch")
        expected = {
            "schema": "AcademyRootGateObservation.v1",
            "candidate": m["candidate"],
            "tree": m["tree"],
            "attempt": evidence.a["attempt"],
            "hostname": m["roles"][role]["hostname"],
            "observed_unix_started": started,
            **facts,
        }
    else:
        C.require(bundle["gate_epoch"] == facts["gate_epoch"], "census_stopped_gate_epoch_binding")
        C.require(facts == _stopped(C, m, evidence, role), "census_actual_stopped_source_drift")
        C.require(started >= facts["stop_completed_unix"], "census_source_predates_original_stop")
        expected = {
            "schema": "AcademyRootStoppedObservation.v1",
            "candidate": m["candidate"],
            "tree": m["tree"],
            "attempt": evidence.a["attempt"],
            "hostname": m["roles"][role]["hostname"],
            "observed_unix": started,
            **{k: facts[k] for k in ("units", "application_pids", "preserved", "quiesce_receipt_sha256")},
            "process_census_sha256": C.digest(C.canonical(facts)),
        }
    C.require(receipt == expected, "census_exact_receipt_source_semantics")
    return bundle


def main():
    """Standalone closed bootstrap; reads no credentials and grants no authority.

    The bootstrap input itself and every fixed sibling module must already be in
    genuine protected root custody. No CLI data can supply observed facts.
    """
    import argparse
    import json
    import stat
    import types

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True)
    args = parser.parse_args()
    import sys

    if not (sys.platform == "linux" and os.getuid() == os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site):
        raise SystemExit("census_bootstrap_trusted_linux_root_I_S")

    def root_bytes(path):
        path = Path(path)
        if not (os.geteuid() == 0 and path.is_absolute() and ".." not in path.parts):
            raise SystemExit("census_bootstrap_root_absolute_path")
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise SystemExit("census_bootstrap_directory_custody")
            opened = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                before = os.fstat(opened)
                if not (
                    stat.S_ISREG(before.st_mode)
                    and before.st_uid == 0
                    and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) == 0o600
                    and before.st_size <= 10_000_000
                ):
                    raise SystemExit("census_bootstrap_file_custody")
                raw = b""
                while len(raw) <= 10_000_000:
                    chunk = os.read(opened, min(65536, 10_000_001 - len(raw)))
                    if not chunk:
                        break
                    raw += chunk
                after = os.fstat(opened)
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ):
                    raise SystemExit("census_bootstrap_file_changed")
                if len(raw) > 10_000_000:
                    raise SystemExit("census_bootstrap_file_bound")
                return raw
            finally:
                os.close(opened)
        finally:
            os.close(fd)

    # A duplicate-aware parse occurs again with the protected common decoder
    # before any receipt can be written. This preliminary parse only selects the
    # fixed sibling common source, whose bytes are root-owned and hash pinned.
    raw_inputs = root_bytes(args.inputs)
    preliminary = json.loads(raw_inputs)
    common_ref = preliminary["common"]
    common_path = Path(common_ref["path"])
    if common_path != Path(__file__).parent / "candidate_execute.py":
        raise SystemExit("census_bootstrap_fixed_common_sibling")
    raw = root_bytes(common_path)
    import hashlib

    if hashlib.sha256(raw).hexdigest() != common_ref["sha256"]:
        raise SystemExit("census_bootstrap_common_hash")
    module = types.ModuleType("academy_census_common")
    module.__file__ = str(common_path)
    exec(compile(raw, str(common_path), "exec"), module.__dict__)  # noqa: S102 -- exact root-private pinned sibling
    C = module.common_api()
    inputs = C.decode(raw_inputs)
    C.exact(
        inputs,
        (
            "schema",
            "kind",
            "common",
            "manifest",
            "approval",
            "evidence_index",
            "role",
            "phase",
            "output",
            "observation",
        ),
    )
    C.require(
        inputs["schema"] == "AcademyCensusInputs.v1" and inputs["kind"] in ("execution", "promotion"),
        "census_bootstrap_schema",
    )
    C.require(
        inputs["observation"] in ("gate", "stopped", "pre_quiescence", "exclusion"), "census_bootstrap_observation"
    )
    manifest = _json(C, inputs["manifest"])
    approval = _json(C, inputs["approval"])
    role, phase = inputs["role"], inputs["phase"]
    if inputs["kind"] == "execution":
        m = manifest
        C.require(m["self_sha256"] == common_ref["sha256"], "census_bootstrap_common_manifest")
        C.validate_manifest(m, role)
        # Common observers read these module globals. Bind only the validated
        # execution manifest; an empty default would match every process argv.
        module.SOURCE, module.VENV = m["source"], m["venv"]
        C = module.common_api()
        C.approval(approval, inputs["manifest"]["sha256"], m, phase)
        evidence = C.Evidence(
            inputs["evidence_index"], m, approval, inputs["approval"]["sha256"], inputs["manifest"]["sha256"]
        )
        evidence.validate_active_authority = lambda a, mm, mh, ph: C.approval(a, mh, mm, ph)
    else:
        promoter_path = Path(__file__).parent / "candidate_promote.py"
        promoter_raw = root_bytes(promoter_path)
        C.require(C.digest(promoter_raw) == manifest["self_sha256"], "census_bootstrap_promoter_hash")
        promoter = types.ModuleType("academy_census_promoter")
        promoter.__file__ = str(promoter_path)
        exec(compile(promoter_raw, str(promoter_path), "exec"), promoter.__dict__)  # noqa: S102 -- fixed root-private pinned sibling
        promoter.COMMON = module
        promoter.validate_manifest(manifest, role)
        promoter.authorization(approval, manifest, inputs["manifest"]["sha256"], phase)
        m = _json(C, manifest["execution_manifest"])
        C.require(
            m["self_sha256"] == common_ref["sha256"] == manifest["common_sha256"], "census_bootstrap_promotion_common"
        )
        C.validate_manifest(m, role)
        # Common observers read these module globals. Bind only the validated
        # execution manifest; an empty default would match every process argv.
        module.SOURCE, module.VENV = m["source"], m["venv"]
        C = module.common_api()
        evidence = promoter.Evidence(
            inputs["evidence_index"],
            manifest,
            m,
            approval,
            inputs["approval"]["sha256"],
            inputs["manifest"]["sha256"],
            manifest["execution_manifest"]["sha256"],
        )
        evidence.validate_active_authority = promoter.authorization
    active = {k: inputs[k] for k in ("kind", "phase", "manifest", "approval")}
    evidence.active_authority = active
    ctx = {
        "common": C,
        "manifest": m,
        "approval": approval,
        "evidence": evidence,
        "role": role,
        "active_authority": active,
        "output": inputs["output"],
    }
    if inputs["observation"] == "exclusion":
        # Caller cannot choose maintenance adoption state through this bootstrap.
        observe_exclusion(ctx, "fenced")
    else:
        {"gate": observe_gate_web, "stopped": observe_stopped, "pre_quiescence": observe_pre_quiescence}[
            inputs["observation"]
        ](ctx)


if __name__ == "__main__":
    main()

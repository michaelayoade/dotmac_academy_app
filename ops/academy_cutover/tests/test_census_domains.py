# ruff: noqa: S101
"""Hosted-only synthetic domain refusals; no host discovery or credentials."""

import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from types import ModuleType, SimpleNamespace

import candidate_census_domains as D
import pytest


class Common:
    @staticmethod
    def require(value, reason):
        if not value:
            raise ValueError(reason)

    @staticmethod
    def exact(value, fields):
        Common.require(type(value) is dict and set(value) == set(fields), "exact_fields")

    @staticmethod
    def hexvalue(value):
        Common.require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "hash")

    @staticmethod
    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

    @staticmethod
    def read_bytes(path, **kwargs):
        Common.require(
            kwargs == {"limit": 2_000_000, "private": True, "root_file": True, "mode": 0o600}, "custody"
        )
        return Path(path).read_bytes()


@pytest.fixture
def intrinsic():
    sources = []
    for name in ("candidate_census_domains.py", "candidate_authority_discovery.py"):
        path = Path(D.__file__).with_name(name)
        sources.append({"path": str(path), "sha256": Common.digest(path.read_bytes())})
    facts = {
        "pid": 23, "starttime_ticks": "456", "procfs_mount_verified": True,
        "uid": 0, "procfs_root_owned_fields": [], "not_applicable_process_fields": ["exe", "cwd"],
        "missing_process_fields": [], "stat_flags_before": 0x00200000,
        "stat_flags_after": 0x00200000, "stat_state_before": "S", "stat_state_after": "S",
        "process_representation": "kernel_thread",
        "uids_real_effective_saved_filesystem": [0, 0, 0, 0],
        "argv": {"sha256": "d" * 64, "bytes": 0,
                 "known_academy_root_indicator": False, "known_job_indicator": False},
        "cgroup": {"sha256": "e" * 64, "bytes": 0,
                   "known_academy_root_indicator": False, "known_job_indicator": False},
    }
    namespaces = {
        name: {"link": [1, index + 10, 0, 41471], "target": name + ":[" + str(index + 20) + "]",
               "namespace": [2, index + 20, 0, 33060]}
        for index, name in enumerate(D.NAMESPACES)
    }
    identifier = D._identity(Common, "web", "synthetic-web", 23, "456", namespaces)
    item = {
        "object_id": identifier, "authority_id": identifier, "pid": 23,
        "starttime_ticks": "456", "namespaces": namespaces, "facts": facts,
        "classification": "non_sender", "non_sender_reason": "stable_pf_kthread",
    }
    proof = {
        "schema": "AcademyCensusDomainObservation.v1", "candidate": "a" * 40, "tree": "b" * 40,
        "role": "web", "hostname": "synthetic-web", "domain": D.PROCESS_DOMAIN, "sources": sources,
        "observed_unix_started": 100, "observed_unix_finished": 101,
        "enumerated_object_ids": [identifier], "objects": [item],
        "snapshot": {"enumerated": 1, "inspected": 1, "raced": 0, "complete": 1, "skipped": 0,
                     "enumeration_complete": True, "classification_complete": False, "gaps": [],
                     "records": [{"facts": copy.deepcopy(facts),
                                  "authority_id": Common.digest(b"synthetic-web\0processes\0" + b"23:456"),
                                  "identity": None, "identity_sha256": Common.digest(b"23:456"),
                                  "unknown_identity": True, "relevance": "unresolved"}]},
        "unresolved_gaps": [], "coverage_complete": True,
    }
    scope = {
        "candidate": "a" * 40, "tree": "b" * 40, "hosts": {"web": "synthetic-web", "lab": "synthetic-lab"},
        "domains": {domain: {"discovery_refs": copy.deepcopy(sources)} for domain in D.DOMAINS},
        "authority_membership": {role: {bucket: [] for bucket in D.BUCKETS} for role in ("web", "lab")},
    }
    return scope, proof


def test_positive_intrinsic_proof_passes_only_pure_validation(intrinsic):
    scope, proof = intrinsic
    assert D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, proof) == set(proof["enumerated_object_ids"])


def test_userspace_marker_absence_is_unknown(intrinsic):
    _, proof = intrinsic
    facts = proof["objects"][0]["facts"]
    facts.update(stat_flags_before=0, stat_flags_after=0, process_representation="userspace_or_transition")
    facts["argv"] = {"known_academy_root_indicator": False, "known_job_indicator": False}
    assert D.classify_process(facts, proof["objects"][0]["namespaces"]) == ("unknown", None)


@pytest.mark.parametrize("mutation,reason", [
    (lambda p: p.update(hostname="wrong-host"), "scope_identity"),
    (lambda p: p["sources"][0].update(sha256="0" * 64), "frozen_source_pin"),
    (lambda p: p["objects"][0].update(starttime_ticks="457"), "fact_identity"),
    (lambda p: p.update(enumerated_object_ids=[]), "exact_object_coverage"),
    (lambda p: p["snapshot"].update(raced=1), "stable_enumeration"),
    (lambda p: p["snapshot"].update(classification_complete=True), "stable_enumeration"),
    (lambda p: p.update(unresolved_gaps=["namespace_unproved"]), "unresolved_objects_or_gaps"),
    (lambda p: p.update(observed_unix_finished=500), "original_interval"),
    (lambda p: p["objects"][0].update(non_sender_reason="no_marker_found"), "positive_classification"),
])
def test_forged_completion_does_not_override_evidence(intrinsic, mutation, reason):
    scope, proof = intrinsic
    mutation(proof)
    proof["coverage_complete"] = True
    with pytest.raises(ValueError, match=reason):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, proof)


def test_stale_source_bytes_refused(intrinsic, monkeypatch):
    scope, proof = intrinsic
    monkeypatch.setattr(Common, "read_bytes", staticmethod(lambda *args, **kwargs: b"different reviewed source"))
    with pytest.raises(ValueError, match="actual_source_hash"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, proof)


def test_missing_namespace_and_state_transition_stay_unknown(intrinsic):
    _, proof = intrinsic
    item = proof["objects"][0]
    assert D.classify_process(item["facts"], {}) == ("unknown", None)
    facts = dict(item["facts"], stat_flags_before=0, stat_flags_after=0, stat_state_before="Z",
                 stat_state_after="S", process_representation="stable_zombie")
    assert D.classify_process(facts, item["namespaces"]) == ("unknown", None)


def test_stable_zombie_requires_both_states(intrinsic):
    _, proof = intrinsic
    facts = dict(proof["objects"][0]["facts"], stat_flags_before=0, stat_flags_after=0,
                 stat_state_before="Z", stat_state_after="Z", process_representation="stable_zombie")
    assert D.classify_process(facts, proof["objects"][0]["namespaces"]) == ("non_sender", "stable_zombie")


def test_omitted_domain_refused(intrinsic):
    scope, _ = intrinsic
    with pytest.raises(ValueError, match="exact_fields"):
        D.require_complete_scope(Common, scope, {D.PROCESS_DOMAIN: {}})


def test_overlapping_frozen_membership_refused(intrinsic):
    scope, _ = intrinsic
    scope["authority_membership"]["web"]["supported"] = ["c" * 64]
    scope["authority_membership"]["web"]["legacy"] = ["c" * 64]
    with pytest.raises(ValueError, match="disjoint_authorities"):
        D.require_complete_scope(Common, scope, {domain: {"web": {}, "lab": {}} for domain in D.DOMAINS})


def test_other_domains_refuse_without_provider_execution():
    for domain in D.DOMAINS:
        if domain != D.PROCESS_DOMAIN:
            with pytest.raises(ValueError, match="adapter_unimplemented"):
                D.collect_domain(Common, {}, "web", domain)


def test_production_host_guard_precedes_source_execution(monkeypatch):
    monkeypatch.setattr(D, "sys", SimpleNamespace(
        platform="linux", version_info=(3, 12),
        flags=SimpleNamespace(isolated=True, no_site=True, dont_write_bytecode=True),
    ))
    monkeypatch.setattr(D, "os", SimpleNamespace(geteuid=lambda: 0))
    monkeypatch.setattr(D, "socket", SimpleNamespace(gethostname=lambda: "wrong-host"))
    with pytest.raises(ValueError, match="host_identity"):
        D.observe_processes(Common, {"roles": {"web": {"hostname": "synthetic-web"}}}, "web")


def test_reducer_cannot_upgrade_authored_other_domains(intrinsic, monkeypatch):
    scope, proof = intrinsic
    # Even a trusted pure-validator result cannot supply seven missing collectors.
    monkeypatch.setattr(D, "validate_domain_proof", lambda *args: set())
    authored = {domain: {role: {"coverage_complete": True} for role in ("web", "lab")} for domain in D.DOMAINS}
    authored[D.PROCESS_DOMAIN]["web"] = proof
    with pytest.raises(ValueError, match="adapter_unimplemented"):
        D.require_complete_scope(Common, scope, authored)


class SyntheticProc:
    """Fixed metadata syscall stand-in; no real procfs access in these tests."""

    def __init__(self, fault=None):
        self.fault = fault
        self.opened = []
        self.closed = []
        self.link_reads = {}
        self.stat_reads = 0
        self.next_fd = 100

    def allocate(self, kind):
        descriptor = self.next_fd
        self.next_fd += 1
        self.opened.append((descriptor, kind))
        return descriptor

    @staticmethod
    def meta(device, inode, mode, uid=0):
        return SimpleNamespace(st_dev=device, st_ino=inode, st_mode=mode, st_uid=uid)

    def open(self, path, flags, *, dir_fd):
        del flags, dir_fd
        if self.fault == "open_pid" and path == "23":
            raise PermissionError
        return self.allocate("ns" if path == "ns" else "pid")

    def fstat(self, descriptor):
        kind = dict(self.opened)[descriptor]
        return self.meta(1, {"root": 1, "pid": 2, "ns": 3}[kind], stat.S_IFDIR | 0o555)

    def stat(self, path, *, dir_fd, follow_symlinks=True):
        del dir_fd
        if path == "23":
            return self.meta(1, 2, stat.S_IFDIR | 0o555)
        if path == "ns":
            return self.meta(1, 3, stat.S_IFDIR | 0o555)
        index = D.NAMESPACES.index(path)
        if not follow_symlinks:
            return self.meta(1, index + 10, stat.S_IFLNK | 0o777)
        inode = index + 20
        if self.fault == "inode_mismatch" and path == "pid":
            inode += 1
        return self.meta(2, inode, stat.S_IFREG | 0o444)

    def readlink(self, path, *, dir_fd):
        del dir_fd
        self.link_reads[path] = self.link_reads.get(path, 0) + 1
        inode = D.NAMESPACES.index(path) + 20
        if self.fault == "postbatch_namespace_change" and self.link_reads[path] > 1:
            inode += 1
        if self.fault == "target_mismatch" and path == "pid":
            return "net:[20]"
        return path + ":[" + str(inode) + "]"

    def close(self, descriptor):
        if descriptor in self.closed:
            raise ValueError("descriptor_closed_twice")
        self.closed.append(descriptor)

    def syscall_module(self):
        return SimpleNamespace(
            open=self.open, fstat=self.fstat, stat=self.stat, readlink=self.readlink, close=self.close,
            O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY, O_NOFOLLOW=os.O_NOFOLLOW, geteuid=lambda: 0,
        )


class SyntheticDiscovery:
    """Mock the already-protected discovery boundary, retaining real adapter code."""

    def __init__(self, snapshot, proc):
        self.snapshot = copy.deepcopy(snapshot)
        self.proc = proc
        self.host = "synthetic-web"
        self.files = 16384 if proc.fault == "budget" else 0
        self.deadline = 0 if proc.fault == "deadline" else float("inf")
        self.processes_called = False

    def processes(self):
        self.processes_called = True

    def domain(self, domain):
        Common.require(domain == "processes", "synthetic_process_only")
        return self.snapshot

    def gap(self, domain, reason, raced=False):
        self.domain(domain)["gaps"].append(reason)
        if raced:
            self.snapshot["raced"] += 1

    def directory(self, path, domain):
        Common.require(path == "/proc" and domain == "processes", "synthetic_fixed_root")
        if self.proc.fault == "directory":
            self.gap(domain, "directory_unavailable")
            return None
        return self.proc.allocate("root")

    def verify_procfs(self, root, domain):
        del root
        if self.proc.fault == "mount":
            self.gap(domain, "procfs_mount_unproved")
            return None
        return 1

    def read_proc_file(self, root, fd, pid, name, device, domain, exceptions):
        del root, fd, pid, name, device, exceptions
        self.proc.stat_reads += 1
        if self.proc.fault == "stat_read":
            self.gap(domain, "procfs_access_denied")
            return None
        start = "457" if self.proc.fault == "pid_reuse" and self.proc.stat_reads > 1 else "456"
        facts = self.snapshot["records"][0]["facts"]
        return (start + "|" + str(facts["stat_flags_after"]) + "|" + facts["stat_state_after"]).encode()

    @staticmethod
    def process_stat(raw, pid):
        del pid
        start, flags, state = raw.decode().split("|")
        return start, int(flags), state

    def names(self, root, domain):
        del root, domain
        return ["23", "24"] if self.proc.fault == "final_pid_set" else ["23"]


@pytest.fixture
def simulated_collector(intrinsic, monkeypatch):
    scope, proof = intrinsic
    proc = SyntheticProc()
    discovery = SyntheticDiscovery(proof["snapshot"], proc)
    module = ModuleType("synthetic_protected_discovery")
    module.HOSTS = {"web": "synthetic-web"}
    module.Discovery = lambda role: discovery
    monkeypatch.setattr(D, "types", SimpleNamespace(ModuleType=lambda name: module))
    monkeypatch.setattr(D, "_sources", lambda C, m: (b"", proof["sources"]))
    monkeypatch.setattr(D, "sys", SimpleNamespace(
        platform="linux", version_info=(3, 12),
        flags=SimpleNamespace(isolated=True, no_site=True, dont_write_bytecode=True),
    ))
    monkeypatch.setattr(D, "os", proc.syscall_module())
    monkeypatch.setattr(D, "socket", SimpleNamespace(gethostname=lambda: "synthetic-web"))
    manifest = {"candidate": scope["candidate"], "tree": scope["tree"],
                "roles": {"web": {"hostname": "synthetic-web"}}}
    return scope, manifest, proof, proc, discovery


def test_actual_observer_assembly_with_synthetic_protected_boundary(simulated_collector):
    scope, manifest, _, proc, discovery = simulated_collector
    observation = D.observe_processes(Common, manifest, "web")
    assert discovery.processes_called
    assert observation["coverage_complete"] is True
    assert observation["unresolved_gaps"] == []
    assert set(observation["objects"][0]["namespaces"]) == set(D.NAMESPACES)
    assert observation["objects"][0]["non_sender_reason"] == "stable_pf_kthread"
    assert D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, observation)
    assert sorted(proc.closed) == sorted(descriptor for descriptor, _ in proc.opened)


def test_actual_userspace_collection_stays_unknown(simulated_collector):
    _, manifest, _, proc, discovery = simulated_collector
    discovery.snapshot["records"][0]["facts"].update(
        stat_flags_before=0, stat_flags_after=0, process_representation="userspace_or_transition",
    )
    observation = D.observe_processes(Common, manifest, "web")
    item = observation["objects"][0]
    assert set(item["namespaces"]) == set(D.NAMESPACES)
    assert item["classification"] == "unknown"
    assert item["non_sender_reason"] is None
    assert observation["coverage_complete"] is False
    assert "process_positive_classification_unresolved" in observation["unresolved_gaps"]
    assert sorted(proc.closed) == sorted(descriptor for descriptor, _ in proc.opened)


@pytest.mark.parametrize("fault", [
    "target_mismatch", "inode_mismatch", "pid_reuse", "postbatch_namespace_change",
    "budget", "deadline", "open_pid", "stat_read", "mount", "directory",
])
def test_actual_namespace_failure_paths_close_every_opened_fd(simulated_collector, fault):
    _, _, proof, proc, discovery = simulated_collector
    proc.fault = fault
    if fault == "budget":
        discovery.files = 16384
    if fault == "deadline":
        discovery.deadline = 0
    assert D._namespaces(discovery, proof["snapshot"]["records"][0]) == {}
    assert discovery.snapshot["gaps"]
    assert sorted(proc.closed) == sorted(descriptor for descriptor, _ in proc.opened)


@pytest.mark.parametrize("fault", ["pid_reuse", "postbatch_namespace_change", "final_pid_set"])
def test_actual_observer_never_completes_after_race(simulated_collector, fault):
    _, manifest, _, proc, _ = simulated_collector
    proc.fault = fault
    observation = D.observe_processes(Common, manifest, "web")
    assert observation["coverage_complete"] is False
    assert observation["unresolved_gaps"]
    assert sorted(proc.closed) == sorted(descriptor for descriptor, _ in proc.opened)


@pytest.mark.parametrize("field,value", [
    ("complete", 0), ("skipped", 1), ("raced", 1), ("inspected", 0),
    ("enumeration_complete", False), ("classification_complete", True),
])
def test_actual_observer_checks_partial_counters_without_gap_strings(simulated_collector, field, value):
    _, manifest, _, proc, discovery = simulated_collector
    discovery.snapshot[field] = value
    observation = D.observe_processes(Common, manifest, "web")
    assert observation["coverage_complete"] is False
    assert "process_stable_snapshot_unproved" in observation["unresolved_gaps"]
    assert sorted(proc.closed) == sorted(descriptor for descriptor, _ in proc.opened)


def test_role_collector_collects_actual_processes_before_refusal(simulated_collector):
    scope, manifest, _, proc, discovery = simulated_collector
    with pytest.raises(ValueError, match="adapter_unimplemented"):
        D.collect_role(Common, manifest, "web", scope)
    assert discovery.processes_called
    assert sorted(proc.closed) == sorted(descriptor for descriptor, _ in proc.opened)


def test_role_reducer_requires_exact_eight_domains(intrinsic):
    scope, proof = intrinsic
    with pytest.raises(ValueError, match="exact_fields"):
        D.require_complete_role_scope(Common, scope, "web", {D.PROCESS_DOMAIN: proof})
    proofs = dict.fromkeys(D.DOMAINS)
    proofs[D.PROCESS_DOMAIN] = proof
    with pytest.raises(ValueError, match="adapter_unimplemented"):
        D.require_complete_role_scope(Common, scope, "web", proofs)

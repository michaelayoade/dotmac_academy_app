# ruff: noqa: S101 -- assertions qualify synthetic census behavior.
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


    @staticmethod
    def services(role):
        return (["academy-v2-web"] + ["academy-v2-" + name for name in (
            "admin-report", "email-digest", "email-outbox", "erp-training-sync", "hr-report",
            "learner-digest", "reminders",
        )]) if role == "web" else ["academy-v2-lab-worker"]

    @staticmethod
    def old_unit_inventory(unit, manifest, role):
        del manifest
        return inactive_inventory(unit, role)

    @staticmethod
    def baseline_runtime(manifest, role):
        return manifest["roles"][role]["runtime_baseline"]


def inactive_inventory(unit, role):
    return {"unit_state": {"MainPID": "0", "ActiveState": "inactive", "SubState": "dead"},
            "start_ticks": None, "argv_sha256": None, "gate_awareness": "legacy_gate_unaware",
            "planned_action": "stop_primary" if unit == Common.services(role)[0] else "drain_only"}


def inactive_owners(role):
    return {unit: {"inventory": inactive_inventory(unit, role), "namespaces": {}, "uid": None,
                   "cwd_sha256": None, "exe_sha256": None} for unit in Common.services(role)}


@pytest.fixture
def intrinsic():
    sources = []
    for name in ("candidate_census_domains.py", "candidate_authority_discovery.py", "candidate_execute.py"):
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
        "object_id": identifier, "authority_refs": [], "pid": 23,
        "starttime_ticks": "456", "namespaces": namespaces, "facts": facts,
        "classification": "non_sender", "non_sender_reason": "stable_pf_kthread",
    }
    proof = {
        "schema": "AcademyCensusDomainObservation.v2", "candidate": "a" * 40, "tree": "b" * 40,
        "role": "web", "hostname": "synthetic-web", "domain": D.PROCESS_DOMAIN, "sources": sources,
        "observed_unix_started": 100, "observed_unix_finished": 101,
        "enumerated_object_ids": [identifier], "objects": [item],
        "snapshot": {"enumerated": 1, "inspected": 1, "raced": 0, "complete": 1, "skipped": 0,
                     "enumeration_complete": True, "classification_complete": False, "gaps": [],
                     "records": [{"facts": copy.deepcopy(facts),
                                  "authority_id": Common.digest(b"synthetic-web\0processes\0" + b"23:456"),
                                  "identity": None, "identity_sha256": Common.digest(b"23:456"),
                                  "unknown_identity": True, "relevance": "unresolved"}]},
        "owners_before": inactive_owners("web"), "owners_after": inactive_owners("web"),
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
    assert D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, proof) == set()


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
        if domain not in (D.PROCESS_DOMAIN, D.SYSTEMD_DOMAIN):
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
    monkeypatch.setattr(D, "validate_domain_proof", lambda *args, **kwargs: set())
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

    def readlink(self, path, *, dir_fd=None):
        del dir_fd
        if isinstance(path, Path):
            return {"cwd": "/synthetic/legacy/source", "exe": "/synthetic/python"}[path.name]
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
            fsencode=os.fsencode,
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
                "self_sha256": proof["sources"][2]["sha256"],
                "helpers": {"census_domains": proof["sources"][0]["sha256"],
                            "census_discovery": proof["sources"][1]["sha256"]},
                "roles": {"web": {"hostname": "synthetic-web", "uid": 1000,
                                  "runtime_baseline": {"units": {unit: {"source": "/synthetic/legacy/source"}
                                                                 for unit in Common.services("web")}}}}}
    return scope, manifest, proof, proc, discovery


def test_actual_observer_assembly_with_synthetic_protected_boundary(simulated_collector):
    scope, manifest, _, proc, discovery = simulated_collector
    observation = D.observe_processes(Common, manifest, "web")
    assert discovery.processes_called
    assert observation["coverage_complete"] is True
    assert observation["unresolved_gaps"] == []
    assert set(observation["objects"][0]["namespaces"]) == set(D.NAMESPACES)
    assert observation["objects"][0]["non_sender_reason"] == "stable_pf_kthread"
    assert D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, observation) == set()
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


def test_role_collector_collects_actual_processes_before_refusal(simulated_collector, monkeypatch):
    scope, manifest, _, proc, discovery = simulated_collector
    calls = []

    def systemd(*_args, **_kwargs):
        assert discovery.processes_called
        calls.append(D.SYSTEMD_DOMAIN)
        return {}

    monkeypatch.setattr(D, "observe_systemd", systemd)
    with pytest.raises(ValueError, match="adapter_unimplemented"):
        D.collect_role(Common, manifest, "web", scope)
    assert discovery.processes_called
    assert calls == [D.SYSTEMD_DOMAIN]
    assert sorted(proc.closed) == sorted(descriptor for descriptor, _ in proc.opened)


def test_role_reducer_requires_exact_eight_domains(intrinsic, monkeypatch):
    scope, proof = intrinsic
    original = D.validate_domain_proof

    def process_validation(C, scope, role, domain, proof, **kwargs):
        if domain == D.SYSTEMD_DOMAIN:
            return set()
        return original(C, scope, role, domain, proof, **kwargs)

    monkeypatch.setattr(D, "validate_domain_proof", process_validation)
    with pytest.raises(ValueError, match="exact_fields"):
        D.require_complete_role_scope(Common, scope, "web", {D.PROCESS_DOMAIN: proof})
    proofs = dict.fromkeys(D.DOMAINS)
    proofs[D.PROCESS_DOMAIN] = proof
    with pytest.raises(ValueError, match="adapter_unimplemented"):
        D.require_complete_role_scope(Common, scope, "web", proofs)


@pytest.fixture
def legacy_collector(simulated_collector, monkeypatch):
    scope, manifest, proof, proc, discovery = simulated_collector
    facts = discovery.snapshot["records"][0]["facts"]
    facts.update(uid=1000, stat_flags_before=0, stat_flags_after=0,
                 process_representation="userspace_or_transition", not_applicable_process_fields=[],
                 uids_real_effective_saved_filesystem=[1000] * 4)
    for field, raw in (("cwd", b"/synthetic/legacy/source"), ("exe", b"/synthetic/python"),
                       ("argv", b"/synthetic/venv/bin/python\0-m\0app.cli\0")):
        facts[field] = {"sha256": Common.digest(raw), "bytes": len(raw),
                        "known_academy_root_indicator": False, "known_job_indicator": False}
    original_stat = Path.stat

    def proc_stat(path, *args, **kwargs):
        if path == Path("/proc/23"):
            return SimpleNamespace(st_uid=1000)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", proc_stat)
    monkeypatch.setattr(Common, "proc_bytes", staticmethod(lambda path: (
        facts["starttime_ticks"] + "|0|S").encode()), raising=False)
    inventory = {"unit_state": {"MainPID": "23", "ActiveState": "active", "SubState": "running"},
                 "start_ticks": "456", "argv_sha256": facts["argv"]["sha256"],
                 "gate_awareness": "legacy_gate_unaware", "planned_action": "stop_primary"}
    calls = []

    def owner(unit, m, role):
        assert m is manifest
        calls.append(unit)
        return copy.deepcopy(inventory if unit == Common.services(role)[0] else inactive_inventory(unit, role))

    monkeypatch.setattr(Common, "old_unit_inventory", staticmethod(owner))
    return scope, manifest, proof, proc, discovery, inventory, calls


def test_actual_fixed_legacy_owner_assembly_and_pure_reconstruction(legacy_collector):
    scope, manifest, _, proc, _, _, calls = legacy_collector
    observation = D.observe_processes(Common, manifest, "web")
    item = observation["objects"][0]
    authority = D.authority_id(Common, "web", "synthetic-web", "academy-v2-web")
    assert calls == Common.services("web") * 2
    assert item["classification"] == "legacy_sender"
    assert item["authority_refs"] == [authority]
    assert authority != item["object_id"]
    assert observation["coverage_complete"] is True
    assert D.validate_domain_proof(
        Common, scope, "web", D.PROCESS_DOMAIN, observation, manifest=manifest,
    ) == {authority}
    with pytest.raises(ValueError, match="owner_manifest_required"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, observation)
    assert sorted(proc.closed) == sorted(descriptor for descriptor, _ in proc.opened)


def test_stable_authority_recipe_survives_restart_without_candidate_or_pid(legacy_collector):
    scope, manifest, _, _, _, _, _ = legacy_collector
    original = D.observe_processes(Common, manifest, "web")
    restarted = copy.deepcopy(original)
    item = restarted["objects"][0]
    item["pid"] = item["facts"]["pid"] = 24
    item["starttime_ticks"] = item["facts"]["starttime_ticks"] = "999"
    item["object_id"] = D._identity(Common, "web", "synthetic-web", 24, "999", item["namespaces"])
    restarted["enumerated_object_ids"] = [item["object_id"]]
    row = restarted["snapshot"]["records"][0]
    row.update(facts=copy.deepcopy(item["facts"]),
               authority_id=Common.digest(b"synthetic-web\0processes\0" + b"24:999"),
               identity_sha256=Common.digest(b"24:999"))
    for field in ("owners_before", "owners_after"):
        restarted[field]["academy-v2-web"]["inventory"].update(start_ticks="999")
        restarted[field]["academy-v2-web"]["inventory"]["unit_state"]["MainPID"] = "24"
    refs = D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, restarted, manifest=manifest)
    assert refs == set(original["objects"][0]["authority_refs"])
    assert item["object_id"] != original["objects"][0]["object_id"]
    assert item["authority_refs"] == original["objects"][0]["authority_refs"]
    assert next(iter(refs)) == Common.digest(Common.canonical({
        "schema": "AcademyLegacyUnitAuthority.v1", "hostname": "synthetic-web", "role": "web",
        "unit": "academy-v2-web",
    }))


@pytest.mark.parametrize("mutation", [
    lambda o: o["inventory"]["unit_state"].update(MainPID="24"),
    lambda o: o["inventory"].update(start_ticks="457"),
    lambda o: o["inventory"].update(argv_sha256="0" * 64),
    lambda o: o.update(uid=1001),
    lambda o: o.update(cwd_sha256="0" * 64),
    lambda o: o.update(exe_sha256="0" * 64),
    lambda o: o["namespaces"]["net"].update(target="net:[999]"),
])
def test_forged_owner_join_never_establishes_userspace_authority(legacy_collector, mutation):
    scope, manifest, _, _, _, _, _ = legacy_collector
    observation = D.observe_processes(Common, manifest, "web")
    for field in ("owners_before", "owners_after"):
        mutation(observation[field]["academy-v2-web"])
    observation["coverage_complete"] = True
    with pytest.raises(ValueError, match=r"owner_baseline_join|positive_classification|ns_inode"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, observation, manifest=manifest)


def test_owner_change_after_whole_snapshot_refuses_live_collection(legacy_collector, monkeypatch):
    _, manifest, _, _, _, inventory, _ = legacy_collector
    count = 0

    def changed(unit, m, role):
        nonlocal count
        del m
        if unit == "academy-v2-web":
            count += 1
            value = copy.deepcopy(inventory)
            if count == 2:
                value["unit_state"]["SubState"] = "exited"
            return value
        return inactive_inventory(unit, role)

    monkeypatch.setattr(Common, "old_unit_inventory", staticmethod(changed))
    observation = D.observe_processes(Common, manifest, "web")
    assert observation["objects"][0]["classification"] == "unknown"
    assert observation["objects"][0]["authority_refs"] == []
    assert observation["coverage_complete"] is False
    assert "legacy_owner_changed_or_unproved" in observation["unresolved_gaps"]


def test_duplicate_unit_mainpid_is_ambiguous_and_never_multi_authority(legacy_collector, monkeypatch):
    _, manifest, _, _, _, inventory, _ = legacy_collector

    def duplicated(unit, m, role):
        del m
        if unit in ("academy-v2-web", "academy-v2-email-outbox"):
            value = copy.deepcopy(inventory)
            value["planned_action"] = "stop_primary" if unit == "academy-v2-web" else "drain_only"
            return value
        return inactive_inventory(unit, role)

    monkeypatch.setattr(Common, "old_unit_inventory", staticmethod(duplicated))
    observation = D.observe_processes(Common, manifest, "web")
    assert observation["objects"][0]["authority_refs"] == []
    assert observation["coverage_complete"] is False
    assert "legacy_owner_duplicate_pid" in observation["unresolved_gaps"]


def test_child_does_not_inherit_legacy_mainpid_authority(legacy_collector):
    _, manifest, _, _, discovery, _, _ = legacy_collector
    observation = D.observe_processes(Common, manifest, "web")
    facts = copy.deepcopy(discovery.snapshot["records"][0]["facts"])
    facts["pid"] = 24
    assert D._owner_refs(Common, "web", "synthetic-web", facts, observation["objects"][0]["namespaces"],
                         observation["owners_before"], observation["owners_after"]) == []


def test_unknown_process_refused_despite_authored_complete_flag(simulated_collector):
    scope, manifest, _, _, discovery = simulated_collector
    discovery.snapshot["records"][0]["facts"].update(
        stat_flags_before=0, stat_flags_after=0, process_representation="userspace_or_transition")
    observation = D.observe_processes(Common, manifest, "web")
    observation.update(coverage_complete=True, unresolved_gaps=[])
    with pytest.raises(ValueError, match="unresolved_objects_or_gaps"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, observation)


def test_intrinsic_non_senders_never_get_frozen_sender_membership(intrinsic):
    scope, proof = intrinsic
    assert proof["objects"][0]["authority_refs"] == []
    proof["objects"][0]["authority_refs"] = ["f" * 64]
    with pytest.raises(ValueError, match="positive_classification"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, proof)


@pytest.mark.parametrize("mutation", [
    lambda m: m.update(candidate="0" * 40),
    lambda m: m.update(tree="0" * 40),
    lambda m: m.update(self_sha256="0" * 64),
    lambda m: m["roles"]["web"].update(hostname="wrong-host"),
])
def test_userspace_manifest_source_and_scope_identity_required(legacy_collector, mutation):
    scope, manifest, _, _, _, _, _ = legacy_collector
    observation = D.observe_processes(Common, manifest, "web")
    mutation(manifest)
    with pytest.raises(ValueError, match="owner_manifest_source_identity"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, observation, manifest=manifest)


def test_reducers_refuse_missing_frozen_legacy_membership_before_missing_adapters(legacy_collector, monkeypatch):
    scope, manifest, _, _, _, _, _ = legacy_collector
    original = D.validate_domain_proof

    def process_validation(C, scope, role, domain, proof, **kwargs):
        if domain == D.SYSTEMD_DOMAIN:
            return set()
        return original(C, scope, role, domain, proof, **kwargs)

    monkeypatch.setattr(D, "validate_domain_proof", process_validation)
    observation = D.observe_processes(Common, manifest, "web")
    proofs = dict.fromkeys(D.DOMAINS)
    proofs[D.PROCESS_DOMAIN] = observation
    with pytest.raises(ValueError, match="legacy_membership_missing"):
        D.require_complete_role_scope(Common, scope, "web", proofs, manifest=manifest)
    authority = observation["objects"][0]["authority_refs"][0]
    scope["authority_membership"]["web"]["legacy"] = [authority]
    with pytest.raises(ValueError, match="adapter_unimplemented"):
        D.require_complete_role_scope(Common, scope, "web", proofs, manifest=manifest)


def test_actual_fixed_executor_source_drift_refuses(intrinsic, monkeypatch):
    scope, proof = intrinsic
    read = Common.read_bytes

    def altered(path, **kwargs):
        return b"source drift" if Path(path).name == "candidate_execute.py" else read(path, **kwargs)

    monkeypatch.setattr(Common, "read_bytes", staticmethod(altered))
    with pytest.raises(ValueError, match="actual_source_hash"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, proof)


@pytest.mark.parametrize("field,value,reason", [
    ("pid", True, "fact_pid"), ("pid", "23", "fact_pid"),
    ("starttime_ticks", 456, "fact_starttime"), ("starttime_ticks", True, "fact_starttime"),
])
def test_process_fact_identity_types_are_strict(intrinsic, field, value, reason):
    scope, proof = intrinsic
    proof["objects"][0]["facts"][field] = value
    with pytest.raises(ValueError, match=reason):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, proof)


def test_namespace_boolean_inode_is_not_an_integer(intrinsic):
    scope, proof = intrinsic
    proof["objects"][0]["namespaces"]["net"]["namespace"][1] = True
    with pytest.raises(ValueError, match="namespace_metadata"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, proof)


def test_changed_owner_proof_refuses_even_with_authored_complete(legacy_collector):
    scope, manifest, _, _, _, _, _ = legacy_collector
    observation = D.observe_processes(Common, manifest, "web")
    observation["owners_after"]["academy-v2-web"]["inventory"]["unit_state"]["SubState"] = "exited"
    observation["coverage_complete"] = True
    with pytest.raises(ValueError, match="owner_changed"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, observation, manifest=manifest)


def test_snapshot_object_join_is_independently_reconstructed(legacy_collector):
    scope, manifest, _, _, _, _, _ = legacy_collector
    observation = D.observe_processes(Common, manifest, "web")
    observation["snapshot"]["records"][0]["facts"]["argv"]["sha256"] = "0" * 64
    # Decouple object facts to model a forged snapshot-only replacement.
    observation["objects"][0]["facts"] = copy.deepcopy(observation["objects"][0]["facts"])
    observation["objects"][0]["facts"]["argv"]["sha256"] = (
        observation["owners_before"]["academy-v2-web"]["inventory"]["argv_sha256"])
    with pytest.raises(ValueError, match="snapshot_object_join"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, observation, manifest=manifest)


def test_owner_read_failure_never_claims_complete(legacy_collector, monkeypatch):
    _, manifest, _, _, _, _, _ = legacy_collector

    def denied(*args):
        del args
        raise PermissionError

    monkeypatch.setattr(Common, "old_unit_inventory", staticmethod(denied))
    observation = D.observe_processes(Common, manifest, "web")
    assert all(owner is None for owner in observation["owners_before"].values())
    assert observation["objects"][0]["classification"] == "unknown"
    assert observation["objects"][0]["authority_refs"] == []
    assert observation["coverage_complete"] is False
    assert "legacy_owner_changed_or_unproved" in observation["unresolved_gaps"]


@pytest.mark.parametrize("field", ["owners_before", "owners_after"])
def test_owner_namespace_metadata_bool_cannot_equal_valid_object_inode(legacy_collector, field):
    scope, manifest, _, _, _, _, _ = legacy_collector
    observation = D.observe_processes(Common, manifest, "web")
    # Python bool/int equality must not hide a changed owner observation.
    observation[field]["academy-v2-web"]["namespaces"]["pid"]["link"][0] = True
    with pytest.raises(ValueError, match=r"namespace_metadata|owner_changed"):
        D.validate_domain_proof(Common, scope, "web", D.PROCESS_DOMAIN, observation, manifest=manifest)

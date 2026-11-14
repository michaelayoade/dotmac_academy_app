"""Protected process observations and a refusing eight-domain scope reducer.

An observation is metadata at its original interval, never an approval or freshness
token. Process and systemd adapters retain unresolved authority and control boundaries.
Validation of a dictionary is deliberately
separate from production collection and cannot establish current observations.
"""

import json
import os
import re
import signal
import socket
import stat
import sys
import time
import types
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
SYSTEMD_DOMAIN = DOMAINS[0]
PROCESS_DOMAIN = DOMAINS[2]
DISCOVERY_SHA256 = "d704750c57e11b533d46affbc5ad8a175c3539494f0490df21cd06241a721373"
NAMESPACES = ("pid", "mnt", "user", "net")
BUCKETS = ("supported", "legacy", "manual", "external")
PROOF_FIELDS = (
    "schema", "candidate", "tree", "role", "hostname", "domain", "sources",
    "observed_unix_started", "observed_unix_finished", "enumerated_object_ids",
    "objects", "snapshot", "owners_before", "owners_after", "unresolved_gaps", "coverage_complete",
)
OBJECT_FIELDS = (
    "object_id", "authority_refs", "pid", "starttime_ticks", "namespaces", "facts",
    "classification", "non_sender_reason",
)


def _pin(C, path, expected):
    C.hexvalue(expected)
    raw = C.read_bytes(path, limit=2_000_000, private=True, root_file=True, mode=0o600)
    C.require(C.digest(raw) == expected, "census_domain_actual_source_hash")
    return raw


def _sources(C, m):
    own = Path(__file__)
    C.require(own.name == "candidate_census_domains.py", "census_domain_fixed_source")
    discovery = own.with_name("candidate_authority_discovery.py")
    _pin(C, own, m["helpers"]["census_domains"])
    C.require(m["helpers"]["census_discovery"] == DISCOVERY_SHA256, "census_domain_approved_discovery")
    raw = _pin(C, discovery, DISCOVERY_SHA256)
    executor = own.with_name("candidate_execute.py")
    _pin(C, executor, m["self_sha256"])
    refs = [
        {"path": str(own), "sha256": m["helpers"]["census_domains"]},
        {"path": str(discovery), "sha256": DISCOVERY_SHA256},
        {"path": str(executor), "sha256": m["self_sha256"]},
    ]
    return raw, refs


def _identity(C, role, hostname, pid, start, namespaces):
    return C.digest(C.canonical({
        "role": role, "hostname": hostname, "domain": PROCESS_DOMAIN,
        "pid": pid, "starttime_ticks": start, "namespaces": namespaces,
    }))


def authority_id(C, role, hostname, unit):
    """SHA256 of canonical JSON(schema, hostname, role, unit), never PID/candidate.

    A restart changes object_id but preserves this legacy unit authority. This
    bounded adapter attributes only MainPID; children never inherit membership.
    """
    return C.digest(C.canonical({
        "schema": "AcademyLegacyUnitAuthority.v1", "hostname": hostname,
        "role": role, "unit": unit,
    }))


def _owners(C, m, role, discovery):
    """Fixed legacy owners; existing executor owns all actual runtime semantics."""
    result = {}
    for unit in C.services(role):
        try:
            inventory = C.old_unit_inventory(unit, m, role)
            pid = int(inventory["unit_state"]["MainPID"])
            owner = {"inventory": inventory, "namespaces": {}, "uid": None,
                     "cwd_sha256": None, "exe_sha256": None}
            if pid:
                start, flags, state = discovery.process_stat(C.proc_bytes(Path("/proc") / str(pid) / "stat"), str(pid))
                C.require(start == inventory["start_ticks"], "census_domain_owner_start_raced")
                owner["namespaces"] = _namespaces(discovery, {"facts": {
                    "pid": pid, "starttime_ticks": start, "stat_flags_after": flags, "stat_state_after": state,
                }})
                proc = Path("/proc") / str(pid)
                owner.update(uid=proc.stat().st_uid,
                             cwd_sha256=C.digest(os.fsencode(os.readlink(proc / "cwd"))),
                             exe_sha256=C.digest(os.fsencode(os.readlink(proc / "exe"))))
            result[unit] = owner
        except (OSError, ValueError, UnicodeError, KeyError, IndexError):
            discovery.gap("processes", "legacy_owner_observation_unproved")
            result[unit] = None
    return result


def _owner_refs(C, role, hostname, facts, namespaces, before, after):
    """Exact unambiguous MainPID join; no name/parent/cgroup inference."""
    if before != after or any(owner is None for owner in before.values()):
        return []
    active = [(unit, owner) for unit, owner in before.items()
              if int(owner["inventory"]["unit_state"]["MainPID"]) != 0]
    pids = [int(owner["inventory"]["unit_state"]["MainPID"]) for _, owner in active]
    if len(pids) != len(set(pids)):
        return []
    matches = []
    for unit, owner in active:
        inventory = owner["inventory"]
        if (int(inventory["unit_state"]["MainPID"]) == facts["pid"]
                and inventory["start_ticks"] == facts["starttime_ticks"]
                and inventory["argv_sha256"] == facts.get("argv", {}).get("sha256")
                and owner["uid"] == facts["uid"]
                and owner["cwd_sha256"] == facts.get("cwd", {}).get("sha256")
                and owner["exe_sha256"] == facts.get("exe", {}).get("sha256")
                and owner["namespaces"] == namespaces and set(namespaces) == set(NAMESPACES)
                and facts.get("missing_process_fields") == []
                and facts.get("not_applicable_process_fields") == []
                and facts.get("process_representation") == "userspace_or_transition"
                and not facts["stat_flags_before"] & 0x00200000
                and not facts["stat_flags_after"] & 0x00200000
                and facts["stat_state_before"] not in ("Z", "X", "x")
                and facts["stat_state_after"] not in ("Z", "X", "x")):
            matches.append(authority_id(C, role, hostname, unit))
    return sorted(matches)


def classify_process(facts, namespaces):
    """Only positive stable intrinsic states justify a non-sender claim."""
    if (
        facts.get("procfs_mount_verified") is not True
        or facts.get("missing_process_fields") != []
        or set(namespaces) != set(NAMESPACES)
        or facts.get("stat_flags_before") is None
        or facts.get("stat_flags_after") is None
    ):
        return "unknown", None
    before, after = facts["stat_flags_before"], facts["stat_flags_after"]
    if type(before) is not int or type(after) is not int or not (0 <= before < 2**32 and 0 <= after < 2**32):
        return "unknown", None
    if before & 0x00200000 and after & 0x00200000 and facts.get("process_representation") == "kernel_thread":
        return "non_sender", "stable_pf_kthread"
    if (
        facts.get("stat_state_before") == facts.get("stat_state_after") == "Z"
        and facts.get("process_representation") == "stable_zombie"
        and not before & 0x00200000 and not after & 0x00200000
    ):
        return "non_sender", "stable_zombie"
    return "unknown", None


def _validate_facts(C, facts):
    required = (
        "pid", "uid", "procfs_mount_verified", "procfs_root_owned_fields", "starttime_ticks",
        "stat_flags_before", "stat_flags_after", "stat_state_before", "stat_state_after",
        "process_representation", "not_applicable_process_fields", "missing_process_fields",
    )
    optional = ("argv", "cgroup", "exe", "cwd", "uids_real_effective_saved_filesystem")
    C.require(type(facts) is dict and set(required) <= set(facts) <= set(required + optional), "census_domain_facts")
    C.require(type(facts["pid"]) is int and 0 < facts["pid"] < 10**10, "census_domain_fact_pid")
    C.require(type(facts["starttime_ticks"]) is str and re.fullmatch(r"[0-9]{1,20}", facts["starttime_ticks"]),
              "census_domain_fact_starttime")
    C.require(type(facts["uid"]) is int and 0 <= facts["uid"] < 2**32, "census_domain_fact_uid")
    C.require(facts["procfs_mount_verified"] is True, "census_domain_procfs_proof")
    for field in ("stat_flags_before", "stat_flags_after"):
        C.require(type(facts[field]) is int and 0 <= facts[field] < 2**32, "census_domain_fact_flags")
    for field in ("stat_state_before", "stat_state_after"):
        C.require(type(facts[field]) is str and facts[field] in tuple("RSDZTtXxKWPI"), "census_domain_fact_state")
    C.require(
        facts["process_representation"] in ("kernel_thread", "stable_zombie", "userspace_or_transition"),
        "census_domain_process_representation",
    )
    for field, allowed in (
        ("procfs_root_owned_fields", ("stat", "status", "cmdline", "cgroup")),
        ("not_applicable_process_fields", ("exe", "cwd")),
        ("missing_process_fields", ("argv", "cgroup", "uids_real_effective_saved_filesystem", "exe", "cwd")),
    ):
        C.require(
            type(facts[field]) is list and len(facts[field]) == len(set(facts[field]))
            and all(value in allowed for value in facts[field]), "census_domain_fact_fields",
        )
    for field in ("argv", "cgroup", "exe", "cwd"):
        if field in facts:
            value = facts[field]
            C.exact(value, ("sha256", "bytes", "known_academy_root_indicator", "known_job_indicator"))
            C.hexvalue(value["sha256"])
            C.require(type(value["bytes"]) is int and 0 <= value["bytes"] <= 1048576, "census_domain_projection_size")
            C.require(
                type(value["known_academy_root_indicator"]) is bool and type(value["known_job_indicator"]) is bool,
                "census_domain_projection_flags",
            )
    if "uids_real_effective_saved_filesystem" in facts:
        uids = facts["uids_real_effective_saved_filesystem"]
        C.require(
            type(uids) is list and len(uids) == 4 and all(type(uid) is int and 0 <= uid < 2**32 for uid in uids),
            "census_domain_status_uids",
        )
    if facts["missing_process_fields"] == []:
        C.require(
            all(field in facts for field in ("argv", "cgroup", "uids_real_effective_saved_filesystem")),
            "census_domain_missing_projection",
        )


def _namespace_identity(meta):
    return [meta.st_dev, meta.st_ino, meta.st_uid, meta.st_mode]


def _namespaces(d, row):
    """Read only fixed proc namespace metadata, bracketed by protected stat reads.

    Namespace magic links are inspected, never opened. Their inode relations are
    snapshot evidence in the observer's trusted mount view, not a root adversary
    boundary. A failed or changed relation invalidates the entire PID namespace set.
    """
    domain = "processes"
    root = d.directory("/proc", domain)
    if root is None:
        return {}
    fd = ns = None
    try:
        device = d.verify_procfs(root, domain)
        if device is None:
            return {}
        facts = row["facts"]
        pid = str(facts["pid"])
        fd = os.open(pid, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        parent = _namespace_identity(os.fstat(fd))
        exceptions = []
        first = d.read_proc_file(root, fd, pid, "stat", device, domain, exceptions)
        if first is None:
            return {}
        start, flags, state = d.process_stat(first, pid)
        if (start, flags, state) != (
            facts["starttime_ticks"], facts["stat_flags_after"], facts["stat_state_after"]
        ):
            raise ValueError
        ns = os.open("ns", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        nsmeta = os.fstat(ns)
        if nsmeta.st_dev != device or nsmeta.st_mode & 0o022 or nsmeta.st_uid not in (0, parent[2]):
            raise ValueError
        result = {}
        for name in NAMESPACES:
            if d.files >= 16384 or time.monotonic() >= d.deadline:
                raise ValueError
            d.files += 1
            link = os.stat(name, dir_fd=ns, follow_symlinks=False)
            target = os.readlink(name, dir_fd=ns)
            match = re.fullmatch(name + r":\[([0-9]{1,20})\]", target)
            inode = os.stat(name, dir_fd=ns)
            if (
                not stat.S_ISLNK(link.st_mode) or link.st_dev != device
                or link.st_uid not in (0, parent[2]) or match is None
                or inode.st_ino != int(match[1])
            ):
                raise ValueError
            result[name] = {
                "link": _namespace_identity(link), "target": target,
                "namespace": _namespace_identity(inode),
            }
        # Recheck every relation after the complete batch, including namespace and
        # PID directory names, so a set assembled across a namespace change fails.
        for name, value in result.items():
            if (
                value["link"] != _namespace_identity(os.stat(name, dir_fd=ns, follow_symlinks=False))
                or value["target"] != os.readlink(name, dir_fd=ns)
                or value["namespace"] != _namespace_identity(os.stat(name, dir_fd=ns))
            ):
                raise ValueError
        last = d.read_proc_file(root, fd, pid, "stat", device, domain, exceptions)
        if (
            last is None or d.process_stat(last, pid) != (start, flags, state)
            or parent != _namespace_identity(os.fstat(fd))
            or parent != _namespace_identity(os.stat(pid, dir_fd=root, follow_symlinks=False))
            or _namespace_identity(nsmeta) != _namespace_identity(os.stat("ns", dir_fd=fd, follow_symlinks=False))
            or d.verify_procfs(root, domain) != device
        ):
            raise ValueError
        return result
    except (OSError, ValueError, UnicodeError):
        d.gap(domain, "process_namespace_identity_unproved", raced=True)
        return {}
    finally:
        for descriptor in (ns, fd, root):
            if descriptor is not None:
                os.close(descriptor)


def observe_processes(C, m, role):
    """Production collector: no caller-supplied observations, commands or providers."""
    C.require(
        role in ("web", "lab") and os.geteuid() == 0 and sys.platform == "linux" and sys.version_info[:2] == (3, 12)
        and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode,
        "census_domain_root_isolated_linux",
    )
    C.require(socket.gethostname() == m["roles"][role]["hostname"], "census_domain_host_identity")
    raw, sources = _sources(C, m)
    module = types.ModuleType("_academy_approved_process_discovery")
    module.__file__ = sources[1]["path"]
    exec(compile(raw, module.__file__, "exec"), module.__dict__)  # noqa: S102
    C.require(module.HOSTS[role] == m["roles"][role]["hostname"], "census_domain_discovery_host_identity")
    started = int(time.time())
    discovery = module.Discovery(role)
    owners_before = _owners(C, m, role, discovery)
    discovery.processes()
    snapshot = discovery.domain("processes")
    objects = []
    for row in snapshot["records"]:
        namespaces = _namespaces(discovery, row)
        facts = row["facts"]
        classification, reason = classify_process(facts, namespaces)
        identifier = _identity(C, role, discovery.host, facts["pid"], facts["starttime_ticks"], namespaces)
        objects.append({
            "object_id": identifier, "authority_refs": [], "pid": facts["pid"],
            "starttime_ticks": facts["starttime_ticks"], "namespaces": namespaces,
            "facts": facts, "classification": classification, "non_sender_reason": reason,
        })
    gaps = list(snapshot["gaps"])
    if snapshot["enumerated"] != len(objects) or not snapshot["enumeration_complete"]:
        gaps.append("process_enumeration_unproved")
    # Namespace inspection extends the original interval and may expose additional
    # races. A process-set change during this stage is never silently accepted.
    root = discovery.directory("/proc", "processes")
    if root is None:
        gaps.append("process_final_enumeration_unproved")
    else:
        try:
            names = discovery.names(root, "processes")
            if names is None or {int(n) for n in names if n.isascii() and n.isdigit()} != {
                obj["pid"] for obj in objects
            }:
                gaps.append("process_final_set_changed")
        finally:
            os.close(root)
    owners_after = _owners(C, m, role, discovery)
    if owners_before != owners_after or any(owner is None for owner in owners_before.values()):
        gaps.append("legacy_owner_changed_or_unproved")
    owner_pids = [int(owner["inventory"]["unit_state"]["MainPID"])
                  for owner in owners_before.values() if owner is not None
                  and int(owner["inventory"]["unit_state"]["MainPID"]) != 0]
    if len(owner_pids) != len(set(owner_pids)):
        gaps.append("legacy_owner_duplicate_pid")
    unique_pids = len({obj["pid"] for obj in objects}) == len(objects)
    if not unique_pids:
        gaps.append("process_duplicate_pid")
    for obj in objects:
        if obj["classification"] == "unknown" and unique_pids:
            refs = _owner_refs(C, role, discovery.host, obj["facts"], obj["namespaces"], owners_before, owners_after)
            if refs:
                obj.update(classification="legacy_sender", authority_refs=refs)
    if any(obj["classification"] == "unknown" for obj in objects):
        gaps.append("process_positive_classification_unresolved")
    for pid in owner_pids:
        if not any(obj["pid"] == pid and obj["classification"] == "legacy_sender" for obj in objects):
            gaps.append("legacy_owner_process_join_unproved")
    _sources(C, m)  # Recheck all protected code pins after the complete observation.
    gaps = sorted(set(gaps + snapshot["gaps"]))
    stable = (
        snapshot["enumeration_complete"] is True
        and snapshot["enumerated"] == snapshot["inspected"] == snapshot["complete"] == len(objects)
        and snapshot["raced"] == snapshot["skipped"] == 0
        and snapshot["classification_complete"] is False
    )
    if not stable:
        gaps = sorted({*gaps, "process_stable_snapshot_unproved"})
    return {
        "schema": "AcademyCensusDomainObservation.v2", "candidate": m["candidate"], "tree": m["tree"],
        "role": role, "hostname": discovery.host, "domain": PROCESS_DOMAIN, "sources": sources,
        "observed_unix_started": started, "observed_unix_finished": int(time.time()),
        "enumerated_object_ids": sorted(obj["object_id"] for obj in objects),
        "objects": sorted(objects, key=lambda obj: obj["object_id"]), "snapshot": snapshot,
        "owners_before": owners_before, "owners_after": owners_after,
        "unresolved_gaps": gaps, "coverage_complete": stable and not gaps,
    }


def collect_domain(C, m, role, domain, *, evidence=None, approval=None, maintenance_status=None):
    C.require(domain in DOMAINS, "census_domain_unknown")
    if domain == SYSTEMD_DOMAIN:
        return observe_systemd(C, m, role, evidence=evidence, approval=approval,
                               maintenance_status=maintenance_status)
    C.require(domain == PROCESS_DOMAIN, "census_domain_adapter_unimplemented")
    return observe_processes(C, m, role)



def _validate_namespaces(C, namespaces):
    C.require(type(namespaces) is dict, "census_domain_namespaces")
    for name, value in namespaces.items():
        C.require(name in NAMESPACES, "census_domain_namespace_name")
        C.exact(value, ("link", "target", "namespace"))
        for field in ("link", "namespace"):
            C.require(
                type(value[field]) is list and len(value[field]) == 4
                and all(type(n) is int and n >= 0 for n in value[field]), "census_domain_namespace_metadata",
            )
        C.require(value["target"] == name + ":[" + str(value["namespace"][1]) + "]", "census_domain_ns_inode")
        C.require(stat.S_ISLNK(value["link"][3]), "census_domain_ns_link_metadata")


def _validate_owners(C, scope, role, proof, manifest):
    units = C.services(role)
    C.exact(proof["owners_before"], units)
    C.exact(proof["owners_after"], units)
    C.require(C.canonical(proof["owners_before"]) == C.canonical(proof["owners_after"]),
              "census_domain_owner_changed")
    if manifest is not None:
        C.require(all(manifest[k] == scope[k] for k in ("candidate", "tree"))
                  and manifest["roles"][role]["hostname"] == scope["hosts"][role]
                  and manifest["self_sha256"] == proof["sources"][2]["sha256"]
                  and manifest["helpers"]["census_domains"] == proof["sources"][0]["sha256"]
                  and manifest["helpers"]["census_discovery"] == proof["sources"][1]["sha256"],
                  "census_domain_owner_manifest_source_identity")
    pids = set()
    runtime = None
    for unit, owner in proof["owners_before"].items():
        C.exact(owner, ("inventory", "namespaces", "uid", "cwd_sha256", "exe_sha256"))
        inventory = owner["inventory"]
        C.exact(inventory, ("unit_state", "start_ticks", "argv_sha256", "gate_awareness", "planned_action"))
        state = inventory["unit_state"]
        C.exact(state, ("MainPID", "ActiveState", "SubState"))
        C.require(type(state["MainPID"]) is str and re.fullmatch(r"0|[1-9][0-9]{0,9}", state["MainPID"]),
                  "census_domain_owner_pid")
        for key in ("ActiveState", "SubState"):
            C.require(type(state[key]) is str and re.fullmatch(r"[a-z][a-z-]{0,63}", state[key]),
                      "census_domain_owner_state")
        C.require(inventory["gate_awareness"] == "legacy_gate_unaware"
                  and inventory["planned_action"] == ("stop_primary" if unit == units[0] else "drain_only"),
                  "census_domain_owner_semantics")
        pid = int(state["MainPID"])
        if pid == 0:
            C.require(inventory["start_ticks"] is None and inventory["argv_sha256"] is None
                      and owner["namespaces"] == {} and owner["uid"] is None
                      and owner["cwd_sha256"] is None and owner["exe_sha256"] is None,
                      "census_domain_inactive_owner")
            continue
        C.require(manifest is not None, "census_domain_owner_manifest_required")
        if runtime is None:
            runtime = C.baseline_runtime(manifest, role)
        C.require(pid > 1 and pid not in pids, "census_domain_owner_duplicate_or_invalid_pid")
        pids.add(pid)
        C.require(type(inventory["start_ticks"]) is str
                  and re.fullmatch(r"[0-9]{1,20}", inventory["start_ticks"]), "census_domain_owner_start")
        C.hexvalue(inventory["argv_sha256"])
        C.hexvalue(owner["cwd_sha256"])
        C.hexvalue(owner["exe_sha256"])
        C.require(type(owner["uid"]) is int and owner["uid"] == manifest["roles"][role]["uid"]
                  and owner["cwd_sha256"] == C.digest(runtime["units"][unit]["source"].encode()),
                  "census_domain_owner_baseline_join")
        C.require(type(owner["namespaces"]) is dict and set(owner["namespaces"]) == set(NAMESPACES),
                  "census_domain_owner_namespaces")
        _validate_namespaces(C, owner["namespaces"])


def validate_domain_proof(C, scope, role, domain, proof, *, manifest=None, evidence=None, approval=None):
    """Return stable owner refs after pure joins; this never proves collection.

    A manifest is mandatory for live legacy owner claims. The genuine source-pinned
    collector calls old_unit_inventory for runtime/HR semantics; this validator
    reconstructs the closed owner/snapshot join without rerunning observations.
    """
    if domain == SYSTEMD_DOMAIN:
        validate_systemd_observation(C, scope, role, proof, manifest=manifest, evidence=evidence, approval=approval)
        if proof["mode"] != "original" and evidence is not None and approval is not None:
            verify_systemd_named_controls(C, manifest, evidence, approval, role, proof["mode"], proof)
        C.require(False, "systemd_campaign_membership_activation_or_control_unresolved")
    C.exact(proof, PROOF_FIELDS)
    C.require(proof["schema"] == "AcademyCensusDomainObservation.v2", "census_domain_schema")
    C.require(
        role in ("web", "lab") and domain == PROCESS_DOMAIN
        and proof["role"] == role and proof["domain"] == domain
        and proof["hostname"] == scope["hosts"][role]
        and all(proof[k] == scope[k] for k in ("candidate", "tree")),
        "census_domain_scope_identity",
    )
    sources = proof["sources"]
    C.require(type(sources) is list and len(sources) == 3, "census_domain_source_triple")
    names = ("candidate_census_domains.py", "candidate_authority_discovery.py", "candidate_execute.py")
    for ref, name in zip(sources, names, strict=True):
        C.exact(ref, ("path", "sha256"))
        C.require(Path(ref["path"]) == Path(__file__).with_name(name), "census_domain_fixed_source_path")
        C.require(ref in scope["domains"][domain]["discovery_refs"], "census_domain_frozen_source_pin")
        _pin(C, ref["path"], ref["sha256"])
    C.require(sources[1]["sha256"] == DISCOVERY_SHA256, "census_domain_approved_discovery")
    C.require(
        all(type(proof[k]) is int for k in ("observed_unix_started", "observed_unix_finished"))
        and 0 < proof["observed_unix_started"] <= proof["observed_unix_finished"] <= int(time.time())
        and proof["observed_unix_finished"] - proof["observed_unix_started"] <= 300,
        "census_domain_original_interval",
    )
    C.require(type(proof["objects"]) is list and len(proof["objects"]) <= 8192, "census_domain_object_bound")
    _validate_owners(C, scope, role, proof, manifest)
    identifiers = []
    authority_refs = set()
    pids = set()
    for obj in proof["objects"]:
        C.exact(obj, OBJECT_FIELDS)
        C.require(type(obj["pid"]) is int and 0 < obj["pid"] < 10**10, "census_domain_pid")
        C.require(
            type(obj["starttime_ticks"]) is str and re.fullmatch(r"[0-9]{1,20}", obj["starttime_ticks"]),
            "census_domain_starttime",
        )
        _validate_namespaces(C, obj["namespaces"])
        facts = obj["facts"]
        _validate_facts(C, facts)
        C.require(
            type(facts) is dict and facts.get("pid") == obj["pid"]
            and facts.get("starttime_ticks") == obj["starttime_ticks"], "census_domain_fact_identity",
        )
        expected = _identity(C, role, proof["hostname"], obj["pid"], obj["starttime_ticks"], obj["namespaces"])
        C.require(obj["object_id"] == expected, "census_domain_object_identity")
        C.require(obj["pid"] not in pids, "census_domain_duplicate_pid")
        pids.add(obj["pid"])
        classification, reason = classify_process(facts, obj["namespaces"])
        refs = []
        if classification == "unknown":
            refs = _owner_refs(C, role, proof["hostname"], facts, obj["namespaces"],
                               proof["owners_before"], proof["owners_after"])
            if refs:
                classification = "legacy_sender"
        C.require((obj["classification"], obj["non_sender_reason"], obj["authority_refs"])
                  == (classification, reason, refs), "census_domain_positive_classification")
        authority_refs.update(refs)
        identifiers.append(expected)
    C.require(
        identifiers == sorted(set(identifiers)) == proof["enumerated_object_ids"], "census_domain_exact_object_coverage"
    )
    snapshot = proof["snapshot"]
    C.exact(snapshot, (
        "enumerated", "inspected", "raced", "complete", "skipped", "enumeration_complete",
        "classification_complete", "gaps", "records",
    ))
    C.require(
        all(type(snapshot[k]) is int for k in ("enumerated", "inspected", "complete", "raced", "skipped"))
        and snapshot["enumerated"] == snapshot["inspected"] == snapshot["complete"] == len(identifiers)
        and snapshot["raced"] == snapshot["skipped"] == 0 and snapshot["enumeration_complete"] is True
        and snapshot["classification_complete"] is False
        and snapshot["gaps"] == [] and len(snapshot["records"]) == len(identifiers),
        "census_domain_stable_enumeration",
    )
    for row in snapshot["records"]:
        C.exact(row, ("authority_id", "identity", "identity_sha256", "unknown_identity", "relevance", "facts"))
        entity = str(row["facts"]["pid"]) + ":" + row["facts"]["starttime_ticks"]
        C.require(
            row["authority_id"] == C.digest((proof["hostname"] + "\0processes\0" + entity).encode())
            and row["identity_sha256"] == C.digest(entity.encode())
            and row["identity"] is None and row["unknown_identity"] is True and row["relevance"] == "unresolved",
            "census_domain_discovery_row_identity",
        )
    C.require(
        sorted(C.digest(C.canonical(row["facts"])) for row in snapshot["records"])
        == sorted(C.digest(C.canonical(obj["facts"])) for obj in proof["objects"]),
        "census_domain_snapshot_object_join",
    )
    C.require(
        proof["unresolved_gaps"] == [] and proof["coverage_complete"] is True
        and all(obj["classification"] in ("non_sender", "legacy_sender") for obj in proof["objects"]),
        "census_domain_unresolved_objects_or_gaps",
    )
    expected_refs = {authority_id(C, role, proof["hostname"], unit)
                     for unit, owner in proof["owners_before"].items()
                     if int(owner["inventory"]["unit_state"]["MainPID"]) != 0}
    C.require(authority_refs == expected_refs, "census_domain_exact_owner_coverage")
    return authority_refs


def collect_role(C, m, role, scope, *, evidence=None, approval=None, maintenance_status=None):
    """Collect actual local process evidence, then fixed remaining local domains.

    Currently refuses at the first missing adapter after collecting processes.
    No partial result or caller-authored proof is promoted to completed scope.
    """
    C.require(
        role in ("web", "lab") and scope["hosts"][role] == m["roles"][role]["hostname"]
        and all(scope[k] == m[k] for k in ("candidate", "tree")), "census_domain_role_scope_identity",
    )
    proofs = {PROCESS_DOMAIN: collect_domain(C, m, role, PROCESS_DOMAIN)}
    for domain in DOMAINS:
        if domain != PROCESS_DOMAIN:
            proofs[domain] = collect_domain(C, m, role, domain, evidence=evidence, approval=approval,
                                             maintenance_status=maintenance_status)
    require_complete_role_scope(C, scope, role, proofs, manifest=m, evidence=evidence, approval=approval)
    return proofs


def require_complete_role_scope(C, scope, role, proofs, *, manifest=None, evidence=None, approval=None):
    """Validate one role's exact eight domains; remote role proofs are separate.

    This cannot succeed until the other six production adapters exist. The
    process dictionary validator is pure validation, not current reproduction.
    """
    C.require(role in ("web", "lab"), "census_domain_role")
    C.exact(proofs, DOMAINS)
    C.exact(scope["authority_membership"][role], BUCKETS)
    seen = set()
    for ids in scope["authority_membership"][role].values():
        C.require(type(ids) is list and ids == sorted(set(ids)), "census_domain_frozen_membership")
        for identifier in ids:
            C.hexvalue(identifier)
        C.require(not seen.intersection(ids), "census_domain_disjoint_authorities")
        seen.update(ids)
    validate_domain_proof(C, scope, role, SYSTEMD_DOMAIN, proofs[SYSTEMD_DOMAIN], manifest=manifest,
                          evidence=evidence, approval=approval)
    refs = validate_domain_proof(C, scope, role, PROCESS_DOMAIN, proofs[PROCESS_DOMAIN], manifest=manifest)
    C.require(refs <= set(scope["authority_membership"][role]["legacy"]), "census_domain_legacy_membership_missing")
    C.require(False, "census_domain_adapter_unimplemented")


def require_complete_scope(C, scope, domain_proofs, *, manifest=None, evidence=None, approval=None):
    """No authored complete flag can bypass missing domains or production adapters.

    This reducer cannot currently succeed: six production domains are explicitly
    unsupported. It validates structural membership before that explicit refusal;
    future domain implementations must add protected reproduction, not flags.
    """
    C.exact(domain_proofs, DOMAINS)
    C.exact(scope["hosts"], ("web", "lab"))
    C.exact(scope["authority_membership"], ("web", "lab"))
    for role in ("web", "lab"):
        C.exact(scope["authority_membership"][role], BUCKETS)
        seen = set()
        for ids in scope["authority_membership"][role].values():
            C.require(type(ids) is list and ids == sorted(set(ids)), "census_domain_frozen_membership")
            for identifier in ids:
                C.hexvalue(identifier)
            C.require(not seen.intersection(ids), "census_domain_disjoint_authorities")
            seen.update(ids)
    for domain in DOMAINS:
        C.exact(domain_proofs[domain], ("web", "lab"))
    process = domain_proofs[PROCESS_DOMAIN]
    for role in ("web", "lab"):
        validate_domain_proof(C, scope, role, SYSTEMD_DOMAIN, domain_proofs[SYSTEMD_DOMAIN][role], manifest=manifest,
                              evidence=evidence, approval=approval)
        refs = validate_domain_proof(C, scope, role, PROCESS_DOMAIN, process[role], manifest=manifest)
        C.require(refs <= set(scope["authority_membership"][role]["legacy"]), "census_domain_legacy_membership_missing")
    C.require(False, "census_domain_adapter_unimplemented")


SYSTEMD_FIELDS = (
    "schema", "candidate", "tree", "role", "hostname", "domain", "sources", "maintenance_sources",
    "observed_unix_started", "observed_unix_finished", "mode", "named_before", "named_after",
    "control_before", "control_after", "discovery", "unit_membership", "enumerated_object_ids", "objects",
    "maintenance_lifecycle", "adapter_accounting", "unresolved_gaps", "coverage_complete",
)
SYSTEMD_OBJECT_FIELDS = (
    "object_id", "unit_sha256", "authority_refs", "classification", "classification_basis_sha256",
    "campaign_bucket", "activation_complete", "control_state", "graph_rows", "definition_rows",
)
DISCOVERY_SCHEMA_SHA256 = "16080f9c31ed12e85ea198970d99aacbc26db3cfdd4a917d8276072e5047a1d4"
SYSTEMD_LISTINGS = ("systemd_installed", "systemd_loaded", "systemd_installed_final", "systemd_loaded_final")


def systemd_authority_id(C, role, hostname, unit):
    """Primary legacy joins preserve the existing unsuffixed authority identifiers."""
    primary = {name + ".service": name for name in C.services(role)}
    if unit in primary:
        return authority_id(C, role, hostname, primary[unit])
    return C.digest(C.canonical({"schema": "AcademySystemdUnitAuthority.v1", "hostname": hostname,
                                 "role": role, "unit": unit}))


def _systemd_object_id(C, role, hostname, unit_sha256):
    return C.digest(C.canonical({"schema": "AcademySystemdUnitObject.v1", "hostname": hostname,
                                 "role": role, "unit_sha256": unit_sha256}))


class SystemdObservationHold(Exception):
    """Terminal adapter refusal: never downgrade cancellation or uncertain cleanup to a gap."""


def _systemd_check(C, budget):
    if budget is None:
        return
    budget["work"] += 1
    if budget["work"] > 1_048_576 or time.monotonic() >= budget["deadline"]:
        raise SystemdObservationHold("systemd_adapter_deadline_or_work_bound")
    discovery = budget.get("discovery")
    if discovery is not None and (discovery.pending_signal is not None or discovery.resource_stopped):
        raise SystemdObservationHold("systemd_adapter_interrupted_or_resource_stopped")
    maintenance = budget.get("maintenance")
    if maintenance is not None:
        for record in maintenance.COMMANDS[budget["command_start"]:]:
            if record.get("cleanup", {}).get("confirmed") is not True:
                raise SystemdObservationHold("systemd_maintenance_cleanup_unconfirmed")
        if maintenance.SPAWNING or maintenance.PENDING:
            raise SystemdObservationHold("systemd_maintenance_child_state_unconfirmed")


def _systemd_signal(discovery, maintenance, budget, number, frame):
    discovery.request_signal(number, frame)
    if budget["phase"] == "maintenance":
        if number == signal.SIGHUP:
            # Cleanup masks INT/TERM, so HUP must remain a non-raising latch through cleanup/restoration.
            maintenance.PENDING = True
        else:
            maintenance.interrupted(number, frame)


def _systemd_maintenance_call(C, budget, operation):
    _systemd_check(C, budget)
    previous = budget["phase"]
    budget["phase"] = "maintenance"
    try:
        return operation()
    finally:
        budget["phase"] = previous
        _systemd_check(C, budget)


def _systemd_module(C, m):
    raw, sources = _sources(C, m)
    module = types.ModuleType("_academy_approved_systemd_discovery")
    module.__file__ = sources[1]["path"]
    exec(compile(raw, module.__file__, "exec"), module.__dict__)  # noqa: S102 -- protected exact Discovery source
    schema_path = Path(__file__).with_name("discovery.schema.json")
    schema_raw = _pin(C, schema_path, DISCOVERY_SCHEMA_SHA256)
    module._systemd_normal_schema = json.loads(schema_raw)
    return module, [*sources, {"path": str(schema_path), "sha256": DISCOVERY_SCHEMA_SHA256}]


def _systemd_component(C, m):
    maintenance = C.maintenance_module(m)  # Existing protected, exact helper loader; no caller provider.
    component = maintenance.validate_component(C, m)
    refs = [dict(m["maintenance"]), dict(m["helpers"]["maintenance"]), dict(component["plan"])]
    return maintenance, component, refs


def _systemd_mode(C, evidence, approval, maintenance_status):
    supplied = (evidence is not None, approval is not None, maintenance_status is not None)
    C.require(all(supplied) or not any(supplied), "systemd_control_context_incomplete")
    if not any(supplied):
        return "original"
    C.require(maintenance_status in ("fenced", "adopted_and_fenced"), "systemd_control_status")
    return maintenance_status


def _systemd_expected_identity(maintenance, C, m, component, role, unit, mode):
    row = maintenance.original_identity_expected(component, role, unit)
    if mode != "original":
        row["effective_config_sha256"] = component["hosts"][role]["units"][unit]["expected_config_sha256"][mode]
        row["unit_text_sha256"] = None  # No reconstructed systemctl-cat text is asserted for controlled units.
        files = list(row["source_files"])
        files.append({"path_sha256": C.digest(str(maintenance.own_path(m, unit, True)).encode()),
                      "body_sha256": C.digest(maintenance.fence_bytes(unit))})
        if mode == "adopted_and_fenced" and unit in maintenance.ADOPT:
            files.append({"path_sha256": C.digest(str(maintenance.own_path(m, unit, False)).encode()),
                          "body_sha256": C.digest(maintenance.adoption_bytes(m, unit))})
        row["source_files"] = sorted(files, key=lambda item: item["path_sha256"])
        if unit.endswith(".service"):
            row["configured_command_sha256"] = C.digest(b"/usr/bin/false")
    return row


def _systemd_control(C, m, maintenance, component, evidence, approval, role, mode, deadline):
    C.require(callable(getattr(evidence, "get", None)) and type(approval) is dict and "attempt" in approval,
              "systemd_genuine_control_context")
    C.require(mode in ("fenced", "adopted_and_fenced") and (role == "lab" or mode == "fenced"),
              "systemd_control_role_status")
    proof = maintenance.verify_observation(C, m, evidence, approval, role, mode, deadline=deadline)
    C.require(proof["status"] == mode and proof.get("host_local_current_state_proven") is True
              and proof["remote_current_state_proven"] is False, "systemd_actual_current_control")
    maintenance.validate_current_body(m, component, role, mode, proof["current"])
    return {"schema": "AcademySystemdNamedControl.v1", "candidate": m["candidate"], "tree": m["tree"],
            "role": role, "status": mode, "attempt": approval["attempt"],
            "component_sha256": m["maintenance"]["sha256"],
            "helper_sha256": m["helpers"]["maintenance"]["sha256"], "proof": proof}


def _systemd_named_snapshot(C, m, maintenance, component, role, mode, deadline, control, budget):
    rows = {}
    for unit in component["hosts"][role]["units"]:
        _systemd_check(C, budget)
        identifier = C.digest(unit.encode())
        try:
            maintenance.read_timeout(deadline)
            if mode == "original":
                rows[identifier] = _systemd_maintenance_call(C, budget, lambda unit=unit:
                    maintenance.original_identity_projection(C, m, component, role, unit, deadline=deadline))
            elif control is not None:
                # verify_observation already checked actual originals, owned bytes, config, jobs and cgroups.
                rows[identifier] = _systemd_expected_identity(maintenance, C, m, component, role, unit, mode)
            else:
                rows[identifier] = None
        except SystemdObservationHold:
            raise
        except (OSError, ValueError, maintenance.Refusal):
            # Only expected metadata refusals become unknown; programming/API errors remain terminal.
            rows[identifier] = None
        _systemd_check(C, budget)
    return rows


def _systemd_graph_join(identifier, identity, graphs, definitions, C=None, budget=None):
    if len(graphs) != 1 or len(definitions) != 1:
        return False
    graph = graphs[0][1]["facts"]
    definition, source_domain = definitions[0][1:]
    facts = definition["facts"]
    if not (graph["requested_identity_sha256"] == identifier and graph["graph_fields_unchanged"] is True
            and graph["membership_before"] == graph["membership_after"]
            and "enumeration_boundary_unavailable" not in graph["gaps"]
            and "membership_changed_or_unavailable" not in graph["gaps"]
            and all(type(value) is bool for value in graph["membership_before"].values())
            and facts["requested_identity_sha256"] == facts["canonical_identity_sha256"] == identifier
            and facts["aliases"]["count"] == 0 and facts["aliases"]["identity_sha256"] == []
            and facts["aliases"]["ordered_sha256"] == "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
            and facts["fragment_kind"] == "regular" and facts["mask"] is False
            and facts["source_acquisition_complete"] is True):
        return False
    for phase in ("initial", "repeated"):
        _systemd_check(C, budget)
        fields = graph[phase]["fields"]
        for key, expected in {"Id": [identifier], "Names": [identifier], **identity["dependencies"]}.items():
            item = fields.get(key)
            if (item is None or item["valid"] is not True or item["unparsed_tail"] is not False
                    or sorted(item["endpoint_sha256"]) != expected):
                return False
    expected = identity["source_files"]
    for phase in ("initial", "repeated"):
        observed = []
        for source in facts["sources"]:
            _systemd_check(C, budget)
            index = source[phase + "_read"]
            if type(index) is not int or not 0 <= index < len(source_domain["source_reads"]):
                return False
            read = source_domain["source_reads"][index]
            path_index = read["path_reference"]
            if type(path_index) is not int or not 0 <= path_index < len(source_domain["path_observations"]):
                return False
            path = source_domain["path_observations"][path_index]
            if (read["phase"] != phase or path["phase"] != phase or read["mask"] is not False
                    or path["kind"] != "selected_regular"
                    or not read["before_sha256"] == read["after_sha256"] == path["metadata_sha256"]):
                return False
            observed.append({"path_sha256": path["path_sha256"], "body_sha256": read["body_sha256"]})
        if sorted(observed, key=lambda row: row["path_sha256"]) != expected:
            return False
    return True


def _systemd_objects(C, m, maintenance, component, role, report, membership, before, after, mode, controls_stable,
                     budget=None):
    domains = report["domains"]
    definition_domain = domains.get("systemd_template_definitions", {"records": []})
    graphs, definitions = {}, {}
    identifiers = {identifier for values in membership.values() for identifier in values}
    for label in SYSTEMD_LISTINGS:
        for row in domains.get(label, {"records": []})["records"]:
            _systemd_check(C, budget)
            identifiers.add(row["identity_sha256"])
    for index, row in enumerate(domains.get("systemd_unit_graph", {"records": []})["records"]):
        identifier = row["identity_sha256"]
        identifiers.add(identifier)
        graphs.setdefault(identifier, []).append((index, row))
    for index, row in enumerate(definition_domain["records"]):
        identifier = row["identity_sha256"]
        identifiers.add(identifier)
        definitions.setdefault(identifier, []).append((index, row, definition_domain))
    C.require(len(identifiers) <= 33792, "systemd_object_union_bound")
    names = {C.digest(unit.encode()): unit for unit in component["hosts"][role]["units"]}
    result = []
    for identifier in sorted(identifiers):
        _systemd_check(C, budget)
        C.hexvalue(identifier)
        identity = before.get(identifier)
        matched = (identity is not None and identity == after.get(identifier) and identifier in names
                   and _systemd_graph_join(identifier, identity, graphs.get(identifier, []),
                                           definitions.get(identifier, []), C, budget))
        result.append({
            "object_id": _systemd_object_id(C, role, report["host"], identifier), "unit_sha256": identifier,
            "authority_refs": [systemd_authority_id(C, role, report["host"], names[identifier])] if matched else [],
            "classification": "named_execution_authority" if matched else "unknown",
            "classification_basis_sha256": C.digest(C.canonical(identity)) if matched else None,
            "campaign_bucket": "unresolved", "activation_complete": False,
            "control_state": "named_fenced" if matched and mode != "original" and controls_stable else "unobserved",
            "graph_rows": [row[0] for row in graphs.get(identifier, [])],
            "definition_rows": [row[0] for row in definitions.get(identifier, [])],
        })
    return sorted(result, key=lambda row: row["object_id"])


def _systemd_gaps(report, objects, before, after, mode, controls_stable):
    gaps = {"systemd_campaign_membership_unresolved", "systemd_activation_semantics_unresolved"}
    for name, domain in report["domains"].items():
        if name in SYSTEMD_LISTINGS and not domain["enumeration_complete"]:
            gaps.add("systemd_listing_membership_unavailable")
        if domain["gaps"] or not domain["enumeration_complete"] or domain["raced"] or domain["skipped"]:
            gaps.add("systemd_discovery_domain_incomplete")
        if name in SYSTEMD_LISTINGS and domain["enumerated"] != len(domain["records"]):
            gaps.add("systemd_listing_coverage_unproved")
    if any(len({row["identity_sha256"] for row in domain["records"]}) != len(domain["records"])
           for domain in report["domains"].values()):
        gaps.add("systemd_duplicate_unit_observations")
    if any(name not in report["domains"] for name in (*SYSTEMD_LISTINGS, "systemd_unit_graph",
                                                     "systemd_template_definitions")):
        gaps.add("systemd_observation_domain_missing")
    if any(row["classification"] == "unknown" for row in objects):
        gaps.add("systemd_named_identity_unresolved")
    if not set(before) <= {row["unit_sha256"] for row in objects}:
        gaps.add("systemd_declared_units_not_observed")
    if before != after or any(value is None for value in before.values()):
        gaps.add("systemd_named_source_changed_or_unproved")
    if mode == "original" or not controls_stable:
        gaps.add("systemd_current_controls_unproved")
    life = report["child_lifecycle"]
    accounting = report["resource_accounting"]
    if (life["spawned"] != life["reaped"] or life["spawned"] != life["group_cleanup_confirmed"]
            or life["group_cleanup_unconfirmed"] or life["termination_requests"]
            or report["signal_interrupted"] or accounting["resource_stopped"]
            or accounting["observation_retention_incomplete"] or accounting["reserved_definition_filesystem_work"]):
        gaps.add("systemd_lifecycle_or_resource_unproved")
    return sorted(gaps)


def observe_systemd(C, m, role, *, evidence=None, approval=None, maintenance_status=None):
    """Actual protected systemd acquisition; never a caller-authored complete dictionary."""
    C.require(role in ("web", "lab") and os.geteuid() == 0 and sys.platform == "linux"
              and sys.version_info[:2] == (3, 12) and sys.flags.isolated and sys.flags.no_site
              and sys.flags.dont_write_bytecode and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
              and hasattr(os, "WNOWAIT"), "census_domain_root_isolated_linux")
    C.require(socket.gethostname() == m["roles"][role]["hostname"], "census_domain_host_identity")
    mode = _systemd_mode(C, evidence, approval, maintenance_status)
    C.require(role == "lab" or mode != "adopted_and_fenced", "systemd_control_role_status")
    module, sources = _systemd_module(C, m)
    C.require(module.HOSTS[role] == m["roles"][role]["hostname"], "census_domain_discovery_host_identity")
    maintenance, component, refs = _systemd_component(C, m)
    discovery = module.Discovery(role)
    deadline = discovery.deadline
    started = int(time.time())
    budget = {"work": 0, "deadline": deadline, "discovery": discovery, "maintenance": maintenance,
              "command_start": len(maintenance.COMMANDS), "phase": "discovery"}
    controls = [None, None]
    previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    def interrupted(number, frame):
        _systemd_signal(discovery, maintenance, budget, number, frame)

    for number in previous:
        signal.signal(number, interrupted)
    try:
        if mode != "original":
            try:
                controls[0] = _systemd_maintenance_call(C, budget, lambda:
                    _systemd_control(C, m, maintenance, component, evidence, approval, role, mode, deadline))
            except SystemdObservationHold:
                raise
            except Exception:
                controls[0] = None  # Preserve the systemd observation, with current control explicitly unresolved.
        before = _systemd_named_snapshot(C, m, maintenance, component, role, mode, deadline, controls[0], budget)
        _systemd_check(C, budget)
        discovery.systemd()
        discovery.template_definitions()
        _systemd_check(C, budget)
        if mode != "original":
            try:
                controls[1] = _systemd_maintenance_call(C, budget, lambda:
                    _systemd_control(C, m, maintenance, component, evidence, approval, role, mode, deadline))
            except SystemdObservationHold:
                raise
            except Exception:
                controls[1] = None
        after = _systemd_named_snapshot(C, m, maintenance, component, role, mode, deadline, controls[1], budget)
    finally:
        try:
            discovery.definition_close_pass()
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
    _systemd_check(C, budget)
    _systemd_module(C, m)  # Recheck all four systemd source/schema pins.
    _maintenance, _component, after_refs = _systemd_component(C, m)
    C.require(component == _component and refs == after_refs, "systemd_component_changed")
    _systemd_check(C, budget)
    limit = module.RESOURCE_PROFILE["normal_json_bytes"]
    with discovery.seal() as sealed:
        raw = sealed.read(limit + 1)
    C.require(len(raw) <= limit, "systemd_sealed_report_bound")
    report = json.loads(raw)
    C.require(report["schema"] == "AcademyAuthorityDiscovery.v3", "systemd_normal_report_refused")
    _systemd_check(C, budget)
    stable = controls[0] is not None and controls[0] == controls[1]
    membership = {label: sorted(C.digest(unit.encode()) for unit in units) for label, units in zip(
        SYSTEMD_LISTINGS, (discovery.installed_units, discovery.loaded_units,
                          discovery.final_installed_units, discovery.final_loaded_units), strict=True)}
    objects = _systemd_objects(C, m, maintenance, component, role, report, membership, before, after, mode, stable,
                               budget)
    records = maintenance.COMMANDS[budget["command_start"]:]
    lifecycle = {"attempted": len(records), "cleanup_confirmed": len(records),
                 "records": records, "records_sha256": C.digest(C.canonical(records)),
                 "spawning": maintenance.SPAWNING, "pending_signal": maintenance.PENDING}
    proof = {"schema": "AcademySystemdCensusDomainObservation.v1", "candidate": m["candidate"], "tree": m["tree"],
             "role": role, "hostname": discovery.host, "domain": SYSTEMD_DOMAIN, "sources": sources,
             "maintenance_sources": refs, "observed_unix_started": started, "observed_unix_finished": int(time.time()),
             "mode": mode, "named_before": before, "named_after": after,
             "control_before": controls[0], "control_after": controls[1], "discovery": report,
             "unit_membership": membership, "maintenance_lifecycle": lifecycle,
             "adapter_accounting": {"capture_reconstruction_work_before_validation": budget["work"],
                                    "work_limit": 1_048_576,
                                    "proof_byte_limit": limit},
             "objects": objects, "enumerated_object_ids": [obj["object_id"] for obj in objects],
             "unresolved_gaps": _systemd_gaps(report, objects, before, after, mode, stable), "coverage_complete": False}
    # Explicit structural partial validation; it grants no current authority or completed scope.
    scope = {"candidate": m["candidate"], "tree": m["tree"], "hosts": {role: discovery.host},
             "domains": {SYSTEMD_DOMAIN: {"discovery_refs": sources}}}
    validate_systemd_observation(C, scope, role, proof, manifest=m, evidence=evidence, approval=approval,
                                 _budget=budget)
    _systemd_check(C, budget)
    module.canonical_size(proof, limit - 1)
    _systemd_check(C, budget)
    with module.stage_json(proof, limit) as staged:
        bounded = staged.read(limit + 1)
    _systemd_check(C, budget)
    C.require(len(bounded) <= limit, "systemd_proof_encoded_bound")
    return proof


def validate_systemd_observation(C, scope, role, proof, *, manifest, evidence=None, approval=None,
                                 _budget=None):
    """Pure structural/source joins for partial evidence; never refreshes observation time."""
    C.exact(proof, SYSTEMD_FIELDS)
    C.require(manifest is not None and proof["schema"] == "AcademySystemdCensusDomainObservation.v1"
              and proof["domain"] == SYSTEMD_DOMAIN and proof["role"] == role
              and proof["hostname"] == scope["hosts"][role] == manifest["roles"][role]["hostname"]
              and all(proof[key] == scope[key] == manifest[key] for key in ("candidate", "tree")),
              "systemd_scope_identity")
    C.require(proof["coverage_complete"] is False and proof["mode"] in ("original", "fenced", "adopted_and_fenced")
              and (role == "lab" or proof["mode"] != "adopted_and_fenced"),
              "systemd_completion_or_mode")
    C.require(all(type(proof[key]) is int for key in ("observed_unix_started", "observed_unix_finished"))
              and 0 < proof["observed_unix_started"] <= proof["observed_unix_finished"] <= int(time.time())
              and proof["observed_unix_finished"] - proof["observed_unix_started"] <= 300, "systemd_original_interval")
    module, sources = _systemd_module(C, manifest)
    budget = _budget if _budget is not None else {"work": 0, "deadline": time.monotonic() + 300}
    _systemd_check(C, budget)
    module.canonical_size(proof, module.RESOURCE_PROFILE["normal_json_bytes"] - 1)
    _systemd_check(C, budget)
    _FixedDiscoveryValidator(C, module._systemd_normal_schema, budget).validate_normal(proof["discovery"])
    _systemd_check(C, budget)
    C.require(proof["sources"] == sources and all(ref in scope["domains"][SYSTEMD_DOMAIN]["discovery_refs"]
                                                for ref in sources), "systemd_frozen_source_pins")
    maintenance, component, refs = _systemd_component(C, manifest)
    C.require(proof["maintenance_sources"] == refs, "systemd_component_source_pins")
    named = {C.digest(unit.encode()): unit for unit in component["hosts"][role]["units"]}
    for label in ("named_before", "named_after"):
        _systemd_check(C, budget)
        C.exact(proof[label], named)
        for identifier, identity in proof[label].items():
            control_label = "control_before" if label == "named_before" else "control_after"
            if proof["mode"] != "original" and proof[control_label] is None:
                C.require(identity is None, "systemd_failed_control_identity_unproved")
            if identity is not None:
                C.require(identity == _systemd_expected_identity(maintenance, C, manifest, component, role,
                                                                named[identifier], proof["mode"]),
                          "systemd_named_identity_recipe")
    for label in ("control_before", "control_after"):
        _systemd_check(C, budget)
        control = proof[label]
        if control is None:
            continue
        C.require(proof["mode"] != "original" and evidence is not None and approval is not None,
                  "systemd_genuine_control_context_required")
        C.exact(control, ("schema", "candidate", "tree", "role", "status", "attempt", "component_sha256",
                          "helper_sha256", "proof"))
        C.require(control["schema"] == "AcademySystemdNamedControl.v1" and control["role"] == role
                  and control["status"] == proof["mode"] and control["attempt"] == approval["attempt"]
                  and all(control[key] == manifest[key] for key in ("candidate", "tree"))
                  and control["component_sha256"] == refs[0]["sha256"]
                  and control["helper_sha256"] == refs[1]["sha256"], "systemd_control_binding")
        retained = maintenance.verify_retained(C, manifest, evidence, approval, role, proof["mode"])
        _systemd_check(C, budget)
        actual = control["proof"]
        C.exact(actual, (*retained, "current", "host_local_current_state_proven"))
        C.require(all(actual[key] == value for key, value in retained.items())
                  and actual["host_local_current_state_proven"] is True, "systemd_actual_retained_control")
        maintenance.validate_current_body(manifest, component, role, proof["mode"], actual["current"])
    report = proof["discovery"]
    _validate_systemd_report(C, module, proof, budget)
    C.require(report["schema"] == "AcademyAuthorityDiscovery.v3" and report["role"] == role
              and report["host"] == proof["hostname"] and report["purpose"] == "readonly_discovery_facts_only"
              and report["coverage_complete"] is report["classification_complete"]
              is report["campaign_authority_claimed"] is False, "systemd_discovery_identity")
    for _name, domain in report["domains"].items():
        C.require(type(domain["records"]) is list and len(domain["records"]) <= 8192, "systemd_domain_record_bound")
        for row in domain["records"]:
            C.hexvalue(row["identity_sha256"])
            C.hexvalue(row["authority_id"])
    C.exact(proof["unit_membership"], SYSTEMD_LISTINGS)
    for label, identifiers in proof["unit_membership"].items():
        C.require(type(identifiers) is list and identifiers == sorted(set(identifiers))
                  and len(identifiers) <= 8192, "systemd_membership_hashes")
        for identifier in identifiers:
            C.hexvalue(identifier)
        listing = report["domains"].get(label)
        if listing is not None:
            if listing["enumeration_complete"]:
                retained = {row["identity_sha256"] for row in listing["records"]}
                C.require(retained <= set(identifiers) and len(identifiers) <= listing["enumerated"],
                          "systemd_listing_membership_join")
                if not report["resource_accounting"]["observation_retention_incomplete"]:
                    C.require(set(identifiers) == retained, "systemd_complete_listing_exact_membership")
    stable = proof["control_before"] is not None and proof["control_before"] == proof["control_after"]
    expected = _systemd_objects(C, manifest, maintenance, component, role, report, proof["unit_membership"],
                                proof["named_before"], proof["named_after"], proof["mode"], stable, budget)
    C.require(proof["objects"] == expected and proof["enumerated_object_ids"] == [row["object_id"] for row in expected],
              "systemd_exact_object_union_and_attribution")
    C.require(proof["unresolved_gaps"] == _systemd_gaps(report, expected, proof["named_before"], proof["named_after"],
                                                      proof["mode"], stable), "systemd_reconstructed_gaps")
    return {ref for row in expected for ref in row["authority_refs"]}


def verify_systemd_named_controls(C, m, evidence, approval, role, status, proof):
    """Reproduce genuine selected-unit controls; never proves dependency/global closure."""
    C.require(status in ("fenced", "adopted_and_fenced") and proof["mode"] == status,
              "systemd_control_status")
    scope = {"candidate": m["candidate"], "tree": m["tree"], "hosts": {role: m["roles"][role]["hostname"]},
             "domains": {SYSTEMD_DOMAIN: {"discovery_refs": proof["sources"]}}}
    budget = {"work": 0, "deadline": time.monotonic() + 300}
    validate_systemd_observation(C, scope, role, proof, manifest=m, evidence=evidence, approval=approval,
                                 _budget=budget)
    maintenance, component, _refs = _systemd_component(C, m)
    module, _sources_now = _systemd_module(C, m)
    discovery = module.Discovery(role)
    discovery.deadline = budget["deadline"]  # One invocation budget, including the preceding validation.
    budget.update(discovery=discovery, maintenance=maintenance,
                  command_start=len(maintenance.COMMANDS), phase="discovery")
    _systemd_check(C, budget)
    previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}

    def interrupted(number, frame):
        _systemd_signal(discovery, maintenance, budget, number, frame)

    try:
        for number in previous:
            signal.signal(number, interrupted)
        current = _systemd_maintenance_call(C, budget, lambda:
            _systemd_control(C, m, maintenance, component, evidence, approval, role, status, discovery.deadline))
    finally:
        try:
            discovery.definition_close_pass()
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
    _systemd_check(C, budget)
    C.require(proof["control_before"] == proof["control_after"] == current, "systemd_current_control_drift")
    matched = {row["unit_sha256"] for row in proof["objects"]
               if row["classification"] == "named_execution_authority" and row["control_state"] == "named_fenced"}
    expected = {C.digest(unit.encode()) for unit in component["hosts"][role]["units"]}
    C.require(matched == expected, "systemd_exact_named_control_object_join")
    return current


def _validate_systemd_report(C, module, proof, budget):
    """Additional semantic joins after the complete pinned normal_v3 structural validation."""
    report = proof["discovery"]
    generic = ("enumerated", "inspected", "raced", "complete", "skipped", "enumeration_complete",
               "classification_complete", "gaps", "records")
    C.exact(report, ("schema", "role", "host", "coverage_complete", "campaign_authority_claimed",
                     "classification_complete", "purpose", "domains", "commands_attempted", "files_attempted",
                     "child_lifecycle", "signal_interrupted", "resource_profile", "resource_profile_sha256",
                     "resource_accounting"))
    profile = module.RESOURCE_PROFILE
    C.require(report["resource_profile"] == profile
              and report["resource_profile_sha256"] == C.digest(C.canonical(profile)), "systemd_resource_profile")
    C.exact(report["child_lifecycle"], ("spawned", "reaped", "group_cleanup_confirmed",
                                      "group_cleanup_unconfirmed", "termination_requests"))
    lifecycle = report["child_lifecycle"]
    C.require(all(type(value) is int and value >= 0 for value in lifecycle.values())
              and lifecycle["spawned"] == lifecycle["reaped"] == lifecycle["group_cleanup_confirmed"]
              and lifecycle["group_cleanup_unconfirmed"] == lifecycle["termination_requests"] == 0,
              "systemd_discovery_child_cleanup")
    accounting = report["resource_accounting"]
    C.exact(accounting, ("captured_payload_bytes", "resource_stopped", "resource_stop_reason",
                         "observation_retention_incomplete", "retained_ordinary_record_json_bytes",
                         "ordinary_filesystem_work", "definition_filesystem_work", "cumulative_filesystem_work",
                         "reserved_definition_filesystem_work"))
    C.require(type(accounting["resource_stopped"]) is bool
              and type(accounting["observation_retention_incomplete"]) is bool
              and type(report["signal_interrupted"]) is bool, "systemd_resource_flags")
    for key in ("captured_payload_bytes", "retained_ordinary_record_json_bytes", "ordinary_filesystem_work",
                "definition_filesystem_work", "cumulative_filesystem_work", "reserved_definition_filesystem_work"):
        C.require(type(accounting[key]) is int and accounting[key] >= 0, "systemd_resource_counter")
    C.require(type(report["commands_attempted"]) is int
              and lifecycle["spawned"] <= report["commands_attempted"] <= module.MAX_COMMANDS
              and type(report["files_attempted"]) is int
              and report["files_attempted"] == accounting["cumulative_filesystem_work"]
              == accounting["ordinary_filesystem_work"] + accounting["definition_filesystem_work"]
              and accounting["cumulative_filesystem_work"] + accounting["reserved_definition_filesystem_work"]
              <= profile["cumulative_filesystem_work"]
              and accounting["definition_filesystem_work"] + accounting["reserved_definition_filesystem_work"]
              <= profile["definition_filesystem_work"]
              and accounting["captured_payload_bytes"] <= profile["captured_payload_bytes"],
              "systemd_resource_accounting")
    allowed = (*SYSTEMD_LISTINGS, "systemd_timers", "systemd_jobs", "systemd_unit_properties", "systemd_unit_graph",
               "systemd_template_definitions", "collector")
    C.require(type(report["domains"]) is dict and set(report["domains"]) <= set(allowed), "systemd_domain_scope")
    graph = report["domains"].get("systemd_unit_graph")
    definitions = report["domains"].get("systemd_template_definitions")
    for name, domain in report["domains"].items():
        _systemd_check(C, budget)
        if name == "systemd_unit_graph":
            C.require(domain["runtime_relation_catalogue"] == module.SYSTEMD_RUNTIME_RELATION_CATALOGUE
                      and domain["runtime_relation_catalogue_sha256"]
                      == module.SYSTEMD_RUNTIME_RELATION_CATALOGUE_SHA256
                      and domain["endpoint_profile"] == module.SYSTEMD_ENDPOINT_PROFILE
                      and domain["endpoint_profile_sha256"] == module.Discovery.endpoint_profile_hash(),
                      "systemd_graph_profiles")
        elif name == "systemd_template_definitions":
            C.require(domain["definition_profile"] == module.SYSTEMD_DEFINITION_PROFILE
                      and domain["definition_profile_sha256"] == module.Discovery.definition_profile_hash(),
                      "systemd_definition_profile")
        # The pinned full schema already closes each domain variant, including optional jobs metadata.
        C.require(set(generic) <= set(domain), "systemd_domain_fields")
        if "empty_pending_jobs_snapshot" in domain:
            C.require(name == "systemd_jobs" and domain["empty_pending_jobs_snapshot"] is True
                      and domain["enumeration_complete"] is True and domain["gaps"] == []
                      and domain["records"] == []
                      and all(domain[key] == 0 for key in ("enumerated", "inspected", "raced", "complete", "skipped")),
                      "systemd_empty_jobs_snapshot")
        C.require(all(type(domain[key]) is int and domain[key] >= 0 for key in
                      ("enumerated", "inspected", "raced", "complete", "skipped"))
                  and type(domain["enumeration_complete"]) is bool and domain["classification_complete"] is False
                  and domain["complete"] <= domain["inspected"] <= domain["enumerated"]
                  and type(domain["gaps"]) is list and len(domain["gaps"]) <= 128
                  and all(type(code) is str and re.fullmatch(r"[a-z_0-9]{1,128}", code) for code in domain["gaps"])
                  and type(domain["records"]) is list and len(domain["records"]) <= 8192
                  and len(domain["records"]) == domain["inspected"], "systemd_domain_counters")
        for row in domain["records"]:
            _systemd_check(C, budget)
            C.exact(row, ("authority_id", "identity", "identity_sha256", "unknown_identity", "relevance", "facts"))
            C.hexvalue(row["identity_sha256"])
            C.hexvalue(row["authority_id"])
            C.require(type(row["unknown_identity"]) is bool and row["relevance"] == "unresolved",
                      "systemd_discovery_row_shape")
            if row["identity"] is not None:
                C.require(row["identity"] in module.KNOWN
                          and C.digest(row["identity"].encode()) == row["identity_sha256"]
                          and row["unknown_identity"] is False, "systemd_discovery_known_identity")
            else:
                C.require(row["unknown_identity"] is True, "systemd_discovery_unknown_identity")
    if graph is not None:
        C.require(len({row["identity_sha256"] for row in graph["records"]}) == len(graph["records"]),
                  "systemd_graph_duplicate_identity")
        for row in graph["records"]:
            _systemd_check(C, budget)
            facts = row["facts"]
            C.exact(facts, ("schema", "runtime_relation_catalogue_sha256", "activation_complete_claimed",
                            "endpoint_profile_sha256", "requested_identity_sha256", "name_shape", "membership_before",
                            "membership_after", "initial", "repeated", "graph_fields_unchanged",
                            "unresolved_endpoint_sha256", "gaps", "classification", "authority_refs"))
            C.require(facts["schema"] == "AcademySystemdUnitGraphFacts.v3"
                      and facts["requested_identity_sha256"] == row["identity_sha256"]
                      and facts["activation_complete_claimed"] is False and facts["classification"] == "unknown"
                      and facts["authority_refs"] == []
                      and facts["endpoint_profile_sha256"] == module.Discovery.endpoint_profile_hash()
                      and facts["runtime_relation_catalogue_sha256"]
                      == module.SYSTEMD_RUNTIME_RELATION_CATALOGUE_SHA256,
                      "systemd_graph_fact_identity")
            for key in ("membership_before", "membership_after"):
                C.exact(facts[key], ("installed", "loaded"))
                C.require(all(value is None or type(value) is bool for value in facts[key].values()),
                          "systemd_graph_membership_shape")
            for key, labels in (("membership_before", SYSTEMD_LISTINGS[:2]),
                                ("membership_after", SYSTEMD_LISTINGS[2:])):
                for field, label in zip(("installed", "loaded"), labels, strict=True):
                    listing = report["domains"].get(label)
                    if listing is not None and listing["enumeration_complete"]:
                        value = facts[key][field]
                        if value is None:
                            C.require("graph_finalization_unavailable" in facts["gaps"],
                                      "systemd_graph_missing_membership")
                        else:
                            C.require(value == (row["identity_sha256"] in proof["unit_membership"][label]),
                                      "systemd_graph_membership_join")
                    else:
                        C.require("enumeration_boundary_unavailable" in facts["gaps"],
                                  "systemd_graph_membership_unavailable_gap")
            for phase in ("initial", "repeated"):
                observation = facts[phase]
                C.exact(observation, ("fields", "gaps", "endpoint_count", "retained_endpoint_count", "unparsed_tail",
                                      "endpoint_profile_sha256", "phase", "runtime_relation_catalogue_sha256",
                                      "original_output"))
                C.require(observation["phase"] == phase and type(observation["unparsed_tail"]) is bool
                          and type(observation["gaps"]) is list
                          and observation["endpoint_profile_sha256"] == facts["endpoint_profile_sha256"]
                          and observation["runtime_relation_catalogue_sha256"]
                          == facts["runtime_relation_catalogue_sha256"],
                          "systemd_graph_read_profile")
                fields = observation["fields"]
                C.require(type(fields) is dict and {"Id", "Names"} <= set(fields)
                          <= set(module.SYSTEMD_RUNTIME_RELATION_CATALOGUE["properties"]), "systemd_graph_fields")
                retained = 0
                for field in fields.values():
                    _systemd_check(C, budget)
                    if field is None:
                        continue
                    C.exact(field, ("projection", "endpoint_sha256", "valid", "endpoint_count",
                                    "retained_endpoint_count", "unparsed_tail"))
                    C.require(type(field["valid"]) is bool and type(field["unparsed_tail"]) is bool
                              and type(field["endpoint_count"]) is int and field["endpoint_count"] >= 0
                              and type(field["endpoint_sha256"]) is list
                              and len(field["endpoint_sha256"]) <= module.SYSTEMD_ENDPOINT_PROFILE["field_attempts"]
                              and type(field["retained_endpoint_count"]) is int
                              and field["retained_endpoint_count"] == len(field["endpoint_sha256"])
                              <= field["endpoint_count"]
                              and (field["valid"] or not field["endpoint_sha256"]), "systemd_graph_endpoint_counts")
                    for identifier in field["endpoint_sha256"]:
                        C.hexvalue(identifier)
                    retained += len(field["endpoint_sha256"])
                C.require(type(observation["endpoint_count"]) is int
                          and type(observation["retained_endpoint_count"]) is int
                          and retained == observation["retained_endpoint_count"] <= observation["endpoint_count"],
                          "systemd_graph_read_counts")
            unchanged = (not facts["initial"]["gaps"] and not facts["repeated"]["gaps"]
                         and facts["initial"]["fields"] == facts["repeated"]["fields"])
            C.require(facts["graph_fields_unchanged"] is bool(unchanged), "systemd_graph_repeated_stability")
    if definitions is not None:
        C.require(len({row["identity_sha256"] for row in definitions["records"]}) == len(definitions["records"]),
                  "systemd_definition_duplicate_identity")
        profile = module.SYSTEMD_DEFINITION_PROFILE
        counts = definitions["definition_accounting"]
        C.exact(counts, ("filesystem_work", "alias_resolution_attempts", "candidate_selection_attempts", "body_bytes",
                         "manager_attempts", "relation_attempts", "encoded_bytes", "unparsed_tail", "selected_paths",
                         "distinct_bodies", "reserved_second_pass_work", "reserved_second_pass_bytes",
                         "reserved_second_pass_reads"))
        C.require(type(counts["unparsed_tail"]) is bool
                  and all(type(value) is int and value >= 0 for key, value in counts.items() if key != "unparsed_tail")
                  and counts["filesystem_work"] == accounting["definition_filesystem_work"]
                  and counts["reserved_second_pass_work"] == accounting["reserved_definition_filesystem_work"]
                  and counts["body_bytes"] + counts["reserved_second_pass_bytes"] <= profile["body_bytes_total"]
                  and counts["manager_attempts"] <= profile["manager_commands"]
                  and counts["alias_resolution_attempts"] <= profile["alias_resolution_attempts"]
                  and counts["candidate_selection_attempts"] <= profile["candidate_selection_attempts"]
                  and counts["relation_attempts"] <= profile["relation_attempts_total"],
                  "systemd_definition_accounting")
        for key, cap in (("path_observations", "path_records"), ("source_reads", "source_read_records"),
                         ("relations", "relation_attempts_total"), ("manager_observations", "manager_commands")):
            C.require(type(definitions[key]) is list and len(definitions[key]) <= profile[cap],
                      "systemd_definition_table_bound")
        for read in definitions["source_reads"]:
            _systemd_check(C, budget)
            C.exact(read, ("phase", "path_reference", "body_sha256", "bytes", "before_sha256", "after_sha256", "mask"))
            C.require(read["phase"] in ("initial", "repeated") and type(read["path_reference"]) is int
                      and 0 <= read["path_reference"] < len(definitions["path_observations"])
                      and type(read["bytes"]) is int and 0 <= read["bytes"] <= profile["body_bytes_per_read"]
                      and type(read["mask"]) is bool, "systemd_definition_read_shape")
            for key in ("body_sha256", "before_sha256", "after_sha256"):
                C.hexvalue(read[key])
        for row in definitions["records"]:
            _systemd_check(C, budget)
            facts = row["facts"]
            C.require(facts["schema"] == "AcademySystemdEffectiveDefinitionFacts.v1"
                      and facts["definition_profile"] == profile
                      and facts["definition_profile_sha256"] == module.Discovery.definition_profile_hash()
                      and facts["requested_identity_sha256"] == row["identity_sha256"]
                      and facts["activation_semantics_complete"] is False and facts["classification"] == "unknown"
                      and facts["authority_refs"] == [] and type(facts["source_acquisition_complete"]) is bool,
                      "systemd_definition_fact_identity")
            C.hexvalue(facts["canonical_identity_sha256"])
            C.require(type(facts["sources"]) is list
                      and len(facts["sources"]) <= profile["selected_files_per_definition"],
                      "systemd_selected_source_count")
            for ref in facts["sources"]:
                C.exact(ref, ("path_reference", "kind", "mask", "initial_read", "repeated_read"))
                C.require(ref["kind"] in ("fragment", "dropin") and type(ref["mask"]) is bool
                          and type(ref["path_reference"]) is int
                          and 0 <= ref["path_reference"] < len(definitions["path_observations"]),
                          "systemd_selected_source_reference")
                for phase in ("initial", "repeated"):
                    index = ref[phase + "_read"]
                    C.require(index is None or (type(index) is int and 0 <= index < len(definitions["source_reads"])
                                               and definitions["source_reads"][index]["phase"] == phase),
                              "systemd_selected_read_reference")
    life = proof["maintenance_lifecycle"]
    C.exact(life, ("attempted", "cleanup_confirmed", "records", "records_sha256", "spawning", "pending_signal"))
    C.require(type(life["records"]) is list and len(life["records"]) <= 1024
              and type(life["attempted"]) is int
              and life["attempted"] == life["cleanup_confirmed"] == len(life["records"])
              and life["records_sha256"] == C.digest(C.canonical(life["records"]))
              and life["spawning"] is life["pending_signal"] is False, "systemd_maintenance_lifecycle")
    for record in life["records"]:
        _systemd_check(C, budget)
        C.exact(record, ("program", "started_unix", "stdout_sha256", "stderr_sha256", "completed_unix", "cleanup"))
        C.exact(record["cleanup"], ("pgid", "confirmed"))
        C.require(record["program"] in ("systemctl", "busctl") and record["cleanup"]["confirmed"] is True
                  and type(record["cleanup"]["pgid"]) is int and record["cleanup"]["pgid"] > 1
                  and type(record["started_unix"]) in (int, float)
                  and type(record["completed_unix"]) in (int, float)
                  and proof["observed_unix_started"] <= record["started_unix"] <= record["completed_unix"]
                  < proof["observed_unix_finished"] + 1, "systemd_maintenance_command_cleanup")
        C.hexvalue(record["stdout_sha256"])
        C.hexvalue(record["stderr_sha256"])
    counters = proof["adapter_accounting"]
    C.exact(counters, ("capture_reconstruction_work_before_validation", "work_limit", "proof_byte_limit"))
    C.require(type(counters["capture_reconstruction_work_before_validation"]) is int
              and 0 <= counters["capture_reconstruction_work_before_validation"] <= counters["work_limit"] == 1_048_576
              and counters["proof_byte_limit"] == module.RESOURCE_PROFILE["normal_json_bytes"],
              "systemd_adapter_counters")


class _SchemaMismatch(Exception):
    """Only a structural mismatch; resource/cancellation exceptions never match a schema branch."""


class _FixedDiscoveryValidator:
    """Bounded supported vocabulary for the pinned normal_v3 closure, not a general schema API."""

    _PATTERNS = frozenset(("^[a-f0-9]{64}$", "^[0-9]+$", "^[a-z_0-9]+$"))
    _KEYWORDS = frozenset(("$ref", "description", "type", "const", "enum", "properties", "required",
                           "additionalProperties", "propertyNames", "minProperties", "maxProperties", "items",
                           "minItems", "maxItems", "uniqueItems", "minimum", "maximum", "pattern",
                           "allOf", "anyOf", "oneOf", "if", "then", "else"))
    _TYPES = frozenset(("null", "boolean", "integer", "number", "string", "array", "object"))

    def __init__(self, C, schema, budget):
        self.C, self.schema, self.budget = C, schema, budget
        self.compiled = set()
        self.constants = {}
        self.enums = {}
        self.nodes = 0
        self.definitions = schema.get("$defs", {})
        C.require(type(self.definitions) is dict and "normal_v3" in self.definitions,
                  "systemd_discovery_schema_entry")
        self.entry = self.definitions["normal_v3"]
        self._compile(self.entry, (), 0)

    def _check(self, schema_depth):
        _systemd_check(self.C, self.budget)
        if schema_depth > 256:
            raise SystemdObservationHold("systemd_schema_depth_bound")

    def _ref(self, reference):
        self.C.require(type(reference) is str and reference.startswith("#/$defs/")
                       and reference.count("/") == 2 and reference[8:] in self.definitions,
                       "systemd_schema_local_reference")
        return self.definitions[reference[8:]]

    def _primitive_items(self, node, seen=()):
        self._check(0)
        if type(node) is not dict or id(node) in seen:
            return False
        seen = (*seen, id(node))
        if "$ref" in node:
            return self._primitive_items(self._ref(node["$ref"]), seen)
        if "type" in node:
            kinds = node["type"] if type(node["type"]) is list else [node["type"]]
            return bool(kinds) and set(kinds) <= self._TYPES - {"array", "object"}
        if "enum" in node:
            return all(type(value) in (str, int, float, bool, type(None)) for value in node["enum"])
        if "const" in node:
            return type(node["const"]) in (str, int, float, bool, type(None))
        for keyword in ("anyOf", "oneOf"):
            if keyword in node:
                return all(self._primitive_items(child, seen) for child in node[keyword])
        return False

    def _compile(self, node, references, depth):
        self._check(depth)
        if type(node) is bool:
            return
        self.C.require(type(node) is dict and set(node) <= self._KEYWORDS, "systemd_schema_keyword")
        if "$ref" in node:
            reference = node["$ref"]
            target = self._ref(reference)
            self.C.require(reference not in references, "systemd_schema_reference_cycle")
            self._compile(target, (*references, reference), depth + 1)
        if id(node) in self.compiled:
            return
        self.nodes += 1
        self.C.require(self.nodes <= 8192, "systemd_schema_node_bound")
        if "type" in node:
            kinds = node["type"] if type(node["type"]) is list else [node["type"]]
            self.C.require(bool(kinds) and all(type(kind) is str and kind in self._TYPES for kind in kinds),
                           "systemd_schema_type")
        if "pattern" in node:
            self.C.require(node["pattern"] in self._PATTERNS, "systemd_schema_pattern")
        if "const" in node:
            self.constants[id(node)] = self._key(node["const"])
        if "enum" in node:
            self.C.require(type(node["enum"]) is list and node["enum"], "systemd_schema_enum")
            self.enums[id(node)] = frozenset(self._key(value) for value in node["enum"])
        if "required" in node:
            self.C.require(type(node["required"]) is list
                           and all(type(key) is str for key in node["required"]), "systemd_schema_required")
        for keyword in ("minProperties", "maxProperties", "minItems", "maxItems"):
            if keyword in node:
                self.C.require(type(node[keyword]) is int and node[keyword] >= 0, "systemd_schema_bound")
        for keyword in ("minimum", "maximum"):
            if keyword in node:
                self.C.require(type(node[keyword]) in (int, float), "systemd_schema_numeric_bound")
        if "uniqueItems" in node:
            self.C.require(type(node["uniqueItems"]) is bool, "systemd_schema_unique_flag")
            if node["uniqueItems"]:
                self.C.require("items" in node and self._primitive_items(node["items"]),
                               "systemd_schema_primitive_uniqueness")
        if "properties" in node:
            self.C.require(type(node["properties"]) is dict
                           and all(type(key) is str for key in node["properties"]), "systemd_schema_properties")
            for child in node["properties"].values():
                self._compile(child, references, depth + 1)
        for keyword in ("items", "additionalProperties", "propertyNames", "if", "then", "else"):
            if keyword in node:
                self._compile(node[keyword], references, depth + 1)
        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword in node:
                self.C.require(type(node[keyword]) is list and node[keyword], "systemd_schema_branches")
                for child in node[keyword]:
                    self._compile(child, references, depth + 1)
        self.compiled.add(id(node))

    def _key(self, value, depth=0):
        self._check(depth)
        if depth > 32:
            raise SystemdObservationHold("systemd_schema_json_depth_bound")
        kind = type(value)
        if kind is bool:
            return ("boolean", value)
        if kind in (int, float):
            return ("number", value)
        if value is None:
            return ("null",)
        if kind is str:
            return ("string", value)
        if kind is list:
            return ("array", tuple(self._key(child, depth + 1) for child in value))
        if kind is dict:
            return ("object", tuple((key, self._key(child, depth + 1)) for key, child in sorted(value.items())))
        raise _SchemaMismatch

    @staticmethod
    def _is_type(value, name):
        kind = type(value)
        if name == "integer":
            return kind is int or (kind is float and value.is_integer())
        if name == "number":
            return kind in (int, float)
        return kind is {"null": type(None), "boolean": bool, "string": str, "array": list, "object": dict}.get(name)

    def _matches(self, node, value, data_depth, schema_depth):
        try:
            self._evaluate(node, value, data_depth, schema_depth)
        except _SchemaMismatch:
            return False
        return True

    def _evaluate(self, node, value, data_depth, schema_depth):
        self._check(schema_depth)
        if data_depth > 32:
            raise SystemdObservationHold("systemd_schema_json_depth_bound")
        if type(node) is bool:
            if not node:
                raise _SchemaMismatch
            return
        if "$ref" in node:
            self._evaluate(self._ref(node["$ref"]), value, data_depth, schema_depth + 1)
        if "type" in node:
            kinds = node["type"] if type(node["type"]) is list else [node["type"]]
            if not any(self._is_type(value, kind) for kind in kinds):
                raise _SchemaMismatch
        if "const" in node and self._key(value) != self.constants[id(node)]:
            raise _SchemaMismatch
        if "enum" in node and self._key(value) not in self.enums[id(node)]:
            raise _SchemaMismatch
        if type(value) is dict:
            if not set(node.get("required", ())) <= set(value):
                raise _SchemaMismatch
            if len(value) < node.get("minProperties", 0) or len(value) > node.get("maxProperties", len(value)):
                raise _SchemaMismatch
            properties = node.get("properties", {})
            for key, child in value.items():
                self._check(schema_depth)
                if "propertyNames" in node:
                    self._evaluate(node["propertyNames"], key, data_depth + 1, schema_depth + 1)
                self._evaluate(properties.get(key, node.get("additionalProperties", True)), child,
                               data_depth + 1, schema_depth + 1)
        if type(value) is list:
            if len(value) < node.get("minItems", 0) or len(value) > node.get("maxItems", len(value)):
                raise _SchemaMismatch
            seen = set()
            for child in value:
                self._check(schema_depth)
                if "items" in node:
                    self._evaluate(node["items"], child, data_depth + 1, schema_depth + 1)
                if node.get("uniqueItems", False):
                    if type(child) not in (str, int, float, bool, type(None)):
                        raise _SchemaMismatch
                    key = self._key(child)
                    if key in seen:
                        raise _SchemaMismatch
                    seen.add(key)
        if type(value) in (int, float):
            if ("minimum" in node and value < node["minimum"]) or ("maximum" in node and value > node["maximum"]):
                raise _SchemaMismatch
        if type(value) is str and "pattern" in node and re.search(node["pattern"], value) is None:
            raise _SchemaMismatch
        for child in node.get("allOf", ()):
            self._evaluate(child, value, data_depth, schema_depth + 1)
        if "anyOf" in node and not any(self._matches(child, value, data_depth, schema_depth + 1)
                                        for child in node["anyOf"]):
            raise _SchemaMismatch
        if "oneOf" in node:
            matched = sum(self._matches(child, value, data_depth, schema_depth + 1) for child in node["oneOf"])
            if matched != 1:
                raise _SchemaMismatch
        if "if" in node:
            branch = "then" if self._matches(node["if"], value, data_depth, schema_depth + 1) else "else"
            if branch in node:
                self._evaluate(node[branch], value, data_depth, schema_depth + 1)

    def validate_normal(self, value):
        try:
            self._evaluate(self.entry, value, 0, 0)
        except _SchemaMismatch:
            self.C.require(False, "systemd_discovery_schema_mismatch")

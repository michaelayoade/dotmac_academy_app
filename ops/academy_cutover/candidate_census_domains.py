"""Protected process observations and a refusing eight-domain scope reducer.

An observation is metadata at its original interval, never an approval or freshness
token. Only the process adapter exists. Validation of a dictionary is deliberately
separate from production collection and cannot establish current observations.
"""

import os
import re
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
PROCESS_DOMAIN = DOMAINS[2]
DISCOVERY_SHA256 = "763188a67c00bc3a205e892727010ba2c4f0dbcd113e7d18d44a7e8f9b818ec4"
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


def collect_domain(C, m, role, domain):
    C.require(domain in DOMAINS, "census_domain_unknown")
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


def validate_domain_proof(C, scope, role, domain, proof, *, manifest=None):
    """Return stable owner refs after pure joins; this never proves collection.

    A manifest is mandatory for live legacy owner claims. The genuine source-pinned
    collector calls old_unit_inventory for runtime/HR semantics; this validator
    reconstructs the closed owner/snapshot join without rerunning observations.
    """
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


def collect_role(C, m, role, scope):
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
            proofs[domain] = collect_domain(C, m, role, domain)
    require_complete_role_scope(C, scope, role, proofs, manifest=m)
    return proofs


def require_complete_role_scope(C, scope, role, proofs, *, manifest=None):
    """Validate one role's exact eight domains; remote role proofs are separate.

    This cannot succeed until the other seven production adapters exist. The
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
    refs = validate_domain_proof(C, scope, role, PROCESS_DOMAIN, proofs[PROCESS_DOMAIN], manifest=manifest)
    C.require(refs <= set(scope["authority_membership"][role]["legacy"]), "census_domain_legacy_membership_missing")
    C.require(False, "census_domain_adapter_unimplemented")


def require_complete_scope(C, scope, domain_proofs, *, manifest=None):
    """No authored complete flag can bypass missing domains or production adapters.

    This reducer cannot currently succeed: seven production domains are explicitly
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
        refs = validate_domain_proof(C, scope, role, PROCESS_DOMAIN, process[role], manifest=manifest)
        C.require(refs <= set(scope["authority_membership"][role]["legacy"]), "census_domain_legacy_membership_missing")
    C.require(False, "census_domain_adapter_unimplemented")

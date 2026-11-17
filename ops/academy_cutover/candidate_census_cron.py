"""Hash-only fixed system-cron source observations, always deliberately partial.

No cron parsing, account discovery, commands, executable reads or environment
resolution. Protected Discovery owns bounded directory/file reads and retention.
Matching fresh passes establish limited source stability, never daemon coverage.
"""

import json
import os
import signal
import stat
import time

DOMAIN = "cron/anacron/at scheduling"
LABEL = "cron_fixed_sources"
EXCLUDED = (
    "accountcrontabs", "runparts", "anacronstate", "atqueues",
    "daemonconfig-runtime", "alternatenamespaces-layouts",
)
PROFILE = {
    "schema": "AcademyCronFixedSourceProfile.v1", "seconds": 60,
    "file_bytes": 65536, "overflow_probe_bytes": 1,
    "captured_payload_bytes": 16777216, "objects": 1024,
    "filesystem_work": 32768, "proof_bytes": 8388608,
    "included": ["/etc/crontab", "/etc/cron.d immediate entries"],
    "excluded": list(EXCLUDED),
}
MANDATORY_GAPS = tuple(sorted((*EXCLUDED, "authority_classification_unresolved",
                               "control_state_unresolved", "non_atomic_source_observation")))
ENTRY_FIELDS = ("source", "name_sha256", "metadata", "status", "body_sha256", "captured_bytes")
PASS_FIELDS = ("etc_before", "etc_after", "cron_d_before", "cron_d_after", "cron_d_status", "entries")
FIELDS = (
    "schema", "candidate", "tree", "role", "hostname", "domain", "sources",
    "observed_unix_started", "observed_unix_finished", "profile", "profile_sha256",
    "passes", "objects", "enumerated_object_ids", "accounting", "unresolved_gaps",
    "coverage_complete", "classification_complete", "control_state",
)
_ACTIVE = None

STATUSES = ("captured", "absent", "rejected_name", "rejected_credential", "rejected_type",
            "rejected_owner", "rejected_mode", "unavailable")


def _checkpoint(C):
    if _ACTIVE is not None:
        C.require(_ACTIVE.pending_signal is None, "cron_interrupted_signal")
        C.require(time.monotonic() < _ACTIVE.deadline, "cron_deadline")


def _integer(C, value, high):
    C.require(type(value) is int and 0 <= value <= high, "cron_integer")


def _meta(d, metadata):
    return list(d.file_identity(metadata))


def _safe_meta(C, metadata):
    C.require(type(metadata) is list and len(metadata) == 8, "cron_metadata")
    for value in metadata:
        _integer(C, value, 2**64 - 1)


def _derive(C, role, hostname, passes):
    by_key = {}
    for phase, snapshot in enumerate(passes):
        for row in snapshot["entries"]:
            key = (row["source"], row["name_sha256"])
            by_key.setdefault(key, [None, None])[phase] = row
    objects = []
    boundaries_stable = (
        all(p["etc_before"] == p["etc_after"] for p in passes)
        and passes[0]["etc_before"] == passes[1]["etc_before"]
        and all(p["cron_d_before"] == p["cron_d_after"] for p in passes)
        and passes[0]["cron_d_before"] == passes[1]["cron_d_before"]
        and passes[0]["cron_d_status"] == passes[1]["cron_d_status"]
        and [(r["source"], r["name_sha256"]) for r in passes[0]["entries"]]
        == [(r["source"], r["name_sha256"]) for r in passes[1]["entries"]]
    )
    for (source, name), reads in sorted(by_key.items()):
        _checkpoint(C)
        identity = {"schema": "AcademyCronSourceIdentity.v1", "role": role,
                    "hostname": hostname, "source": source, "name_sha256": name}
        stable = (reads[0] is not None and reads[0] == reads[1]
                  and reads[0]["status"] in ("captured", "absent")
                  and boundaries_stable)
        objects.append({"object_id": C.digest(C.canonical(identity)), **identity,
                        "reads": reads, "source_stable": bool(stable),
                        "classification": "unknown", "authority_refs": [],
                        "control_state": "unresolved"})
    return sorted(objects, key=lambda row: row["object_id"])


def _gaps(passes, objects):
    gaps = set(MANDATORY_GAPS)
    if any(p["etc_before"] != p["etc_after"] or p["cron_d_before"] != p["cron_d_after"] for p in passes):
        gaps.add("source_anchor_changed")
    if any(p["cron_d_status"] in ("unavailable", "changed") for p in passes):
        gaps.add("cron_d_unavailable")
    if passes[0] != passes[1]:
        gaps.add("source_passes_changed")
    if any(not row["source_stable"] for row in objects):
        gaps.add("source_acquisition_unresolved")
    return sorted(gaps)


def encode(C, proof):
    """Bound the complete JSON tree before allocating its encoded bytes."""
    budget = PROFILE["proof_bytes"]
    nodes = 0

    def size(value, depth=0):
        nonlocal nodes
        _checkpoint(C)
        nodes += 1
        C.require(depth <= 32 and nodes <= 200000, "cron_proof_encoding_bound")
        if value is None or type(value) in (bool, int):
            C.require(type(value) is not int or abs(value) < 2**65, "cron_proof_encoding_bound")
            return len(json.dumps(value))
        if type(value) is str:
            C.require(len(value) <= budget, "cron_proof_encoding_bound")
            return len(json.dumps(value, ensure_ascii=True))
        C.require(type(value) in (list, dict), "cron_proof_encoding_type")
        total = 2
        values = value.items() if type(value) is dict else enumerate(value)
        for key, item in values:
            if type(value) is dict:
                C.require(type(key) is str, "cron_proof_encoding_type")
                total += size(key, depth + 1) + 1
            total += size(item, depth + 1) + 1
            C.require(total <= budget, "cron_proof_encoding_bound")
        return total

    size(proof)
    raw = C.canonical(proof)
    C.require(len(raw) <= budget, "cron_proof_encoding_bound")
    return raw


def observe(C, m, role, discovery_module, sources):
    """Observe only the fixed trusted /etc view; all exception text is discarded."""
    global _ACTIVE
    C.require(role in ("web", "lab"), "cron_role")
    started = int(time.time())

    class Bounded(discovery_module.Discovery):
        def __init__(self):
            super().__init__(role)
            self.deadline = min(self.deadline, time.monotonic() + PROFILE["seconds"])
            self.work = 0
            self.work_events = {}
            self.seen = set()

        def charge(self, amount=1):
            self.work_events[str(amount)] = self.work_events.get(str(amount), 0) + 1
            self.work += amount
            C.require(self.work <= PROFILE["filesystem_work"], "cron_work_bound")
            C.require(self.pending_signal is None, "cron_interrupted_signal")
            C.require(time.monotonic() < self.deadline, "cron_deadline")

        def interrupted(self, domain):
            self.charge()
            return super().interrupted(domain)

        def read_payload(self, fd, requested, domain, **kwargs):
            self.charge()
            remaining = PROFILE["captured_payload_bytes"] - self.captured_payload_bytes
            C.require(remaining > 0, "cron_payload_bound")
            result = super().read_payload(fd, min(requested, remaining), domain, **kwargs)
            C.require(self.captured_payload_bytes <= PROFILE["captured_payload_bytes"], "cron_payload_bound")
            return result

    d = Bounded()
    _ACTIVE = d
    snapshots = []
    saved = {}
    try:
        for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            saved[number] = signal.signal(number, d.request_signal)
        for _phase in range(2):
            d.charge(20)  # Conservative reservation for protected component opens/cleanup.
            etc = d.directory("/etc", LABEL)
            C.require(etc is not None, "cron_etc_unavailable")
            directory = None
            try:
                d.charge()
                before = _meta(d, os.fstat(etc))
                rows = []

                def entry(fd, name, source, rows=rows):
                    d.charge()
                    row = {"source": source, "name_sha256": C.digest(os.fsencode(name)),
                           "metadata": None, "status": "unavailable", "body_sha256": None,
                           "captured_bytes": 0}
                    key = (source, row["name_sha256"])
                    d.seen.add(key)
                    C.require(len(d.seen) <= PROFILE["objects"], "cron_object_bound")
                    eligible = False
                    try:
                        metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        row["status"] = "absent"
                    except OSError:
                        pass
                    else:
                        row["metadata"] = _meta(d, metadata)
                        if not discovery_module.CRON_NAME.fullmatch(name):
                            row["status"] = "rejected_name"
                        elif discovery_module.CREDENTIAL_NAME.search(name):
                            row["status"] = "rejected_credential"
                        elif not stat.S_ISREG(metadata.st_mode):
                            row["status"] = "rejected_type"
                        elif metadata.st_uid != 0:
                            row["status"] = "rejected_owner"
                        elif metadata.st_mode & 0o022:
                            row["status"] = "rejected_mode"
                        else:
                            eligible = True
                    admitted = dict(row)
                    C.require(d.record(LABEL, row["name_sha256"], admitted), "cron_retention_refused")
                    if eligible:
                        d.charge(10)  # read_file's bounded open/stat/cleanup operations.
                        prior = d.captured_payload_bytes
                        raw = d.read_file(fd, name, 0, LABEL, PROFILE["file_bytes"], tuple(row["metadata"]))
                        row["captured_bytes"] = d.captured_payload_bytes - prior
                        if raw is not None:
                            row["status"] = "captured"
                            row["body_sha256"] = C.digest(raw)
                        raw = None
                        C.require(d.replace_record_facts(admitted, row), "cron_retention_replacement_refused")
                    rows.append(admitted)

                entry(etc, "crontab", "etc_crontab")
                d.charge()
                try:
                    meta = os.stat("cron.d", dir_fd=etc, follow_symlinks=False)
                except FileNotFoundError:
                    cron_before, cron_after, status = None, None, "absent"
                except OSError:
                    cron_before, cron_after, status = None, None, "unavailable"
                else:
                    cron_before, cron_after, status = _meta(d, meta), None, "unavailable"
                    if stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022:
                        d.charge(20)
                        directory = d.directory("/etc/cron.d", LABEL)
                        if directory is not None:
                            d.charge()
                            if _meta(d, os.fstat(directory)) == cron_before:
                                names = d.names(directory, LABEL)
                                if names is not None:
                                    C.require(len(names) <= PROFILE["objects"] - 1, "cron_object_bound")
                                    C.require(len(names) == len(set(names)), "cron_duplicate_names")
                                    for name in names:
                                        entry(directory, name, "etc_cron_d")
                                    status = "enumerated"
                            d.charge(2)
                            observed = _meta(d, os.fstat(directory))
                            named = _meta(d, os.stat("cron.d", dir_fd=etc, follow_symlinks=False))
                            cron_after = observed if observed == named else None
                            if cron_after is None and status == "enumerated":
                                status = "changed"
                d.charge(21)
                fresh = d.directory("/etc", LABEL)
                C.require(fresh is not None, "cron_etc_unavailable")
                try:
                    after = _meta(d, os.fstat(fresh))
                    C.require(_meta(d, os.fstat(etc)) == after, "cron_etc_changed")
                finally:
                    os.close(fresh)
                # A second anchored stat distinguishes stable absence from permission failure.
                d.charge()
                if status == "absent":
                    try:
                        os.stat("cron.d", dir_fd=etc, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        status = "unavailable"
                    else:
                        status = "unavailable"
                snapshots.append({"etc_before": before, "etc_after": after,
                                  "cron_d_before": cron_before, "cron_d_after": cron_after,
                                  "cron_d_status": status,
                                  "entries": sorted(rows, key=lambda r: (r["source"], r["name_sha256"]))})
            finally:
                if directory is not None:
                    os.close(directory)
                os.close(etc)
        d.charge()
        C.require(not d.resource_stopped and not d.observation_retention_incomplete
                  and not d.normal_evidence_refused, "cron_resource_refused")
        objects = _derive(C, role, m["roles"][role]["hostname"], snapshots)
        C.require(len(objects) <= PROFILE["objects"], "cron_object_bound")
        proof = {"schema": "AcademyCronSourceObservation.v1", "candidate": m["candidate"],
                 "tree": m["tree"], "role": role, "hostname": m["roles"][role]["hostname"],
                 "domain": DOMAIN, "sources": sources, "observed_unix_started": started,
                 "observed_unix_finished": int(time.time()), "profile": PROFILE,
                 "profile_sha256": C.digest(C.canonical(PROFILE)), "passes": snapshots,
                 "objects": objects, "enumerated_object_ids": [r["object_id"] for r in objects],
                 "accounting": {"captured_payload_bytes": d.captured_payload_bytes,
                                "filesystem_work": d.work, "work_events": d.work_events,
                                "retained_records": len(d.record_ledger),
                                "retained_json_bytes": d.ordinary_record_json_bytes},
                 "unresolved_gaps": _gaps(snapshots, objects), "coverage_complete": False,
                 "classification_complete": False, "control_state": "unresolved"}
        encode(C, proof)
        return proof
    except (OSError, TypeError, KeyError, UnicodeError, discovery_module.ResourceLimitError):
        C.require(False, "cron_acquisition_failed")
    finally:
        for number, handler in saved.items():
            signal.signal(number, handler)


def validate(C, scope, role, proof, *, sources=None):
    """Reconstruct the exact partial observation; timestamps never become freshness."""
    _checkpoint(C)
    C.exact(proof, FIELDS)
    C.require(proof["schema"] == "AcademyCronSourceObservation.v1" and proof["domain"] == DOMAIN,
              "cron_schema_domain")
    C.require(role in ("web", "lab") and proof["role"] == role
              and proof["hostname"] == scope["hosts"][role]
              and proof["candidate"] == scope["candidate"] and proof["tree"] == scope["tree"], "cron_scope")
    C.require(sources is not None and proof["sources"] == sources, "cron_sources")
    C.require(proof["profile"] == PROFILE and type(proof["profile"]) is dict
              and proof["profile_sha256"] == C.digest(C.canonical(PROFILE)), "cron_profile")
    # Equality alone would admit False/0 or True/1 in a claimed profile.
    C.require(C.canonical(proof["profile"]) == C.canonical(PROFILE), "cron_profile_types")
    for field in ("observed_unix_started", "observed_unix_finished"):
        _integer(C, proof[field], 2**53 - 1)
    C.require(0 <= proof["observed_unix_finished"] - proof["observed_unix_started"] <= 61, "cron_interval")
    C.require(proof["coverage_complete"] is False and proof["classification_complete"] is False
              and proof["control_state"] == "unresolved", "cron_partial_only")
    passes = proof["passes"]
    C.require(type(passes) is list and len(passes) == 2, "cron_two_passes")
    total = count = 0
    for snapshot in passes:
        _checkpoint(C)
        C.exact(snapshot, PASS_FIELDS)
        for field in ("etc_before", "etc_after"):
            _safe_meta(C, snapshot[field])
            C.require(stat.S_ISDIR(snapshot[field][4]) and snapshot[field][2] == 0
                      and not snapshot[field][4] & 0o022, "cron_etc_policy")
        for field in ("cron_d_before", "cron_d_after"):
            if snapshot[field] is not None:
                _safe_meta(C, snapshot[field])
        status = snapshot["cron_d_status"]
        C.require(type(status) is str and status in ("absent", "unavailable", "enumerated", "changed"),
                  "cron_directory_status")
        if status == "absent":
            C.require(snapshot["cron_d_before"] is None and snapshot["cron_d_after"] is None, "cron_absence")
        if status == "enumerated":
            for field in ("cron_d_before", "cron_d_after"):
                value = snapshot[field]
                C.require(value is not None, "cron_directory_anchor")
                C.require(stat.S_ISDIR(value[4]) and value[2] == 0 and not value[4] & 0o022, "cron_directory_policy")
        rows = snapshot["entries"]
        C.require(type(rows) is list and 1 <= len(rows) <= PROFILE["objects"], "cron_entries")
        keys = []
        for row in rows:
            _checkpoint(C)
            C.exact(row, ENTRY_FIELDS)
            C.require(type(row["source"]) is str and row["source"] in ("etc_crontab", "etc_cron_d"), "cron_source")
            C.hexvalue(row["name_sha256"])
            keys.append((row["source"], row["name_sha256"]))
            C.require(type(row["status"]) is str and row["status"] in STATUSES, "cron_status")
            _integer(C, row["captured_bytes"], PROFILE["file_bytes"] + 1)
            total += row["captured_bytes"]
            count += 1
            meta = row["metadata"]
            if meta is not None:
                _safe_meta(C, meta)
            if row["status"] == "absent":
                C.require(meta is None, "cron_absent_metadata")
            elif row["status"] != "unavailable":
                C.require(meta is not None, "cron_missing_metadata")
            if row["status"] == "captured":
                C.hexvalue(row["body_sha256"])
                C.require(stat.S_ISREG(meta[4]) and meta[2] == 0 and not meta[4] & 0o022
                          and row["captured_bytes"] == meta[5] <= PROFILE["file_bytes"], "cron_captured_policy")
            else:
                C.require(row["body_sha256"] is None, "cron_rejected_body")
                if row["status"] != "unavailable":
                    C.require(row["captured_bytes"] == 0, "cron_rejected_bytes")
            if row["status"] == "rejected_type":
                C.require(not stat.S_ISREG(meta[4]), "cron_rejected_type")
            if row["status"] == "rejected_owner":
                C.require(stat.S_ISREG(meta[4]) and meta[2] != 0, "cron_rejected_owner")
            if row["status"] == "rejected_mode":
                C.require(stat.S_ISREG(meta[4]) and meta[2] == 0 and meta[4] & 0o022, "cron_rejected_mode")
        C.require(keys == sorted(set(keys)), "cron_duplicate_or_order")
        C.require(sum(source == "etc_crontab" for source, _ in keys) == 1
                  and ("etc_crontab", C.digest(b"crontab")) in keys, "cron_fixed_crontab")
        C.require(status in ("enumerated", "changed") or all(source == "etc_crontab" for source, _ in keys),
                  "cron_directory_membership")
    objects = _derive(C, role, proof["hostname"], passes)
    C.require(len(objects) <= PROFILE["objects"] and proof["objects"] == objects
              and C.canonical(proof["objects"]) == C.canonical(objects), "cron_object_reconstruction")
    C.require(proof["enumerated_object_ids"] == [row["object_id"] for row in objects], "cron_object_ids")
    C.require(proof["unresolved_gaps"] == _gaps(passes, objects), "cron_mandatory_gaps")
    accounting = proof["accounting"]
    C.exact(accounting, ("captured_payload_bytes", "filesystem_work", "work_events",
                         "retained_records", "retained_json_bytes"))
    for key, high in (("captured_payload_bytes", PROFILE["captured_payload_bytes"]),
                      ("filesystem_work", PROFILE["filesystem_work"]), ("retained_records", 2048),
                      ("retained_json_bytes", PROFILE["proof_bytes"])):
        _integer(C, accounting[key], high)
    C.require(accounting["captured_payload_bytes"] == total and accounting["retained_records"] == count,
              "cron_accounting")
    events = accounting["work_events"]
    C.require(type(events) is dict and set(events) <= {"1", "2", "10", "20", "21"}, "cron_work_events")
    for value in events.values():
        _integer(C, value, PROFILE["filesystem_work"])
    C.require(accounting["filesystem_work"] == sum(int(k) * v for k, v in events.items())
              and accounting["filesystem_work"] >= count, "cron_accounting_work")
    directory_attempts = 0
    admitted_reads = 0
    minimum_checkpoints = count + 7
    for snapshot in passes:
        metadata = snapshot["cron_d_before"]
        trusted_directory = (metadata is not None and stat.S_ISDIR(metadata[4])
                             and metadata[2] == 0 and not metadata[4] & 0o022)
        directory_attempts += int(trusted_directory)
        if snapshot["cron_d_status"] in ("enumerated", "changed"):
            minimum_checkpoints += len(snapshot["entries"]) + 1
        for row in snapshot["entries"]:
            metadata = row["metadata"]
            eligible = (metadata is not None and stat.S_ISREG(metadata[4]) and metadata[2] == 0
                        and not metadata[4] & 0o022
                        and row["status"] not in ("rejected_name", "rejected_credential"))
            if eligible:
                admitted_reads += 1
                minimum_checkpoints += 1  # protected read_file interruption check
                reads = (row["captured_bytes"] + 65535) // 65536
                if row["status"] == "captured":
                    reads += 1  # successful reads must also observe EOF
                minimum_checkpoints += 2 * reads  # payload admission and capture checks
    C.require(events.get("20", 0) == 2 + directory_attempts and events.get("21", 0) == 2
              and events.get("10", 0) == admitted_reads
              and events.get("2", 0) <= directory_attempts
              and events.get("1", 0) >= minimum_checkpoints, "cron_work_reconstruction")
    retained_bytes = 0
    for snapshot in passes:
        for row in snapshot["entries"]:
            name = row["name_sha256"]
            record = {"authority_id": C.digest((proof["hostname"] + "\0" + LABEL + "\0" + name).encode()),
                      "identity": None, "identity_sha256": C.digest(name.encode()),
                      "unknown_identity": True, "relevance": "unresolved", "facts": row}
            retained_bytes += len(C.canonical(record))
    C.require(accounting["retained_json_bytes"] == retained_bytes, "cron_retention_accounting")
    encode(C, proof)
    return True

"""Root read-only host facts; never a campaign census or exclusion proof."""

import argparse
import errno
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

HOSTS = {"web": "vmi2490731", "lab": "academy-labs"}
ROOTS = (
    b"/home/dotmac/projects/dotmac_academy_v2",
    b"dotmac_academy_app",
    b"academy-v2-release-",
    b"academy-v2-csp-stage-",
    b"/srv/academy",
)
JOB_HINTS = (b"app.cli", b"email-outbox")
KNOWN = frozenset(
    {"academy-web.service", "academy-labs.service"}
    | {
        "academy-v2-" + name + suffix
        for name in (
            "email-outbox",
            "email-delivery",
            "lab-reconcile",
            "lab-cleanup",
            "lab-expiry",
            "lab-pool",
            "lab-idle",
        )
        for suffix in (".service", ".timer")
    }
)
UNIT = re.compile(r"[A-Za-z0-9_.:@\\-]{1,255}\Z")
CRON_NAME = re.compile(r"[A-Za-z0-9_-]{1,255}\Z")
CREDENTIAL_NAME = re.compile(
    r"(?:env|key|keys|pem|token|password|passwd|shadow|credential|credentials|"
    r"secret|secrets|openbao|vault|ssh|authorized_keys|known_hosts|"
    r"id_rsa|id_dsa|id_ecdsa|id_ed25519|private|certificate|bearer)",
    re.IGNORECASE,
)
MAX_ROWS = 8192
MAX_FILES = 16384
MAX_BYTES = 1048576
MAX_COMMAND_BYTES = 8388608
MAX_COMMANDS = 73732
MAX_SECONDS = 300
COMMON_PROPERTIES = (
    "Id",
    "Names",
    "LoadState",
    "ActiveState",
    "SubState",
    "FragmentPath",
    "DropInPaths",
    "Triggers",
    "TriggeredBy",
    "Requires",
    "Wants",
    "Before",
    "After",
    "Job",
    "JobTimeoutUSec",
)
EXEC_CONTEXT_PROPERTIES = ("User", "WorkingDirectory", "EnvironmentFiles")
SERVICE_PROPERTIES = ("ExecStart",)
RETRY_PROPERTIES = frozenset(("EnvironmentFiles", "ExecStart", "TimersMonotonic", "TimersCalendar"))
REPEATED_PROPERTIES = frozenset(("EnvironmentFiles", "ExecStart", "TimersMonotonic", "TimersCalendar"))
REPEATED_REPRESENTATION = "AcademySystemctlRepeatedProperty.v1"
TYPED_PROPERTIES = {
    "EnvironmentFiles": ("a(sb)", {
        ".service": "Service", ".socket": "Socket", ".mount": "Mount", ".swap": "Swap"
    }),
    "ExecStart": ("a(sasbttttuii)", {".service": "Service"}),
    "TimersMonotonic": ("a(stt)", {".timer": "Timer"}),
    "TimersCalendar": ("a(sst)", {".timer": "Timer"}),
}
BUS_UNIT_PREFIX = "/org/freedesktop/systemd1/unit/"
BUS_INTERFACE_PREFIX = "org.freedesktop.systemd1."
BUS_OBJECT = re.compile(
    r"/org/freedesktop/systemd1/unit/[A-Za-z_][A-Za-z0-9_]{0,764}\Z"
)
TIMER_PROPERTIES = (
    "NextElapseUSecRealtime",
    "NextElapseUSecMonotonic",
    "LastTriggerUSec",
    "Unit",
    "TimersCalendar",
    "TimersMonotonic",
)
PROPERTIES = (
    COMMON_PROPERTIES + EXEC_CONTEXT_PROPERTIES + SERVICE_PROPERTIES + TIMER_PROPERTIES
)
# Linux include/linux/sched.h PF_KTHREAD; /proc/PID/stat field 9 flags.
# https://github.com/torvalds/linux/blob/master/include/linux/sched.h
PF_KTHREAD = 0x00200000
PROCESS_STATES = frozenset("RSDZTtXxKWPI")
JOB_TYPES = frozenset(
    (
        "start",
        "verify-active",
        "stop",
        "reload",
        "restart",
        "try-restart",
        "reload-or-start",
        "nop",
    )
)


class SnapshotChangedError(ValueError):
    """Observed anchored-file snapshot mismatch; never contains raw file data."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def projection(data):
    return {
        "sha256": digest(data),
        "bytes": len(data),
        "known_academy_root_indicator": any(root in data for root in ROOTS),
        "known_job_indicator": any(hint in data for hint in JOB_HINTS),
    }


class Discovery:
    def __init__(self, role):
        self.host = HOSTS[role]
        self.deadline = time.monotonic() + MAX_SECONDS
        self.commands = 0
        self.files = 0
        self.domains = {}
        self.loaded_units = set()
        self.installed_units = set()
        self.pending_signal = None
        self.child_phase = "idle"
        self.child_cleanup_failed = False
        self.owned_child = None
        self.child_metadata = {
            "spawned": 0,
            "reaped": 0,
            "group_cleanup_confirmed": 0,
            "group_cleanup_unconfirmed": 0,
            "termination_requests": 0,
        }

    def request_signal(self, number, _frame):
        # Never raise across Popen's spawn window; retain the returned child handle.
        self.pending_signal = number
        self.child_metadata["termination_requests"] += 1

    def interrupted(self, domain):
        if self.pending_signal is not None:
            self.gap(domain, "interrupted_signal")
            return True
        return False

    def domain(self, name):
        return self.domains.setdefault(
            name,
            {
                "enumerated": 0,
                "inspected": 0,
                "raced": 0,
                "complete": 0,
                "skipped": 0,
                "enumeration_complete": False,
                "classification_complete": False,
                "gaps": [],
                "records": [],
            },
        )

    def gap(self, name, reason, raced=False):
        domain = self.domain(name)
        if reason not in domain["gaps"]:
            domain["gaps"].append(reason)
        if raced:
            domain["raced"] += 1

    def record(self, domain, entity, facts):
        target = self.domain(domain)
        if len(target["records"]) >= MAX_ROWS:
            self.gap(domain, "row_limit")
            target["skipped"] += 1
            return False
        target["records"].append(
            {
                "authority_id": digest(
                    (self.host + "\0" + domain + "\0" + entity).encode()
                ),
                "identity": entity if entity in KNOWN else None,
                "identity_sha256": digest(entity.encode()),
                "unknown_identity": entity not in KNOWN,
                "relevance": "unresolved",
                "facts": facts,
            }
        )
        target["inspected"] += 1
        # Complete fact projection, never authority classification.
        target["complete"] += 1
        return True

    def run(self, args, domain, *, getter=False):
        if getter:
            allowed = {
                (BUS_INTERFACE_PREFIX + interface, field)
                for field, (_signature, interfaces) in TYPED_PROPERTIES.items()
                for interface in interfaces.values()
            } | {(BUS_INTERFACE_PREFIX + "Unit", field) for field in ("Id", "Names")}
            if (
                len(args) != 5 or args[:2] != [
                    "get-property", "org.freedesktop.systemd1"
                ]
                or not BUS_OBJECT.fullmatch(args[2])
                or (args[3], args[4]) not in allowed
            ):
                self.gap(domain, "typed_getter_request_rejected")
                return None
            command = [
                "/usr/bin/busctl", "--system", "--no-pager", "--timeout=5", *args
            ]
        else:
            command = [
                "/usr/bin/systemctl", "--system", "--no-pager", "--no-legend", *args
            ]
        if self.interrupted(domain):
            return None
        if self.child_cleanup_failed:
            self.gap(domain, "prior_child_cleanup_unconfirmed")
            return None
        if self.commands >= MAX_COMMANDS or time.monotonic() >= self.deadline:
            self.gap(domain, "command_or_time_limit")
            return None
        self.commands += 1
        child = None
        output = bytearray()
        okay = True
        try:
            self.child_phase = "spawning"
            # Fixed read-only verbs; unit operands come from validated JSON enumeration.
            child = subprocess.Popen(  # noqa: S603
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"},
                shell=False,
                start_new_session=True,
                close_fds=True,
            )
            self.owned_child = child
            self.child_phase = "owned_unreaped"
            self.child_metadata["spawned"] += 1
            end = min(self.deadline, time.monotonic() + 10)
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while True:
                    if self.interrupted(domain):
                        raise InterruptedError
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    if not selector.select(min(remaining, 0.1)):
                        continue
                    block = os.read(child.stdout.fileno(), 65536)
                    if not block:
                        break
                    output.extend(block)
                    if len(output) > MAX_COMMAND_BYTES:
                        raise ValueError
            # Observe exit without releasing the leader PID/PGID reservation.
            while True:
                if self.interrupted(domain):
                    raise InterruptedError
                status = os.waitid(
                    os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
                )
                if status is not None:
                    break
                if time.monotonic() >= end:
                    raise TimeoutError
                time.sleep(0.01)
            if status.si_code != os.CLD_EXITED or status.si_status != 0:
                okay = False
                self.gap(domain, "command_failed")
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            okay = False
            self.gap(domain, "command_unavailable_timeout_or_bound")
        finally:
            if child is not None:
                # Never poll/wait/reap before this delivered signal. An unreaped
                # direct child reserves its PID, preventing PGID reuse here.
                confirmed = True
                reserved = False
                try:
                    os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    reserved = True
                except OSError:
                    confirmed = False
                    self.gap(domain, "child_leader_ownership_unconfirmed")
                if reserved:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except OSError:
                        confirmed = False
                try:
                    if reserved:
                        child.wait(timeout=1)
                        self.child_phase = "reaped"
                        self.child_metadata["reaped"] += 1
                except (OSError, subprocess.TimeoutExpired):
                    confirmed = False
                else:
                    # Signal 0 delivers no signal. If any group exists after
                    # reap (even PGID reuse), refuse; never kill it after reap.
                    if reserved:
                        try:
                            os.killpg(child.pid, 0)
                        except ProcessLookupError:
                            pass
                        except OSError:
                            confirmed = False
                        else:
                            confirmed = False
                if not confirmed:
                    self.child_cleanup_failed = True
                    okay = False
                    self.gap(domain, "child_cleanup_unconfirmed")
                    self.child_metadata["group_cleanup_unconfirmed"] += 1
                else:
                    self.child_metadata["group_cleanup_confirmed"] += 1
                if child.stdout is not None:
                    child.stdout.close()
                if confirmed:
                    self.owned_child = None
            self.child_phase = "idle"
        if self.interrupted(domain):
            okay = False
        return bytes(output) if okay else None

    def jobs_listing(self, domain):
        # systemd v255 systemctl-list-jobs.c uses table_print, not JSON output.
        # No --after/--before: only the four-column, no-legend/plain format.
        raw = self.run(["list-jobs", "--plain"], domain)
        if raw is None:
            return set()
        target = self.domain(domain)
        if raw == b"":
            # Exact exit-zero empty stdout is a pending-job snapshot only.
            target["enumeration_complete"] = True
            target["empty_pending_jobs_snapshot"] = True
            return set()
        try:
            lines = raw.splitlines()
            target["enumerated"] = len(lines)
            if len(lines) > MAX_ROWS:
                target["skipped"] += len(lines)
                self.gap(domain, "row_limit")
                return set()
            rows = []
            for line in lines:
                fields = line.decode("ascii").split()
                if len(fields) != 4:
                    raise ValueError
                job_id, unit, job_type, job_state = fields
                if (
                    not re.fullmatch(r"[1-9][0-9]{0,9}", job_id)
                    or int(job_id) >= 2**32
                    or not UNIT.fullmatch(unit)
                    or job_type not in JOB_TYPES
                    or job_state not in {"waiting", "running"}
                ):
                    raise ValueError
                rows.append(
                    {
                        "job": int(job_id),
                        "unit": unit,
                        "type": job_type,
                        "state": job_state,
                    }
                )
            # Validate the full bounded representation before projecting any row.
            for row in rows:
                self.record(
                    domain,
                    row["unit"],
                    {
                        "row_projection": projection(
                            json.dumps(row, sort_keys=True).encode()
                        )
                    },
                )
            target["enumeration_complete"] = True
            return {row["unit"] for row in rows}
        except (ValueError, UnicodeError):
            self.gap(domain, "unsupported_or_bounded_format")
            return set()

    def listing(self, command, key, domain):
        if command == "list-jobs":
            return self.jobs_listing(domain)
        raw = self.run([command, "--all", "--output=json"], domain)
        if raw is None:
            return set()
        try:
            rows = json.loads(raw)
            if not isinstance(rows, list) or len(rows) > MAX_ROWS:
                raise ValueError
            self.domain(domain)["enumerated"] = len(rows)
            names = set()
            for row in rows:
                value = row[key]
                if not isinstance(value, str) or not UNIT.fullmatch(value):
                    raise ValueError
                names.add(value)
                self.record(
                    domain,
                    value,
                    {
                        "row_projection": projection(
                            json.dumps(row, sort_keys=True).encode()
                        )
                    },
                )
            self.domain(domain)["enumerated"] = len(rows)
            self.domain(domain)["enumeration_complete"] = True
            return names
        except (ValueError, TypeError, KeyError, UnicodeError):
            self.gap(domain, "unsupported_or_bounded_format")
            return set()

    @staticmethod
    def bus_unit_path(name):
        # v255 bus_label_escape: initial digits and every non-ASCII-alnum byte
        # become underscore + lowercase hex; underscore itself is escaped.
        label = "".join(
            chr(value)
            if (
                65 <= value <= 90 or 97 <= value <= 122
                or (index > 0 and 48 <= value <= 57)
            )
            else "_" + format(value, "02x")
            for index, value in enumerate(name.encode("utf-8"))
        )
        return BUS_UNIT_PREFIX + label

    @staticmethod
    def bus_id_matches(raw, name):
        # busctl C-escaped strings are accepted only when strict JSON-compatible.
        if raw is None or not raw.startswith(b's "') or not raw.endswith(b'"\n'):
            return False
        try:
            value = json.loads(raw[2:-1])
            return isinstance(value, str) and value == name
        except (ValueError, UnicodeError):
            return False

    @staticmethod
    def unit_name_shape(name):
        # Syntactic metadata only: templates/instances can still be authorities.
        stem, separator, suffix = name.rpartition(".")
        template = None
        shape = "plain" if separator and stem and suffix and "@" not in suffix else "unsupported"
        if shape == "plain" and "@" in stem:
            prefix, instance = stem.split("@", 1)
            if prefix:
                shape = "instance" if instance else "template"
                template = prefix + "@." + suffix
            else:
                shape = "unsupported"
        return {
            "shape": shape,
            "template_name_sha256": digest(template.encode()) if template else None,
        }

    @staticmethod
    def bus_names(raw):
        # busctl's C escapes are not generally JSON: accept only the common
        # ASCII subset usable by UNIT, rejecting unsupported escapes fail-closed.
        if raw is None or len(raw) > MAX_COMMAND_BYTES:
            return None
        try:
            text = raw.decode("ascii")
            header = re.match(r"as (0|[1-9][0-9]{0,3})(?= |\n)", text)
            if header is None:
                return None
            count = int(header[1])
            if count > MAX_ROWS:
                return None
            offset = header.end()
            values = set()
            decoder = json.JSONDecoder()
            for _index in range(count):
                if text[offset:offset + 2] != ' "':
                    return None
                offset += 1
                value, end = decoder.raw_decode(text, offset)
                token = text[offset:end]
                # UNIT names require only escaped backslash among JSON escapes.
                # Reject all others rather than misinterpret busctl C encoding.
                if '\\' in token.replace('\\\\', ''):
                    return None
                if not isinstance(value, str) or not UNIT.fullmatch(value):
                    return None
                if value in values:
                    return None
                values.add(value)
                offset = end
            return values if text[offset:] == "\n" else None
        except (ValueError, UnicodeError):
            return None

    def typed_alias_empty_fallback(self, name, canonical, fields, props, facts, domain):
        path = self.bus_unit_path(canonical)
        binding = {
            "canonical_identity_sha256": digest(canonical.encode()),
            "canonical_enumerated": True,
            "before_id_matches_canonical": False,
            "after_id_matches_canonical": False,
            "before_names_bind_requested_and_canonical": False,
            "after_names_bind_requested_and_canonical": False,
            "names_set_stable": False,
        }
        facts["typed_alias_binding"] = binding
        facts["typed_alias_empty_evidence"] = {}
        facts["typed_getter_output"] = {}
        facts["typed_getter_failure"] = {}
        # These retain exact-enumerated-identity semantics, never alias success.
        facts["typed_unit_id_before_matches"] = False
        facts["typed_unit_id_after_matches"] = False

        def read_binding(phase):
            raw_id = self.run(
                ["get-property", "org.freedesktop.systemd1", path,
                 BUS_INTERFACE_PREFIX + "Unit", "Id"], domain, getter=True,
            )
            if raw_id is not None:
                binding[phase + "_id_output"] = projection(raw_id)
            matches = self.bus_id_matches(raw_id, canonical)
            binding[phase + "_id_matches_canonical"] = matches
            if not matches:
                return None
            raw_names = self.run(
                ["get-property", "org.freedesktop.systemd1", path,
                 BUS_INTERFACE_PREFIX + "Unit", "Names"], domain, getter=True,
            )
            if raw_names is not None:
                binding[phase + "_names_output"] = projection(raw_names)
            values = self.bus_names(raw_names)
            bound = values is not None and {name, canonical} <= values
            binding[phase + "_names_bind_requested_and_canonical"] = bound
            return values if bound else None

        before = read_binding("before")
        if before is None:
            self.gap(domain, "typed_alias_binding_unconfirmed")
            return
        candidates = {}
        for field in fields:
            signature, interfaces = TYPED_PROPERTIES[field]
            interface = next(
                value for suffix, value in interfaces.items() if canonical.endswith(suffix)
            )
            raw = self.run(
                ["get-property", "org.freedesktop.systemd1", path,
                 BUS_INTERFACE_PREFIX + interface, field], domain, getter=True,
            )
            if raw is None:
                facts["typed_getter_failure"][field] = "command_failed_or_unavailable"
                continue
            facts["typed_getter_output"][field] = projection(raw)
            if raw == signature.encode("ascii") + b" 0\n":
                candidates[field] = signature
            else:
                facts["typed_getter_failure"][field] = "nonempty_or_wrong_signature"
        after = read_binding("after")
        binding["names_set_stable"] = after is not None and before == after
        if not binding["names_set_stable"]:
            self.gap(domain, "typed_alias_binding_unconfirmed")
            return
        # All pre/post Id+Names checks and runner cleanup succeeded first.
        for field, signature in candidates.items():
            props[field] = projection(b"")
            facts["typed_alias_empty_evidence"][field] = {
                "signature": signature,
                "typed_empty_confirmed": True,
                "alias_binding_confirmed": True,
                "getter_output": facts["typed_getter_output"][field],
            }
        if set(fields) - props.keys():
            self.gap(domain, "typed_empty_unresolved")

    def typed_empty_fallback(self, name, enumerated, props, facts, domain, canonical=None):
        fields = sorted(
            field
            for field, (_signature, interfaces) in TYPED_PROPERTIES.items()
            if field not in props and name.endswith(tuple(interfaces))
        )
        if not fields:
            return
        if name not in enumerated or not UNIT.fullmatch(name):
            self.gap(domain, "typed_getter_request_rejected")
            return
        if canonical is not None and canonical != name:
            if (
                canonical not in enumerated or not UNIT.fullmatch(canonical)
                or canonical.rpartition(".")[2] != name.rpartition(".")[2]
            ):
                self.gap(domain, "typed_alias_binding_unconfirmed")
                return
            self.typed_alias_empty_fallback(name, canonical, fields, props, facts, domain)
            return
        path = self.bus_unit_path(name)
        facts["typed_getter_output"] = {}
        facts["typed_getter_failure"] = {}
        facts["typed_empty_evidence"] = {}
        facts["typed_unit_id_before_matches"] = False
        facts["typed_unit_id_after_matches"] = False
        before = self.run(
            ["get-property", "org.freedesktop.systemd1", path,
             BUS_INTERFACE_PREFIX + "Unit", "Id"], domain, getter=True,
        )
        if before is not None:
            facts["typed_unit_id_before_output"] = projection(before)
        before_matches = self.bus_id_matches(before, name)
        facts["typed_unit_id_before_matches"] = before_matches
        if not before_matches:
            self.gap(domain, "typed_unit_identity_unconfirmed")
            return
        candidates = {}
        for field in fields:
            signature, interfaces = TYPED_PROPERTIES[field]
            interface = next(
                value for suffix, value in interfaces.items() if name.endswith(suffix)
            )
            raw = self.run(
                ["get-property", "org.freedesktop.systemd1", path,
                 BUS_INTERFACE_PREFIX + interface, field], domain, getter=True,
            )
            if raw is None:
                facts["typed_getter_failure"][field] = "command_failed_or_unavailable"
                continue
            facts["typed_getter_output"][field] = projection(raw)
            if raw == signature.encode("ascii") + b" 0\n":
                candidates[field] = signature
            else:
                facts["typed_getter_failure"][field] = "nonempty_or_wrong_signature"
        after = self.run(
            ["get-property", "org.freedesktop.systemd1", path,
             BUS_INTERFACE_PREFIX + "Unit", "Id"], domain, getter=True,
        )
        if after is not None:
            facts["typed_unit_id_after_output"] = projection(after)
        after_matches = self.bus_id_matches(after, name)
        facts["typed_unit_id_after_matches"] = after_matches
        if not after_matches:
            self.gap(domain, "typed_unit_identity_unconfirmed")
            return
        # Apply only after both identity reads and every owned-child cleanup.
        for field, signature in candidates.items():
            props[field] = projection(b"")
            facts["typed_empty_evidence"][field] = {
                "signature": signature,
                "typed_empty_confirmed": True,
                "unit_id_before_matches": True,
                "unit_id_after_matches": True,
                "getter_output": facts["typed_getter_output"][field],
                "unit_id_before_output": facts["typed_unit_id_before_output"],
                "unit_id_after_output": facts["typed_unit_id_after_output"],
            }
        if set(fields) - props.keys():
            self.gap(domain, "typed_empty_unresolved")

    def systemd(self):
        installed = self.listing("list-unit-files", "unit_file", "systemd_installed")
        loaded = self.listing("list-units", "unit", "systemd_loaded")
        self.loaded_units = loaded
        self.installed_units = installed
        self.listing("list-timers", "unit", "systemd_timers")
        self.listing("list-jobs", "unit", "systemd_jobs")
        domain = "systemd_unit_properties"
        enumerated = installed | loaded
        names = sorted(enumerated)
        self.domain(domain)["enumerated"] = len(names)
        if len(names) > MAX_ROWS:
            self.gap(domain, "union_units_truncated")
            self.domain(domain)["skipped"] += len(names) - MAX_ROWS
        for index, name in enumerate(names[:MAX_ROWS]):
            if self.interrupted(domain):
                self.domain(domain)["skipped"] += min(len(names), MAX_ROWS) - index
                break
            applicable = COMMON_PROPERTIES
            if name.endswith((".service", ".socket", ".mount", ".swap")):
                applicable += EXEC_CONTEXT_PROPERTIES
            if name.endswith(".service"):
                applicable += SERVICE_PROPERTIES
            elif name.endswith(".timer"):
                applicable += TIMER_PROPERTIES
            elif name.endswith(".path"):
                applicable += ("Unit",)
            not_applicable = sorted(set(PROPERTIES) - set(applicable))
            raw = self.run(
                ["show", "--all", "--property=" + ",".join(applicable), "--", name],
                domain,
            )
            canonical = None
            facts = {
                "name_shape": self.unit_name_shape(name),
                "properties": {},
                "missing_properties": sorted(applicable),
                "not_applicable_properties": not_applicable,
                "property_retry_output": {},
                "property_retry_failure": {},
            }
            if raw is None:
                facts["command_failure_class"] = "command_failed_or_unavailable"
                if self.record(domain, name, facts):
                    self.domain(domain)["complete"] -= 1
                continue
            facts["property_original_output"] = projection(raw)
            props = facts["properties"]
            occurrences = {}
            try:
                for line in raw.splitlines():
                    if self.interrupted(domain) or time.monotonic() >= self.deadline:
                        facts["property_parse_failure_class"] = "parser_work_interrupted_or_deadline"
                        raise ValueError
                    if b"=" not in line:
                        facts["property_parse_failure_class"] = "line_missing_equals"
                    key, value = line.split(b"=", 1)
                    if not key.isascii():
                        facts["property_parse_failure_class"] = "non_ascii_key"
                        facts["property_parse_failure_key_sha256"] = digest(key)
                    field = key.decode("ascii")
                    if field not in applicable:
                        facts["property_parse_failure_class"] = "unknown_key"
                        facts["property_parse_failure_key_sha256"] = digest(key)
                        raise ValueError
                    if field in props and field not in REPEATED_PROPERTIES:
                        facts["property_parse_failure_class"] = "duplicate_key"
                        facts["property_parse_failure_key_sha256"] = digest(key)
                        raise ValueError
                    if field in REPEATED_PROPERTIES:
                        values = occurrences.setdefault(field, [])
                        if len(values) >= MAX_ROWS:
                            facts["property_parse_failure_class"] = "repeated_occurrence_limit"
                            facts["property_parse_failure_key_sha256"] = digest(key)
                            raise ValueError
                        values.append(value)
                    if field not in props:
                        props[field] = projection(value)
                    if field == "Id" and value.isascii():
                        candidate = value.decode("ascii")
                        if UNIT.fullmatch(candidate):
                            canonical = candidate
                # Finalize once, only after the entire initial textual parse succeeds.
                repeated_evidence = {}
                repeated_aggregates = {}
                for field, values in occurrences.items():
                    if len(values) < 2:
                        continue
                    frame = bytearray(REPEATED_REPRESENTATION.encode("ascii") + b"\0")
                    frame.extend(len(values).to_bytes(8, "big"))
                    ordered = []
                    for value in values:
                        if self.interrupted(domain) or time.monotonic() >= self.deadline:
                            facts["property_parse_failure_class"] = "parser_work_interrupted_or_deadline"
                            raise ValueError
                        frame.extend(len(value).to_bytes(8, "big"))
                        frame.extend(value)
                        ordered.append(projection(value))
                    aggregate = projection(frame)
                    repeated_aggregates[field] = aggregate
                    repeated_evidence[field] = {
                        "representation": REPEATED_REPRESENTATION,
                        "count": len(values),
                        "ordered_occurrences": ordered,
                        "aggregate": aggregate,
                    }
                props.update(repeated_aggregates)
                if repeated_evidence:
                    facts["repeated_property_evidence"] = repeated_evidence
            except (ValueError, UnicodeError):
                facts["command_failure_class"] = "unsupported_property_format"
                self.gap(domain, "unsupported_or_bounded_format")
            else:
                # One bounded retry for each omitted supported complex property.
                retry_fields = (set(applicable) - props.keys()) & RETRY_PROPERTIES
                for field in sorted(retry_fields):
                    retry = self.run(
                        ["show", "--all", "--property=" + field, "--", name], domain
                    )
                    if retry is None:
                        facts["property_retry_failure"][field] = (
                            "command_failed_or_unavailable"
                        )
                        continue
                    facts["property_retry_output"][field] = projection(retry)
                    lines = retry.splitlines()
                    prefix = field.encode("ascii") + b"="
                    if len(lines) == 1 and lines[0].startswith(prefix):
                        props[field] = projection(lines[0][len(prefix) :])
                    else:
                        facts["property_retry_failure"][field] = (
                            "omitted_or_unsupported_property_format"
                        )
                self.typed_empty_fallback(name, enumerated, props, facts, domain, canonical)
                if facts["property_retry_failure"].keys() - props.keys():
                    self.gap(domain, "property_retry_unresolved")
            missing = sorted(set(applicable) - props.keys())
            facts["missing_properties"] = missing
            if missing:
                self.gap(domain, "property_omission_unresolved")
            recorded = self.record(domain, name, facts)
            if recorded and (missing or "command_failure_class" in facts):
                self.domain(domain)["complete"] -= 1
        self.domain(domain)["enumeration_complete"] = (
            self.domain("systemd_installed")["enumeration_complete"]
            and self.domain("systemd_loaded")["enumeration_complete"]
        )

    @staticmethod
    def file_identity(meta):
        return (
            meta.st_dev,
            meta.st_ino,
            meta.st_uid,
            meta.st_gid,
            meta.st_mode,
            meta.st_size,
            meta.st_mtime_ns,
            meta.st_ctime_ns,
        )

    def read_file(self, directory, name, owner, domain, limit=MAX_BYTES, expected=None):
        if self.interrupted(domain):
            return None
        if self.files >= MAX_FILES or time.monotonic() >= self.deadline:
            self.gap(domain, "file_or_time_limit")
            return None
        self.files += 1
        fd = None
        try:
            fd = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
            )
            before = os.fstat(fd)
            if expected is not None and self.file_identity(before) != expected:
                raise SnapshotChangedError
            named_before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                self.gap(domain, "file_nonregular")
                return None
            if before.st_uid != owner:
                self.gap(domain, "file_unsafe_owner")
                return None
            data = bytearray()
            while len(data) <= limit:
                block = os.read(fd, min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            after = os.fstat(fd)
            named_after = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if len(data) > limit:
                self.gap(domain, "file_byte_bound")
                return None
            if self.file_identity(before) != self.file_identity(after):
                raise SnapshotChangedError
            if self.file_identity(before) != self.file_identity(named_before):
                raise SnapshotChangedError
            if self.file_identity(before) != self.file_identity(named_after):
                raise SnapshotChangedError
            return bytes(data)
        except SnapshotChangedError:
            self.gap(domain, "file_snapshot_changed", raced=True)
            return None
        except FileNotFoundError:
            self.gap(domain, "file_missing_path")
            return None
        except PermissionError:
            self.gap(domain, "file_access_denied")
            return None
        except OSError as error:
            self.gap(
                domain,
                "file_unsafe_symlink"
                if error.errno == errno.ELOOP
                else "file_os_error",
            )
            return None
        finally:
            if fd is not None:
                os.close(fd)

    def directory(self, path, domain, missing_absence=False):
        # Resolve every component beneath a root FD without following symlinks.
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in path.strip("/").split("/"):
                next_fd = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
                os.close(fd)
                fd = next_fd
                meta = os.fstat(fd)
                if meta.st_uid != 0 or meta.st_mode & 0o022:
                    raise ValueError
            return fd
        except FileNotFoundError:
            os.close(fd)
            if missing_absence:
                self.record(
                    domain, path,
                    {"missing_path": True, "absence_at_observation": True},
                )
                self.domain(domain)["enumerated"] = 1
                self.domain(domain)["enumeration_complete"] = True
            else:
                self.gap(domain, "directory_missing_path")
            return None
        except PermissionError:
            os.close(fd)
            self.gap(domain, "directory_access_denied")
            return None
        except (OSError, ValueError):
            os.close(fd)
            self.gap(domain, "directory_unsafe_or_os_error")
            return None

    def names(self, fd, domain):
        # scandir iterator avoids materializing an unbounded directory listing.
        result = []
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    if self.interrupted(domain):
                        return None
                    if len(result) >= MAX_FILES or time.monotonic() >= self.deadline:
                        raise ValueError
                    result.append(entry.name)
            return sorted(result)
        except (OSError, ValueError):
            self.gap(domain, "directory_enumeration_denied_or_bound")
            return None

    @staticmethod
    def process_stat(raw, pid):
        # comm can contain spaces and closing parentheses; final ')' delimits it.
        close = raw.rfind(b")")
        if not raw.startswith(str(pid).encode() + b" (") or close < 0:
            raise ValueError
        fields = raw[close + 2 :].split()
        if (
            len(fields) < 20
            or not fields[19].isdigit()
            or not fields[6].isdigit()
            or len(fields[6]) > 10
        ):
            raise ValueError
        flags = int(fields[6])
        state = fields[0].decode("ascii")
        if flags >= 2**32 or state not in PROCESS_STATES:
            raise ValueError
        return fields[19].decode("ascii"), flags, state

    def verify_procfs(self, root, domain):
        # Bootstrap only from protected fixed /proc/<our PID>/mountinfo.
        # No symlink traversal through /proc/self and no external helpers.
        own = None
        try:
            meta = os.fstat(root)
            named = os.stat("/proc", follow_symlinks=False)
            if (
                self.file_identity(meta) != self.file_identity(named)
                or not stat.S_ISDIR(meta.st_mode)
                or meta.st_uid != 0
                or meta.st_mode & 0o022
            ):
                raise ValueError
            own_pid = str(os.getpid())
            own = os.open(
                own_pid, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root
            )
            own_meta = os.fstat(own)
            own_named = os.stat(own_pid, dir_fd=root, follow_symlinks=False)
            if (
                self.file_identity(own_meta) != self.file_identity(own_named)
                or own_meta.st_dev != meta.st_dev
                or own_meta.st_uid != 0
                or own_meta.st_mode & 0o022
            ):
                raise ValueError
            mount_meta = os.stat("mountinfo", dir_fd=own, follow_symlinks=False)
            if (
                mount_meta.st_dev != meta.st_dev
                or mount_meta.st_uid != 0
                or mount_meta.st_mode & 0o022
                or not stat.S_ISREG(mount_meta.st_mode)
            ):
                raise ValueError
            raw = self.read_file(
                own, "mountinfo", 0, domain, MAX_BYTES,
                expected=self.file_identity(mount_meta),
            )
            if raw is None:
                raise ValueError
            matches = 0
            device = str(os.major(meta.st_dev)).encode() + b":" + str(
                os.minor(meta.st_dev)
            ).encode()
            lines = raw.splitlines()
            if not lines or len(lines) > MAX_FILES:
                raise ValueError
            for line in lines:
                fields = line.split()
                if fields.count(b"-") != 1:
                    raise ValueError
                separator = fields.index(b"-")
                if separator < 6 or len(fields) != separator + 4:
                    raise ValueError
                target = fields[4]
                if target == b"/proc":
                    if (
                        fields[2] != device or fields[3] != b"/"
                        or fields[separator + 1] != b"proc"
                        or fields[separator + 2] != b"proc"
                    ):
                        raise ValueError
                    matches += 1
                elif target.startswith(b"/proc/"):
                    component = target[len(b"/proc/") :].split(b"/", 1)[0]
                    # Refuse PID/self overmounts, even same-device bind mounts.
                    if component.isdigit() or component in (b"self", b"thread-self"):
                        raise ValueError
            if (
                matches != 1
                or self.file_identity(meta) != self.file_identity(
                    os.stat("/proc", follow_symlinks=False)
                )
                or self.file_identity(own_meta) != self.file_identity(os.fstat(own))
                or self.file_identity(own_meta) != self.file_identity(
                    os.stat(own_pid, dir_fd=root, follow_symlinks=False)
                )
            ):
                raise ValueError
            return meta.st_dev
        except (OSError, ValueError):
            self.gap(domain, "procfs_mount_unproved")
            return None
        finally:
            if own is not None:
                os.close(own)

    def read_proc_file(self, root, directory, pid, name, device, domain, exceptions):
        # This reader is restricted to already-qualified kernel procfs metadata.
        limits = {"stat": 16384, "status": 65536, "cmdline": MAX_BYTES, "cgroup": 65536}
        if name not in limits or not re.fullmatch(r"[1-9][0-9]{0,9}", pid):
            self.gap(domain, "procfs_field_or_pid_rejected")
            return None
        if self.interrupted(domain):
            return None
        if self.files >= MAX_FILES or time.monotonic() >= self.deadline:
            self.gap(domain, "file_or_time_limit")
            return None
        self.files += 1
        fd = None
        try:
            proc_meta = os.fstat(root)
            proc_named = os.stat("/proc", follow_symlinks=False)
            parent = os.fstat(directory)
            parent_named = os.stat(pid, dir_fd=root, follow_symlinks=False)
            if (
                proc_meta.st_dev != device or proc_meta.st_uid != 0
                or proc_meta.st_mode & 0o022
                or self.file_identity(proc_meta) != self.file_identity(proc_named)
                or parent.st_dev != device or not stat.S_ISDIR(parent.st_mode)
                or parent.st_mode & 0o022
                or self.file_identity(parent) != self.file_identity(parent_named)
            ):
                raise ValueError
            fd = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
            )
            before = os.fstat(fd)
            named_before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (
                before.st_dev != device or not stat.S_ISREG(before.st_mode)
                or before.st_uid not in (0, parent.st_uid)
                or before.st_mode & 0o022
                or self.file_identity(before) != self.file_identity(named_before)
            ):
                raise ValueError
            data = bytearray()
            limit = limits[name]
            # Kernel proc files normally report size0; bound bytes actually read.
            while len(data) <= limit:
                block = os.read(fd, min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if len(data) > limit:
                self.gap(domain, "procfs_file_byte_bound")
                return None
            if (
                self.file_identity(before) != self.file_identity(os.fstat(fd))
                or self.file_identity(before) != self.file_identity(
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                )
                or self.file_identity(parent) != self.file_identity(os.fstat(directory))
                or self.file_identity(parent) != self.file_identity(
                    os.stat(pid, dir_fd=root, follow_symlinks=False)
                )
                or self.file_identity(proc_meta) != self.file_identity(
                    os.stat("/proc", follow_symlinks=False)
                )
            ):
                raise SnapshotChangedError
            if before.st_uid == 0 and parent.st_uid != 0 and name not in exceptions:
                exceptions.append(name)
            return bytes(data)
        except SnapshotChangedError:
            self.gap(domain, "procfs_snapshot_changed", raced=True)
            return None
        except FileNotFoundError:
            self.gap(domain, "procfs_path_missing")
            return None
        except PermissionError:
            self.gap(domain, "procfs_access_denied")
            return None
        except OSError:
            self.gap(domain, "procfs_os_error")
            return None
        except ValueError:
            self.gap(domain, "procfs_identity_or_permissions_unproved")
            return None
        finally:
            if fd is not None:
                os.close(fd)

    def processes(self):
        domain = "processes"
        root = self.directory("/proc", domain)
        if root is None:
            return
        try:
            device = self.verify_procfs(root, domain)
            if device is None:
                return
            names = self.names(root, domain)
            if names is None:
                return
            pids = [name for name in names if name.isascii() and name.isdigit()]
            self.domain(domain)["enumerated"] = len(pids)
            self.domain(domain)["enumeration_complete"] = True
            for index, pid in enumerate(pids):
                if self.interrupted(domain):
                    self.domain(domain)["skipped"] += len(pids) - index
                    break
                fd = None
                try:
                    if not re.fullmatch(r"[1-9][0-9]{0,9}", pid):
                        self.gap(domain, "procfs_field_or_pid_rejected")
                        self.gap(domain, "process_identity_unconfirmed")
                        continue
                    fd = os.open(
                        pid, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root
                    )
                    uid = os.fstat(fd).st_uid
                    root_owned_fields = []
                    first = self.read_proc_file(
                        root, fd, pid, "stat", device, domain, root_owned_fields
                    )
                    if first is None:
                        self.gap(domain, "process_identity_unconfirmed")
                        continue
                    start, flags_before, state_before = self.process_stat(first, pid)
                    kernel_before = bool(flags_before & PF_KTHREAD)
                    skip_links = kernel_before or state_before == "Z"
                    facts = {
                        "pid": int(pid),
                        "uid": uid,
                        "procfs_mount_verified": True,
                        "procfs_root_owned_fields": root_owned_fields,
                        "starttime_ticks": start,
                        "stat_flags_before": flags_before,
                        "stat_state_before": state_before,
                    }
                    failed = False
                    missing_fields = []
                    for field in ("cmdline", "cgroup"):
                        data = self.read_proc_file(
                            root, fd, pid, field, device, domain, root_owned_fields
                        )
                        if data is None:
                            failed = True
                            missing_fields.append(
                                "argv" if field == "cmdline" else field
                            )
                        else:
                            facts["argv" if field == "cmdline" else field] = projection(
                                data
                            )
                    status = self.read_proc_file(
                        root, fd, pid, "status", device, domain, root_owned_fields
                    )
                    if status is None:
                        failed = True
                        missing_fields.append("uids_real_effective_saved_filesystem")
                    else:
                        uid_lines = [
                            line
                            for line in status.splitlines()
                            if line.startswith(b"Uid:")
                        ]
                        uids = uid_lines[0].split()[1:] if len(uid_lines) == 1 else []
                        if len(uids) != 4 or any(
                            not value.isdigit() or len(value) > 10
                            or int(value) >= 2**32
                            for value in uids
                        ):
                            failed = True
                            missing_fields.append("uids_real_effective_saved_filesystem")
                            self.gap(domain, "process_status_uid_unsupported")
                        else:
                            facts["uids_real_effective_saved_filesystem"] = [
                                int(value) for value in uids
                            ]
                            if uid != 0 and uid not in (
                                facts["uids_real_effective_saved_filesystem"]
                            ):
                                failed = True
                                self.gap(domain, "procfs_uid_attribution_unresolved")
                    if not skip_links:
                        for field in ("exe", "cwd"):
                            try:
                                facts[field] = projection(
                                    os.fsencode(os.readlink(field, dir_fd=fd))
                                )
                            except OSError:
                                failed = True
                                missing_fields.append(field)
                                # Unavailable is not evidence that a PID vanished.
                                self.gap(domain, "userspace_process_link_unavailable")
                    last = self.read_proc_file(
                        root, fd, pid, "stat", device, domain, root_owned_fields
                    )
                    if last is None:
                        self.gap(domain, "process_identity_unconfirmed")
                        continue
                    last_start, flags_after, state_after = self.process_stat(last, pid)
                    if last_start != start:
                        self.gap(domain, "process_identity_raced", raced=True)
                        continue
                    kernel_after = bool(flags_after & PF_KTHREAD)
                    if kernel_after != kernel_before:
                        self.gap(domain, "process_kind_changed")
                        continue
                    facts["stat_flags_after"] = flags_after
                    facts["stat_state_after"] = state_after
                    stable_zombie = state_before == "Z" and state_after == "Z"
                    if kernel_before or stable_zombie:
                        facts["process_representation"] = (
                            "kernel_thread" if kernel_before else "stable_zombie"
                        )
                        facts["not_applicable_process_fields"] = ["exe", "cwd"]
                    else:
                        facts["process_representation"] = "userspace_or_transition"
                        facts["not_applicable_process_fields"] = []
                        if skip_links:
                            failed = True
                            missing_fields.extend(("exe", "cwd"))
                            self.gap(domain, "process_representation_changed")
                    anchored = os.stat(pid, dir_fd=root, follow_symlinks=False)
                    retained = os.fstat(fd)
                    if (anchored.st_dev, anchored.st_ino, anchored.st_uid) != (
                        retained.st_dev,
                        retained.st_ino,
                        uid,
                    ):
                        self.gap(domain, "process_identity_raced", raced=True)
                        continue
                    facts["missing_process_fields"] = sorted(set(missing_fields))
                    if failed:
                        self.gap(domain, "process_projection_incomplete")
                    recorded = self.record(domain, pid + ":" + start, facts)
                    if failed and recorded:
                        self.domain(domain)["complete"] -= 1
                except FileNotFoundError:
                    self.gap(domain, "process_path_missing_identity_unconfirmed")
                except (OSError, ValueError, UnicodeError):
                    self.gap(domain, "process_unreadable_or_unsupported")
                    self.gap(domain, "process_identity_unconfirmed")
                finally:
                    if fd is not None:
                        os.close(fd)
            final = self.names(root, domain)
            if final is None or {
                n for n in final if n.isascii() and n.isdigit()
            } != set(pids):
                self.gap(domain, "process_set_changed", raced=True)
            if self.verify_procfs(root, domain) != device:
                self.gap(domain, "procfs_final_mount_unproved")
                self.domain(domain)["complete"] = 0
                self.domain(domain)["enumeration_complete"] = False
        finally:
            os.close(root)

    def read_nsswitch(self, directory, domain):
        # Mode-check the anchored name, then require that exact tuple in read_file.
        # Its same-FD and named before/after checks keep the mode proof attached.
        try:
            meta = os.stat("nsswitch.conf", dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
                self.gap(domain, "nss_file_unsafe_metadata")
                return None
            raw = self.read_file(
                directory, "nsswitch.conf", 0, domain, MAX_BYTES, self.file_identity(meta)
            )
            return (raw, meta) if raw is not None else None
        except FileNotFoundError:
            self.gap(domain, "file_missing_path")
        except PermissionError:
            self.gap(domain, "file_access_denied")
        except OSError:
            self.gap(domain, "file_os_error")
        return None

    def nss_provider_projection(self, body):
        # This deliberately supports a strict subset; never resolve NSS or load providers.
        labels = frozenset((
            "files", "systemd", "compat", "dns", "nis", "nisplus", "ldap", "sss",
            "winbind", "db", "resolve", "myhostname", "mymachines", "hesiod",
        ))
        providers = []
        whitespace_pattern = re.compile(rb"[ \t]*")
        token_pattern = re.compile(rb"[A-Za-z0-9_.-]{1,255}(?=[ \t\[]|$)")
        position = 0
        while position < len(body):
            if self.interrupted("nss_provider_layout") or time.monotonic() >= self.deadline:
                self.gap("nss_provider_layout", "file_or_time_limit")
                return None
            position = whitespace_pattern.match(body, position).end()
            if position == len(body):
                break
            token = token_pattern.match(body, position)
            if token is None or len(providers) >= MAX_ROWS:
                return None
            raw = token[0]
            position = token.end()
            if raw.decode("ascii") not in labels:
                self.gap("nss_provider_layout", "unknown_provider_semantics_unresolved")
            provider = {
                "label": raw.decode("ascii") if raw.decode("ascii") in labels else "unknown-token",
                "token_sha256": digest(raw),
                "action_clause_sha256": [],
            }
            while True:
                position = whitespace_pattern.match(body, position).end()
                if position == len(body) or body[position:position + 1] != b"[":
                    break
                end = body.find(b"]", position + 1)
                if end == -1:
                    return None
                clause = body[position:end + 1]
                actions = clause[1:-1].strip().split()
                statuses = set()
                if not actions or len(provider["action_clause_sha256"]) >= 1:
                    return None
                for action in actions:
                    match = re.fullmatch(
                        rb"(!?)(SUCCESS|UNAVAIL|NOTFOUND|TRYAGAIN)=(RETURN|CONTINUE|MERGE)",
                        action, re.IGNORECASE,
                    )
                    if match is None or match[2].upper() in statuses:
                        return None
                    statuses.add(match[2].upper())
                provider["action_clause_sha256"].append(digest(clause))
                position = end + 1
                if position < len(body) and body[position:position + 1] not in (b" ", b"\t"):
                    return None
            providers.append(provider)
        return providers or None

    def nss_layout(self):
        domain = "nss_provider_layout"
        self.gap(domain, "nss_accounts_not_enumerated")
        etc = self.directory("/etc", domain)
        if etc is None:
            return
        try:
            snapshot = self.read_nsswitch(etc, domain)
        finally:
            os.close(etc)
        if snapshot is None:
            return
        raw, meta = snapshot
        source = {
            "sha256": digest(raw),
            "bytes": len(raw),
            "stat": dict(zip(
                ("dev", "ino", "uid", "gid", "mode", "size", "mtime_ns", "ctime_ns"),
                self.file_identity(meta), strict=True,
            )),
        }
        selected = {b"passwd": [], b"group": []}
        continuation = False
        for line in raw.split(b"\n"):
            if self.interrupted(domain) or time.monotonic() >= self.deadline:
                self.gap(domain, "file_or_time_limit")
                return
            content = line.split(b"#", 1)[0]
            if any((byte < 32 and byte != 9) or byte == 127 for byte in content):
                # libc whitespace/control boundaries exceed this strict SP/HT subset.
                self.gap(domain, "nss_control_boundary_unsupported")
            match = re.match(rb"^[ \t]*(passwd|group)(?=[ \t:]|$)", content)
            continued = continuation
            continuation = content.rstrip(b" \t").endswith(b"\\")
            if continued or continuation:
                # Even an unrelated continuation can obscure a database boundary.
                self.gap(domain, "nss_continuation_unsupported")
            if match is None:
                continue
            database = match[1]
            inline_comment = b"#" in line
            if inline_comment:
                # glibc provider tokens do not acquire shell-style inline comments.
                self.gap(domain, "nss_inline_comment_unsupported")
            if sum(len(rows) for rows in selected.values()) >= MAX_ROWS:
                self.gap(domain, "row_limit")
                return
            selected[database].append((line, content, continued or continuation or inline_comment))
        boundaries_supported = not {
            "nss_continuation_unsupported", "nss_control_boundary_unsupported"
        }.intersection(self.domain(domain)["gaps"])
        syntax_complete = boundaries_supported
        self.domain(domain)["enumerated"] = 2
        for database, lines in selected.items():
            supported = len(lines) == 1
            providers = None
            if not lines:
                self.gap(domain, "nss_database_missing_unresolved")
            elif len(lines) != 1:
                self.gap(domain, "nss_duplicate_database_unresolved")
            else:
                _line, content, continued = lines[0]
                match = re.fullmatch(rb"[ \t]*(?:passwd|group)[ \t]*:[ \t]*(.*)", content)
                if match is not None and not continued:
                    providers = self.nss_provider_projection(match[1])
                supported = providers is not None
                if not supported:
                    self.gap(domain, "nss_syntax_or_clause_unsupported")
            # A continuation anywhere makes all interpretation explicitly partial.
            supported = supported and boundaries_supported
            self.record(domain, "nss:" + database.decode("ascii"), {
                "nss_database": database.decode("ascii"),
                "nss_source": source,
                "nss_line_sha256": [digest(line) for line, _content, _continued in lines],
                "nss_parse_supported": supported,
                "nss_providers": providers if supported else [],
                "account_enumeration_proven": False,
            })
            if not supported:
                self.domain(domain)["complete"] -= 1
            syntax_complete = syntax_complete and supported
        self.domain(domain)["enumeration_complete"] = syntax_complete

    def user_manager_topology(self):
        domain = "user_manager_topology"
        self.gap(domain, "user_managers_not_collected_no_sessions_launched")
        self.gap(domain, "nss_accounts_not_enumerated")
        names = sorted(self.installed_units | self.loaded_units)
        for name in names:
            if self.interrupted(domain) or time.monotonic() >= self.deadline:
                self.gap(domain, "file_or_time_limit")
                return
            if not name.startswith("user@") or not name.endswith(".service"):
                continue
            raw_uid = name[5:-8]
            if not raw_uid:
                # Uninstantiated template is outside numeric-instance membership scope.
                continue
            if not re.fullmatch(r"0|[1-9][0-9]{0,9}", raw_uid) or int(raw_uid) >= 4294967295:
                self.gap(domain, "user_manager_uid_representation_unresolved")
                continue
            self.domain(domain)["enumerated"] += 1
            self.record(domain, name, {
                "uid": int(raw_uid),
                "unit_file_installed": name in self.installed_units,
                "system_unit_loaded": name in self.loaded_units,
                "user_manager_bus_queried": False,
                "manager_availability_proven": False,
                "account_enumeration_proven": False,
            })
        self.domain(domain)["enumeration_complete"] = (
            self.domain("systemd_installed")["enumeration_complete"]
            and self.domain("systemd_loaded")["enumeration_complete"]
            and "user_manager_uid_representation_unresolved" not in self.domain(domain)["gaps"]
            and "row_limit" not in self.domain(domain)["gaps"]
        )

    def schedulers_accounts(self):
        domain = "accounts_user_managers"
        etc = self.directory("/etc", domain)
        users = {}
        if etc is not None:
            try:
                raw = self.read_file(etc, "passwd", 0, domain)
                if raw is not None:
                    lines = raw.splitlines()
                    self.domain(domain)["enumerated"] = len(lines)
                    if len(lines) > MAX_ROWS:
                        self.gap(domain, "row_limit")
                    else:
                        for line in lines:
                            fields = line.split(b":")
                            if (
                                len(fields) != 7
                                or not fields[2].isdigit()
                                or not fields[3].isdigit()
                            ):
                                self.gap(domain, "unsupported_account_format")
                                continue
                            account = fields[0].decode("ascii")
                            users[account] = int(fields[2])
                            self.record(
                                domain,
                                account,
                                {
                                    "uid": int(fields[2]),
                                    "gid": int(fields[3]),
                                    "home": projection(fields[5]),
                                    "shell": projection(fields[6]),
                                    "system_user_manager_loaded": "user@"
                                    + str(int(fields[2]))
                                    + ".service"
                                    in self.loaded_units,
                                    "manager_availability_proven": False,
                                    "manager_collected": False,
                                },
                            )
                        self.domain(domain)["enumeration_complete"] = not self.domain(
                            domain
                        )["gaps"]
            except UnicodeError:
                self.gap(domain, "unsupported_account_format")
            finally:
                os.close(etc)
        self.gap(domain, "nss_accounts_not_enumerated")
        self.gap(domain, "user_managers_not_collected_no_sessions_launched")
        for path, representation in (
            ("/etc/cron.d", "debian_system_cron"),
            ("/etc/cron.hourly", "run_parts_metadata"),
            ("/etc/cron.daily", "run_parts_metadata"),
            ("/etc/cron.weekly", "run_parts_metadata"),
            ("/etc/cron.monthly", "run_parts_metadata"),
            ("/var/spool/cron/crontabs", "debian_account_cron"),
            ("/var/spool/cron", "unsupported_spool_metadata"),
            ("/var/spool/cron/atjobs", "unsupported_at_metadata"),
            ("/var/spool/at", "unsupported_at_metadata"),
        ):
            self.scheduler_directory(path, representation, users)
        domain = "system_cron_fixed"
        etc = self.directory("/etc", domain)
        if etc is not None:
            try:
                self.domain(domain)["enumerated"] = 2
                for name in ("crontab", "anacrontab"):
                    try:
                        os.stat(name, dir_fd=etc, follow_symlinks=False)
                    except FileNotFoundError:
                        self.record(
                            domain, "/etc/" + name,
                            {"missing_path": True, "absence_at_observation": True},
                        )
                        continue
                    except OSError:
                        self.gap(domain, "fixed_scheduler_path_unreadable")
                        continue
                    raw = self.read_file(etc, name, 0, domain)
                    if raw is not None:
                        self.record(
                            domain, "/etc/" + name, {"content": projection(raw)}
                        )
                self.domain(domain)["enumeration_complete"] = True
            finally:
                os.close(etc)

    @staticmethod
    def scheduler_body_policy(name, representation, users, meta):
        # Filename grammar is necessary but not an absence/classification proof.
        # Other spool/at representations are metadata-only until separately reviewed.
        if CREDENTIAL_NAME.search(name) or not CRON_NAME.fullmatch(name):
            return False, "scheduler_name_rejected"
        if not stat.S_ISREG(meta.st_mode):
            return False, "nonregular_entry_unresolved"
        if representation == "debian_system_cron":
            if meta.st_uid == 0 and not meta.st_mode & 0o022:
                return True, None
            return False, "scheduler_owner_or_mode_unresolved"
        if representation == "debian_account_cron":
            if name not in users:
                return False, "scheduler_account_filename_unresolved"
            if meta.st_uid == users[name] and stat.S_IMODE(meta.st_mode) == 0o600:
                return True, None
            return False, "scheduler_owner_or_mode_unresolved"
        if representation == "run_parts_metadata":
            if meta.st_uid != 0 or meta.st_mode & 0o022:
                return False, "scheduler_owner_or_mode_unresolved"
            if not meta.st_mode & 0o111:
                return False, "run_parts_not_executable"
            return False, "periodic_scripts_metadata_only"
        return False, "unsupported_spool_metadata_only"

    def scheduler_directory(self, path, representation, users):
        domain = "scheduler_" + digest(path.encode())[:16]
        fd = self.directory(path, domain, missing_absence=True)
        if fd is None:
            return
        try:
            names = self.names(fd, domain)
            if names is None:
                return
            self.domain(domain)["enumerated"] = len(names)
            self.domain(domain)["enumeration_complete"] = True
            for index, name in enumerate(names):
                if self.interrupted(domain):
                    self.domain(domain)["skipped"] += len(names) - index
                    break
                try:
                    meta = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    facts = {
                        "uid": meta.st_uid,
                        "gid": meta.st_gid,
                        "mode": stat.S_IMODE(meta.st_mode),
                        "size": meta.st_size,
                        "mtime_ns": meta.st_mtime_ns,
                        "body_collected": False,
                        "scheduler_definition_supported": False,
                    }
                    body, reason = self.scheduler_body_policy(
                        name, representation, users, meta
                    )
                    if body:
                        raw = self.read_file(
                            fd,
                            name,
                            meta.st_uid,
                            domain,
                            expected=self.file_identity(meta),
                        )
                        if raw is None:
                            reason = "scheduler_content_unavailable"
                        else:
                            facts["content"] = projection(raw)
                            facts["body_collected"] = True
                            facts["scheduler_definition_supported"] = True
                    # Retain metadata for ignored/rejected entries, but never
                    # combine pre-open metadata with a different file snapshot.
                    after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if self.file_identity(meta) != self.file_identity(after):
                        self.gap(domain, "scheduler_entry_raced_or_denied", raced=True)
                        continue
                    if reason is not None:
                        self.gap(domain, reason)
                    recorded = self.record(domain, path + "/" + name, facts)
                    if not facts["body_collected"] and recorded:
                        self.domain(domain)["complete"] -= 1
                except FileNotFoundError:
                    self.gap(domain, "scheduler_path_missing")
                except OSError:
                    self.gap(domain, "scheduler_entry_unreadable")
            if self.names(fd, domain) != names:
                self.gap(domain, "scheduler_set_changed", raced=True)
        finally:
            os.close(fd)

    def collect(self):
        self.systemd()
        self.processes()
        self.schedulers_accounts()
        self.nss_layout()
        self.user_manager_topology()
        for domain, reason in (
            ("database_sessions", "not_collected_no_database_access"),
            ("containers", "not_collected_no_container_access"),
            ("external_senders", "operator_scope_unanswered"),
            ("manual_senders", "operator_scope_unanswered"),
            ("authority_classification", "all_entities_unresolved"),
            ("activation_semantics", "hash_only_relationships_require_review"),
            ("temporal_consistency", "non_atomic_snapshot_no_exclusion"),
        ):
            self.gap(domain, reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=sorted(HOSTS))
    args = parser.parse_args()
    discovery = Discovery(args.role)
    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(number, discovery.request_signal)
    preconditions = (
        sys.version_info[:2] == (3, 12)
        and sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
        and os.geteuid() == 0
        and os.uname().nodename == HOSTS[args.role]
        and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
        and hasattr(os, "WNOWAIT")
    )
    if preconditions:
        try:
            discovery.collect()
        except Exception:  # Never serialize exception text or raw command output.
            discovery.gap("collector", "unexpected_failure")
    else:
        discovery.gap("collector", "precondition_refused")
    discovery.interrupted("collector")
    result = {
        "schema": "AcademyAuthorityDiscovery.v1",
        "role": args.role,
        "host": HOSTS[args.role],
        "coverage_complete": False,
        "campaign_authority_claimed": False,
        "classification_complete": False,
        "purpose": "readonly_discovery_facts_only",
        "domains": discovery.domains,
        "commands_attempted": discovery.commands,
        "files_attempted": discovery.files,
        "child_lifecycle": discovery.child_metadata,
        "signal_interrupted": discovery.pending_signal is not None,
    }
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()

"""Root read-only host facts; never a campaign census or exclusion proof."""

import argparse
import errno
import hashlib
import io
import json
import math
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
# An explicit endpoint-only resource profile; all other discovery caps remain separate.
SYSTEMD_ENDPOINT_PROFILE = {
    "schema": "AcademySystemdEndpointProfile.v1",
    "scope": "endpoint_acquisition_only",
    "counting": "decoded_attempts_including_malformed_and_duplicates",
    "overflow": "refuse_before_decode_mark_lower_bound",
    "field_attempts": 4096,
    "unit_read_attempts": 8192,
    "initial_pass_attempts": 65536,
    "repeated_pass_attempts": 65536,
    "total_attempts": 131072,
}
# Source-pinned endpoint catalogue; categories are observations, never authority.
SYSTEMD_RUNTIME_RELATION_CATALOGUE = {'schema': 'AcademySystemdRuntimeRelationCatalogue.v1',
 'source_version': 'systemd.v255',
 'scope': 'runtime_unit_endpoint_acquisition_only',
 'activation_complete_claimed': False,
 'sources': ['https://github.com/systemd/systemd/blob/v255/src/core/dbus-unit.c',
             'https://github.com/systemd/systemd/blob/v255/src/basic/unit-def.h',
             'https://github.com/systemd/systemd/blob/v255/src/core/unit-dependency-atom.c',
             'https://github.com/systemd/systemd/blob/v255/src/core/unit-dependency-atom.h',
             'https://github.com/systemd/systemd/blob/v255/src/core/unit.c#L2901-L2932'],
 'properties': {'Id': {'signature': 's',
                       'interface': 'Unit',
                       'direction': 'self',
                       'inverse': None,
                       'category': 'identity'},
                'Names': {'signature': 'as',
                          'interface': 'Unit',
                          'direction': 'self_aliases',
                          'inverse': None,
                          'category': 'identity'},
                'Triggers': {'signature': 'as',
                             'interface': 'Unit',
                             'direction': 'forward',
                             'inverse': 'TriggeredBy',
                             'category': 'event_activation'},
                'TriggeredBy': {'signature': 'as',
                                'interface': 'Unit',
                                'direction': 'inverse',
                                'inverse': 'Triggers',
                                'category': 'event_activation'},
                'Requires': {'signature': 'as',
                             'interface': 'Unit',
                             'direction': 'forward',
                             'inverse': 'RequiredBy',
                             'category': 'start_pull'},
                'Wants': {'signature': 'as',
                          'interface': 'Unit',
                          'direction': 'forward',
                          'inverse': 'WantedBy',
                          'category': 'start_pull'},
                'Before': {'signature': 'as',
                           'interface': 'Unit',
                           'direction': 'forward',
                           'inverse': 'After',
                           'category': 'ordering'},
                'After': {'signature': 'as',
                          'interface': 'Unit',
                          'direction': 'inverse',
                          'inverse': 'Before',
                          'category': 'ordering'},
                'Requisite': {'signature': 'as',
                              'interface': 'Unit',
                              'direction': 'forward',
                              'inverse': 'RequisiteOf',
                              'category': 'precondition'},
                'BindsTo': {'signature': 'as',
                            'interface': 'Unit',
                            'direction': 'forward',
                            'inverse': 'BoundBy',
                            'category': 'start_pull_and_liveness'},
                'PartOf': {'signature': 'as',
                           'interface': 'Unit',
                           'direction': 'forward',
                           'inverse': 'ConsistsOf',
                           'category': 'stop_restart_propagation'},
                'Upholds': {'signature': 'as',
                            'interface': 'Unit',
                            'direction': 'forward',
                            'inverse': 'UpheldBy',
                            'category': 'continuous_start'},
                'RequiredBy': {'signature': 'as',
                               'interface': 'Unit',
                               'direction': 'inverse',
                               'inverse': 'Requires',
                               'category': 'start_pull'},
                'RequisiteOf': {'signature': 'as',
                                'interface': 'Unit',
                                'direction': 'inverse',
                                'inverse': 'Requisite',
                                'category': 'precondition'},
                'WantedBy': {'signature': 'as',
                             'interface': 'Unit',
                             'direction': 'inverse',
                             'inverse': 'Wants',
                             'category': 'start_pull'},
                'BoundBy': {'signature': 'as',
                            'interface': 'Unit',
                            'direction': 'inverse',
                            'inverse': 'BindsTo',
                            'category': 'start_pull_and_liveness'},
                'UpheldBy': {'signature': 'as',
                             'interface': 'Unit',
                             'direction': 'inverse',
                             'inverse': 'Upholds',
                             'category': 'continuous_start'},
                'ConsistsOf': {'signature': 'as',
                               'interface': 'Unit',
                               'direction': 'inverse',
                               'inverse': 'PartOf',
                               'category': 'stop_restart_propagation'},
                'Conflicts': {'signature': 'as',
                              'interface': 'Unit',
                              'direction': 'forward',
                              'inverse': 'ConflictedBy',
                              'category': 'stop_conflict'},
                'ConflictedBy': {'signature': 'as',
                                 'interface': 'Unit',
                                 'direction': 'inverse',
                                 'inverse': 'Conflicts',
                                 'category': 'stop_conflict'},
                'OnSuccess': {'signature': 'as',
                              'interface': 'Unit',
                              'direction': 'forward',
                              'inverse': 'OnSuccessOf',
                              'category': 'event_activation'},
                'OnSuccessOf': {'signature': 'as',
                                'interface': 'Unit',
                                'direction': 'inverse',
                                'inverse': 'OnSuccess',
                                'category': 'event_activation'},
                'OnFailure': {'signature': 'as',
                              'interface': 'Unit',
                              'direction': 'forward',
                              'inverse': 'OnFailureOf',
                              'category': 'event_activation'},
                'OnFailureOf': {'signature': 'as',
                                'interface': 'Unit',
                                'direction': 'inverse',
                                'inverse': 'OnFailure',
                                'category': 'event_activation'},
                'PropagatesReloadTo': {'signature': 'as',
                                       'interface': 'Unit',
                                       'direction': 'forward',
                                       'inverse': 'ReloadPropagatedFrom',
                                       'category': 'reload_propagation'},
                'ReloadPropagatedFrom': {'signature': 'as',
                                         'interface': 'Unit',
                                         'direction': 'inverse',
                                         'inverse': 'PropagatesReloadTo',
                                         'category': 'reload_propagation'},
                'PropagatesStopTo': {'signature': 'as',
                                     'interface': 'Unit',
                                     'direction': 'forward',
                                     'inverse': 'StopPropagatedFrom',
                                     'category': 'stop_propagation'},
                'StopPropagatedFrom': {'signature': 'as',
                                       'interface': 'Unit',
                                       'direction': 'inverse',
                                       'inverse': 'PropagatesStopTo',
                                       'category': 'stop_propagation'},
                'JoinsNamespaceOf': {'signature': 'as',
                                     'interface': 'Unit',
                                     'direction': 'symmetric',
                                     'inverse': 'JoinsNamespaceOf',
                                     'category': 'namespace_membership'},
                'SliceOf': {'signature': 'as',
                            'interface': 'Unit',
                            'direction': 'contains_endpoint',
                            'inverse': None,
                            'category': 'slice_membership',
                            'internal_inverse': 'UNIT_IN_SLICE',
                            'internal_inverse_exported': False},
                'Following': {'signature': 's',
                              'interface': 'Unit',
                              'direction': 'follows_endpoint',
                              'inverse': None,
                              'category': 'identity'},
                'Unit': {'signature': 's',
                         'interface': 'Timer_or_Path',
                         'direction': 'activates_endpoint',
                         'inverse': None,
                         'category': 'event_activation'}},
 'unsupported_path_requirements': {'Unit.RequiresMountsFor': {'signature': 'as',
                                                              'reason': 'paths_not_unit_endpoints'},
                                   'Path.Paths': {'signature': 'a(ss)',
                                                  'reason': 'paths_not_unit_endpoints'}},
 'unresolved_activation_requirements': ['socket_accept_service_and_instances',
                                        'timer_path_unit_defaults',
                                        'automount_mount_defaults',
                                        'type_specific_implicit_dependencies',
                                        'activation_source_cause_and_control_authority'],
 'default_target_inference': 'forbidden',
 'inverse_scope': 'exported_unit_properties'}
SYSTEMD_RUNTIME_RELATION_CATALOGUE_SHA256 = '0e2b40165f68b647b1f181ddc39329f264fa3021ba5f1e7da727b3e0efb5f846'
# Captured payload counts only explicit read results, including rejected bytes.
MIB = 1024 * 1024
RESOURCE_PROFILE = {
    "schema": "AcademyDiscoveryResourceProfile.v2",
    "ordinary_filesystem_work": 16384,
    "definition_filesystem_work": 262144,
    "cumulative_filesystem_work": 278528,
    "captured_payload_bytes": 256 * MIB,
    "record_json_bytes": 2 * MIB,
    "ordinary_record_json_bytes": 46 * MIB,
    "definition_domain_json_bytes": 16 * MIB,
    "metadata_json_bytes": MIB,
    "normal_json_bytes": 63 * MIB,
    "failure_json_bytes": MIB,
    "overflow_probe_bytes": 1,
    "readlink_bytes": 65536,
    "json_depth": 32,
    "json_container_entries": 262144,
    "json_nodes": 4000000,
    "json_string_characters": 2 * MIB,
    "json_key_characters": 256,
    "json_integer_bits": 128,
}
DEFINITION_DOMAIN = "systemd_template_definitions"
JSON_OPTIONS = dict(sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


class ResourceLimitError(ValueError):
    """Fixed resource refusal; never carries payload or exception text."""


def canonical_size(value, limit, *, forbidden_containers=None):
    """Validate before encoding; count ASCII JSON without allocating escaped strings.

    Keys and strings are scanned only after their primitive bounds are checked.
    Container identity is tracked on the active path, permitting shared acyclic trees.
    Tuples are deliberately accepted: historical file identities encode as arrays.
    """
    total = 0
    nodes = 0
    active = set()

    def charge(size):
        nonlocal total
        total += size
        if total > limit:
            raise ResourceLimitError

    def string(text, key=False):
        if len(text) > RESOURCE_PROFILE["json_key_characters" if key else "json_string_characters"]:
            raise ResourceLimitError
        charge(2)
        for character in text:
            code = ord(character)
            charge(2 if character in '\"\\\b\f\n\r\t' else 6 if code < 32 or 127 <= code <= 65535
                   else 12 if code > 65535 else 1)

    def walk(item, depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > RESOURCE_PROFILE["json_nodes"] or depth > RESOURCE_PROFILE["json_depth"]:
            raise ResourceLimitError
        kind = type(item)
        if item is None:
            charge(4)
        elif kind is bool:
            charge(4 if item else 5)
        elif kind is int:
            if item.bit_length() > RESOURCE_PROFILE["json_integer_bits"]:
                raise ResourceLimitError
            charge(len(str(item)))
        elif kind is float:
            if not math.isfinite(item):
                raise ResourceLimitError
            charge(len(json.dumps(item, **JSON_OPTIONS)))
        elif kind is str:
            string(item)
        elif kind in (dict, list, tuple):
            if forbidden_containers is not None and id(item) in forbidden_containers:
                raise ResourceLimitError
            if id(item) in active or len(item) > RESOURCE_PROFILE["json_container_entries"]:
                raise ResourceLimitError
            active.add(id(item))
            charge(2 + max(0, len(item) - 1))
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ResourceLimitError
                    nodes += 1
                    if nodes > RESOURCE_PROFILE["json_nodes"]:
                        raise ResourceLimitError
                    string(key, key=True)
                    charge(1)
                    walk(child, depth + 1)
            else:
                for child in item:
                    walk(child, depth + 1)
            active.remove(id(item))
        else:
            raise ResourceLimitError

    walk(value)
    return total


def canonical_bytes(value, limit):
    canonical_size(value, limit)
    return json.dumps(value, **JSON_OPTIONS).encode("ascii")


def stage_json(value, limit):
    """No bytes escape until the entire validated document (newline included) fits."""
    expected = canonical_size(value, limit - 1) + 1
    staged = io.BytesIO()
    for chunk in json.JSONEncoder(**JSON_OPTIONS).iterencode(value):
        block = chunk.encode("ascii")
        if staged.tell() + len(block) + 1 > limit:
            raise ResourceLimitError
        staged.write(block)
    staged.write(b"\n")
    if staged.tell() != expected:
        raise ResourceLimitError
    staged.seek(0)
    return staged


# Source proposal only: manager UnitPath never authorizes an additional root.
SYSTEMD_DEFINITION_ROOTS = (
    "/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
    "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached",
    "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
    "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
    "/run/systemd/generator.late",
)
SYSTEMD_DEFINITION_PROFILE = {
    "schema": "AcademySystemdDefinitionProfile.v2", "parser_family": 255,
    "target_selection": "observed_initial_final_units_and_lookup_templates",
    "allowed_roots": list(SYSTEMD_DEFINITION_ROOTS),
    "allowed_linked_files": [],
    "definition_targets": 1024, "manager_roots": 32, "path_bytes": 4096,
    # unit-file.c v255 FOLLOW_MAX is 8, independently of filesystem traversal.
    # https://github.com/systemd/systemd/blob/v255/src/basic/unit-file.c#L140
    "alias_hops": 8, "alias_resolution_attempts": 16777216,
    "candidate_selection_attempts": 1048576, "path_symlink_hops": 32, "map_names": 8192,
    "selected_files_per_definition": 64, "selected_files_total": 1536,
    "body_bytes_per_read": 262144, "body_bytes_total": 33554432,
    "filesystem_work": 262144, "manager_commands": 4, "manager_record_bytes": 1024, "manager_output_bytes": 131072,
    "relation_attempts_per_definition": 1024, "relation_attempts_total": 8192,
    "evidence_bytes": 16777216, "path_records": 4096, "path_record_bytes": 768,
    "source_read_records": 3072, "source_read_record_bytes": 512,
    "relation_record_bytes": 256, "definition_header_bytes": 8192,
}
DEFINITION_UNIT_TYPES = frozenset((
    "service", "socket", "target", "device", "mount", "automount", "swap", "timer", "path", "slice", "scope",
))
DEFINITION_DEPENDENCIES = frozenset((
    "Requires", "Requisite", "Wants", "BindsTo", "BindTo", "Upholds", "Conflicts", "Before", "After",
    "OnSuccess", "OnFailure", "RequiresOverridable", "RequisiteOverridable", "PropagatesReloadTo",
    "PropagateReloadTo", "ReloadPropagatedFrom",
    "PropagateReloadFrom", "PropagatesStopTo", "StopPropagatedFrom", "PartOf", "JoinsNamespaceOf",
))
DEFINITION_EXEC = frozenset((
    "ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost",
))
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
GRAPH_PROPERTIES = ('Id',
 'Names',
 'Triggers',
 'TriggeredBy',
 'Requires',
 'Wants',
 'Before',
 'After',
 'Requisite',
 'BindsTo',
 'PartOf',
 'Upholds',
 'RequiredBy',
 'RequisiteOf',
 'WantedBy',
 'BoundBy',
 'UpheldBy',
 'ConsistsOf',
 'Conflicts',
 'ConflictedBy',
 'OnSuccess',
 'OnSuccessOf',
 'OnFailure',
 'OnFailureOf',
 'PropagatesReloadTo',
 'ReloadPropagatedFrom',
 'PropagatesStopTo',
 'StopPropagatedFrom',
 'JoinsNamespaceOf',
 'SliceOf',
 'Following')
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


class DefinitionRefusedError(ValueError):
    """Fixed diagnostic code only, never an observed path or body."""


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
        self.role = role
        self.host = HOSTS[role]
        self.captured_payload_bytes = 0
        self.resource_stopped = False
        self.resource_stop_reason = None
        self.observation_retention_incomplete = False
        self.normal_evidence_refused = False
        self.ordinary_record_json_bytes = 0
        # Strong references prevent id reuse; values are (domain, record, encoded size).
        self.record_ledger = {}
        self._readlink_adapter = None
        self.deadline = time.monotonic() + MAX_SECONDS
        self.commands = 0
        self.files = 0
        self.definition_files = 0
        self.domains = {}
        self.loaded_units = set()
        self.installed_units = set()
        self.final_installed_units = set()
        self.final_loaded_units = set()
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
        if self.resource_stopped:
            self.gap(domain, self.resource_stop_reason or "captured_payload_limit")
            return True
        if self.pending_signal is not None:
            self.gap(domain, "interrupted_signal")
            return True
        return False

    def domain(self, name):
        if type(name) is not str or not re.fullmatch(r"[a-z_0-9]{1,64}", name):
            self.metadata_refused()
        # Reserve one finalization slot so the collector can always report refusal.
        if name not in self.domains and len(self.domains) >= (32 if name == "collector" else 31):
            self.metadata_refused()
        target = self.domains.setdefault(
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
        if name == "systemd_unit_graph" and "endpoint_profile" not in target:
            target["runtime_relation_catalogue"] = SYSTEMD_RUNTIME_RELATION_CATALOGUE
            target["runtime_relation_catalogue_sha256"] = SYSTEMD_RUNTIME_RELATION_CATALOGUE_SHA256
            target["endpoint_profile"] = dict(SYSTEMD_ENDPOINT_PROFILE)
            target["endpoint_profile_sha256"] = self.endpoint_profile_hash()
            target["endpoint_accounting"] = {
                phase: {"endpoint_count": 0, "retained_endpoint_count": 0,
                        "unparsed_tail": False}
                for phase in ("initial", "repeated", "total")
            }
        return target

    @staticmethod
    def endpoint_profile_hash():
        return digest(json.dumps(SYSTEMD_ENDPOINT_PROFILE, **JSON_OPTIONS).encode("ascii"))

    def gap(self, name, reason, raced=False):
        domain = self.domain(name)
        if type(reason) is not str or not re.fullmatch(r"[a-z_0-9]{1,128}", reason):
            self.metadata_refused()
        if reason not in domain["gaps"]:
            if len(domain["gaps"]) >= 128:
                self.metadata_refused()
            domain["gaps"].append(reason)
        if raced:
            domain["raced"] += 1

    def payload_allowance(self, requested, domain, end=None):
        if self.interrupted(domain):
            raise ResourceLimitError
        if time.monotonic() >= min(self.deadline, end if end is not None else self.deadline):
            self.gap(domain, "file_or_time_limit")
            raise ResourceLimitError
        remaining = RESOURCE_PROFILE["captured_payload_bytes"] - self.captured_payload_bytes
        if remaining <= 0:
            self.resource_stopped = True
            self.resource_stop_reason = self.resource_stop_reason or "captured_payload_limit"
            self.gap(domain, self.resource_stop_reason)
            raise ResourceLimitError
        if requested <= 0:
            raise ResourceLimitError
        return min(requested, remaining)

    def charge_payload(self, size):
        self.captured_payload_bytes += size
        if self.captured_payload_bytes >= RESOURCE_PROFILE["captured_payload_bytes"]:
            self.resource_stopped = True
            self.resource_stop_reason = self.resource_stop_reason or "captured_payload_limit"

    def read_payload(self, fd, requested, domain, *, end=None, reader=None):
        allowance = self.payload_allowance(requested, domain, end)
        block = os.read(fd, allowance) if reader is None else reader(fd, allowance)
        self.charge_payload(len(block))
        if len(block) > allowance:  # Defensive against an invalid injected adapter.
            raise ResourceLimitError
        return block

    def read_link(self, directory, name, domain):
        """Anchored proc exe/cwd only. No unbounded Python readlink fallback."""
        if name not in ("exe", "cwd"):
            raise ResourceLimitError
        return self.read_link_payload(directory, name, domain, RESOURCE_PROFILE["readlink_bytes"])

    def native_readlink_bytes(self, directory, name, request, domain):
        """One sized native call; the caller charges and checks the returned bytes."""
        if self._readlink_adapter is None:
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            adapter = libc.readlinkat
            adapter.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
            adapter.restype = ctypes.c_ssize_t
            self._readlink_adapter = (ctypes, adapter, libc)
        ctypes, adapter, _libc = self._readlink_adapter
        buffer = ctypes.create_string_buffer(request)
        # Loading and allocation precede this final stop/deadline check.
        if self.payload_allowance(request, domain) != request:
            raise ResourceLimitError
        count = adapter(directory, os.fsencode(name), buffer, request)
        if count < 0:
            raise OSError
        if count > request:
            raise ResourceLimitError
        return buffer.raw[:count]

    def read_link_payload(self, directory, name, domain, maximum, *, reader=None,
                          unavailable="userspace_process_link_unavailable"):
        """Sized capture for a validated anchored leaf; no path traversal operand."""
        leaf = os.fsencode(name)
        if not leaf or len(leaf) > 255 or leaf in (b".", b"..") or b"/" in leaf or b"\x00" in leaf:
            raise ResourceLimitError
        request = self.payload_allowance(min(maximum, RESOURCE_PROFILE["readlink_bytes"]), domain)
        try:
            block = (self.native_readlink_bytes(directory, name, request, domain) if reader is None
                     else reader(directory, name, request))
            self.charge_payload(len(block))
            if len(block) >= request:
                raise ResourceLimitError
            return block
        except (ImportError, AttributeError, OSError, TypeError, ResourceLimitError):
            self.gap(domain, unavailable)
            raise ResourceLimitError from None

    def stop_retention(self):
        self.observation_retention_incomplete = True
        self.resource_stopped = True
        self.resource_stop_reason = self.resource_stop_reason or "observation_retention_limit"

    def metadata_refused(self):
        # No domain/gap lookup here: this channel must also work when those are full.
        self.stop_retention()
        self.normal_evidence_refused = True
        raise ResourceLimitError

    def retention_refused(self, domain):
        self.stop_retention()
        self.gap(domain, "observation_retention_limit")
        self.domain(domain)["skipped"] += 1
        return False

    def record(self, domain, entity, facts):
        target = self.domain(domain)
        if len(target["records"]) >= MAX_ROWS:
            self.gap(domain, "row_limit")
            target["skipped"] += 1
            return False
        record = {
            "authority_id": digest((self.host + "\0" + domain + "\0" + entity).encode()),
            "identity": entity if entity in KNOWN else None,
            "identity_sha256": digest(entity.encode()),
            "unknown_identity": entity not in KNOWN,
            "relevance": "unresolved",
            "facts": facts,
        }
        try:
            size = canonical_size(record, RESOURCE_PROFILE["record_json_bytes"],
                                  forbidden_containers=self.record_ledger)
            if (domain != DEFINITION_DOMAIN and self.ordinary_record_json_bytes + size
                    > RESOURCE_PROFILE["ordinary_record_json_bytes"]):
                raise ResourceLimitError
        except ResourceLimitError:
            return self.retention_refused(domain)
        target["records"].append(record)
        self.record_ledger[id(facts)] = (domain, record, size)
        if domain != DEFINITION_DOMAIN:
            self.ordinary_record_json_bytes += size
        target["inspected"] += 1
        target["complete"] += 1
        return True

    def replace_record_facts(self, existing_facts, replacement):
        """Measure the containing record before committing, preserving facts identity."""
        domain, record, previous_size = self.record_ledger[id(existing_facts)]
        candidate = dict(record, facts=replacement)
        try:
            size = canonical_size(candidate, RESOURCE_PROFILE["record_json_bytes"],
                                  forbidden_containers=self.record_ledger)
            delta = size - previous_size
            if (domain != DEFINITION_DOMAIN and self.ordinary_record_json_bytes + delta
                    > RESOURCE_PROFILE["ordinary_record_json_bytes"]):
                raise ResourceLimitError
        except ResourceLimitError:
            return self.retention_refused(domain)
        existing_facts.clear()
        existing_facts.update(replacement)
        self.record_ledger[id(existing_facts)] = (domain, record, size)
        if domain != DEFINITION_DOMAIN:
            self.ordinary_record_json_bytes += delta
        return True

    def run(self, args, domain, *, getter=False):
        manager_request = False
        if getter:
            allowed = {
                (BUS_INTERFACE_PREFIX + interface, field)
                for field, (_signature, interfaces) in TYPED_PROPERTIES.items()
                for interface in interfaces.values()
            } | {(BUS_INTERFACE_PREFIX + "Unit", field) for field in ("Id", "Names")}
            manager_request = (
                domain == DEFINITION_DOMAIN and len(args) == 5
                and args[:4] == ["get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                 "org.freedesktop.systemd1.Manager"]
                and args[4] in ("UnitPath", "Version")
            )
            unit_request = (
                len(args) == 5 and args[:2] == ["get-property", "org.freedesktop.systemd1"]
                and BUS_OBJECT.fullmatch(args[2]) and (args[3], args[4]) in allowed
            )
            if manager_request and self.definition_state()["manager_pending"] != args[4]:
                self.gap(domain, "typed_getter_request_rejected")
                return None
            if not (manager_request or unit_request):
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
        try:
            self.payload_allowance(1, domain)
        except ResourceLimitError:
            return None
        self.commands += 1
        child = None
        output = bytearray()
        okay = True
        try:
            # A child cannot be admitted without capacity to observe its output.
            self.payload_allowance(1, domain)
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
                    block = self.read_payload(
                        child.stdout.fileno(), min(65536, MAX_COMMAND_BYTES + 1 - len(output)), domain, end=end
                    )
                    if not block:
                        break
                    output.extend(block)
                    limit = SYSTEMD_DEFINITION_PROFILE["manager_output_bytes"] if manager_request else MAX_COMMAND_BYTES
                    if len(output) > limit:
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
            # Derived row hashes preserve historical spacing; report framing is canonical.
            for row in rows:
                self.record(
                    domain,
                    row["unit"],
                    {
                        "row_projection": projection(
                            json.dumps(row, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("ascii")
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
                            json.dumps(row, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("ascii")
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

    @staticmethod
    def graph_properties(name):
        return GRAPH_PROPERTIES + (("Unit",) if name.endswith((".timer", ".path")) else ())

    @staticmethod
    def systemctl_unit_array_tokens(value, *, positions=False):
        """Decode only the v255 shell_maybe_quote(unit, 0) image for UNIT.

        bus-print-properties.c prints scalar strings raw and space-joins quoted
        array elements. Within our approved UNIT alphabet, only backslash needs
        quoting: the entire token is double-quoted and each backslash doubled.
        This is one CLI layer, never decoding native unit escapes such as \\x2d.
        Reject other shell syntax, unnecessary quotes, and noncanonical spacing.
        Yield an empty (invalid) token on refusal; never allocate a large token.
        positions=True also reports whether an unparsed tail remains, so callers
        can refuse at a resource boundary without decoding a lookahead endpoint.
        https://github.com/systemd/systemd/blob/v255/src/basic/escape.c#L474
        https://github.com/systemd/systemd/blob/v255/src/basic/escape.h#L11
        """
        cursor = 0
        while cursor < len(value):
            quoted = value[cursor] == 34
            cursor += quoted
            token = bytearray()
            closed = not quoted
            while cursor < len(value):
                char = value[cursor]
                if quoted and char == 34:
                    cursor += 1
                    closed = True
                    break
                if not quoted and char == 32:
                    break
                if len(token) >= 255 or char == 34:
                    yield (b"", cursor < len(value)) if positions else b""
                    return
                if char == 92:
                    if not quoted or value[cursor:cursor + 2] != b"\\\\":
                        yield (b"", cursor < len(value)) if positions else b""
                        return
                    cursor += 1
                token.append(char)
                cursor += 1
            if (not closed or not token or (quoted and 92 not in token)
                    or (cursor < len(value) and value[cursor] != 32)):
                yield (b"", cursor < len(value)) if positions else b""
                return
            yield (bytes(token), cursor < len(value)) if positions else bytes(token)
            if cursor < len(value):
                cursor += 1
                if cursor == len(value):
                    yield (b"", False) if positions else b""

    @staticmethod
    def parse_unit_graph(raw, fields, *, graph_only=False, phase="initial",
                         pass_remaining=None, total_remaining=None, stopped=None):
        """Version 3 endpoint accounting, separate from overall acquisition.

        endpoint_count is exact performed decodes, including invalid/duplicates.
        unparsed_tail means this only lower-bounds potentially required work;
        it never claims the remaining raw bytes contain valid endpoints.
        No endpoint is decoded beyond a cap; byte-position lookahead detects a
        nonempty tail. Invalid fields retain no hashes, even after a valid prefix.
        """
        if phase not in ("initial", "repeated"):
            raise ValueError("unsupported endpoint phase")
        profile = SYSTEMD_ENDPOINT_PROFILE
        pass_cap = profile[phase + "_pass_attempts"]
        pass_remaining = pass_cap if pass_remaining is None else max(0, min(pass_cap, pass_remaining))
        total_cap = profile["total_attempts"]
        total_remaining = total_cap if total_remaining is None else max(0, min(total_cap, total_remaining))
        result = {field: None for field in fields}
        gaps = []
        output = {
            "fields": result, "gaps": gaps, "endpoint_count": 0,
            "retained_endpoint_count": 0, "unparsed_tail": False,
            "endpoint_profile_sha256": Discovery.endpoint_profile_hash(), "phase": phase,
            "runtime_relation_catalogue_sha256": SYSTEMD_RUNTIME_RELATION_CATALOGUE_SHA256,
            "original_output": projection(raw) if raw is not None else None,
        }
        if raw is None:
            gaps.append("observation_unavailable")
            return output
        if len(raw) > MAX_COMMAND_BYTES:
            gaps.append("graph_byte_bound")
            output["unparsed_tail"] = True
            return output
        seen = set()
        if raw.count(b"\n") > MAX_ROWS:
            gaps.append("graph_line_bound")
            output["unparsed_tail"] = True
            return output
        lines = raw.split(b"\n", MAX_ROWS)
        if lines[-1:] == [b""]:
            lines.pop()
        if len(lines) > MAX_ROWS:
            gaps.append("graph_line_bound")
            output["unparsed_tail"] = True
            return output
        for line in lines:
            if stopped is not None and stopped():
                gaps.append("graph_work_interrupted_or_deadline")
                output["unparsed_tail"] = True
                break
            key, equals, value = line.partition(b"=")
            if not equals:
                gaps.append("line_missing_equals")
                continue
            field = key.decode("ascii", errors="replace")
            if field not in result:
                if graph_only:
                    gaps.append("unexpected_graph_key")
                continue
            duplicate = field in seen
            if duplicate:
                gaps.append("duplicate_graph_key")
                item = result[field]
                item["valid"] = False
                item["endpoint_sha256"] = []
                item["retained_endpoint_count"] = 0
            else:
                seen.add(field)
                item = {"projection": projection(value), "endpoint_sha256": [], "valid": False,
                        "endpoint_count": 0, "retained_endpoint_count": 0,
                        "unparsed_tail": False}
                result[field] = item
            valid = not duplicate
            pending = bool(value)
            if field in ("Id", "Unit", "Following"):
                # systemctl scalar strings are raw; one attempted native identity.
                tokens = iter(((value, False),)) if value else iter(())
                if field == "Id" and not value:
                    gaps.append("unsupported_graph_value")
                    valid = False
            else:
                tokens = Discovery.systemctl_unit_array_tokens(value, positions=True)
            while pending:
                if stopped is not None and stopped():
                    gaps.append("graph_work_interrupted_or_deadline")
                    valid = False
                    item["unparsed_tail"] = True
                    break
                used = output["endpoint_count"]
                limits = (
                    (item["endpoint_count"] >= profile["field_attempts"], "field"),
                    (used >= profile["unit_read_attempts"], "unit"),
                    (used >= pass_remaining, phase + "_pass"),
                    (used >= total_remaining, "total"),
                )
                exhausted = ["graph_endpoint_" + dimension + "_budget" for hit, dimension in limits if hit]
                if exhausted:
                    gaps.extend(exhausted)
                    valid = False
                    item["unparsed_tail"] = True
                    break
                token, pending = next(tokens)
                # Charge before validation, including duplicate property occurrences.
                output["endpoint_count"] += 1
                item["endpoint_count"] += 1
                if (not token or len(token) > 255 or not token.isascii()
                        or not UNIT.fullmatch(token.decode("ascii"))):
                    gaps.append("unsupported_graph_value")
                    valid = False
                    item["unparsed_tail"] |= pending
                    break
                if valid:
                    item["endpoint_sha256"].append(digest(token))
            item["valid"] = valid
            if not valid:
                item["endpoint_sha256"] = []
            item["retained_endpoint_count"] = len(item["endpoint_sha256"])
            output["unparsed_tail"] |= item["unparsed_tail"]
        if set(fields) - seen:
            gaps.append("missing_graph_fields")
        output["retained_endpoint_count"] = sum(
            item["retained_endpoint_count"] for item in result.values() if item is not None
        )
        output["gaps"] = sorted(set(gaps))
        return output

    def collect_unit_graph(self, raw, fields, *, graph_only=False):
        domain = self.domain("systemd_unit_graph")
        accounting = domain["endpoint_accounting"]
        phase = "repeated" if graph_only else "initial"
        result = self.parse_unit_graph(
            raw, fields, graph_only=graph_only, phase=phase,
            pass_remaining=SYSTEMD_ENDPOINT_PROFILE[phase + "_pass_attempts"] - accounting[phase]["endpoint_count"],
            total_remaining=SYSTEMD_ENDPOINT_PROFILE["total_attempts"] - accounting["total"]["endpoint_count"],
            stopped=lambda: self.interrupted("systemd_unit_graph") or time.monotonic() >= self.deadline,
        )
        for dimension in (phase, "total"):
            counter = accounting[dimension]
            counter["endpoint_count"] += result["endpoint_count"]
            counter["retained_endpoint_count"] += result["retained_endpoint_count"]
            counter["unparsed_tail"] |= result["unparsed_tail"]
        for reason in result["gaps"]:
            self.gap("systemd_unit_graph", reason)
        return result

    def retain_unit_graph(self, name, installed, loaded, initial):
        """Retain each captured read before any later host operation can fail."""
        facts = {
            "schema": "AcademySystemdUnitGraphFacts.v3",
            "runtime_relation_catalogue_sha256": SYSTEMD_RUNTIME_RELATION_CATALOGUE_SHA256,
            "activation_complete_claimed": False,
            "endpoint_profile_sha256": self.endpoint_profile_hash(),
            "requested_identity_sha256": digest(name.encode()),
            "name_shape": self.unit_name_shape(name),
            "membership_before": {"installed": name in installed, "loaded": name in loaded},
            "membership_after": {"installed": None, "loaded": None},
            "initial": initial,
            "repeated": self.parse_unit_graph(None, self.graph_properties(name), phase="repeated"),
            "graph_fields_unchanged": False,
            "unresolved_endpoint_sha256": None,
            "gaps": ["graph_finalization_unavailable", "enumeration_boundary_unavailable"],
            "classification": "unknown",
            "authority_refs": [],
        }
        if self.record("systemd_unit_graph", name, facts):
            self.domain("systemd_unit_graph")["complete"] -= 1
            return facts
        return None

    def graph_stopped(self):
        return self.interrupted("systemd_unit_graph") or time.monotonic() >= self.deadline

    def finish_unit_graph(self, installed, loaded, observations):
        domain = "systemd_unit_graph"
        target = self.domain(domain)
        final_installed = set()
        final_loaded = set()
        for command, key, diagnostic in (
            ("list-unit-files", "unit_file", "systemd_installed_final"),
            ("list-units", "unit", "systemd_loaded_final"),
        ):
            self.domain(diagnostic)
            if self.graph_stopped():
                self.gap(diagnostic, "graph_work_interrupted_or_deadline")
                continue
            names = self.listing(command, key, diagnostic)
            if key == "unit_file":
                final_installed = names
            else:
                final_loaded = names
        self.final_installed_units = final_installed
        self.final_loaded_units = final_loaded
        installed_ok = self.domain("systemd_installed_final")["enumeration_complete"]
        loaded_ok = self.domain("systemd_loaded_final")["enumeration_complete"]
        initial_ok = all(self.domain(name)["enumeration_complete"] for name in (
            "systemd_installed", "systemd_loaded"
        ))
        target["enumeration_complete"] = initial_ok and installed_ok and loaded_ok
        if not target["enumeration_complete"]:
            self.gap(domain, "enumeration_boundary_unavailable")
        if (installed_ok and installed != final_installed) or (loaded_ok and loaded != final_loaded):
            self.gap(domain, "enumeration_membership_changed", raced=True)
        names = sorted(installed | loaded | final_installed | final_loaded)
        target["enumerated"] = len(names)
        target["skipped"] = max(target["skipped"], len(names) - target["inspected"])
        endpoints = set()
        for name in names:
            if self.graph_stopped():
                self.gap(domain, "graph_work_interrupted_or_deadline")
                self.gap(domain, "graph_finalization_unavailable")
                return
            endpoints.add(digest(name.encode()))
        if len(names) > MAX_ROWS:
            self.gap(domain, "union_units_truncated")
        for name in names:
            if self.graph_stopped():
                self.gap(domain, "graph_work_interrupted_or_deadline")
                self.gap(domain, "graph_finalization_unavailable")
                break
            facts = observations.get(name)
            if facts is None:
                if len(target["records"]) >= MAX_ROWS:
                    continue
                unavailable = self.parse_unit_graph(None, self.graph_properties(name))
                facts = self.retain_unit_graph(name, installed, loaded, unavailable)
                if facts is None:
                    continue
                target["skipped"] -= 1
            initial, repeated = facts["initial"], facts["repeated"]
            gaps = set(initial["gaps"] + repeated["gaps"])
            unchanged = not gaps and initial["fields"] == repeated["fields"]
            if not unchanged:
                gaps.add("graph_fields_changed_or_unavailable")
            after = {
                "installed": name in final_installed if installed_ok else None,
                "loaded": name in final_loaded if loaded_ok else None,
            }
            if facts["membership_before"] != after:
                gaps.add("membership_changed_or_unavailable")
            if not target["enumeration_complete"]:
                gaps.add("enumeration_boundary_unavailable")
            unresolved = set()
            for observation in (initial, repeated):
                for item in observation["fields"].values():
                    if item is None:
                        continue
                    for endpoint in item["endpoint_sha256"]:
                        if self.graph_stopped():
                            self.gap(domain, "graph_work_interrupted_or_deadline")
                            self.gap(domain, "graph_finalization_unavailable")
                            return
                        if endpoint not in endpoints:
                            unresolved.add(endpoint)
            if unresolved:
                gaps.add("unresolved_graph_endpoint")
            replacement = dict(
                facts, membership_after=after, graph_fields_unchanged=unchanged,
                unresolved_endpoint_sha256=sorted(unresolved), gaps=sorted(gaps),
            )
            admitted = self.replace_record_facts(facts, replacement)
            for reason in sorted(gaps):
                self.gap(domain, reason)
            if not gaps and admitted:
                target["complete"] += 1

    def systemd(self):
        installed = self.listing("list-unit-files", "unit_file", "systemd_installed")
        loaded = self.listing("list-units", "unit", "systemd_loaded")
        self.loaded_units = loaded
        self.installed_units = installed
        self.listing("list-timers", "unit", "systemd_timers")
        self.listing("list-jobs", "unit", "systemd_jobs")
        domain = "systemd_unit_properties"
        enumerated = installed | loaded
        graph_observations = {}
        # Independent fixed pass reserves; endpoint acquisition is not full census.
        self.domain("systemd_unit_graph")
        names = sorted(enumerated)
        self.domain(domain)["enumerated"] = len(names)
        self.domain("systemd_unit_graph")["enumerated"] = len(names)
        if len(names) > MAX_ROWS:
            self.gap(domain, "union_units_truncated")
            self.domain(domain)["skipped"] += len(names) - MAX_ROWS
        for index, name in enumerate(names[:MAX_ROWS]):
            if self.interrupted(domain) or time.monotonic() >= self.deadline:
                if self.pending_signal is None:
                    self.gap(domain, "command_or_time_limit")
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
            graph_fields = self.graph_properties(name)
            # Acquire the v3 graph in the same read while preserving the closed
            # historical property-record vocabulary and missing-field accounting.
            requested = applicable + tuple(field for field in graph_fields if field not in applicable)
            raw = self.run(
                ["show", "--all", "--property=" + ",".join(requested), "--", name],
                domain,
            )
            initial_graph = self.collect_unit_graph(raw, graph_fields)
            graph_facts = self.retain_unit_graph(name, installed, loaded, initial_graph)
            if graph_facts is not None:
                graph_observations[name] = graph_facts
            if not self.graph_stopped():
                repeated_raw = self.run(
                    ["show", "--all", "--property=" + ",".join(graph_fields), "--", name],
                    "systemd_unit_graph",
                )
                repeated_graph = self.collect_unit_graph(repeated_raw, graph_fields, graph_only=True)
                if graph_facts is not None:
                    self.replace_record_facts(graph_facts, dict(graph_facts, repeated=repeated_graph))
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
                        if field in graph_fields:
                            # collect_unit_graph retains and validates these fields,
                            # including duplicates and malformed endpoint values.
                            continue
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
        self.finish_unit_graph(installed, loaded, graph_observations)

    @staticmethod
    def definition_profile_hash():
        return digest(json.dumps(SYSTEMD_DEFINITION_PROFILE, sort_keys=True, separators=(",", ":")).encode("ascii"))

    def definition_state(self):
        if not hasattr(self, "_definition"):
            self._definition = {
                "work": 0, "reserved_work": 0, "body_bytes": 0, "reserved_bytes": 0,
                "manager_attempts": 0, "relation_attempts": 0, "encoded_bytes": 0,
                "unparsed_tail": False, "phase": "initial", "directories": {}, "fds": set(),
                "paths": {}, "sources": {}, "selected_paths": set(), "source_keys": {}, "manager": [], "failures": [],
                "null_reference": None, "null_identity": None, "manager_pending": None,
                "active_roots": (), "last_reduction": None, "alias_attempts": 0, "selection_attempts": 0,
                "candidate_scans": {}, "root_snapshots": {},
            }
            domain = self.domain(DEFINITION_DOMAIN)
            domain.update(
                definition_profile=dict(SYSTEMD_DEFINITION_PROFILE),
                definition_profile_sha256=self.definition_profile_hash(),
                manager_observations=[], path_observations=[], source_reads=[], relations=[],
                definition_accounting={
                    "filesystem_work": 0, "alias_resolution_attempts": 0, "candidate_selection_attempts": 0,
                    "body_bytes": 0, "manager_attempts": 0,
                    "relation_attempts": 0, "encoded_bytes": 0, "unparsed_tail": False,
                    "selected_paths": 0, "distinct_bodies": 0, "reserved_second_pass_work": 0,
                    "reserved_second_pass_bytes": 0, "reserved_second_pass_reads": 0,
                },
            )
        return self._definition

    def definition_refuse(self, code):
        state = self.definition_state()
        if code not in state["failures"]:
            state["failures"].append(code)
        if code.endswith("_bound") or code == "definition_interrupted":
            state["unparsed_tail"] = True
        self.gap(DEFINITION_DOMAIN, code, raced=code == "definition_snapshot_changed")
        raise DefinitionRefusedError(code)

    def definition_charge(self, amount=1):
        state = self.definition_state()
        if self.interrupted(DEFINITION_DOMAIN) or time.monotonic() >= self.deadline:
            self.definition_refuse("definition_interrupted")
        if state["work"] + state["reserved_work"] + amount > min(
            SYSTEMD_DEFINITION_PROFILE["filesystem_work"], RESOURCE_PROFILE["definition_filesystem_work"]
        ):
            self.definition_refuse("definition_filesystem_work_bound")
        if (self.files + state["reserved_work"] + amount
                > RESOURCE_PROFILE["cumulative_filesystem_work"]):
            self.definition_refuse("definition_shared_file_bound")
        state["work"] += amount
        self.files += amount
        self.definition_files += amount

    def definition_syscall(self, operation, *args, **kwargs):
        """Fixed filesystem seam for hosted synthetic qualification; no subprocess."""
        if operation == "readlink":
            return self.native_readlink_bytes(kwargs["dir_fd"], args[0], kwargs["maximum"], DEFINITION_DOMAIN)
        operations = {
            "open": os.open, "close": os.close, "stat": os.stat, "fstat": os.fstat,
            "scandir": os.scandir, "read": os.read,
        }
        return operations[operation](*args, **kwargs)

    def definition_io(self, operation, *args, **kwargs):
        self.definition_charge()
        if operation == "read":
            try:
                return self.read_payload(
                    args[0], args[1], DEFINITION_DOMAIN,
                    reader=lambda fd, count: self.definition_syscall("read", fd, count),
                )
            except ResourceLimitError:
                self.definition_refuse("definition_interrupted")
        if operation == "readlink":
            try:
                block = self.read_link_payload(
                    kwargs["dir_fd"], args[0], DEFINITION_DOMAIN,
                    SYSTEMD_DEFINITION_PROFILE["path_bytes"] + RESOURCE_PROFILE["overflow_probe_bytes"],
                    reader=lambda fd, name, count: self.definition_syscall("readlink", name, dir_fd=fd, maximum=count),
                    unavailable="definition_link_value_unsupported",
                )
            except ResourceLimitError:
                self.definition_refuse(
                    "definition_interrupted" if self.resource_stopped else "definition_link_value_unsupported"
                )
            return os.fsdecode(block)
        return self.definition_syscall(operation, *args, **kwargs)

    def definition_open(self, path, flags, **kwargs):
        state = self.definition_state()
        # Reserve the close before opening, including during a partial failure.
        self.definition_charge(2)
        state["work"] -= 1
        self.files -= 1
        self.definition_files -= 1
        state["reserved_work"] += 1
        try:
            fd = self.definition_syscall("open", path, flags, **kwargs)
        except OSError:
            state["reserved_work"] -= 1
            raise
        state["fds"].add(fd)
        return fd

    def definition_close(self, fd):
        state = self.definition_state()
        if fd not in state["fds"]:
            return
        state["fds"].remove(fd)
        state["reserved_work"] -= 1
        state["work"] += 1
        self.files += 1
        self.definition_files += 1
        try:
            self.definition_syscall("close", fd)
        except OSError:
            self.gap(DEFINITION_DOMAIN, "definition_close_failed")
            if "definition_close_failed" not in state["failures"]:
                state["failures"].append("definition_close_failed")

    def definition_append(self, table, record, cap, byte_cap):
        state = self.definition_state()
        if self.interrupted(DEFINITION_DOMAIN) or time.monotonic() >= self.deadline:
            self.definition_refuse("definition_interrupted")
        target = self.domain(DEFINITION_DOMAIN)[table]
        if len(target) >= cap:
            self.definition_refuse("definition_" + table + "_bound")
        encoded = len(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        # Leave one MiB for domain framing, bounded diagnostics, profile, and indices.
        if encoded > byte_cap:
            self.definition_refuse("definition_" + table + "_record_bound")
        if state["encoded_bytes"] + encoded + 1 > SYSTEMD_DEFINITION_PROFILE["evidence_bytes"] - 1048576:
            self.definition_refuse("definition_evidence_bound")
        index = len(target)
        target.append(record)
        state["encoded_bytes"] += encoded + 1
        return index

    @staticmethod
    def definition_unit_parts(name):
        # unit-name.c v255 permits additional @ in the instance, never the prefix.
        if not isinstance(name, str) or not name.isascii() or not UNIT.fullmatch(name):
            return None
        stem, dot, suffix = name.rpartition(".")
        if not dot or not stem or suffix not in DEFINITION_UNIT_TYPES or stem.startswith("@"):
            return None
        prefix, at, instance = stem.partition("@")
        return prefix, instance if at else None, suffix

    @staticmethod
    def definition_typed_strings(raw, signature):
        """busctl typed as/s subset: exact count, double quotes, no escapes."""
        if raw is None or len(raw) > SYSTEMD_DEFINITION_PROFILE["manager_output_bytes"] or not raw.endswith(b"\n"):
            return None
        if not raw.isascii() or b"\\" in raw or b"\r" in raw or b"\x00" in raw:
            return None
        data = raw[:-1]
        if signature == "s":
            if not data.startswith(b's "') or not data.endswith(b'"') or b'"' in data[3:-1]:
                return None
            return [data[3:-1].decode("ascii")]
        if not data.startswith(b"as "):
            return None
        count_raw, space, rest = data[3:].partition(b" ")
        if not count_raw.isdigit() or len(count_raw) > 2 or str(int(count_raw)).encode() != count_raw:
            return None
        count = int(count_raw)
        if count > SYSTEMD_DEFINITION_PROFILE["manager_roots"]:
            return None
        if count == 0:
            return [] if not space else None
        values = []
        cursor = 0
        while cursor < len(rest) and len(values) < count:
            if rest[cursor:cursor + 1] != b'"':
                return None
            end = rest.find(b'"', cursor + 1)
            if end < 0 or end - cursor - 1 > SYSTEMD_DEFINITION_PROFILE["path_bytes"]:
                return None
            values.append(rest[cursor + 1:end].decode("ascii"))
            cursor = end + 1
            if cursor < len(rest):
                if rest[cursor:cursor + 1] != b" ":
                    return None
                cursor += 1
                if cursor == len(rest):
                    return None
        return values if cursor == len(rest) and len(values) == count else None

    def manager_unitpath_snapshot(self, phase):
        state = self.definition_state()
        values = {}
        references = []
        for field, signature in (("UnitPath", "as"), ("Version", "s")):
            if state["manager_attempts"] >= SYSTEMD_DEFINITION_PROFILE["manager_commands"]:
                self.definition_refuse("definition_manager_command_bound")
            state["manager_attempts"] += 1
            state["manager_pending"] = field
            try:
                raw = self.run([
                    "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                    "org.freedesktop.systemd1.Manager", field,
                ], DEFINITION_DOMAIN, getter=True)
            finally:
                state["manager_pending"] = None
            parsed = self.definition_typed_strings(raw, signature)
            record = {"phase": phase, "property": field, "output": projection(raw) if raw is not None else None,
                      "typed_value_valid": parsed is not None,
                      "value_count": len(parsed) if parsed is not None else None}
            references.append(self.definition_append("manager_observations", record,
                                                      SYSTEMD_DEFINITION_PROFILE["manager_commands"],
                                                      SYSTEMD_DEFINITION_PROFILE["manager_record_bytes"]))
            values[field] = parsed
        roots, version = values["UnitPath"], values["Version"]
        if roots is None or version is None:
            self.definition_refuse("definition_manager_value_unsupported")
        if not roots or len(roots) != len(set(roots)):
            self.definition_refuse("definition_unitpath_unsupported")
        if any(root not in SYSTEMD_DEFINITION_ROOTS for root in roots):
            self.definition_refuse("unitpath_root_outside_profile")
        # Distribution suffixes remain opaque, but cannot silently select another parser family.
        if not re.fullmatch(r"255(?:[. -][A-Za-z0-9_.+~:() -]{1,250})?", version[0]):
            self.definition_refuse("definition_parser_version_unsupported")
        return {"roots": roots, "version": version[0], "references": references}

    @staticmethod
    def definition_allowed_path(path, *, dev_null=False):
        if not isinstance(path, str) or not path.isascii() or "\x00" in path or not path.startswith("/"):
            return False
        if len(path.encode("ascii")) > SYSTEMD_DEFINITION_PROFILE["path_bytes"] or os.path.normpath(path) != path:
            return False
        return (dev_null and path == "/dev") or any(
            path == root or path.startswith(root + "/") for root in SYSTEMD_DEFINITION_ROOTS
        )

    def definition_link(self, parent, name, expected):
        """The only definition readlink site; bounded, bracketed opaque link bytes."""
        if expected.st_size > SYSTEMD_DEFINITION_PROFILE["path_bytes"]:
            self.definition_refuse("definition_path_bytes_bound")
        target = self.definition_io("readlink", name, dir_fd=parent)
        if not isinstance(target, str) or not target.isascii() or len(target.encode()) > 4096 or "\x00" in target:
            self.definition_refuse("definition_link_value_unsupported")
        after = self.definition_io("stat", name, dir_fd=parent, follow_symlinks=False)
        if self.file_identity(expected) != self.file_identity(after):
            self.definition_refuse("definition_snapshot_changed")
        return target

    def definition_lookup_target_allowed(self, path):
        return self.definition_allowed_path(path) and (
            any(path.startswith(root + "/") for root in self.definition_state()["active_roots"])
            or path in SYSTEMD_DEFINITION_PROFILE["allowed_linked_files"]
        )

    def definition_path_record(self, path, kind, identity=None, target=None, **extra):
        state = self.definition_state()
        record = {
            "phase": state["phase"], "path_sha256": digest(os.fsencode(path)), "kind": kind,
            "metadata_sha256": digest(json.dumps(identity).encode()) if identity is not None else None,
            "target_sha256": digest(os.fsencode(target)) if target is not None else None, **extra,
        }
        return self.definition_append("path_observations", record,
                                      SYSTEMD_DEFINITION_PROFILE["path_records"],
                                      SYSTEMD_DEFINITION_PROFILE["path_record_bytes"])

    def definition_check_chain(self, chain):
        for node in chain:
            before = self.definition_io("fstat", node["fd"])
            if self.file_identity(before) != node["identity"]:
                self.definition_refuse("definition_snapshot_changed")
            if node["parent"] is not None:
                named = self.definition_io("stat", node["name"], dir_fd=node["parent"], follow_symlinks=False)
                if self.file_identity(named) != node["named_identity"]:
                    self.definition_refuse("definition_snapshot_changed")

    def definition_directory(self, path, *, dev_null=False):
        """Anchored component walker with checked links and prepaid descriptor closes."""
        state = self.definition_state()
        if not self.definition_allowed_path(path, dev_null=dev_null):
            self.definition_refuse("definition_link_outside_profile")
        cache = state["directories"]
        if "/" not in cache:
            fd = self.definition_open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            meta = self.definition_io("fstat", fd)
            if meta.st_uid != 0 or meta.st_mode & 0o022:
                self.definition_refuse("definition_unsafe_metadata")
            cache["/"] = {"fd": fd, "parent": None, "name": "", "identity": self.file_identity(meta),
                          "named_identity": self.file_identity(meta), "chain": [], "resolved": "/"}
        current = cache["/"]
        components = path.strip("/").split("/")
        chain = [current]
        hops = 0
        while components:
            component, components = components[0], components[1:]
            candidate = os.path.join(current["resolved"], component)
            try:
                meta = self.definition_io("stat", component, dir_fd=current["fd"], follow_symlinks=False)
            except FileNotFoundError:
                parent_identity = self.definition_io("fstat", current["fd"])
                try:
                    self.definition_io("stat", component, dir_fd=current["fd"], follow_symlinks=False)
                except FileNotFoundError:
                    self.definition_check_chain(chain)
                    if self.file_identity(parent_identity) != self.file_identity(
                        self.definition_io("fstat", current["fd"])
                    ):
                        self.definition_refuse("definition_snapshot_changed")
                    self.definition_path_record(path, "absent")
                    return None
                self.definition_refuse("definition_snapshot_changed")
            if meta.st_uid != 0 or (not stat.S_ISLNK(meta.st_mode) and meta.st_mode & 0o022):
                self.definition_refuse("definition_unsafe_metadata")
            if stat.S_ISLNK(meta.st_mode):
                hops += 1
                if hops > SYSTEMD_DEFINITION_PROFILE["path_symlink_hops"]:
                    self.definition_refuse("definition_path_hops_bound")
                target = self.definition_link(current["fd"], component, meta)
                final = os.path.normpath(os.path.join(current["resolved"], target, *components))
                if not self.definition_allowed_path(final, dev_null=dev_null):
                    self.definition_refuse("definition_link_outside_profile")
                self.definition_path_record(candidate, "component_symlink", self.file_identity(meta), target)
                # Retain the link's named identity while following its approved destination.
                chain.append({"fd": current["fd"], "parent": current["fd"], "name": component,
                              "identity": current["identity"], "named_identity": self.file_identity(meta)})
                components = final.strip("/").split("/")
                current = cache["/"]
                continue
            if not stat.S_ISDIR(meta.st_mode):
                self.definition_refuse("definition_non_directory")
            if candidate not in cache:
                fd = self.definition_open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current["fd"])
                opened = self.definition_io("fstat", fd)
                if self.file_identity(meta) != self.file_identity(opened):
                    self.definition_refuse("definition_snapshot_changed")
                cache[candidate] = {
                    "fd": fd, "parent": current["fd"], "name": component,
                    "identity": self.file_identity(opened), "named_identity": self.file_identity(meta),
                    "resolved": candidate,
                }
            current = cache[candidate]
            chain.append(current)
        self.definition_check_chain(chain)
        return {"fd": current["fd"], "chain": chain, "resolved": current["resolved"]}

    def definition_scan(self, path, scope="root"):
        directory = self.definition_directory(path)
        if directory is None:
            return {"path": path, "resolved": path, "entries": {}, "absent": True, "identity": None, "custody": []}
        fd = directory["fd"]
        before = self.definition_io("fstat", fd)
        entries = {}
        # scandir and close are prepaid. Charge before EVERY iterator advance,
        # including EOF/failed advances; no zero-allowance directory fetch occurs.
        self.definition_charge(2)
        with self.definition_syscall("scandir", fd) as iterator:
            while True:
                self.definition_charge()
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                name = entry.name
                if len(entries) >= SYSTEMD_DEFINITION_PROFILE["map_names"]:
                    self.definition_refuse("definition_directory_entries_bound")
                relevant = self.definition_unit_parts(name) is not None
                if scope == "root":
                    relevant |= any(
                        name.endswith(suffix) and (
                            self.definition_unit_parts(name[:-len(suffix)]) is not None
                            or name[:-len(suffix)] in DEFINITION_UNIT_TYPES
                        ) for suffix in (".d", ".wants", ".requires", ".upholds")
                    )
                elif scope == "dropin":
                    relevant = name.endswith(".conf")
                if not relevant:
                    entries[name] = {"ignored": True}
                    continue
                meta = self.definition_io("stat", name, dir_fd=fd, follow_symlinks=False)
                target = self.definition_link(fd, name, meta) if stat.S_ISLNK(meta.st_mode) else None
                entries[name] = {"identity": self.file_identity(meta), "target": target,
                                 "mode": meta.st_mode, "size": meta.st_size, "uid": meta.st_uid}
        self.definition_check_chain(directory["chain"])
        if self.file_identity(before) != self.file_identity(self.definition_io("fstat", fd)):
            self.definition_refuse("definition_snapshot_changed")
        packed = [(name, entries[name]) for name in sorted(entries)]
        reference = self.definition_path_record(
            path, "directory", self.file_identity(before),
            entries_sha256=digest(json.dumps(packed, sort_keys=True, ensure_ascii=True).encode()), entries=len(entries),
        )
        custody = [(node["name"], node["identity"], node["named_identity"]) for node in directory["chain"]]
        return {**directory, "path": path, "entries": entries, "absent": False, "reference": reference,
                "identity": self.file_identity(before), "custody": custody}

    def snapshot_unit_roots(self, roots):
        snapshots = [self.definition_scan(root) for root in roots]
        self.definition_state()["root_snapshots"] = {item["path"]: item for item in snapshots}
        return snapshots

    def definition_candidate_scan(self, root, candidate, scope):
        """Only a fully captured current-pass root proves an immediate absence."""
        self.definition_selection_step()
        state = self.definition_state()
        path = root + "/" + candidate
        key = (path, scope)
        if key in state["candidate_scans"]:
            return state["candidate_scans"][key]
        snapshot = state["root_snapshots"].get(root)
        if snapshot is not None and not snapshot["absent"] and candidate not in snapshot["entries"]:
            # The root observation is the negative observation's evidence. Do not
            # create a path record or walk an absent child for each target.
            result = {"path": path, "resolved": snapshot["resolved"] + "/" + candidate,
                      "entries": {}, "absent": True, "identity": snapshot["identity"],
                      "custody": snapshot["custody"], "reference": snapshot["reference"]}
            return result
        result = self.definition_scan(path, scope)
        state["candidate_scans"][key] = result
        return result

    def definition_selection_step(self):
        """Charge root setup, candidate visits (even duplicates), and scan entry.

        Each charge checks stop/deadline before construction or a cache fast path.
        This CPU budget is independent of definition filesystem work.
        """
        state = self.definition_state()
        if self.interrupted(DEFINITION_DOMAIN) or time.monotonic() >= self.deadline:
            self.definition_refuse("definition_interrupted")
        if state["selection_attempts"] >= SYSTEMD_DEFINITION_PROFILE["candidate_selection_attempts"]:
            self.definition_refuse("definition_candidate_selection_bound")
        state["selection_attempts"] += 1

    def definition_alias_step(self):
        """Bound CPU work independently of filesystem work, including misses."""
        state = self.definition_state()
        if self.interrupted(DEFINITION_DOMAIN) or time.monotonic() >= self.deadline:
            self.definition_refuse("definition_interrupted")
        if state["alias_attempts"] >= SYSTEMD_DEFINITION_PROFILE["alias_resolution_attempts"]:
            self.definition_refuse("definition_alias_resolution_bound")
        state["alias_attempts"] += 1

    def definition_verify_null(self):
        state = self.definition_state()
        if state["null_reference"] is not None:
            return state["null_reference"]
        directory = self.definition_directory("/dev", dev_null=True)
        if directory is None:
            self.definition_refuse("definition_mask_unverified")
        before = self.definition_io("stat", "null", dir_fd=directory["fd"], follow_symlinks=False)
        after = self.definition_io("stat", "null", dir_fd=directory["fd"], follow_symlinks=False)
        self.definition_check_chain(directory["chain"])
        if (not stat.S_ISCHR(before.st_mode) or before.st_uid != 0 or before.st_rdev != os.makedev(1, 3)
                or self.file_identity(before) != self.file_identity(after) or before.st_rdev != after.st_rdev):
            self.definition_refuse("definition_mask_unverified")
        identity = self.file_identity(before)
        if state["null_identity"] is not None and state["null_identity"] != identity:
            self.definition_refuse("definition_snapshot_changed")
        state["null_identity"] = identity
        state["null_reference"] = self.definition_path_record(
            "/dev/null", "verified_null_mask", self.file_identity(before)
        )
        return state["null_reference"]

    @staticmethod
    def definition_alias_compatible(source, target):
        left = Discovery.definition_unit_parts(source)
        right = Discovery.definition_unit_parts(target)
        if left is None or right is None or source == target or left[2] != right[2]:
            return False
        if left[2] not in ("service", "socket", "target", "device", "timer", "path"):
            return False
        if left[1] is not None and left[2] == "device":
            return False
        if (left[1] is None) != (right[1] is None):
            return False
        if left[1] == "" and right[1] != "":
            return False
        return right[1] in (left[1], "")

    def build_unit_name_map(self, snapshots):
        """v255 ordered first mapping, then reverse aliases; never read bodies."""
        mapping = {}
        expanded = {item["path"] for item in snapshots} | {item["resolved"] for item in snapshots}
        for root in snapshots:
            self.definition_alias_step()
            for name, metadata in sorted(root["entries"].items()):
                self.definition_alias_step()
                if self.definition_unit_parts(name) is None or "identity" not in metadata or name in mapping:
                    continue
                if len(mapping) >= SYSTEMD_DEFINITION_PROFILE["map_names"]:
                    self.definition_refuse("definition_map_names_bound")
                path = os.path.join(root["path"], name)
                mode = metadata["mode"]
                if stat.S_ISDIR(mode):
                    continue
                if metadata["uid"] != 0 or (not stat.S_ISLNK(mode) and mode & 0o022):
                    self.definition_refuse("definition_unsafe_metadata")
                item = {"path": path, "metadata": metadata, "destination": None, "kind": "regular"}
                if stat.S_ISREG(mode):
                    item["kind"] = "empty_mask" if metadata["size"] == 0 else "regular"
                elif stat.S_ISLNK(mode):
                    destination = os.path.normpath(os.path.join(root["resolved"], metadata["target"]))
                    if destination == "/dev/null":
                        item["kind"] = "null_mask"
                        self.definition_verify_null()
                    elif any(destination.startswith(lookup + "/") for lookup in expanded):
                        # chase(... CHASE_NOFOLLOW|CHASE_NONEXISTENT) resolves
                        # intermediate components, never the alias's final name.
                        parent = self.definition_directory(os.path.dirname(destination))
                        if parent is not None:
                            destination = os.path.join(parent["resolved"], os.path.basename(destination))
                        if not any(destination.startswith(lookup + "/") for lookup in expanded):
                            item["kind"], item["destination_path"] = "linked_unit", destination
                            mapping[name] = item
                            continue
                        target = os.path.basename(destination)
                        if not self.definition_alias_compatible(name, target):
                            self.definition_path_record(path, "ignored_incompatible_alias", metadata["identity"],
                                                        metadata["target"])
                            continue
                        item["kind"], item["destination"] = "alias", target
                    else:
                        item["kind"], item["destination_path"] = "linked_unit", destination
                else:
                    continue
                mapping[name] = item
        return mapping

    def resolve_template_fragment(self, name, mapping):
        parts = self.definition_unit_parts(name)
        if parts is None:
            self.definition_refuse("definition_unit_name_unsupported")

        def resolve(start):
            self.definition_alias_step()
            current = start
            seen = set()
            for _ in range(SYSTEMD_DEFINITION_PROFILE["alias_hops"]):
                self.definition_alias_step()
                if current in seen:
                    return None, current, "definition_alias_cycle"
                seen.add(current)
                item = mapping.get(current)
                if item is None:
                    info = self.definition_unit_parts(current)
                    if current != start and info is not None and info[1] not in (None, ""):
                        current = info[0] + "@." + info[2]
                        item = mapping.get(current)
                    if item is None:
                        failure = "definition_fragment_absent" if current == start else "definition_alias_dangling"
                        return None, current, failure
                if item["kind"] == "alias":
                    current = item["destination"]
                    continue
                if item["kind"] == "linked_unit" and (
                    item["destination_path"] not in SYSTEMD_DEFINITION_PROFILE["allowed_linked_files"]
                ):
                    return item, current, "definition_linked_unit_unprofiled"
                return item, current, None
            return None, current, "definition_alias_hops_bound"

        item, canonical, failure = resolve(name)
        if failure in ("definition_fragment_absent", "definition_alias_dangling") and parts[1] not in (None, ""):
            item, canonical, failure = resolve(parts[0] + "@." + parts[2])
        aliases = set()
        if item is not None and failure is None and item["kind"] not in ("empty_mask", "null_mask"):
            canonical_parts = self.definition_unit_parts(canonical)
            if parts[1] not in (None, "") and canonical_parts[1] == "":
                canonical = canonical_parts[0] + "@" + parts[1] + "." + parts[2]
            # add_names(unit-file.c): template aliases inherit an established instance;
            # an existing instance fragment pointing elsewhere excludes that alias.
            for alias in mapping:
                self.definition_alias_step()
                resolved, _destination, error = resolve(alias)
                if resolved is None or error is not None or resolved["path"] != item["path"]:
                    continue
                alias_parts = self.definition_unit_parts(alias)
                if parts[1] not in (None, "") and alias_parts[1] == "":
                    inherited = alias_parts[0] + "@" + parts[1] + "." + alias_parts[2]
                    explicit, _destination, _error = resolve(inherited)
                    if explicit is not None and explicit["path"] != item["path"]:
                        continue
                    aliases.add(inherited)
                elif (parts[1] is None) == (alias_parts[1] is None) and (
                    parts[1] in (None, "") or alias_parts[1] == parts[1]
                ):
                    aliases.add(alias)
            aliases.add(name)
        return {"requested": name, "canonical": canonical, "fragment": item, "failure": failure,
                "aliases": aliases - {canonical}}

    @staticmethod
    def definition_candidate_dirs(name):
        """Port v255 unit_file_find_dirs recursion, not a specificity score."""
        if name in DEFINITION_UNIT_TYPES:
            return [name]
        parts = Discovery.definition_unit_parts(name)
        if parts is None:
            return []
        prefix, instance, suffix = parts
        result = [name]
        if instance not in (None, ""):
            result.extend(Discovery.definition_candidate_dirs(prefix + "@." + suffix))
        chopped = False
        while "-" in prefix:
            dash = prefix.rfind("-")
            if dash == 0:
                break
            if dash + 1 < len(prefix) or chopped:
                prefix = prefix[:dash + 1]
                built = prefix + ("@" + instance if instance not in (None, "") else "") + "." + suffix
                result.extend(Discovery.definition_candidate_dirs(built))
                break
            prefix = prefix[:dash]
            chopped = True
        return list(dict.fromkeys(result))

    def select_definition_sources(self, resolution, roots):
        fragment = resolution["fragment"]
        selected = []
        consulted = []
        dependencies = []
        if fragment is not None and resolution["failure"] is None:
            selected.append({"path": fragment["path"], "kind": "fragment", "metadata": fragment["metadata"],
                             "mask": fragment["kind"] in ("empty_mask", "null_mask")})
        if resolution["failure"] is not None or fragment is None or fragment["kind"] in ("empty_mask", "null_mask"):
            return {"selected": selected, "consulted": consulted, "dependencies": dependencies, "ambiguities": []}
        groups = [(resolution["canonical"], "canonical")]
        groups.extend((alias, "alias") for alias in sorted(resolution["aliases"]))
        groups.append((resolution["canonical"].rpartition(".")[2], "type"))
        ambiguities = set()
        for directory_suffix, file_suffix, directive in (
            (".d", ".conf", None), (".wants", None, "Wants"),
            (".requires", None, "Requires"), (".upholds", None, "Upholds"),
        ):
            winners = {}
            visited = set()
            ambiguous_winners = set()
            for unit, group in groups:
                for root in roots:
                    self.definition_selection_step()
                    for candidate in self.definition_candidate_dirs(unit):
                        self.definition_selection_step()
                        path = root + "/" + candidate + directory_suffix
                        if path in visited:
                            continue
                        visited.add(path)
                        snapshot = self.definition_candidate_scan(
                            root, candidate + directory_suffix, "dropin" if directive is None else "dependency"
                        )
                        consulted.append(snapshot)
                        for filename, metadata in sorted(snapshot["entries"].items()):
                            if "identity" not in metadata or (file_suffix and not filename.endswith(file_suffix)):
                                continue
                            if not file_suffix and self.definition_unit_parts(filename) is None:
                                continue
                            entry = {
                                "path": path + "/" + filename, "kind": "dropin" if directive is None else "dependency",
                                "metadata": metadata, "group": group, "unit": unit, "directive": directive,
                            }
                            previous = winners.get(filename)
                            if previous is None:
                                winners[filename] = entry
                            elif previous["group"] == group == "alias" and previous["unit"] != unit:
                                ambiguous_winners.add(filename)
            for filename in sorted(winners):
                winner = winners[filename]
                if filename in ambiguous_winners:
                    ambiguities.add(directory_suffix + "/" + filename)
                    continue
                if winner["kind"] == "dependency":
                    dependencies.append(winner)
                else:
                    selected.append(winner)
        if len(selected) > SYSTEMD_DEFINITION_PROFILE["selected_files_per_definition"]:
            self.definition_refuse("definition_selected_per_target_bound")
        return {"selected": selected, "consulted": consulted, "dependencies": dependencies,
                "ambiguities": [digest(os.fsencode(value)) for value in sorted(ambiguities)]}

    def definition_source_object(self, selected):
        path = selected["path"]
        expected = selected["metadata"]["identity"]
        chain = []
        for hop in range(SYSTEMD_DEFINITION_PROFILE["path_symlink_hops"] + 1):
            if path == "/dev/null":
                reference = self.definition_verify_null()
                self.definition_check_chain(chain)
                return {"path": path, "mask": True, "reference": reference, "chain": chain}
            if not self.definition_lookup_target_allowed(path):
                self.definition_refuse("definition_linked_target_unprofiled")
            parent_path, name = os.path.split(path)
            parent = self.definition_directory(parent_path)
            if parent is None:
                self.definition_refuse("definition_selected_source_missing")
            meta = self.definition_io("stat", name, dir_fd=parent["fd"], follow_symlinks=False)
            if hop == 0 and self.file_identity(meta) != expected:
                self.definition_refuse("definition_snapshot_changed")
            chain.extend(parent["chain"])
            if meta.st_uid != 0 or (not stat.S_ISLNK(meta.st_mode) and meta.st_mode & 0o022):
                self.definition_refuse("definition_unsafe_metadata")
            if stat.S_ISLNK(meta.st_mode):
                if hop >= SYSTEMD_DEFINITION_PROFILE["path_symlink_hops"]:
                    self.definition_refuse("definition_path_hops_bound")
                target = self.definition_link(parent["fd"], name, meta)
                self.definition_path_record(path, "selected_symlink", self.file_identity(meta), target)
                chain.append({"fd": parent["fd"], "parent": parent["fd"], "name": name,
                              "identity": self.file_identity(self.definition_io("fstat", parent["fd"])),
                              "named_identity": self.file_identity(meta)})
                path = os.path.normpath(os.path.join(parent["resolved"], target))
                continue
            if not stat.S_ISREG(meta.st_mode):
                self.definition_refuse("definition_selected_nonregular")
            reference = self.definition_path_record(path, "selected_regular", self.file_identity(meta))
            return {"path": os.path.join(parent["resolved"], name), "parent": parent["fd"], "name": name,
                    "metadata": meta, "chain": chain, "reference": reference, "mask": meta.st_size == 0}
        self.definition_refuse("definition_path_hops_bound")

    def read_definition_source(self, selected):
        """Only definition-body read site; selected, bounded, anchored and bracketed."""
        state = self.definition_state()
        phase = state["phase"]
        if selected["path"] not in state["selected_paths"]:
            if phase != "initial":
                self.definition_refuse("definition_selected_sources_changed")
            if len(state["selected_paths"]) >= SYSTEMD_DEFINITION_PROFILE["selected_files_total"]:
                self.definition_refuse("definition_selected_total_bound")
            state["selected_paths"].add(selected["path"])
        if phase == "repeated":
            reserved_key = state["source_keys"].get(selected["path"])
            if reserved_key is not None:
                reserved = state["sources"][reserved_key]
                state["reserved_work"] -= reserved["reserved_work"]
                state["reserved_bytes"] -= reserved["reserved_bytes"]
                reserved["reserved_work"] = reserved["reserved_bytes"] = 0
        source = self.definition_source_object(selected)
        if source["path"] == "/dev/null":
            return {"path_reference": source["reference"], "source_key": None, "mask": True}
        key = source["path"]
        state["source_keys"][selected["path"]] = key
        cache = state["sources"].get(key)
        expected = self.file_identity(source["metadata"])
        if cache is not None and cache["identity"] != expected:
            self.definition_refuse("definition_snapshot_changed")
        if cache is None:
            if phase != "initial":
                self.definition_refuse("definition_selected_sources_changed")
            if len(state["sources"]) >= SYSTEMD_DEFINITION_PROFILE["selected_files_total"]:
                self.definition_refuse("definition_selected_total_bound")
            size = source["metadata"].st_size
            if size < 0 or size > SYSTEMD_DEFINITION_PROFILE["body_bytes_per_read"]:
                self.definition_refuse("definition_body_read_bound")
            # Include the second selected-path traversal, chain brackets, read
            # syscalls and descriptor closes; all roots are separately rechecked.
            cost = 16 + (size + 65535) // 65536 + 10 * len(source["chain"])
            body_cap = SYSTEMD_DEFINITION_PROFILE["body_bytes_total"]
            if state["body_bytes"] + state["reserved_bytes"] + 2 * size > body_cap:
                self.definition_refuse("definition_body_total_bound")
            if state["work"] + state["reserved_work"] + 2 * cost > SYSTEMD_DEFINITION_PROFILE["filesystem_work"]:
                self.definition_refuse("definition_second_pass_reservation_bound")
            if (self.files + state["reserved_work"] + 2 * cost
                    > RESOURCE_PROFILE["cumulative_filesystem_work"]):
                self.definition_refuse("definition_shared_file_bound")
            state["reserved_bytes"] += size
            state["reserved_work"] += cost
            cache = {"identity": expected, "size": size, "reserved_work": cost, "reserved_bytes": size,
                     "reads": {"initial": None, "repeated": None}, "body": None}
            state["sources"][key] = cache
        if cache["reads"][phase] is not None:
            return {"path_reference": source["reference"], "source_key": key, "mask": source["mask"]}
        self.definition_check_chain(source["chain"])
        fd = None
        try:
            fd = self.definition_open(source["name"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                      dir_fd=source["parent"])
            before = self.definition_io("fstat", fd)
            named_before = self.definition_io("stat", source["name"], dir_fd=source["parent"], follow_symlinks=False)
            if self.file_identity(before) != expected or self.file_identity(named_before) != expected:
                self.definition_refuse("definition_snapshot_changed")
            if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022:
                self.definition_refuse("definition_unsafe_metadata")
            body = bytearray()
            # Read exactly the bracketed size, never cap+1 bytes. The paired size,
            # timestamps, named identities and second body hash detect changes.
            while len(body) < cache["size"]:
                amount = min(65536, cache["size"] - len(body))
                body_cap = SYSTEMD_DEFINITION_PROFILE["body_bytes_total"]
                if state["body_bytes"] + state["reserved_bytes"] + amount > body_cap:
                    self.definition_refuse("definition_body_total_bound")
                block = self.definition_io("read", fd, amount)
                state["body_bytes"] += len(block)
                if not block:
                    self.definition_refuse("definition_snapshot_changed")
                body.extend(block)
            after = self.definition_io("fstat", fd)
            named_after = self.definition_io("stat", source["name"], dir_fd=source["parent"], follow_symlinks=False)
            self.definition_check_chain(source["chain"])
            if self.file_identity(after) != expected or self.file_identity(named_after) != expected:
                self.definition_refuse("definition_snapshot_changed")
            record = {
                "phase": phase, "path_reference": source["reference"], "body_sha256": digest(body), "bytes": len(body),
                "before_sha256": digest(json.dumps(expected).encode()),
                "after_sha256": digest(json.dumps(self.file_identity(after)).encode()), "mask": source["mask"],
            }
            cache["reads"][phase] = self.definition_append("source_reads", record,
                                                             SYSTEMD_DEFINITION_PROFILE["source_read_records"],
                                                             SYSTEMD_DEFINITION_PROFILE["source_read_record_bytes"])
            if phase == "initial":
                cache["body"] = bytes(body)
            elif digest(body) != digest(cache["body"]):
                self.definition_refuse("definition_snapshot_changed")
        finally:
            if fd is not None:
                self.definition_close(fd)
        return {"path_reference": source["reference"], "source_key": key, "mask": source["mask"]}

    @staticmethod
    def definition_snapshot_projection(snapshot):
        return {"path": snapshot["path"], "resolved": snapshot["resolved"], "entries": snapshot["entries"],
                "absent": snapshot["absent"], "identity": snapshot["identity"], "custody": snapshot["custody"]}

    def definition_dependency_entry(self, entry, name):
        metadata = entry["metadata"]
        filename = os.path.basename(entry["path"])
        mask = False
        compatibility = "not_symlink"
        if metadata["uid"] != 0 or (not stat.S_ISLNK(metadata["mode"]) and metadata["mode"] & 0o022):
            self.definition_refuse("definition_unsafe_metadata")
        if stat.S_ISREG(metadata["mode"]) and metadata["size"] == 0:
            mask = True
        elif stat.S_ISLNK(metadata["mode"]):
            target = os.path.normpath(os.path.join(os.path.dirname(entry["path"]), metadata["target"]))
            if target == "/dev/null":
                self.definition_verify_null()
                mask = True
            else:
                mask = self.definition_dependency_mask(target)
            # A mismatched target basename is a v255 warning, not rejection.
            compatibility = "matching" if filename == os.path.basename(metadata["target"]) else "mismatched_warning"
        reference = self.definition_path_record(
            entry["path"], "dependency_mask" if mask else "dependency_entry", metadata["identity"], metadata["target"],
            compatibility=compatibility,
        )
        if mask or not stat.S_ISLNK(metadata["mode"]):
            return None
        parts = self.definition_unit_parts(filename)
        owner = self.definition_unit_parts(name)
        if parts[1] == "":
            if owner[1] not in (None, ""):
                filename = parts[0] + "@" + owner[1] + "." + parts[2]
            else:
                return {"directive": entry["directive"], "source": reference, "value": filename,
                        "symbolic_template": True, "origin": "dependency_directory"}
        return {"directive": entry["directive"], "source": reference, "value": filename,
                "origin": "dependency_directory"}

    def definition_dependency_mask(self, path):
        """Metadata-only null_or_empty_path equivalent within the approved roots."""
        seen = set()
        for _ in range(SYSTEMD_DEFINITION_PROFILE["path_symlink_hops"]):
            if path == "/dev/null":
                self.definition_verify_null()
                return True
            if not self.definition_lookup_target_allowed(path):
                self.definition_refuse("definition_linked_target_unprofiled")
            if path in seen:
                return False  # v255 null_or_empty_path error is not a dependency mask.
            seen.add(path)
            directory = self.definition_directory(os.path.dirname(path))
            if directory is None:
                return False
            name = os.path.basename(path)
            try:
                before = self.definition_io("stat", name, dir_fd=directory["fd"], follow_symlinks=False)
            except FileNotFoundError:
                try:
                    self.definition_io("stat", name, dir_fd=directory["fd"], follow_symlinks=False)
                except FileNotFoundError:
                    self.definition_check_chain(directory["chain"])
                    self.definition_path_record(path, "dangling_dependency_target")
                    return False
                self.definition_refuse("definition_snapshot_changed")
            target = None
            if stat.S_ISLNK(before.st_mode):
                target = self.definition_link(directory["fd"], name, before)
            after = self.definition_io("stat", name, dir_fd=directory["fd"], follow_symlinks=False)
            self.definition_check_chain(directory["chain"])
            if self.file_identity(before) != self.file_identity(after):
                self.definition_refuse("definition_snapshot_changed")
            self.definition_path_record(path, "dependency_target", self.file_identity(before), target)
            if target is None:
                return stat.S_ISREG(before.st_mode) and before.st_size == 0
            path = os.path.normpath(os.path.join(directory["resolved"], target))
        self.definition_refuse("definition_path_hops_bound")

    @staticmethod
    def parse_definition_assignments(body, source, unit_type=None):
        """Bounded v255 conf-parser logical lines; no shell/INI reset semantics.

        Comments are skipped before continuation concatenation. An odd trailing
        backslash becomes one space; native backslashes in values are retained.
        Dependencies use EXTRACT_RETAIN_ESCAPE alone, so quotes are ordinary
        bytes, not shell grouping (load-fragment.c:265, extract-word.c:134).
        """
        if len(body) > SYSTEMD_DEFINITION_PROFILE["body_bytes_per_read"]:
            yield {"kind": "syntax", "source": source, "value": "", "directive": "Unsupported"}
            return
        try:
            text = body.decode("utf-8-sig")
        except UnicodeDecodeError:
            yield {"kind": "syntax", "source": source, "value": "", "directive": "Unsupported"}
            return
        if "\x00" in text:
            yield {"kind": "syntax", "source": source, "value": "", "directive": "Unsupported"}
            return
        section = None
        allowed_sections = {"Unit", "Install"}
        if unit_type is not None:
            allowed_sections.add(unit_type.capitalize())
        else:
            allowed_sections.update(("Service", "Socket", "Timer", "Path", "Mount", "Swap"))
        continuation = ""
        lines = iter(text.split("\n"))
        for raw in lines:
            raw = raw.rstrip("\r")
            if raw.lstrip(" \t\r\v\f").startswith(("#", ";")):
                continue
            logical = continuation + raw
            escapes = len(logical) - len(logical.rstrip("\\"))
            if escapes % 2:
                continuation = logical[:-1] + " "
                continue
            continuation = ""
            logical = logical.strip(" \t\r\v\f")
            if not logical:
                continue
            if logical.startswith("["):
                if not logical.endswith("]"):
                    yield {"kind": "syntax", "source": source, "value": "", "directive": "Unsupported"}
                    section = None
                else:
                    section = logical[1:-1]
                continue
            key, equals, value = logical.partition("=")
            key, value = key.strip(" \t\r\v\f"), value.strip(" \t\r\v\f")
            if section not in allowed_sections:
                continue  # v255 ignores assignments outside the unit's sections.
            if not equals or not key:
                yield {"kind": "syntax", "source": source, "value": "", "directive": "Unsupported"}
                continue
            if section == "Unit" and key in DEFINITION_DEPENDENCIES:
                kind, directive = "dependency", key
            elif (section, key) in (("Timer", "Unit"), ("Path", "Unit"), ("Socket", "Service"), ("Socket", "Accept")):
                kind, directive = "projection", section + "." + key
            elif section in ("Service", "Socket", "Mount", "Swap") and key in DEFINITION_EXEC:
                kind, directive = "projection", key
            elif section == "Install":
                kind, directive = "install_intent", "InstallIntent"
            else:
                kind, directive = "unsupported", "Unsupported"
                value = section + "." + logical
            yield {"kind": kind, "directive": directive, "value": value, "source": source,
                   "origin": "assignment"}
        if continuation:
            # v255 parses a final continuation at EOF as a logical line too.
            yield from Discovery.parse_definition_assignments(
                ("[" + (section or "") + "]\n" + continuation).encode("utf-8"), source, unit_type
            )

    @staticmethod
    def definition_expand_specifiers(name, value):
        parts = Discovery.definition_unit_parts(name)
        prefix, instance, suffix = parts
        fixed = {"p": prefix, "j": prefix.rsplit("-", 1)[-1], "%": "%"}
        if instance != "":
            fixed.update(i=instance or "", n=name, N=name[:-(len(suffix) + 1)])
        result = []
        symbolic = set()
        cursor = minimum_length = 0
        while cursor < len(value):
            char = value[cursor]
            cursor += 1
            if char != "%":
                piece, minimum = char, 1
            else:
                if cursor == len(value):
                    return None, "", "specifier_unsupported"
                specifier = value[cursor]
                cursor += 1
                if specifier in fixed:
                    piece = fixed[specifier]
                    minimum = len(piece)
                    if specifier == "%":
                        # %% expands deterministically to a literal percent,
                        # which cannot occur in a native unit name. Do not let
                        # it masquerade as a symbolic placeholder afterward.
                        return None, "", "dependency_name_unsupported"
                elif specifier in "inN" and instance == "":
                    symbolic.add(specifier)
                    piece = "%" + specifier
                    minimum = {"i": 1, "n": len(prefix) + len(suffix) + 3,
                               "N": len(prefix) + 2}[specifier]
                else:
                    return None, "", "specifier_unsupported"
            minimum_length += minimum
            # v255 unit_name_printf uses UNIT_NAME_MAX; stop expansion before
            # allocating an oversized result, including repeated %p/%n attacks.
            if minimum_length > 255:
                return None, "", "dependency_name_unsupported"
            result.append(piece)
        return "".join(result), "".join(sorted(symbolic)), None

    def reduce_definition_relations(self, name, assignments):
        state = self.definition_state()
        start = len(self.domain(DEFINITION_DOMAIN)["relations"])
        attempts = 0
        requirements = {"activation_semantics_incomplete"}
        progress = {"range": [start, start], "attempts": 0, "requirements": requirements}
        state["last_reduction"] = progress
        for assignment in assignments:
            if self.interrupted(DEFINITION_DOMAIN) or time.monotonic() >= self.deadline:
                self.definition_refuse("definition_interrupted")
            kind = assignment["kind"]
            value = assignment["value"]
            if kind == "dependency":
                # No C unescaping or quote removal under EXTRACT_RETAIN_ESCAPE.
                words = re.finditer(r"[^ \t\r\n\v\f]+", value)
            else:
                words = iter((value,))
            for word in words:
                if attempts >= SYSTEMD_DEFINITION_PROFILE["relation_attempts_per_definition"]:
                    self.definition_refuse("definition_relation_target_bound")
                if state["relation_attempts"] >= SYSTEMD_DEFINITION_PROFILE["relation_attempts_total"]:
                    self.definition_refuse("definition_relation_total_bound")
                attempts += 1
                progress["attempts"] = attempts
                state["relation_attempts"] += 1
                word = word.group() if kind == "dependency" else word
                record = {"directive": assignment["directive"], "source": assignment["source"],
                          "origin": assignment.get("origin", "assignment"), "kind": kind,
                          "value_sha256": digest(word.encode("utf-8"))}
                if kind == "dependency":
                    expanded, symbolic, failure = self.definition_expand_specifiers(name, word)
                    if assignment.get("symbolic_template"):
                        symbolic = "i"
                    target_parts = self.definition_unit_parts(expanded) if expanded is not None else None
                    if symbolic:
                        # Only literal characters can be checked before an actual
                        # binding exists: %i or %n may supply even the suffix.
                        shape = expanded
                        for specifier in symbolic:
                            shape = shape.replace("%" + specifier, "")
                        if shape and (not shape.isascii() or not UNIT.fullmatch(shape)):
                            failure = "dependency_name_unsupported"
                        record.update(kind="symbolic", value_sha256=digest(expanded.encode()), specifiers=symbolic,
                                      symbolic_type="specifier")
                        if assignment.get("symbolic_template"):
                            record["symbolic_type"] = "implicit_instance"
                        requirements.add("symbolic_binding_unresolved")
                    elif target_parts is not None:
                        # unit.c resolve_template propagates an existing instance;
                        # a literal template in an abstract definition stays symbolic.
                        if target_parts[1] == "":
                            owner = self.definition_unit_parts(name)
                            if owner[1] == "":
                                # unit_add_name rejects abstract Unit objects;
                                # do not apply resolve_template's plain-owner
                                # prefix fallback to an abstract definition.
                                # v255 unit.c:235-257 and 3085-3133.
                                record.update(kind="symbolic", symbolic_type="implicit_instance")
                                requirements.add("symbolic_binding_unresolved")
                            else:
                                inherited = owner[1] if owner[1] is not None else owner[0]
                                expanded = target_parts[0] + "@" + inherited + "." + target_parts[2]
                        record["value_sha256"] = digest(expanded.encode())
                    else:
                        failure = failure or "dependency_name_unsupported"
                    if failure:
                        requirements.add(failure)
                        record["kind"] = "unresolved"
                elif kind == "syntax":
                    requirements.add("definition_syntax_unsupported")
                elif kind == "install_intent":
                    requirements.add("install_intent_not_enabled_state")
                elif kind == "unsupported":
                    requirements.add("directive_semantics_unresolved")
                if kind != "dependency":
                    record["value_bytes"] = len(word.encode("utf-8"))
                self.definition_append("relations", record,
                                       SYSTEMD_DEFINITION_PROFILE["relation_attempts_total"],
                                       SYSTEMD_DEFINITION_PROFILE["relation_record_bytes"])
                progress["range"][1] = len(self.domain(DEFINITION_DOMAIN)["relations"])
        return {"range": [start, len(self.domain(DEFINITION_DOMAIN)["relations"])],
                "attempts": attempts, "requirements": sorted(requirements)}

    def definition_close_pass(self):
        state = self.definition_state()
        for fd in list(state["fds"]):
            self.definition_close(fd)
        state["directories"] = {}
        state["candidate_scans"] = {}
        state["root_snapshots"] = {}
        state["null_reference"] = None

    @staticmethod
    def definition_resolution_projection(resolution):
        fragment = resolution["fragment"]
        return {"canonical": resolution["canonical"], "aliases": sorted(resolution["aliases"]),
                "failure": resolution["failure"],
                "fragment": (fragment["path"], fragment["kind"]) if fragment is not None else None}

    def definition_commit(self, name, facts):
        """Admit a fully constructed header; no post-append fact mutations."""
        state = self.definition_state()
        if self.interrupted(DEFINITION_DOMAIN) or time.monotonic() >= self.deadline:
            self.definition_refuse("definition_interrupted")
        domain = self.domain(DEFINITION_DOMAIN)
        candidate = {
            "authority_id": digest((self.host + "\0" + DEFINITION_DOMAIN + "\0" + name).encode()),
            "identity": name if name in KNOWN else None, "identity_sha256": digest(name.encode()),
            "unknown_identity": name not in KNOWN, "relevance": "unresolved", "facts": facts,
        }
        encoded = len(json.dumps(candidate, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        if len(domain["records"]) >= SYSTEMD_DEFINITION_PROFILE["definition_targets"]:
            self.definition_refuse("definition_target_bound")
        if encoded > SYSTEMD_DEFINITION_PROFILE["definition_header_bytes"]:
            self.definition_refuse("definition_header_bound")
        if state["encoded_bytes"] + encoded + 1 > SYSTEMD_DEFINITION_PROFILE["evidence_bytes"] - 1048576:
            self.definition_refuse("definition_evidence_bound")
        if self.record(DEFINITION_DOMAIN, name, facts):
            state["encoded_bytes"] += encoded + 1
            if not facts["source_acquisition_complete"]:
                domain["complete"] -= 1

    def template_definitions(self):
        """Effective selected definition evidence, never fabricated runtime facts."""
        state = self.definition_state()
        domain = self.domain(DEFINITION_DOMAIN)
        staged = {}
        before = after = None
        roots_before = []
        mapping_before = {}
        stable = False
        enumeration_ok = False
        # All four listings precede definition acquisition. They are membership
        # boundaries, not an atomic snapshot or a bracket around these body reads.
        boundary_failures = set()
        if not all(self.domain(label)["enumeration_complete"] for label in (
            "systemd_installed", "systemd_loaded", "systemd_installed_final", "systemd_loaded_final"
        )):
            boundary_failures.add("definition_enumeration_boundary_unavailable")
        if (self.installed_units != self.final_installed_units
                or self.loaded_units != self.final_loaded_units):
            boundary_failures.add("definition_enumeration_membership_changed")
        for reason in sorted(boundary_failures):
            self.gap(DEFINITION_DOMAIN, reason, raced=reason == "definition_enumeration_membership_changed")
        try:
            before = self.manager_unitpath_snapshot("initial")
            state["active_roots"] = tuple(before["roots"])
            roots_before = self.snapshot_unit_roots(before["roots"])
            state["active_roots"] = tuple({root["path"] for root in roots_before} | {
                root["resolved"] for root in roots_before
            })
            mapping_before = self.build_unit_name_map(roots_before)
            actually_enumerated = (self.installed_units | self.loaded_units
                                   | self.final_installed_units | self.final_loaded_units)
            targets = actually_enumerated | {
                name for name in mapping_before
                if (parts := self.definition_unit_parts(name)) is not None and parts[1] == ""
            }
            # Listing rows are bounded to 8192 each, and the lookup map to 8192.
            # Count every observed name before rejecting unsupported names, and
            # refuse the whole target set before opening any selected body.
            domain["enumerated"] = len(targets)
            if len(targets) > SYSTEMD_DEFINITION_PROFILE["definition_targets"]:
                self.definition_refuse("definition_target_bound")
            if any(self.definition_unit_parts(name) is None for name in targets):
                self.definition_refuse("definition_unit_name_unsupported")
            live_roots = [root["path"] for root in roots_before if not root["absent"]]
            for name in sorted(targets):
                resolution = self.resolve_template_fragment(name, mapping_before)
                selected = self.select_definition_sources(resolution, live_roots)
                staged[name] = {"resolution": resolution, "selection": selected, "sources": [], "dependencies": []}
                for source in selected["selected"]:
                    observed = self.read_definition_source(source)
                    staged[name]["sources"].append({**observed, "kind": source["kind"]})
                for entry in selected["dependencies"]:
                    observed = self.definition_dependency_entry(entry, resolution["canonical"])
                    if observed is not None:
                        staged[name]["dependencies"].append({**observed, "kind": "dependency"})
            self.definition_close_pass()
            state["phase"] = "repeated"
            roots_after = self.snapshot_unit_roots(before["roots"])
            mapping_after = self.build_unit_name_map(roots_after)
            if ([self.definition_snapshot_projection(root) for root in roots_before]
                    != [self.definition_snapshot_projection(root) for root in roots_after]
                    or mapping_before != mapping_after):
                self.definition_refuse("definition_snapshot_changed")
            live_roots = [root["path"] for root in roots_after if not root["absent"]]
            for name, pending in staged.items():
                resolution = self.resolve_template_fragment(name, mapping_after)
                selected = self.select_definition_sources(resolution, live_roots)
                previous = pending["selection"]
                if (self.definition_resolution_projection(resolution)
                        != self.definition_resolution_projection(pending["resolution"])
                        or selected["selected"] != previous["selected"]
                        or [self.definition_snapshot_projection(item) for item in selected["consulted"]]
                        != [self.definition_snapshot_projection(item) for item in previous["consulted"]]
                        or selected["dependencies"] != previous["dependencies"]):
                    self.definition_refuse("definition_selected_sources_changed")
                for source in selected["selected"]:
                    self.read_definition_source(source)
                repeated_dependencies = []
                for entry in selected["dependencies"]:
                    observed = self.definition_dependency_entry(entry, resolution["canonical"])
                    if observed is not None:
                        repeated_dependencies.append({**observed, "kind": "dependency"})
                def normalize(items):
                    return [{key: value for key, value in item.items() if key != "source"} for item in items]
                if normalize(repeated_dependencies) != normalize(pending["dependencies"]):
                    self.definition_refuse("definition_snapshot_changed")
            stable = True
        except DefinitionRefusedError:
            pass
        except PermissionError:
            self.gap(DEFINITION_DOMAIN, "definition_access_denied")
            state["failures"].append("definition_access_denied")
        except OSError:
            self.gap(DEFINITION_DOMAIN, "definition_filesystem_unavailable")
            state["failures"].append("definition_filesystem_unavailable")
        finally:
            self.definition_close_pass()
            state["phase"] = "repeated"
            try:
                after = self.manager_unitpath_snapshot("repeated")
                if before is None or before["roots"] != after["roots"] or before["version"] != after["version"]:
                    self.definition_refuse("definition_manager_changed")
            except DefinitionRefusedError:
                stable = False
        enumeration_ok = (
            stable and not state["failures"] and not boundary_failures
        )
        # Parse only selected bodies. Two body hashes establish limited observed
        # stability; no atomic snapshot, sender exclusion, or activation closure.
        for _name, pending in staged.items():
            def assignments(pending=pending):
                for source_kind in ("fragment", "dropin"):
                    if source_kind == "dropin":
                        yield from pending["dependencies"]
                    for source in pending["sources"]:
                        key = source["source_key"]
                        if (source["kind"] == source_kind and key is not None
                                and state["sources"][key]["body"] is not None):
                            cache = state["sources"][key]
                            yield from self.parse_definition_assignments(
                                cache["body"], cache["reads"]["initial"],
                                self.definition_unit_parts(pending["resolution"]["canonical"])[2],
                            )
            try:
                pending["reduction"] = self.reduce_definition_relations(
                    pending["resolution"]["canonical"], assignments()
                )
            except DefinitionRefusedError:
                progress = state["last_reduction"]
                pending["reduction"] = {"range": list(progress["range"]), "attempts": progress["attempts"],
                                        "requirements": sorted(progress["requirements"])}
                enumeration_ok = False
                break
        manager_before = [i for i, item in enumerate(domain["manager_observations"]) if item["phase"] == "initial"]
        manager_after = [i for i, item in enumerate(domain["manager_observations"]) if item["phase"] == "repeated"]
        for name, pending in staged.items():
            resolution = pending["resolution"]
            reduction = pending.get("reduction", {"range": [0, 0], "attempts": 0,
                                                  "requirements": ["definition_relations_unavailable"]})
            requirements = set(reduction["requirements"]) | set(state["failures"]) | boundary_failures
            if resolution["failure"]:
                requirements.add(resolution["failure"])
                self.gap(DEFINITION_DOMAIN, resolution["failure"])
            if pending["selection"]["ambiguities"]:
                requirements.add("definition_alias_order_ambiguous")
                self.gap(DEFINITION_DOMAIN, "definition_alias_order_ambiguous")
            sources = []
            for source in pending["sources"]:
                key = source["source_key"]
                reads = state["sources"][key]["reads"] if key is not None else {"initial": None, "repeated": None}
                sources.append({"path_reference": source["path_reference"], "kind": source["kind"],
                                "mask": source["mask"], "initial_read": reads["initial"],
                                "repeated_read": reads["repeated"]})
            aliases = sorted(resolution["aliases"])
            facts = {
                "schema": "AcademySystemdEffectiveDefinitionFacts.v1", "source_kind": "effective_unit_definition",
                "name_shape": self.unit_name_shape(name),
                "definition_profile": dict(SYSTEMD_DEFINITION_PROFILE),
                "definition_profile_sha256": self.definition_profile_hash(),
                "manager_before": manager_before, "manager_after": manager_after,
                "requested_identity_sha256": digest(name.encode()),
                "canonical_identity_sha256": digest(resolution["canonical"].encode()),
                "fragment_kind": resolution["fragment"]["kind"] if resolution["fragment"] is not None else None,
                "linked_target_sha256": (
                    digest(resolution["fragment"]["destination_path"].encode())
                    if resolution["fragment"] is not None and resolution["fragment"]["kind"] == "linked_unit" else None
                ),
                "aliases": {"count": len(aliases), "ordered_sha256": digest(json.dumps(aliases).encode()),
                            "identity_sha256": [digest(alias.encode()) for alias in aliases]},
                "mask": (resolution["fragment"] is not None
                         and resolution["fragment"]["kind"] in ("empty_mask", "null_mask")),
                "sources": sources, "relation_range": reduction["range"], "relation_attempts": reduction["attempts"],
                "unresolved_requirements": sorted(requirements | {"activation_semantics_incomplete"}),
                "source_acquisition_complete": bool(enumeration_ok and not resolution["failure"]
                                                    and not pending["selection"]["ambiguities"]),
                "activation_semantics_complete": False, "classification": "unknown", "authority_refs": [],
            }
            try:
                self.definition_commit(name, facts)
            except DefinitionRefusedError:
                enumeration_ok = False
                break
        domain["enumeration_complete"] = enumeration_ok
        domain["skipped"] = domain["enumerated"] - domain["inspected"]
        domain["definition_accounting"] = {
            "filesystem_work": state["work"], "alias_resolution_attempts": state["alias_attempts"],
            "candidate_selection_attempts": state["selection_attempts"],
            "body_bytes": state["body_bytes"],
            "manager_attempts": state["manager_attempts"], "relation_attempts": state["relation_attempts"],
            "encoded_bytes": state["encoded_bytes"], "unparsed_tail": state["unparsed_tail"],
            "selected_paths": len(state["selected_paths"]), "distinct_bodies": len(state["sources"]),
            "reserved_second_pass_work": state["reserved_work"],
            "reserved_second_pass_bytes": state["reserved_bytes"],
            "reserved_second_pass_reads": sum(
                source["reads"]["repeated"] is None for source in state["sources"].values()
            ),
        }
        # Bodies and raw lookup maps are transient parser inputs, never report data.
        for source in state["sources"].values():
            source["body"] = None

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
        if (self.files - self.definition_files >= MAX_FILES
                or (self.files + (self._definition["reserved_work"] if hasattr(self, "_definition") else 0)
                    >= RESOURCE_PROFILE["cumulative_filesystem_work"])
                or time.monotonic() >= self.deadline):
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
                block = self.read_payload(fd, min(65536, limit + 1 - len(data)), domain)
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
        except ResourceLimitError:
            return None
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
                while True:
                    if self.interrupted(domain):
                        return None
                    if time.monotonic() >= self.deadline:
                        raise ValueError
                    entry = next(entries, None)
                    if entry is None:
                        break
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
        if (self.files - self.definition_files >= MAX_FILES
                or (self.files + (self._definition["reserved_work"] if hasattr(self, "_definition") else 0)
                    >= RESOURCE_PROFILE["cumulative_filesystem_work"])
                or time.monotonic() >= self.deadline):
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
                block = self.read_payload(fd, min(65536, limit + 1 - len(data)), domain)
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
        except ResourceLimitError:
            return None
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
                                    self.read_link(fd, field, domain)
                                )
                            except (OSError, ResourceLimitError):
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
            recorded = self.record(domain, "nss:" + database.decode("ascii"), {
                "nss_database": database.decode("ascii"),
                "nss_source": source,
                "nss_line_sha256": [digest(line) for line, _content, _continued in lines],
                "nss_parse_supported": supported,
                "nss_providers": providers if supported else [],
                "account_enumeration_proven": False,
            })
            if not supported and recorded:
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

    def recount_retained_graph(self):
        """One final linear recount; performed decode counters never decrease."""
        target = self.domains.get("systemd_unit_graph")
        if target is None:
            return
        accounting = target["endpoint_accounting"]
        for phase in ("initial", "repeated", "total"):
            accounting[phase]["retained_endpoint_count"] = 0
        for record in target["records"]:
            facts = record["facts"]
            for phase in ("initial", "repeated"):
                count = sum(len(item["endpoint_sha256"]) for item in facts[phase]["fields"].values()
                            if item is not None)
                accounting[phase]["retained_endpoint_count"] += count
                accounting["total"]["retained_endpoint_count"] += count

    def resource_accounting(self):
        return {
            "captured_payload_bytes": self.captured_payload_bytes,
            "resource_stopped": self.resource_stopped,
            "resource_stop_reason": self.resource_stop_reason,
            "observation_retention_incomplete": self.observation_retention_incomplete,
            "retained_ordinary_record_json_bytes": self.ordinary_record_json_bytes,
            "ordinary_filesystem_work": self.files - self.definition_files,
            "definition_filesystem_work": self.definition_files,
            "cumulative_filesystem_work": self.files,
            "reserved_definition_filesystem_work": (
                self._definition["reserved_work"] if hasattr(self, "_definition") else 0
            ),
        }

    def envelope(self, *, failure=False):
        result = {
            "schema": "AcademyAuthorityDiscoveryFailure.v3" if failure else "AcademyAuthorityDiscovery.v3",
            "role": self.role,
            "host": self.host,
            "coverage_complete": False,
            "campaign_authority_claimed": False,
            "classification_complete": False,
            "purpose": "readonly_discovery_facts_only",
            "domains": {} if failure else self.domains,
            "commands_attempted": self.commands,
            "files_attempted": self.files,
            "child_lifecycle": self.child_metadata,
            "signal_interrupted": self.pending_signal is not None,
            "resource_profile": RESOURCE_PROFILE,
            "resource_profile_sha256": digest(json.dumps(RESOURCE_PROFILE, **JSON_OPTIONS).encode("ascii")),
            "resource_accounting": self.resource_accounting(),
        }
        if failure:
            result.update(reason="normal_evidence_resource_or_encoding_refusal", normal_evidence_not_emitted=True)
        return result

    def seal(self):
        try:
            self.recount_retained_graph()
            if self.normal_evidence_refused:
                raise ResourceLimitError
            result = self.envelope()
            # Retain only metadata references; never copy or rescan record arrays.
            metadata = dict(result)
            metadata["domains"] = {
                name: dict(domain, records=[]) for name, domain in self.domains.items()
                if name != DEFINITION_DOMAIN
            }
            if len(self.domains) > 32:
                raise ResourceLimitError
            commas = sum(max(0, len(domain["records"]) - 1) for name, domain in self.domains.items()
                         if name != DEFINITION_DOMAIN)
            definition_size = 0
            if DEFINITION_DOMAIN in self.domains:
                definition_size = canonical_size(
                    self.domains[DEFINITION_DOMAIN], RESOURCE_PROFILE["definition_domain_json_bytes"]
                )
                # Account its property key/framing here; its entire value is exclusive.
                metadata["domains"][DEFINITION_DOMAIN] = None
            metadata_size = canonical_size(metadata, RESOURCE_PROFILE["metadata_json_bytes"] + 4)
            metadata_size += commas + 1 - (4 if definition_size else 0)
            if metadata_size > RESOURCE_PROFILE["metadata_json_bytes"]:
                raise ResourceLimitError
            total = metadata_size + self.ordinary_record_json_bytes + definition_size
            if total > RESOURCE_PROFILE["normal_json_bytes"]:
                raise ResourceLimitError
            staged = stage_json(result, RESOURCE_PROFILE["normal_json_bytes"])
            if staged.seek(0, io.SEEK_END) != total:
                raise ResourceLimitError
            staged.seek(0)
            return staged
        except Exception:  # Fixed failure variant, never exception/payload text.
            self.stop_retention()
            self.normal_evidence_refused = True
            return stage_json(self.envelope(failure=True), RESOURCE_PROFILE["failure_json_bytes"])

    def emit(self, stream):
        staged = self.seal()
        # Past this boundary any exception is delivery failure. Never append JSON.
        with staged:
            while block := staged.read(65536):
                offset = 0
                while offset < len(block):
                    written = stream.write(block[offset:])
                    if type(written) is not int or written <= 0 or written > len(block) - offset:
                        raise OSError("discovery delivery failed")
                    offset += written
            stream.flush()

    def collect(self):
        self.systemd()
        self.processes()
        self.schedulers_accounts()
        self.nss_layout()
        self.user_manager_topology()
        self.template_definitions()
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
    discovery.emit(sys.stdout.buffer)


if __name__ == "__main__":
    main()

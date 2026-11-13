"""Closed, nonce-bound current leaf observations over an existing approved SSH path.

No profile is provisioned here. ``m['census_transport'][role]`` must reference an
already approved static v2 root-private profile with packet directory paths,
never future source/bootstrap/index hashes. Missing profiles refuse. Coordinator API:
request_current(C,m,evidence,role,operation,original_source_ref,active_authority,profile_ref,
output). Peer API: observe_local_leaf(C,m,evidence,protected_request). Verification:
verify_current(C,m,evidence,expected_binding,source_ref,transport_evidence) consumes one intent.

The caller supplies the actual Evidence constructed by the protected bootstrap.
The producer's pinned _authority independently repeats current validation. No injected
loader, command, observation dictionary or historical timestamp is accepted as
current proof. Only the coordinator joins original stop receipts and gate epochs.
"""

import hashlib
import os
import re
import selectors
import signal
import socket
import subprocess
import sys
import time
import types
from pathlib import Path

OPERATIONS = {"gate-web": "web", "stopped-web": "web", "stopped-lab": "lab"}
MAX_BYTES = 1_000_000
MAX_REQUEST = 16_384
MAX_SECONDS = 30
# Successful transport results are usable only in their issuing process.
# Persisted artifacts are audit inputs and never substitute for a new live call.
_ISSUED = {}
_UNCERTAIN_CHILDREN = []
# Dot-prefixed names (for example .ssh) are safe; _path rejects literal . and .. segments.
PATH = re.compile(r"/root/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\Z")
HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
BINDING_FIELDS = (
    "candidate",
    "tree",
    "attempt",
    "authority_scope_sha256",
    "producer_sha256",
    "transport_sha256",
    "execution_manifest_sha256",
    "execution_approval_sha256",
    "active_authority",
    "role",
    "hostname",
    "operation",
    "original_source",
    "gate_epoch",
    "original_stop_ref",
    "peer_inputs",
    "peer_evidence_index",
)
REQUEST_FIELDS = ("schema", "nonce", "issued_unix", "expires_unix", "binding")
RESPONSE_FIELDS = (
    "schema",
    "request",
    "observed_unix_started",
    "observed_unix_finished",
    "facts",
)
PROFILE_FIELDS = (
    "schema",
    "caller_hostname",
    "role",
    "hostname",
    "endpoint",
    "port",
    "user",
    "identity",
    "known_hosts",
    "peer_producer",
    "peer_packet_root",
    "local_packet_root",
)


def _require(condition, reason):
    if not condition:
        raise ValueError("census_transport_" + reason)


def _exact(value, fields):
    _require(type(value) is dict and set(value) == set(fields), "closed_fields")


def _path(value):
    _require(type(value) is str and PATH.fullmatch(value) is not None, "protected_path")
    _require(all(part not in (".", "..") for part in value.split("/")), "path_segments")
    return value


def _ref(ref):
    _exact(ref, ("path", "sha256"))
    _path(ref["path"])
    _require(type(ref["sha256"]) is str and HEX.fullmatch(ref["sha256"]), "ref_hash")


def _pin(C, ref, limit=MAX_BYTES):
    _ref(ref)
    raw = C.read_bytes(ref["path"], limit=limit, private=True, root_file=True, mode=0o600)
    _require(hashlib.sha256(raw).hexdigest() == ref["sha256"], "source_hash")
    return raw


def _trusted(C, m):
    """Require the actual fixed common source; this is not a callback plug-in API."""
    _require(
        sys.platform == "linux"
        and sys.version_info[:2] == (3, 12)
        and os.getuid() == os.geteuid() == 0
        and sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode,
        "linux_root_B_I_S",
    )
    own = Path(__file__).absolute()
    _path(str(own))
    common = own.with_name("candidate_execute.py")
    namespace = getattr(getattr(C, "common_api", None), "__globals__", {})
    _require(namespace.get("__file__") == str(common), "fixed_common")
    for name in ("require", "read_bytes", "write_new", "decode", "canonical"):
        _require(getattr(C, name, None) is namespace.get(name) and callable(namespace.get(name)), "actual_common_api")
    _pin(C, {"path": str(common), "sha256": m["self_sha256"]}, 2_000_000)
    _pin(C, {"path": str(own), "sha256": m["helpers"]["census_transport"]}, 2_000_000)
    producer_path = own.with_name("candidate_external_census.py")
    raw = _pin(C, {"path": str(producer_path), "sha256": m["helpers"]["external_census"]}, 2_000_000)
    producer = types.ModuleType("academy_fixed_transport_producer")
    producer.__file__ = str(producer_path)
    exec(compile(raw, str(producer_path), "exec"), producer.__dict__)  # noqa: S102 -- fixed root-private hash-pinned sibling
    return producer


def _authority(C, m, producer, active, evidence):
    _require(evidence.m == m and evidence.active_authority == active, "actual_evidence_binding")
    producer._authority(C, m, evidence, active)
    return evidence


def _profile(C, m, role, profile_ref, *, runtime=True, credentials=True):
    _require(role in ("web", "lab"), "role")
    _require(m.get("census_transport", {}).get(role) == profile_ref, "approved_existing_profile_required")
    value = C.decode(_pin(C, profile_ref))
    _exact(value, PROFILE_FIELDS)
    _require(value["schema"] == "AcademyCensusTransportProfile.v2", "profile_schema")
    _require(value["role"] == role and value["hostname"] == m["roles"][role]["hostname"], "profile_host")
    other = "lab" if role == "web" else "web"
    _require(value["caller_hostname"] == m["roles"][other]["hostname"], "only_approved_other_role_caller")
    if runtime:
        _require(value["caller_hostname"] == socket.gethostname(), "approved_caller_host")
    _require(type(value["endpoint"]) is str and HOST.fullmatch(value["endpoint"]), "endpoint")
    _require(
        ".." not in value["endpoint"] and type(value["port"]) is int and 1 <= value["port"] <= 65535, "endpoint_port"
    )
    _require(value["user"] == ("root" if role == "web" else "dotmac"), "prescribed_ssh_user")
    for name in ("identity", "known_hosts", "peer_producer"):
        _ref(value[name])
    for name in ("peer_packet_root", "local_packet_root"):
        _path(value[name])
    _require(Path(value["peer_producer"]["path"]).name == "candidate_external_census.py", "fixed_peer_producer")
    _require(value["peer_producer"]["sha256"] == m["helpers"]["external_census"], "peer_producer_hash")
    if credentials:
        # Only actual runtime use opens existing credentials; never emit bytes.
        for name in ("identity", "known_hosts"):
            _pin(C, value[name], 65_536)
    return value


def validate_profile(C, m, role, profile_ref):
    """Static approved v2 profile validation; never opens authentication files."""
    return _profile(C, m, role, profile_ref, runtime=False, credentials=False)


def _derived(profile, operation, basename):
    _require(OPERATIONS.get(operation) == profile["role"], "leaf_DAG")
    _path(profile["peer_packet_root"])
    _path(profile["local_packet_root"])
    return (str(Path(profile["peer_packet_root"]) / basename), str(Path(profile["local_packet_root"]) / basename))


def _mirror(profile, peer_path):
    _path(peer_path)
    try:
        relative = Path(peer_path).relative_to(profile["peer_packet_root"])
    except ValueError:
        raise ValueError("census_transport_peer_packet_containment") from None
    _require(relative.parts and all(part not in (".", "..") for part in relative.parts), "mirror_relative_path")
    return _path(str(Path(profile["local_packet_root"]) / relative))


def archived_source_ref(C, m, role, operation, original_ref, profile_ref):
    """Resolve an exact archived local mirror; archived bytes are never live proof."""
    profile = _profile(C, m, role, profile_ref, credentials=False)
    _ref(original_ref)
    peer, local = _derived(profile, operation, "raw-" + operation + ".json")
    _require(original_ref["path"] == peer, "fixed_original_peer_path")
    mirror = {"path": local, "sha256": original_ref["sha256"]}
    _pin(C, mirror)
    return mirror


def _read_now(C, path):
    _path(path)
    raw = C.read_bytes(path, limit=MAX_BYTES, private=True, root_file=True, mode=0o600)
    return raw, {"path": path, "sha256": hashlib.sha256(raw).hexdigest()}


def _validate_bootstrap(C, m, value, binding, actual_peer_path):
    _exact(
        value,
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
    active = binding["active_authority"]
    _require(
        value["schema"] == "AcademyCensusInputs.v1"
        and value["kind"] == active["kind"]
        and value["phase"] == active["phase"],
        "bootstrap_current_authority",
    )
    _require(
        value["manifest"] == active["manifest"] and value["approval"] == active["approval"],
        "bootstrap_exact_authority_refs",
    )
    _require(
        value["role"] == binding["role"] and value["observation"] == binding["operation"].split("-")[0],
        "bootstrap_fixed_observation",
    )
    _path(actual_peer_path)
    packet = Path(actual_peer_path).parent
    _require(
        Path(actual_peer_path).name == "current-" + binding["operation"] + "-inputs.json", "fixed_bootstrap_basename"
    )
    _require(
        binding["original_source"]["path"] == str(packet / ("raw-" + binding["operation"] + ".json")),
        "fixed_peer_original_source_path",
    )
    _require(Path(binding["peer_evidence_index"]["path"]).is_relative_to(packet), "peer_seed_packet_containment")
    _ref(value["common"])
    _require(
        Path(value["common"]["path"]).name == "candidate_execute.py" and value["common"]["sha256"] == m["self_sha256"],
        "bootstrap_pinned_common",
    )
    _require(value["evidence_index"] == binding["peer_evidence_index"]["path"], "bootstrap_seed_index_path")
    _path(value["output"])


def _seed_index(C, raw):
    index = C.decode(raw)
    _require(type(index) is dict and type(index.get("entries")) is dict, "seed_index_shape")
    forbidden = set(OPERATIONS) | {"sources-" + name for name in OPERATIONS}
    _require(not forbidden.intersection(index["entries"]), "seed_index_no_leaf_recursion")
    for entry in index["entries"].values():
        _require(type(entry) is dict and type(entry.get("path")) is str, "seed_index_entry")
        _path(entry["path"])
        _require(
            not Path(entry["path"]).name.startswith(("current-intent-", "current-result-", "current-peer-nonce-")),
            "seed_index_no_future_challenge",
        )
    return index


def _dynamic_inputs(C, m, profile, operation, binding):
    peer, local = _derived(profile, operation, "current-" + operation + "-inputs.json")
    raw, local_ref = _read_now(C, local)
    value = C.decode(raw)
    _require(type(value) is dict and type(value.get("evidence_index")) is str, "bootstrap_seed_index_required")
    index_raw, index_local_ref = _read_now(C, _mirror(profile, value["evidence_index"]))
    peer_index = {"path": value["evidence_index"], "sha256": index_local_ref["sha256"]}
    current = dict(binding, peer_evidence_index=peer_index)
    _validate_bootstrap(C, m, value, current, peer)
    _require(
        value["common"]
        == {
            "path": str(Path(profile["peer_producer"]["path"]).with_name("candidate_execute.py")),
            "sha256": m["self_sha256"],
        },
        "bootstrap_fixed_peer_common",
    )
    _seed_index(C, index_raw)
    return {"path": peer, "sha256": local_ref["sha256"]}, peer_index, local_ref, index_local_ref


def _argv(profile, bootstrap_path):
    """Every remote-shell token has a closed path/constant grammar."""
    _exact(profile, PROFILE_FIELDS)
    _require(profile["role"] in ("web", "lab"), "role")
    _require(profile["user"] == ("root" if profile["role"] == "web" else "dotmac"), "prescribed_ssh_user")
    _require(type(profile["endpoint"]) is str and HOST.fullmatch(profile["endpoint"]), "endpoint")
    _require(type(profile["port"]) is int and 1 <= profile["port"] <= 65535, "endpoint_port")
    for name in ("peer_producer", "identity", "known_hosts"):
        _ref(profile[name])
    _require(Path(profile["peer_producer"]["path"]).name == "candidate_external_census.py", "fixed_peer_producer")
    remote = (["/usr/bin/sudo", "-n", "--"] if profile["role"] == "lab" else []) + [
        "/usr/bin/python3.12",
        "-B",
        "-I",
        "-S",
        profile["peer_producer"]["path"],
        "--inputs",
        _path(bootstrap_path),
        "--current-request-stdin",
    ]
    return [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "UserKnownHostsFile=" + profile["known_hosts"]["path"],
        "-i",
        profile["identity"]["path"],
        "-p",
        str(profile["port"]),
        "-l",
        profile["user"],
        "--",
        profile["endpoint"],
        " ".join(remote),
    ]


class _Child:
    """One child; deferred signals cover spawning; no reaping before group kill."""

    def __init__(self):
        self.pending = False
        self.phase = "idle"
        self.cleanup_confirmed = False

    def interrupt(self, _number, _frame):
        self.pending = True

    def run(self, argv, payload, expires_unix):
        _require(len(payload) <= MAX_REQUEST, "stdin_bound")
        _require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL and hasattr(os, "WNOWAIT"), "child_ownership")
        prior = {}
        child = None
        output = bytearray()
        okay = False
        end = time.monotonic() + min(MAX_SECONDS - 1, expires_unix - time.time())
        _require(end > time.monotonic(), "current_envelope_deadline")
        try:
            for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                prior[number] = signal.signal(number, self.interrupt)
            self.phase = "spawning"
            child = subprocess.Popen(  # noqa: S603 -- fixed module-owned SSH argv
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                shell=False,
                start_new_session=True,
                close_fds=True,
            )
            self.phase = "owned_unreaped"
            for stream in (child.stdin, child.stdout):
                os.set_blocking(stream.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdin, selectors.EVENT_WRITE)
                selector.register(child.stdout, selectors.EVENT_READ)
                sent = 0
                while selector.get_map():
                    _require(not self.pending and time.monotonic() < end, "interrupted_or_timeout")
                    for key, _mask in selector.select(min(0.05, max(0, end - time.monotonic()))):
                        if key.fileobj is child.stdin:
                            try:
                                sent += os.write(child.stdin.fileno(), payload[sent : sent + 4096])
                            except BlockingIOError:
                                continue
                            if sent == len(payload):
                                selector.unregister(child.stdin)
                                child.stdin.close()
                        else:
                            try:
                                block = os.read(child.stdout.fileno(), 65_536)
                            except BlockingIOError:
                                continue
                            if not block:
                                selector.unregister(child.stdout)
                            output.extend(block)
                            _require(len(output) <= MAX_BYTES, "stdout_bound")
            while True:
                _require(not self.pending and time.monotonic() < end, "interrupted_or_timeout")
                status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if status is not None:
                    okay = status.si_code == os.CLD_EXITED and status.si_status == 0
                    break
                time.sleep(0.01)
        except (Exception, KeyboardInterrupt, SystemExit):
            okay = False
        finally:
            if child is not None:
                reserved = False
                confirmed = True
                try:
                    os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    reserved = True
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=1)
                    self.phase = "reaped"
                    try:
                        os.killpg(child.pid, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        confirmed = False
                except (OSError, subprocess.TimeoutExpired):
                    confirmed = False
                finally:
                    for stream in (child.stdin, child.stdout):
                        if stream is not None:
                            stream.close()
                self.cleanup_confirmed = reserved and confirmed
                if not self.cleanup_confirmed:
                    _UNCERTAIN_CHILDREN.append(child)
            for number, handler in prior.items():
                signal.signal(number, handler)
        # Confirmed LOCAL SSH cleanup does not establish remote process cleanup.
        # Any failure retains the durable intent, refuses, and permits no auto-retry.
        _require(okay and self.cleanup_confirmed and not self.pending, "child_failed_or_cleanup_unconfirmed")
        return bytes(output)


def _request(value, now=None):
    _exact(value, REQUEST_FIELDS)
    _require(value["schema"] == "AcademyCensusCurrentRequest.v1", "request_schema")
    _require(type(value["nonce"]) is str and HEX.fullmatch(value["nonce"]), "nonce")
    start, end = value["issued_unix"], value["expires_unix"]
    _require(type(start) is int and type(end) is int and 0 < start < end <= start + MAX_SECONDS, "request_interval")
    now = int(time.time()) if now is None else now
    _require(start <= now < end, "request_expired_or_future")
    binding = value["binding"]
    _exact(binding, BINDING_FIELDS)
    _require(OPERATIONS.get(binding["operation"]) == binding["role"], "leaf_DAG")
    _ref(binding["original_source"])
    _ref(binding["peer_inputs"])
    _ref(binding["peer_evidence_index"])
    for name in (
        "producer_sha256",
        "transport_sha256",
        "authority_scope_sha256",
        "execution_manifest_sha256",
        "execution_approval_sha256",
    ):
        _require(type(binding[name]) is str and HEX.fullmatch(binding[name]), "binding_hash")
    _require(type(binding["gate_epoch"]) is str and 0 < len(binding["gate_epoch"]) <= 255, "epoch")
    if binding["operation"] == "gate-web":
        _require(binding["original_stop_ref"] is None, "gate_no_stop")
    else:
        _ref(binding["original_stop_ref"])
    return binding


def _leaf_facts(operation, source):
    _require(type(source) is dict and type(source.get("facts")) is dict, "original_source_facts")
    _require(source.get("schema") == "AcademyLocalCensusSource.v1", "original_source_schema")
    _require(source.get("adapter") == operation.split("-")[0], "original_source_adapter")
    facts = source["facts"]
    if operation == "gate-web":
        names = (
            "hold_id",
            "owner_record_sha256",
            "gate_approval_sha256",
            "supervisor_pid",
            "supervisor_start_ticks",
            "lock_inode",
            "lock_kernel_row",
            "state_sha256",
        )
    else:
        names = ("units", "application_pids", "preserved")
    _require(all(name in facts for name in names), "original_leaf_fields")
    return {name: facts[name] for name in names}


def _binding(C, m, producer, evidence, role, operation, original, source):
    _require(OPERATIONS.get(operation) == role, "leaf_DAG")
    _require(
        source["candidate"] == m["candidate"]
        and source["tree"] == m["tree"]
        and source["attempt"] == evidence.a["attempt"],
        "original_candidate",
    )
    _require(
        source["role"] == role
        and source["hostname"] == m["roles"][role]["hostname"]
        and source["producer_sha256"] == m["helpers"]["external_census"],
        "original_host_producer",
    )
    stop_ref = None
    if operation != "gate-web":
        # Historical receipt lookup is coordinator-only, never a peer leaf call.
        prior = evidence.phase("quiesce-" + role, role, "quiesce", fresh=False)
        stop_ref = evidence.value["entries"]["quiesce-" + role]
        stop_ref = {name: stop_ref[name] for name in ("path", "sha256")}
        _ref(stop_ref)
        _require(
            source["facts"]["quiesce_receipt_sha256"] == stop_ref["sha256"]
            and source["facts"]["stop_completed_unix"] == prior["observations"]["stop_completed_unix"],
            "original_stop_join",
        )
    return {
        "candidate": m["candidate"],
        "tree": m["tree"],
        "attempt": evidence.a["attempt"],
        "authority_scope_sha256": producer.load_scope(C, m)[1],
        "producer_sha256": m["helpers"]["external_census"],
        "transport_sha256": m["helpers"]["census_transport"],
        "execution_manifest_sha256": evidence.manifest_hash,
        "execution_approval_sha256": evidence.approval_hash,
        "active_authority": evidence.active_authority,
        "role": role,
        "hostname": m["roles"][role]["hostname"],
        "operation": operation,
        "original_source": original,
        "gate_epoch": source["facts"].get("hold_id", source["facts"].get("gate_epoch")),
        "original_stop_ref": stop_ref,
    }


def _response(request, response, now=None):
    _request(request, now)
    _exact(response, RESPONSE_FIELDS)
    _require(
        response["schema"] == "AcademyCensusCurrentLeaf.v1" and response["request"] == request, "exact_challenge_echo"
    )
    start, end = response["observed_unix_started"], response["observed_unix_finished"]
    _require(
        type(start) is int and type(end) is int and request["issued_unix"] <= start <= end < request["expires_unix"],
        "response_interval",
    )
    _require(end <= (int(time.time()) if now is None else now), "response_future")
    return response["facts"]


def request_current(C, m, evidence, role, operation, original_source_ref, active_authority, profile_ref, output):
    _require(m.get("census_transport", {}).get(role) == profile_ref, "approved_existing_profile_required")
    producer = _trusted(C, m)
    profile = _profile(C, m, role, profile_ref, credentials=False)
    evidence = _authority(C, m, producer, active_authority, evidence)
    local_source = archived_source_ref(C, m, role, operation, original_source_ref, profile_ref)
    source = C.decode(_pin(C, local_source))
    binding = _binding(C, m, producer, evidence, role, operation, original_source_ref, source)
    peer_inputs, peer_index, local_inputs, local_index = _dynamic_inputs(C, m, profile, operation, binding)
    binding.update(peer_inputs=peer_inputs, peer_evidence_index=peer_index)
    current_approval = C.decode(_pin(C, active_authority["approval"]))
    issued = int(time.time())
    expires = current_approval["expires_unix"]
    _require(type(expires) is int and issued < expires, "current_envelope_expired")
    request = {
        "schema": "AcademyCensusCurrentRequest.v1",
        "nonce": os.urandom(32).hex(),
        "issued_unix": issued,
        "expires_unix": min(issued + MAX_SECONDS, expires),
        "binding": binding,
    }
    _request(request)
    output = Path(_path(str(output)))
    intent = output / ("current-intent-" + request["nonce"] + ".json")
    C.write_new(intent, request)  # Durable before SSH; retained on every failure.
    _require(_profile(C, m, role, profile_ref) == profile, "profile_changed_before_SSH")
    raw = _Child().run(_argv(profile, peer_inputs["path"]), C.canonical(request) + b"\n", request["expires_unix"])
    response = C.decode(raw)
    _response(request, response)
    _authority(C, m, producer, active_authority, evidence)
    # Recheck actual profile/key/trust bytes and current authority after transport.
    _require(_profile(C, m, role, profile_ref) == profile, "profile_changed")
    _pin(C, local_inputs)
    _pin(C, local_index)
    _pin(C, local_source)
    _require(response["facts"] == _leaf_facts(operation, source), "live_reconstruction_mismatch")
    result = {
        "schema": "AcademyCensusTransportEvidence.v1",
        "intent": {"path": str(intent), "sha256": hashlib.sha256(C.canonical(request) + b"\n").hexdigest()},
        "request": request,
        "response": response,
        "cleanup_confirmed": True,
    }
    C.write_new(output / ("current-result-" + request["nonce"] + ".json"), result)
    _ISSUED[request["nonce"]] = hashlib.sha256(C.canonical(result)).hexdigest()
    return result


def observe_local_leaf(C, m, evidence, protected_request):
    """Only fixed nonrecursive physical observers run on the peer."""
    producer = _trusted(C, m)
    binding = _request(protected_request)
    role, operation = binding["role"], binding["operation"]
    _require(socket.gethostname() == binding["hostname"] == m["roles"][role]["hostname"], "actual_peer_hostname")
    _authority(C, m, producer, binding["active_authority"], evidence)
    _require(
        binding["producer_sha256"] == m["helpers"]["external_census"]
        and binding["transport_sha256"] == m["helpers"]["census_transport"],
        "actual_peer_sources",
    )
    source = C.decode(_pin(C, binding["original_source"]))
    for name in ("candidate", "tree", "attempt", "role", "hostname", "producer_sha256"):
        _require(source[name] == binding[name], "peer_original_binding")
    _require(
        binding["candidate"] == m["candidate"]
        and binding["tree"] == m["tree"]
        and binding["attempt"] == evidence.a["attempt"]
        and binding["authority_scope_sha256"] == producer.load_scope(C, m)[1]
        and binding["execution_manifest_sha256"] == evidence.manifest_hash
        and binding["execution_approval_sha256"] == evidence.approval_hash,
        "peer_current_binding",
    )
    _require(
        binding["gate_epoch"] == source["facts"].get("hold_id", source["facts"].get("gate_epoch")),
        "peer_original_epoch",
    )
    if operation != "gate-web":
        _require(
            binding["original_stop_ref"]["sha256"] == source["facts"]["quiesce_receipt_sha256"],
            "peer_original_stop_join",
        )
    bootstrap = C.decode(_pin(C, binding["peer_inputs"]))
    _validate_bootstrap(C, m, bootstrap, binding, binding["peer_inputs"]["path"])
    _require(
        bootstrap["common"]
        == {"path": str(Path(__file__).absolute().with_name("candidate_execute.py")), "sha256": m["self_sha256"]},
        "actual_peer_bootstrap_common",
    )
    index_raw = _pin(C, binding["peer_evidence_index"])
    _seed_index(C, index_raw)
    _require(evidence.sha256 == binding["peer_evidence_index"]["sha256"], "actual_peer_E_index_hash")
    # Replay reservation is root-private, exclusive and retained on every failure.
    C.write_new(
        str(
            Path(binding["peer_inputs"]["path"]).parent / ("current-peer-nonce-" + protected_request["nonce"] + ".json")
        ),
        protected_request,
    )
    started = int(time.time())
    if operation == "gate-web":
        facts = producer._gate(C, m, evidence, "web")
    else:
        stopped = C.stopped(role, m)
        facts = {
            "units": stopped["units"],
            "application_pids": stopped["matching_application_pids"],
            "preserved": C.preserved(role, m),
        }
    _authority(C, m, producer, binding["active_authority"], evidence)
    _pin(C, binding["peer_inputs"])
    _pin(C, binding["peer_evidence_index"])
    _pin(C, binding["original_source"])
    _require(evidence.sha256 == binding["peer_evidence_index"]["sha256"], "actual_peer_E_index_hash_after")
    _require(facts == _leaf_facts(operation, source), "peer_live_reconstruction")
    response = {
        "schema": "AcademyCensusCurrentLeaf.v1",
        "request": protected_request,
        "observed_unix_started": started,
        "observed_unix_finished": int(time.time()),
        "facts": facts,
    }
    _response(protected_request, response)
    return response


def verify_current(C, m, evidence, expected_binding, source_ref, transport_evidence):
    """Consume an exact locally issued durable challenge, never arbitrary JSON."""
    producer = _trusted(C, m)
    _exact(transport_evidence, ("schema", "intent", "request", "response", "cleanup_confirmed"))
    _require(
        transport_evidence["schema"] == "AcademyCensusTransportEvidence.v1"
        and transport_evidence["cleanup_confirmed"] is True,
        "transport_evidence",
    )
    request = C.decode(_pin(C, transport_evidence["intent"], MAX_REQUEST))
    _require(
        request == transport_evidence["request"] and request["binding"] == expected_binding, "local_issued_binding"
    )
    _require(
        _ISSUED.pop(request["nonce"], None) == hashlib.sha256(C.canonical(transport_evidence)).hexdigest(),
        "live_nonce_not_issued_or_replayed",
    )
    evidence = _authority(C, m, producer, expected_binding["active_authority"], evidence)
    facts = _response(request, transport_evidence["response"])
    profile_ref = m.get("census_transport", {}).get(expected_binding["role"])
    _require(profile_ref is not None, "approved_existing_profile_required")
    mirror = archived_source_ref(
        C, m, expected_binding["role"], expected_binding["operation"], expected_binding["original_source"], profile_ref
    )
    _require(source_ref == mirror, "exact_local_mirror_ref")
    raw = _pin(C, source_ref)
    _require(source_ref["sha256"] == expected_binding["original_source"]["sha256"], "verified_source_bytes_required")
    source = C.decode(raw)
    _require(facts == _leaf_facts(expected_binding["operation"], source), "verified_live_facts")
    _authority(C, m, producer, expected_binding["active_authority"], evidence)
    # Exclusive durable consumption prevents replay, including across processes.
    C.write_new(transport_evidence["intent"]["path"] + ".consumed", {"nonce": request["nonce"]})
    return facts

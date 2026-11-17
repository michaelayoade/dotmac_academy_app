"""One-use KV reader protocol for an already-authorized custody ceremony.

This module creates no custody authority or approval. Its caller owns the pinned
private target/specification and supplies the genuine root/listener close hook.
No credential is released unless reader, policy and custody closure all succeed.
"""

import hashlib
import http.client
import json
import re
import socket
import threading
import time
from urllib.parse import urlsplit

RESPONSE_LIMIT = 262144
INVENTORY_LIMIT = 512
TTL = 600
CLOSE_FIELDS = ("root_revoked", "config_restored_exact", "socket_gone", "unsealed_healthy")


class ReaderRefused(Exception):
    """Fixed safe code only; never include API bodies, credentials or exceptions."""


def require(value, code):
    if not value:
        raise ReaderRefused(code)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def constant(_value):
        raise ReaderRefused("nonfinite_json")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError):
        raise ReaderRefused("invalid_json") from None
    require(type(value) is dict, "response_object_required")
    return value


class LoopbackAPI:
    """Bounded direct HTTP, with no proxy, DNS target or redirect following."""

    def __init__(self, endpoint):
        parsed = urlsplit(endpoint)
        require(parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "::1")
                and parsed.username is None and parsed.password is None
                and parsed.path in ("", "/") and not parsed.query and not parsed.fragment,
                "untrusted_endpoint")
        require(type(parsed.port) is int and 0 < parsed.port < 65536, "explicit_port_required")
        self.host, self.port = parsed.hostname, parsed.port

    def __call__(self, method, path, token, body=None, *, deadline=None):
        deadline = min(time.monotonic() + 15, deadline) if deadline is not None else time.monotonic() + 15
        require(time.monotonic() < deadline, "request_deadline")
        require(method in ("GET", "POST", "PUT", "DELETE", "LIST"), "method_refused")
        require(type(path) is str and 0 < len(path) <= 1024
                and all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) and part not in (".", "..")
                        for part in path.split("/")), "api_path_refused")
        require(token is None or (type(token) is str and re.fullmatch(r"[A-Za-z0-9_.-]{8,4096}", token)),
                "token_shape_refused")
        data = None if body is None else json.dumps(body, allow_nan=False).encode()
        require(data is None or len(data) <= RESPONSE_LIMIT, "request_bound")
        connection = http.client.HTTPConnection(self.host, self.port, timeout=max(0.01, deadline - time.monotonic()))
        stop = threading.Event()
        guard = watchdog = None
        try:
            connection.connect()
            guard = connection.sock.dup()

            def expire():
                if not stop.wait(max(0, deadline - time.monotonic())):
                    try:
                        guard.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

            watchdog = threading.Thread(target=expire, daemon=True)
            watchdog.start()
            headers = {"Content-Type": "application/json"}
            if token is not None:
                headers["X-Vault-Token"] = token
            connection.request(method, "/v1/" + path, data, headers)
            response = connection.getresponse()
            length = response.getheader("Content-Length")
            require(length is None or (re.fullmatch(r"[0-9]{1,12}", length)
                    and int(length) <= RESPONSE_LIMIT), "response_bound")
            raw = response.read(RESPONSE_LIMIT + 1)
            require(time.monotonic() < deadline, "request_deadline")
            require(len(raw) <= RESPONSE_LIMIT, "response_bound")
            require(length is None or len(raw) == int(length), "incomplete_response")
            require(not 300 <= response.status < 400, "redirect_refused")
            return response.status, strict_json(raw) if raw else {}
        except ReaderRefused:
            raise
        except Exception:
            raise ReaderRefused("transport_uncertain") from None
        finally:
            stop.set()
            connection.close()
            if watchdog is not None:
                watchdog.join(timeout=1)
            if guard is not None:
                guard.close()


class _BudgetAPI:
    def __init__(self, api, seconds):
        self.api = api
        self.deadline = time.monotonic() + seconds

    def __call__(self, method, path, token, body=None):
        require(time.monotonic() < self.deadline, "phase_deadline")
        result = self.api(method, path, token, body, deadline=self.deadline)
        require(time.monotonic() < self.deadline, "phase_deadline")
        return result


def policy_text(path):
    require(type(path) is str and 0 < len(path) <= 512, "record_path_refused")
    parts = path.split("/")
    require(len(parts) >= 3 and parts[1] == "data"
            and all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) and part not in (".", "..")
                    for part in parts), "record_path_refused")
    return 'path "' + path + '" {\n  capabilities = ["read"]\n}\n'


def close_custody(backend, run, root):
    """Invoke the pinned custody backend, not caller-authored closure flags.

    Even failed root retirement must attempt listener/configuration restoration.
    The private caller protects and pins `backend` and the genuine run ledger.
    """
    revoked = restored = {}
    try:
        revoked = backend.revoke_root(run, root)
    except BaseException:
        revoked = {"root_revoked": False}
    finally:
        try:
            restored = backend.cmd_breakglass_off(run).get("breakglass_off", {})
        except BaseException:
            restored = {}
    require(type(revoked) is dict and revoked.get("root_revoked") is True
            and type(restored) is dict and restored.get("config_restored_exact") is True
            and restored.get("socket_gone") is True and restored.get("unsealed_after_restart") is True
            and type(restored.get("tcp_after")) is int and restored["tcp_after"] == 405,
            "custody_backend_closure_unproved")
    return {"root_revoked": True, "config_restored_exact": True, "socket_gone": True,
            "unsealed_healthy": True, "tcp_generate_root_code": 405}


def validate_handoff(raw, *, run, sources, policy, policy_sha256, fields, now):
    """Validate a fresh packet from the pinned authenticated private server pipe.

    This is a transport/structure check, not authentication of an authored JSON
    receipt. The caller owns SSH/server custody and never logs the raw packet.
    """
    require(type(raw) is bytes and 0 < len(raw) <= 65536, "handoff_packet_bound")
    value = strict_json(raw)
    require(set(value) == {"schema", "run", "reader_sha256", "base_sha256", "server_sha256",
                           "observed_unix", "evidence", "credentials"}, "handoff_shape_refused")
    require(set(sources) == {"reader_sha256", "base_sha256", "server_sha256"}
            and all(type(sha) is str and re.fullmatch(r"[0-9a-f]{64}", sha) for sha in sources.values())
            and all(value.get(key) == expected for key, expected in sources.items()), "handoff_source_refused")
    require(value["schema"] == "AcademyHeldAdminCredentialHandoff.v1" and value["run"] == run
            and type(value["observed_unix"]) is int and type(now) is int
            and 0 <= now - value["observed_unix"] <= 120, "handoff_identity_or_age_refused")
    evidence = value["evidence"]
    require(type(evidence) is dict and evidence.get("schema") == "OneUseCredentialReadEvidence.v1"
            and evidence.get("run") == run and evidence.get("policy") == policy
            and evidence.get("policy_sha256") == policy_sha256
            and evidence.get("reader_retired") is True and evidence.get("policy_retired") is True
            and type(evidence.get("data_gets")) is int and evidence["data_gets"] == 1
            and evidence.get("handoff_attempted") is True and evidence.get("handoff_performed") is False,
            "handoff_evidence_refused")
    closure = evidence.get("closure")
    require(type(closure) is dict and all(closure.get(key) is True for key in CLOSE_FIELDS)
            and type(closure.get("tcp_generate_root_code")) is int
            and closure["tcp_generate_root_code"] == 405, "handoff_closure_refused")
    credentials = value["credentials"]
    require(type(credentials) is dict and set(credentials) == set(fields)
            and all(type(credentials[field]) is str and 0 < len(credentials[field].encode()) <= 16000
                    and "\0" not in credentials[field] for field in fields), "handoff_fields_refused")
    return dict(credentials)


def _ok(api, root, method, path, body=None):
    status, value = api(method, path, root, body)
    require(200 <= status < 300, "issuer_request_refused")
    return value


def _owned_tokens(api, root, policy, run):
    keys = _ok(api, root, "LIST", "auth/token/accessors").get("data", {}).get("keys")
    require(type(keys) is list and len(keys) <= INVENTORY_LIMIT and len(set(keys)) == len(keys)
            and all(type(key) is str and re.fullmatch(r"[A-Za-z0-9_.-]{8,128}", key) for key in keys),
            "token_inventory_refused")
    owned = []
    for accessor in keys:
        status, value = api("POST", "auth/token/lookup-accessor", root, {"accessor": accessor})
        if status == 400:
            continue
        require(status == 200, "accessor_lookup_uncertain")
        data = value.get("data", {})
        if policy in data.get("policies", []):
            # A mis-shaped token still belongs to this run and must be retired.
            # A holder from another run must never be adopted or revoked.
            require(data.get("meta") == {"ceremony": run}, "foreign_policy_holder")
            owned.append(accessor)
    return owned


def _retire(api, root, policy, text, run, create_attempted, known_accessor):
    """Independent reserved cleanup budgets; an inventory error cannot starve policy removal."""
    errors = []

    def retire_accessor(bounded, accessor):
        status, value = bounded("POST", "auth/token/lookup-accessor", root, {"accessor": accessor})
        if status == 400:
            return
        data = value.get("data", {})
        require(status == 200 and policy in data.get("policies", [])
                and data.get("meta") == {"ceremony": run}, "accessor_ownership_unproved")
        _ok(bounded, root, "POST", "auth/token/revoke-accessor", {"accessor": accessor})
        status, _ = bounded("POST", "auth/token/lookup-accessor", root, {"accessor": accessor})
        require(status == 400, "reader_retirement_unproved")

    if known_accessor is not None:
        try:
            retire_accessor(_BudgetAPI(api, 10), known_accessor)
        except BaseException:
            errors.append("known_reader_retirement_unproved")
    if create_attempted:
        try:
            bounded = _BudgetAPI(api, 10)
            # Recovers an orphan even if its create response was lost. No create retry.
            for accessor in _owned_tokens(bounded, root, policy, run):
                retire_accessor(bounded, accessor)
        except BaseException:
            errors.append("reader_inventory_unproved")
    try:
        bounded = _BudgetAPI(api, 10)
        status, value = bounded("GET", "sys/policies/acl/" + policy, root)
        if status != 404:
            require(status == 200 and value.get("data", {}).get("policy") == text, "owned_policy_changed")
            _ok(bounded, root, "DELETE", "sys/policies/acl/" + policy)
            status, _ = bounded("GET", "sys/policies/acl/" + policy, root)
            require(status == 404, "policy_retirement_unproved")
    except BaseException:
        errors.append("policy_retirement_unproved")
    require(not errors, "reader_or_policy_retirement_unproved")


def _verify_reader(api, root, token, accessor, policy, path, run):
    data = _ok(api, root, "POST", "auth/token/lookup-accessor", {"accessor": accessor}).get("data", {})
    require(data.get("policies") == [policy] and data.get("identity_policies", []) == []
            and not data.get("entity_id") and data.get("type") == "service"
            and data.get("orphan") is True and data.get("renewable") is False
            and type(data.get("num_uses")) is int and data["num_uses"] == 1
            and type(data.get("explicit_max_ttl")) is int and data["explicit_max_ttl"] == TTL
            and type(data.get("ttl")) is int and 0 < data["ttl"] <= TTL
            and data.get("meta") == {"ceremony": run}, "reader_shape_refused")
    denied = [path + "-other", path + "/child", path.replace("/data/", "/metadata/", 1),
              "sys/mounts", "auth/token/lookup-self", "auth/token/revoke-self"]
    paths = [path, *denied]
    value = _ok(api, root, "POST", "sys/capabilities-accessor", {"accessor": accessor, "paths": paths})
    caps = value.get("data", value)
    require(caps.get(path) == ["read"] and all(caps.get(p) == ["deny"] for p in denied),
            "capability_matrix_refused")
    after = _ok(api, root, "POST", "auth/token/lookup-accessor", {"accessor": accessor}).get("data", {})
    require(after.get("num_uses") == 1, "accessor_checks_consumed_use")
    require(type(token) is str and token, "reader_token_missing")


def acquire_once(api, root, *, run, policy, path, fields, close_authority, handoff, audit):
    """Caller hooks are protected custody code, never authored receipt/flag inputs.

    `close_authority` must reproduce root/config/socket/health closure. `handoff`
    is called once, after closure, with only the selected held fields. Its result
    and audit callbacks must never serialize credential values. No API data GET,
    token creation or handoff is automatically retried on uncertainty.
    """
    held, token, text = {}, "", ""
    known_accessor = None
    raw_api = api
    api = _BudgetAPI(raw_api, 45)
    error = None
    policy_attempted = create_attempted = retired = False
    closure = {}
    started = time.monotonic()
    evidence = {"schema": "OneUseCredentialReadEvidence.v1", "reader_retired": False,
                "policy_retired": False, "data_gets": 0, "handoff_attempted": False,
                "handoff_performed": False}
    try:
        require(type(root) is str and re.fullmatch(r"[A-Za-z0-9_.-]{8,4096}", root), "issuer_token_refused")
        require(type(run) is str and re.fullmatch(r"[A-Za-z0-9_-]{8,64}", run), "run_refused")
        require(type(policy) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{7,100}", policy), "policy_name_refused")
        require(type(fields) is tuple and 1 <= len(fields) <= 4 and len(set(fields)) == len(fields)
                and all(type(field) is str and re.fullmatch(r"[A-Za-z0-9_]{1,64}", field) for field in fields),
                "field_selection_refused")
        text = policy_text(path)
        evidence.update(run=run, policy=policy, policy_sha256=hashlib.sha256(text.encode()).hexdigest())
        me = _ok(api, root, "GET", "auth/token/lookup-self").get("data", {})
        require("root" in me.get("policies", []), "genuine_custody_root_required")
        status, _ = api("GET", "sys/policies/acl/" + policy, root)
        require(status == 404, "policy_must_be_absent")
        audit("policy_create_attempt", dict(evidence))
        policy_attempted = True
        _ok(api, root, "PUT", "sys/policies/acl/" + policy, {"policy": text})
        require(_ok(api, root, "GET", "sys/policies/acl/" + policy).get("data", {}).get("policy") == text,
                "policy_readback_refused")
        audit("reader_create_attempt", dict(evidence))
        create_attempted = True
        auth = _ok(api, root, "POST", "auth/token/create-orphan", {
            "policies": [policy], "no_default_policy": True, "type": "service", "ttl": "600s",
            "explicit_max_ttl": "600s", "num_uses": 1, "renewable": False,
            "display_name": "one-use-credential-reader", "meta": {"ceremony": run},
        }).get("auth", {})
        token, accessor = auth.get("client_token"), auth.get("accessor")
        require(type(accessor) is str and re.fullmatch(r"[A-Za-z0-9_.-]{8,128}", accessor), "accessor_missing")
        known_accessor = accessor
        evidence["reader_accessor"] = accessor
        _verify_reader(api, root, token, accessor, policy, path, run)
        audit("one_data_get_attempt", dict(evidence))
        require(time.monotonic() - started < 120, "acquisition_deadline")
        evidence["data_gets"] = 1  # mark BEFORE the request; uncertain responses are never retried
        status, value = api("GET", path, token)
        require(status == 200, "single_read_refused")
        data = value.get("data", {}).get("data")
        require(type(data) is dict and all(type(data.get(field)) is str
                and 0 < len(data[field].encode()) <= 16000 and "\0" not in data[field] for field in fields),
                "credential_shape_refused")
        held = {field: data[field] for field in fields}
        value = data = None
    except BaseException as exc:
        error = exc if isinstance(exc, ReaderRefused) else ReaderRefused("acquisition_uncertain")
        held.clear()
    finally:
        try:
            # The protected caller uses this boundary to defer further signals
            # while mandatory retirement/root/listener cleanup is in progress.
            audit("cleanup_begin", dict(evidence))
        except BaseException:
            error = ReaderRefused("cleanup_audit_unproved")
            held.clear()
        if policy_attempted:
            try:
                _retire(raw_api, root, policy, text, run, create_attempted, known_accessor)
                retired = True
                evidence.update(reader_retired=True, policy_retired=True)
            except BaseException:
                error = ReaderRefused("reader_or_policy_retirement_unproved")
                held.clear()
        token = ""
        try:
            closure = close_authority()
            require(type(closure) is dict and all(closure.get(key) is True for key in CLOSE_FIELDS)
                    and type(closure.get("tcp_generate_root_code")) is int
                    and closure["tcp_generate_root_code"] == 405, "custody_closure_unproved")
        except BaseException:
            error = ReaderRefused("custody_closure_unproved")
            held.clear()
        root = ""
    try:
        require(error is None and retired and held, "credential_withheld")
        require(time.monotonic() - started < 120, "handoff_deadline")
        evidence["closure"] = {key: closure[key] for key in (*CLOSE_FIELDS, "tcp_generate_root_code")}
        audit("closure_verified", dict(evidence))
        # Only this trusted sink receives values. Do not retain, return or print its result.
        evidence["handoff_attempted"] = True
        audit("handoff_attempt", dict(evidence))
        handoff(held)
        evidence["handoff_performed"] = True
        audit("handoff_completed", dict(evidence))
        return evidence
    except BaseException:
        raise error if error is not None else ReaderRefused("handoff_unproved") from None
    finally:
        held.clear()

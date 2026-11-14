# ruff: noqa: S101 -- synthetic protocol qualification only.
"""No custody, host or real credential is used by these fault-injection cases."""

import copy
import json

import candidate_credential_reader as R
import pytest

PATH = "secret/data/synthetic/credential"
POLICY = "synthetic-reader-20990101"
RUN = "20990101T000000Z"
ROOT = "synthetic-issuer-only"
TOKEN = "synthetic-reader-only"  # noqa: S105 -- noncredential used only by the fake API
ACCESSOR = "synthetic-accessor-only"
CLOSE = {**dict.fromkeys(R.CLOSE_FIELDS, True), "tcp_generate_root_code": 405}


class API:
    def __init__(self, failure=None, exhaust=True):
        self.failure, self.exhaust = failure, exhaust
        self.policies, self.tokens = {}, {}
        self.calls = []
        self.data_gets = self.creates = 0

    def __call__(self, method, path, token, body=None, *, deadline=None):
        self.calls.append((method, path))
        if path == "auth/token/lookup-self":
            return 200, {"data": {"policies": ["root"], "accessor": "synthetic-root-accessor"}}
        if path == "sys/policies/acl/" + POLICY:
            if method == "PUT":
                self.policies[POLICY] = body["policy"]
                if self.failure == "policy_response_lost":
                    raise OSError("synthetic transport failure")
                return 204, {}
            if method == "DELETE":
                self.policies.pop(POLICY, None)
                return 204, {}
            return (200, {"data": {"policy": self.policies[POLICY]}}) if POLICY in self.policies else (404, {})
        if path == "auth/token/create-orphan":
            self.creates += 1
            data = {"policies": [POLICY], "identity_policies": [], "entity_id": "", "type": "service",
                    "orphan": True, "renewable": False, "num_uses": 1, "explicit_max_ttl": 600,
                    "ttl": 599, "meta": {"ceremony": RUN}}
            if self.failure == "wrong_shape":
                data["policies"] = ["default", POLICY]
            self.tokens[ACCESSOR] = data
            if self.failure == "create_response_lost":
                raise OSError("synthetic transport failure")
            return 200, {"auth": {"client_token": TOKEN, "accessor": ACCESSOR}}
        if path == "auth/token/accessors":
            if self.failure == "inventory_error":
                return 500, {}
            if self.failure == "inventory_bound":
                return 200, {"data": {"keys": ["synthetic-accessor-" + str(i) for i in range(513)]}}
            return 200, {"data": {"keys": list(self.tokens)}}
        if path == "auth/token/lookup-accessor":
            key = body["accessor"]
            return (200, {"data": copy.deepcopy(self.tokens[key])}) if key in self.tokens else (400, {})
        if path == "auth/token/revoke-accessor":
            if self.failure == "retirement_unavailable":
                return 500, {}
            self.tokens.pop(body["accessor"], None)
            return 204, {}
        if path == "sys/capabilities-accessor":
            if self.failure == "accessor_consumes_use":
                self.tokens[ACCESSOR]["num_uses"] = 0
            return 200, {"data": {p: ["read"] if p == PATH else ["deny"] for p in body["paths"]}}
        if path == PATH:
            assert method == "GET" and token == TOKEN
            self.data_gets += 1
            if self.failure == "read_response_lost":
                raise OSError("synthetic transport failure")
            if self.exhaust:
                self.tokens.pop(ACCESSOR, None)
            return 200, {"data": {"data": {"username": "synthetic-user", "password": "synthetic-held-value",
                                           "unselected": "synthetic-unselected"}}}
        raise AssertionError("unexpected synthetic API request")


def acquire(api, *, closure=None, audit=None, handoff=None):
    events, received = [], []

    def close():
        events.append("close")
        return dict(CLOSE) if closure is None else closure

    def deliver(fields):
        events.append("handoff")
        received.append(dict(fields))
        if handoff is not None:
            handoff(fields)

    result = R.acquire_once(api, ROOT, run=RUN, policy=POLICY, path=PATH,
                            fields=("username", "password"), close_authority=close,
                            handoff=deliver, audit=audit or (lambda *_args: None))
    return result, events, received


@pytest.mark.parametrize("exhaust", [False, True])
def test_one_get_and_selected_memory_handoff_after_reader_policy_and_authority_close(exhaust):
    api = API(exhaust=exhaust)
    evidence, events, received = acquire(api)
    assert events == ["close", "handoff"]
    assert received == [{"username": "synthetic-user", "password": "synthetic-held-value"}]
    assert api.data_gets == api.creates == 1 and not api.tokens and not api.policies
    assert evidence["reader_retired"] and evidence["policy_retired"] and evidence["handoff_performed"]
    assert "synthetic-held-value" not in json.dumps(evidence)


@pytest.mark.parametrize("failure", ["policy_response_lost", "create_response_lost", "wrong_shape",
                                     "accessor_consumes_use", "read_response_lost"])
def test_uncertainty_or_bad_reader_never_retries_or_hands_off_and_retires_owned_orphan(failure):
    api = API(failure=failure)
    closed, delivered = [], []
    with pytest.raises(R.ReaderRefused):
        R.acquire_once(api, ROOT, run=RUN, policy=POLICY, path=PATH, fields=("password",),
                       close_authority=lambda: closed.append(True) or dict(CLOSE),
                       handoff=delivered.append, audit=lambda *_args: None)
    assert closed == [True] and delivered == []
    assert api.creates <= 1 and api.data_gets <= 1
    assert not api.tokens and not api.policies


def test_preexisting_policy_is_never_adopted_deleted_or_used():
    api = API()
    api.policies[POLICY] = R.policy_text(PATH)
    with pytest.raises(R.ReaderRefused):
        acquire(api)
    assert POLICY in api.policies and api.creates == api.data_gets == 0


def test_unproved_orphan_retirement_withholds_credential_even_if_root_close_claims_success():
    api = API(failure="retirement_unavailable", exhaust=False)
    delivered = []
    with pytest.raises(R.ReaderRefused, match="retirement"):
        R.acquire_once(api, ROOT, run=RUN, policy=POLICY, path=PATH, fields=("password",),
                       close_authority=lambda: dict(CLOSE), handoff=delivered.append, audit=lambda *_args: None)
    assert api.data_gets == 1 and api.tokens and delivered == []
    assert not api.policies  # policy retirement is attempted even when token retirement fails


@pytest.mark.parametrize("failure", ["inventory_error", "inventory_bound"])
def test_known_accessor_and_policy_retire_even_when_inventory_cannot_be_proved(failure):
    api = API(failure=failure, exhaust=False)
    delivered = []
    with pytest.raises(R.ReaderRefused):
        R.acquire_once(api, ROOT, run=RUN, policy=POLICY, path=PATH, fields=("password",),
                       close_authority=lambda: dict(CLOSE), handoff=delivered.append, audit=lambda *_args: None)
    assert api.data_gets == 1 and delivered == []
    assert not api.tokens and not api.policies


@pytest.mark.parametrize("field", [*R.CLOSE_FIELDS, "tcp_generate_root_code"])
def test_incomplete_custody_closure_withholds_values(field):
    api = API()
    closure = dict(CLOSE)
    closure[field] = False
    with pytest.raises(R.ReaderRefused, match="closure"):
        acquire(api, closure=closure)
    assert not api.tokens and not api.policies


def test_handoff_failure_is_not_repeated_and_has_an_attempt_event():
    api = API()
    attempted, audit = [], []

    def handoff(_fields):
        attempted.append(True)
        raise OSError("synthetic sink failure")

    with pytest.raises(R.ReaderRefused):
        acquire(api, handoff=handoff, audit=lambda phase, data: audit.append((phase, data)))
    assert attempted == [True]
    assert [data["handoff_attempted"] for phase, data in audit if phase == "handoff_attempt"] == [True]
    assert "handoff_completed" not in [phase for phase, _ in audit]


@pytest.mark.parametrize("path", ["secret/data/../other", "secret/data/x?query=y", "secret/data/x/", "other/x"])
def test_unsafe_record_path_is_refused_before_mutation_and_still_closes_authority(path):
    api = API()
    closed = []
    with pytest.raises(R.ReaderRefused):
        R.acquire_once(api, ROOT, run=RUN, policy=POLICY, path=path, fields=("password",),
                       close_authority=lambda: closed.append(True) or dict(CLOSE),
                       handoff=lambda _fields: pytest.fail("unexpected handoff"), audit=lambda *_args: None)
    assert closed == [True] and api.calls == []


@pytest.mark.parametrize("endpoint", ["https://example.invalid:8200", "http://localhost:8200",
                                     "http://127.0.0.1:8200/path", "http://u:p@127.0.0.1:8200",
                                     "http://127.0.0.1"])
def test_endpoint_requires_explicit_literal_loopback_port(endpoint):
    with pytest.raises(R.ReaderRefused):
        R.LoopbackAPI(endpoint)


def test_duplicate_nonfinite_or_nonobject_api_json_is_refused():
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[]'):
        with pytest.raises(R.ReaderRefused):
            R.strict_json(raw)


def test_expired_handoff_deadline_withholds_values_after_cleanup(monkeypatch):
    clock = [0]
    monkeypatch.setattr(R.time, "monotonic", lambda: clock[0])
    api = API()
    received = []

    def close():
        clock[0] = 121
        return dict(CLOSE)

    with pytest.raises(R.ReaderRefused):
        R.acquire_once(api, ROOT, run=RUN, policy=POLICY, path=PATH, fields=("password",),
                       close_authority=close, handoff=received.append, audit=lambda *_args: None)
    assert received == [] and not api.tokens and not api.policies


@pytest.mark.parametrize("failure", [None, "root", "restore"])
def test_genuine_backend_wiring_always_attempts_root_then_config_close(failure):
    events = []

    class Backend:
        def revoke_root(self, run, root):
            assert (run, root) == ("synthetic-run", ROOT)
            events.append("root")
            if failure == "root":
                raise OSError("synthetic revocation failure")
            return {"root_revoked": True}

        def cmd_breakglass_off(self, run):
            assert run == "synthetic-run"
            events.append("restore")
            if failure == "restore":
                raise OSError("synthetic restoration failure")
            return {"breakglass_off": {"config_restored_exact": True, "socket_gone": True,
                                      "unsealed_after_restart": True, "tcp_after": 405}}

    if failure is None:
        assert R.close_custody(Backend(), "synthetic-run", ROOT) == CLOSE
    else:
        with pytest.raises(R.ReaderRefused):
            R.close_custody(Backend(), "synthetic-run", ROOT)
    assert events == ["root", "restore"]

# ruff: noqa: S101 -- hosted native server, synthetic values and isolated dev roots only.
"""Explicitly selected by the hosted native job; no production custody is used."""

import os
import secrets
import socket
import subprocess
import time
from pathlib import Path

import candidate_credential_reader as R
import pytest


@pytest.fixture
def server():
    binary = Path(os.environ["ACADEMY_OPENBAO_NATIVE"])
    assert binary.is_file()
    root = secrets.token_hex(24)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env = dict(os.environ, BAO_DEV_ROOT_TOKEN_ID=root)
    process = subprocess.Popen(  # noqa: S603 -- hosted pinned executable, isolated synthetic dev server
        [str(binary), "server", "-dev", "-dev-listen-address=127.0.0.1:" + str(port)],
        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    api = R.LoopbackAPI("http://127.0.0.1:" + str(port))
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            assert process.poll() is None, "synthetic server exited before readiness"
            try:
                if api("GET", "sys/health", root)[0] == 200:
                    break
            except R.ReaderRefused:
                pass
            time.sleep(0.1)
        else:
            pytest.fail("synthetic server readiness deadline")
        yield api, root
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def issuer(api, root):
    status, value = api("POST", "auth/token/create-orphan", root,
                        {"policies": ["root"], "no_default_policy": True,
                         "ttl": "120s", "explicit_max_ttl": "120s", "renewable": False})
    assert status == 200
    return value["auth"]["client_token"]


@pytest.mark.parametrize("fault", [None, "create_response_lost", "read_response_lost", "closure_incomplete"])
def test_native_one_read_shape_accessor_budget_cleanup_and_handoff_contract(server, fault):
    api, root = server
    own_root = issuer(api, root)
    path = "secret/data/native/" + secrets.token_hex(8)
    run = "native_" + secrets.token_hex(8)
    policy = "native-reader-" + secrets.token_hex(8)
    values = {"username": "synthetic-user", "password": secrets.token_hex(24), "extra": "not-handed-off"}
    assert api("POST", path, root, {"data": values})[0] == 200
    calls, delivered, closed, remaining = [], [], [], []

    def observed(method, target, token, body=None, *, deadline=None):
        calls.append((method, target))
        result = api(method, target, token, body, deadline=deadline)
        if (target == "auth/token/lookup-accessor" and result[0] == 200
                and policy in result[1]["data"]["policies"]):
            remaining.append(result[1]["data"]["num_uses"])
        if fault == "create_response_lost" and target == "auth/token/create-orphan":
            raise OSError("synthetic lost response after successful create")
        if fault == "read_response_lost" and target == path:
            raise OSError("synthetic lost response after single data read")
        return result

    def close():
        # Root revocation is real. Listener/config flags below are hook-contract
        # fixtures, not a claim that this test performs a production ceremony.
        assert api("GET", "sys/policies/acl/" + policy, root)[0] == 404
        assert api("POST", "auth/token/revoke-self", own_root)[0] == 204
        assert api("GET", "auth/token/lookup-self", own_root)[0] == 403
        closed.append(True)
        proof = {**dict.fromkeys(R.CLOSE_FIELDS, True), "tcp_generate_root_code": 405}
        if fault == "closure_incomplete":
            proof["socket_gone"] = False
        return proof

    def handoff(fields):
        assert closed == [True]
        delivered.append(dict(fields))

    if fault is None:
        evidence = R.acquire_once(observed, own_root, run=run, policy=policy, path=path,
                                  fields=("username", "password"), close_authority=close,
                                  handoff=handoff, audit=lambda *_args: None)
        assert delivered == [{key: values[key] for key in ("username", "password")}]
        assert evidence["reader_retired"] and evidence["policy_retired"]
        assert evidence["handoff_performed"] and evidence["data_gets"] == 1
        assert remaining and all(n == 1 for n in remaining)
    else:
        with pytest.raises(R.ReaderRefused):
            R.acquire_once(observed, own_root, run=run, policy=policy, path=path,
                           fields=("username", "password"), close_authority=close,
                           handoff=handoff, audit=lambda *_args: None)
        assert delivered == []
    assert closed == [True]
    assert calls.count(("POST", "auth/token/create-orphan")) == 1
    assert calls.count(("GET", path)) == (0 if fault == "create_response_lost" else 1)
    assert api("GET", "sys/policies/acl/" + policy, root)[0] == 404
    status, result = api("LIST", "auth/token/accessors", root)
    assert status == 200
    for accessor in result["data"]["keys"]:
        status, result = api("POST", "auth/token/lookup-accessor", root, {"accessor": accessor})
        assert status == 200 and policy not in result["data"]["policies"]


def test_native_single_use_token_cannot_perform_a_second_data_read(server):
    api, root = server
    policy = "native-once-" + secrets.token_hex(8)
    path = "secret/data/native/once"
    assert api("POST", path, root, {"data": {"value": "synthetic"}})[0] == 200
    assert api("PUT", "sys/policies/acl/" + policy, root, {"policy": R.policy_text(path)})[0] == 204
    status, value = api("POST", "auth/token/create-orphan", root,
                        {"policies": [policy], "no_default_policy": True, "type": "service",
                         "num_uses": 1, "ttl": "600s", "explicit_max_ttl": "600s", "renewable": False})
    assert status == 200
    token = value["auth"]["client_token"]
    assert api("GET", path, token)[0] == 200
    assert api("GET", path, token)[0] == 403

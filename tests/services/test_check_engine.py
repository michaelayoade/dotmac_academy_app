from unittest.mock import MagicMock

from app.services.checks.engine import run_checks
from app.services.labengine.interface import ExecResult


def _engine(stdout="", code=0):
    e = MagicMock()
    e.exec.return_value = ExecResult(stdout, "", code)
    e.ssh_exec.return_value = ExecResult(stdout, "", code)
    return e


def test_probe_ping_pass():
    eng = _engine(stdout="2 packets transmitted, 2 received", code=0)
    checks = [
        {
            "id": "c1",
            "type": "probe",
            "node": "client",
            "probe": {"kind": "ping", "target": "10.9.0.{{o}}", "count": 2, "min_success": 1},
            "weight": 2,
        }
    ]
    out = run_checks(checks, eng, MagicMock(nodes={"client": "c"}), {"o": 1})
    assert out["score"] == 2
    assert out["max_score"] == 2
    assert out["per_check"][0]["pass"] is True


def test_command_jsonpath_fail_reports_actual():
    eng = _engine(stdout='{"state":"Idle"}', code=0)
    checks = [
        {
            "id": "bgp",
            "type": "command",
            "node": "r1",
            "command": "vtysh -c 'show ip bgp json'",
            "assert": {"jsonpath": "$.state", "equals": "Established"},
            "weight": 1,
        }
    ]
    out = run_checks(checks, eng, MagicMock(nodes={"r1": "r1c"}), {})
    assert out["score"] == 0
    assert out["per_check"][0]["pass"] is False
    assert out["per_check"][0]["actual"] == "Idle"


def test_command_jsonpath_pass_established():
    eng = _engine(stdout='{"state":"Established"}', code=0)
    checks = [
        {
            "id": "bgp",
            "type": "command",
            "node": "r1",
            "command": "vtysh -c 'show ip bgp json'",
            "assert": {"jsonpath": "$.state", "equals": "Established"},
            "weight": 3,
        }
    ]
    out = run_checks(checks, eng, MagicMock(nodes={"r1": "r1c"}), {})
    assert out["score"] == 3
    assert out["per_check"][0]["pass"] is True
    assert out["per_check"][0]["actual"] == "Established"


def test_command_transport_ssh_routes_to_ssh_exec():
    eng = _engine(stdout="anything", code=0)
    checks = [
        {
            "id": "ros",
            "type": "command",
            "node": "r1",
            "transport": "ssh",
            "user": "admin",
            "password": "{{pw}}",
            "command": "/interface print",
            "assert": {"regex": "ether1"},
            "weight": 1,
        }
    ]
    eng.ssh_exec.return_value = ExecResult("ether1: up", "", 0)
    out = run_checks(checks, eng, MagicMock(nodes={"r1": "r1c"}), {"pw": "secret"})
    eng.ssh_exec.assert_called_once()
    eng.exec.assert_not_called()
    _args, kwargs = eng.ssh_exec.call_args
    assert kwargs.get("user") == "admin"
    assert kwargs.get("password") == "secret"
    assert out["score"] == 1
    assert out["per_check"][0]["pass"] is True


def test_command_exit_code_default():
    eng = _engine(stdout="", code=0)
    checks = [{"id": "x", "type": "command", "node": "c", "command": "true", "weight": 1}]
    out = run_checks(checks, eng, MagicMock(nodes={"c": "cc"}), {})
    assert out["score"] == 1
    assert out["per_check"][0]["actual"] == 0
    assert out["per_check"][0]["expected"] == 0


def test_config_grep():
    eng = _engine(stdout="ip address 10.0.5.1/24\n", code=0)
    checks = [
        {
            "id": "cfg",
            "type": "config_grep",
            "node": "r1",
            "file": "/etc/frr/frr.conf",
            "contains": "10.0.{{o}}.1/24",
            "weight": 1,
        }
    ]
    out = run_checks(checks, eng, MagicMock(nodes={"r1": "r1c"}), {"o": 5})
    assert out["score"] == 1
    assert out["per_check"][0]["pass"] is True
    assert out["per_check"][0]["expected"] == "10.0.5.1/24"


def test_eval_check_shape():
    from app.services.checks.engine import eval_check

    eng = _engine(stdout="1 packets transmitted, 1 received", code=0)
    check = {
        "id": "p",
        "type": "probe",
        "node": "c",
        "probe": {"kind": "ping", "target": "10.0.0.1", "count": 1, "min_success": 1},
        "weight": 4,
    }
    res = eval_check(check, eng, MagicMock(nodes={"c": "cc"}), {})
    assert set(res) == {"id", "weight", "pass", "actual", "expected"}
    assert res["id"] == "p"
    assert res["weight"] == 4

from unittest.mock import MagicMock, patch

from app.services.labengine.containerlab import ContainerlabEngine
from app.services.labengine.interface import ExecResult, LabHandle


def test_exec_runs_docker_exec():
    eng = ContainerlabEngine(workdir="/tmp/labs")
    handle = MagicMock(nodes={"r1": "clab-dal-u1-linux-1-r1"})
    with patch("subprocess.run") as run:
        run.return_value = MagicMock(stdout="ok\n", stderr="", returncode=0)
        res = eng.exec(handle, "r1", ["echo", "ok"])
        assert isinstance(res, ExecResult)
        assert res.stdout.strip() == "ok"
        assert res.exit_code == 0
        args = run.call_args[0][0]
        assert args == ["docker", "exec", "clab-dal-u1-linux-1-r1", "echo", "ok"]
        assert args[:3] == ["docker", "exec", "clab-dal-u1-linux-1-r1"]


def test_deploy_writes_topology_and_calls_containerlab(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path))
    with patch("subprocess.run") as run:
        run.return_value = MagicMock(
            stdout='[{"name":"clab-i-r1","ipv4_address":"172.20.20.3/24","kind":"vr-ros"}]',
            stderr="",
            returncode=0,
        )
        h = eng.deploy(
            "name: x\ntopology:\n  nodes:\n    r1: {kind: vr-ros, image: vrnetlab/vr-routeros}",
            "i",
        )
        assert h.nodes["r1"].endswith("-r1")
        assert h.mgmt["r1"] == "172.20.20.3"
        assert h.kinds["r1"] == "vr-ros"


def test_ssh_exec_uses_mgmt_ip():
    eng = ContainerlabEngine(workdir="/tmp/labs")
    handle = LabHandle(
        instance_name="i",
        nodes={"r1": "c"},
        mgmt={"r1": "172.20.20.3"},
        kinds={"r1": "vr-ros"},
    )
    with patch("subprocess.run") as run:
        run.return_value = MagicMock(stdout="address\n", stderr="", returncode=0)
        res = eng.ssh_exec(handle, "r1", "/ip address print", user="admin", password="pw")
        assert res.exit_code == 0
        assert "admin@172.20.20.3" in run.call_args[0][0]

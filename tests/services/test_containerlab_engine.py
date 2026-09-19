import os
from unittest.mock import MagicMock, patch

import pytest

from app.services import lab_operations
from app.services.labengine import containerlab
from app.services.labengine.containerlab import ContainerlabEngine
from app.services.labengine.interface import ExecResult, LabHandle, WrongLabHostError


def test_exec_runs_docker_exec():
    eng = ContainerlabEngine(workdir="/tmp/labs", lab_host_role="lab")
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
        assert run.call_args.kwargs["timeout"] == 480


def test_external_command_timeouts_are_strictly_below_their_leases():
    assert (
        containerlab._DEPLOY_TIMEOUT_SECONDS
        < lab_operations.LEASE_SECONDS_BY_KIND["deploy"]
    )
    assert (
        containerlab._DESTROY_TIMEOUT_SECONDS
        < lab_operations.LEASE_SECONDS_BY_KIND["destroy"]
    )
    assert (
        containerlab._CHECK_COMMAND_TIMEOUT_SECONDS
        < lab_operations.LEASE_SECONDS_BY_KIND["check"]
    )


def test_deploy_writes_topology_and_calls_containerlab(tmp_path, monkeypatch):
    real_exists = os.path.exists
    monkeypatch.setattr(
        "app.services.labengine.containerlab.os.path.exists",
        lambda path: True if path == "/dev/kvm" else real_exists(path),
    )
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
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
    eng = ContainerlabEngine(workdir="/tmp/labs", lab_host_role="lab")
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


@pytest.mark.parametrize(
    "method", ["inventory", "deploy", "ssh_exec", "destroy", "reset", "exec", "status"]
)
def test_operations_refuse_on_web_host_without_side_effects(tmp_path, method):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="web")
    handle = LabHandle(instance_name="i", nodes={"r1": "c"}, mgmt={"r1": "127.0.0.1"}, kinds={"r1": "linux"})
    with patch("subprocess.run") as run:
        with pytest.raises(WrongLabHostError):
            {
                "inventory": eng.inventory,
                "deploy": lambda: eng.deploy("name: x", "i"),
                "ssh_exec": lambda: eng.ssh_exec(handle, "r1", "true"),
                "destroy": lambda: eng.destroy("i"),
                "reset": lambda: eng.reset("name: x", "i"),
                "exec": lambda: eng.exec(handle, "r1", ["true"]),
                "status": lambda: eng.status("i"),
            }[method]()
        run.assert_not_called()
    assert not (tmp_path / "i").exists()


def test_destroy_raises_when_containerlab_fails(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    topo = tmp_path / "i" / "topo.clab.yml"
    topo.parent.mkdir()
    topo.write_text("name: i")
    with patch("subprocess.run") as run:
        run.return_value = MagicMock(stdout="", stderr="permission denied", returncode=1)
        with pytest.raises(RuntimeError, match="destroy failed: permission denied"):
            eng.destroy("i")


def test_destroy_treats_an_absent_topology_as_already_destroyed(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    with patch("subprocess.run") as run:
        run.return_value = MagicMock(stdout="{}", stderr="", returncode=0)
        eng.destroy("missing")
    run.assert_called_once_with(
        ["sudo", "-n", "containerlab", "inspect", "--all", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert not (tmp_path / "missing").exists()


def test_destroy_uses_the_inspected_path_when_the_expected_topology_is_missing(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    with patch("subprocess.run") as run:
        run.side_effect = [
            MagicMock(
                stdout=(
                    '[{"lab_name":"missing","absLabPath":"/srv/labs/missing.clab.yml",'
                    '"state":"running"}]'
                ),
                stderr="",
                returncode=0,
            ),
            MagicMock(stdout="", stderr="", returncode=0),
        ]
        eng.destroy("missing")
    assert run.call_count == 2
    assert run.call_args_list[1].args[0] == [
        "sudo",
        "-n",
        "containerlab",
        "destroy",
        "-t",
        "/srv/labs/missing.clab.yml",
        "--cleanup",
    ]
    assert not (tmp_path / "missing").exists()


def test_inventory_maps_lab_names_to_inspected_topology_paths(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    one_path = str(tmp_path / "dal-one" / "topo.clab.yml")
    two_path = str(tmp_path / "dal-two" / "topo.clab.yml")
    with patch("subprocess.run") as run:
        run.return_value = MagicMock(
            stdout=(
                f'[{{"lab_name":"dal-one","absLabPath":"{one_path}"}},'
                f'{{"lab_name":"dal-two","labPath":"{two_path}"}}]'
            ),
            stderr="",
            returncode=0,
        )
        assert eng.inventory() == {
            "dal-one": one_path,
            "dal-two": two_path,
        }


def test_inventory_excludes_a_lab_whose_path_is_outside_this_engines_workdir(tmp_path):
    """A dal-*-named lab is not automatically Academy's — only its real path is proof.

    An unrelated containerlab lab on the same host could coincidentally share
    the ``dal-`` naming convention (an operator's own test, or plain
    coincidence). ``inventory()`` must exclude it rather than let
    ``reconcile_runtime`` treat it as a rowless orphan eligible for destroy.
    """
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    with patch("subprocess.run") as run:
        run.return_value = MagicMock(
            stdout=(
                '[{"lab_name":"dal-imposter",'
                '"absLabPath":"/some/other/operators/lab.clab.yml"}]'
            ),
            stderr="",
            returncode=0,
        )
        assert eng.inventory() == {}


def test_destroy_does_not_hide_an_inspection_failure(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    with patch("subprocess.run") as run:
        run.return_value = MagicMock(stdout="", stderr="runtime unavailable", returncode=1)
        with pytest.raises(RuntimeError, match="inspect failed: runtime unavailable"):
            eng.destroy("missing")


@pytest.mark.parametrize(
    "topology",
    [
        "nodes:\n  r1: {kind: vr-ros}",
        'topology:\n  nodes:\n    r1:\n      kind: "vr-ros"',
        "topology:\n  defaults:\n    kind: vr-ros\n  nodes:\n    r1: {}",
    ],
)
def test_vr_deploy_refuses_without_kvm_before_writing_or_shelling_out(
    tmp_path, monkeypatch, topology
):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    monkeypatch.setattr("app.services.labengine.containerlab.os.path.exists", lambda _: False)
    with patch("subprocess.run") as run, pytest.raises(RuntimeError, match="requires /dev/kvm"):
        eng.deploy(topology, "i")
    run.assert_not_called()
    assert not (tmp_path / "i").exists()

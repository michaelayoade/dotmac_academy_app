import os
import signal
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from app.services import lab_operations
from app.services.labengine import containerlab
from app.services.labengine.containerlab import ContainerlabEngine
from app.services.labengine.interface import ExecResult, LabHandle, WrongLabHostError


def _fake_popen(returncode: int = 0, stdout: str = "", stderr: str = "", pid: int = 4321):
    """A Popen-shaped double: ``.communicate()`` then ``.returncode``.

    Mirrors the real ``Popen`` contract that ``_run_contained`` relies on —
    ``communicate()`` returns the (stdout, stderr) pair, and ``.returncode``
    is only meaningful (and read) after that call.
    """
    proc = MagicMock()
    proc.pid = pid
    proc.communicate.return_value = (stdout, stderr)
    proc.returncode = returncode
    return proc


def test_exec_runs_docker_exec():
    eng = ContainerlabEngine(workdir="/tmp/labs", lab_host_role="lab")
    handle = MagicMock(nodes={"r1": "clab-dal-u1-linux-1-r1"})
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(stdout="ok\n")
        res = eng.exec(handle, "r1", ["echo", "ok"])
        assert isinstance(res, ExecResult)
        assert res.stdout.strip() == "ok"
        assert res.exit_code == 0
        args = popen.call_args[0][0]
        assert args == ["docker", "exec", "clab-dal-u1-linux-1-r1", "echo", "ok"]
        assert args[:3] == ["docker", "exec", "clab-dal-u1-linux-1-r1"]
        assert popen.call_args.kwargs["start_new_session"] is True
        assert popen.return_value.communicate.call_args.kwargs["timeout"] == 480


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
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(
            stdout='[{"name":"clab-i-r1","ipv4_address":"172.20.20.3/24","kind":"vr-ros"}]',
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
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(stdout="address\n")
        res = eng.ssh_exec(handle, "r1", "/ip address print", user="admin", password="pw")
        assert res.exit_code == 0
        assert "admin@172.20.20.3" in popen.call_args[0][0]


@pytest.mark.parametrize(
    "method", ["inventory", "deploy", "ssh_exec", "destroy", "reset", "exec", "status"]
)
def test_operations_refuse_on_web_host_without_side_effects(tmp_path, method):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="web")
    handle = LabHandle(instance_name="i", nodes={"r1": "c"}, mgmt={"r1": "127.0.0.1"}, kinds={"r1": "linux"})
    with patch("subprocess.Popen") as popen:
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
        popen.assert_not_called()
    assert not (tmp_path / "i").exists()


def test_destroy_raises_when_containerlab_fails(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    topo = tmp_path / "i" / "topo.clab.yml"
    topo.parent.mkdir()
    topo.write_text("name: i")
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(returncode=1, stderr="permission denied")
        with pytest.raises(RuntimeError, match="destroy failed: permission denied"):
            eng.destroy("i")


def test_destroy_treats_an_absent_topology_as_already_destroyed(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(stdout="{}")
        eng.destroy("missing")
    popen.assert_called_once_with(
        ["sudo", "-n", "containerlab", "inspect", "--all", "--format", "json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    assert not (tmp_path / "missing").exists()


def test_destroy_refuses_when_the_inspected_path_does_not_match_the_expected_topology(tmp_path):
    """An exact-name collision must not get destroyed at an unverified path.

    ``inspect`` reporting a different path for this exact instance_name would
    be anomalous for a lab this engine actually deployed (it always writes to
    ``self._topo_path(instance_name)``) — but nothing ruled that out before,
    so a same-named lab from elsewhere would have been destroyed wherever
    ``inspect`` said it lived. It must be refused instead.
    """
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(
            stdout=(
                '[{"lab_name":"missing","absLabPath":"/srv/labs/missing.clab.yml",'
                '"state":"running"}]'
            ),
        )
        with pytest.raises(RuntimeError, match="destroy refused"):
            eng.destroy("missing")
    popen.assert_called_once()  # only the inspect call; never proceeds to destroy


def test_destroy_uses_the_inspected_path_when_it_matches_the_expected_topology(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    expected_path = str(tmp_path / "missing" / "topo.clab.yml")
    with patch("subprocess.Popen") as popen:
        popen.side_effect = [
            _fake_popen(
                stdout=(
                    f'[{{"lab_name":"missing","absLabPath":"{expected_path}",'
                    f'"state":"running"}}]'
                ),
            ),
            _fake_popen(stdout=""),
        ]
        eng.destroy("missing")
    assert popen.call_count == 2
    assert popen.call_args_list[1].args[0] == [
        "sudo",
        "-n",
        "containerlab",
        "destroy",
        "-t",
        expected_path,
        "--cleanup",
    ]
    assert not (tmp_path / "missing").exists()


def test_inventory_maps_lab_names_to_inspected_topology_paths(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    one_path = str(tmp_path / "dal-one" / "topo.clab.yml")
    two_path = str(tmp_path / "dal-two" / "topo.clab.yml")
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(
            stdout=(
                f'[{{"lab_name":"dal-one","absLabPath":"{one_path}"}},'
                f'{{"lab_name":"dal-two","labPath":"{two_path}"}}]'
            ),
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
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(
            stdout=(
                '[{"lab_name":"dal-imposter",'
                '"absLabPath":"/some/other/operators/lab.clab.yml"}]'
            ),
        )
        assert eng.inventory() == {}


def test_destroy_does_not_hide_an_inspection_failure(tmp_path):
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(returncode=1, stderr="runtime unavailable")
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
    with patch("subprocess.Popen") as popen, pytest.raises(RuntimeError, match="requires /dev/kvm"):
        eng.deploy(topology, "i")
    popen.assert_not_called()
    assert not (tmp_path / "i").exists()


@pytest.mark.parametrize(
    "topology",
    [
        "nodes:\n  r1: {kind: vr-ros}",
        'topology:\n  nodes:\n    r1:\n      kind: "vr-ros"',
        "topology:\n  defaults:\n    kind: vr-ros\n  nodes:\n    r1: {}",
    ],
)
def test_vr_reset_refuses_the_redeploy_half_without_kvm(tmp_path, monkeypatch, topology):
    """reset() calls the unlocked deploy helper directly (to avoid a nested
    lock acquisition) rather than the public deploy() wrapper. The KVM
    fail-closed guard must still apply to it, not only to deploy() — a
    regression this once was, since it lives in ``_deploy_unlocked`` now,
    not only in the ``deploy()`` wrapper.

    destroy() running first (and its own file-missing fallback inspect
    subprocess call) is existing, unchanged behavior — only the doomed
    deploy attempt itself must never be reached.
    """
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    monkeypatch.setattr("app.services.labengine.containerlab.os.path.exists", lambda _: False)
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(stdout="{}")
        with pytest.raises(RuntimeError, match="requires /dev/kvm"):
            eng.reset(topology, "i")
        deploy_calls = [c for c in popen.call_args_list if "deploy" in c.args[0]]
        assert deploy_calls == []
    assert not (tmp_path / "i").exists()


# --- Stage 1 process-containment: _run_contained / _terminate_process_group ---


@pytest.mark.parametrize(
    "call_site",
    [
        lambda eng: eng.inventory(),
        lambda eng: eng.deploy("name: x", "i"),
        lambda eng: eng.destroy("i"),
        lambda eng: eng.exec(
            LabHandle(instance_name="i", nodes={"r1": "c"}, mgmt={"r1": "1.2.3.4"}, kinds={"r1": "linux"}),
            "r1",
            ["true"],
        ),
        lambda eng: eng.ssh_exec(
            LabHandle(instance_name="i", nodes={"r1": "c"}, mgmt={"r1": "1.2.3.4"}, kinds={"r1": "linux"}),
            "r1",
            "true",
        ),
    ],
)
def test_every_call_site_runs_in_its_own_session(tmp_path, call_site):
    """Every one of the five call sites goes through _run_contained with
    start_new_session=True — the property os.killpg relies on."""
    eng = ContainerlabEngine(workdir=str(tmp_path), lab_host_role="lab")
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(stdout="[]")
        call_site(eng)
        assert popen.called
        for call in popen.call_args_list:
            assert call.kwargs["start_new_session"] is True
            assert call.kwargs["stdout"] == subprocess.PIPE
            assert call.kwargs["stderr"] == subprocess.PIPE
            assert call.kwargs["text"] is True


def _spawn_grandchild_tree(marker_dir: str) -> list[str]:
    """A command whose direct child immediately forks a grandchild, both of
    which sleep far longer than any test timeout and write a pidfile so the
    test can check whether they are still alive after cleanup.
    """
    script = f"""
import os, sys, time
open({os.path.join(marker_dir, "child.pid")!r}, "w").write(str(os.getpid()))
pid = os.fork()
if pid == 0:
    open({os.path.join(marker_dir, "grandchild.pid")!r}, "w").write(str(os.getpid()))
    time.sleep(60)
    sys.exit(0)
time.sleep(60)
"""
    return [sys.executable, "-c", script]


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    else:
        return True


def _spy_on_real_popen(monkeypatch) -> list[subprocess.Popen]:
    """Let ``_run_contained`` spawn a genuinely real OS process (through the
    real, unmocked ``subprocess.Popen``) while also capturing a handle to it
    for the test to inspect afterwards — proving OS-level signal delivery
    against a real process, not a ``MagicMock`` standing in for one.
    """
    created: list[subprocess.Popen] = []
    real_popen = subprocess.Popen

    def _spy(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        created.append(proc)
        return proc

    monkeypatch.setattr(subprocess, "Popen", _spy)
    return created


def test_timeout_terminates_a_real_spawned_child_process(monkeypatch):
    """A real (non-mock) child process is actually gone after a timeout."""
    created = _spy_on_real_popen(monkeypatch)
    cmd = [sys.executable, "-c", "import time; time.sleep(60)"]
    with pytest.raises(subprocess.TimeoutExpired):
        containerlab._run_contained(cmd, timeout=0.2)
    proc = created[0]
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _pid_alive(proc.pid):
            time.sleep(0.05)
        assert not _pid_alive(proc.pid), "child process survived timeout teardown"
    finally:
        if _pid_alive(proc.pid):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)


def test_timeout_terminates_an_orphaned_grandchild_too(tmp_path, monkeypatch):
    """The core process-group property: a grandchild the direct child forked
    must be gone too, not just the direct child — proving the teardown
    signals the whole group (os.killpg), not just proc itself.
    """
    marker = tmp_path / "markers"
    marker.mkdir()
    created = _spy_on_real_popen(monkeypatch)
    cmd = _spawn_grandchild_tree(str(marker))
    # Timeout is well above the near-instant fork(), so the grandchild is
    # already alive by the time _run_contained's communicate() times out.
    with pytest.raises(subprocess.TimeoutExpired):
        containerlab._run_contained(cmd, timeout=1.0)
    proc = created[0]
    try:
        assert (marker / "grandchild.pid").exists(), "grandchild never started"
        grandchild_pid = int((marker / "grandchild.pid").read_text())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _pid_alive(grandchild_pid):
            time.sleep(0.05)
        assert not _pid_alive(grandchild_pid), "grandchild outlived process-group teardown"
    finally:
        if _pid_alive(proc.pid):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        proc.wait(timeout=5)


def test_cancellation_mid_communicate_follows_the_same_group_cleanup_path(monkeypatch):
    """A non-timeout exception raised mid-communicate (e.g. KeyboardInterrupt
    reaching this call) must still tear down the process group before
    propagating, not just a TimeoutExpired. The exception itself is
    simulated via monkeypatch on the real process's ``communicate`` — the
    process it stands in for is a genuinely real, separately spawned OS
    process, so signal delivery is still proven against the real thing.
    """
    cmd = [sys.executable, "-c", "import time; time.sleep(60)"]
    real_proc = subprocess.Popen(cmd, start_new_session=True)  # noqa: S603
    monkeypatch.setattr(
        real_proc, "communicate", MagicMock(side_effect=KeyboardInterrupt())
    )
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: real_proc)
    try:
        with pytest.raises(KeyboardInterrupt):
            containerlab._run_contained(cmd, timeout=30)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _pid_alive(real_proc.pid):
            time.sleep(0.05)
        assert not _pid_alive(real_proc.pid), "child survived a cancelled communicate()"
    finally:
        if _pid_alive(real_proc.pid):
            os.killpg(real_proc.pid, signal.SIGKILL)
        real_proc.wait(timeout=5)


def test_run_contained_returns_a_completed_process_shaped_result():
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(returncode=0, stdout="ok", stderr="")
        result = containerlab._run_contained(["true"], timeout=5)
    assert isinstance(result, subprocess.CompletedProcess)
    assert result.returncode == 0
    assert result.stdout == "ok"
    assert result.stderr == ""


def test_run_contained_nonzero_exit_still_returns_normally():
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_popen(returncode=1, stdout="", stderr="boom")
        result = containerlab._run_contained(["false"], timeout=5)
    assert result.returncode == 1
    assert result.stderr == "boom"


def test_terminate_process_group_swallows_already_terminated_process():
    """ProcessLookupError at either signalling step must not mask the caller's
    real exception — it means the group is already gone, not a new failure.
    """
    proc = MagicMock()
    proc.pid = 99999999  # exceedingly unlikely to be a real pid
    with patch(
        "app.services.labengine.containerlab.os.killpg",
        side_effect=ProcessLookupError,
    ):
        containerlab._terminate_process_group(proc)  # must not raise
    proc.wait.assert_called_once()

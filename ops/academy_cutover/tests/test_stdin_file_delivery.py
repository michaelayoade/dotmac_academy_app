# ruff: noqa: S101 -- assertions qualify the closed hosted process adapter.
"""Hosted POSIX delivery regression; one fixed local child, never SSH or a DB."""

import hashlib
import importlib.util
import inspect
import json
import os
import socket
import stat
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

# Capture before conftest's autouse refusal fixture replaces process entry points.
# Keep this capability private; the adapter never forwards caller argv or env.
_ORIGINAL_POPEN = subprocess.Popen
assert _ORIGINAL_POPEN.__module__ == "subprocess"
assert inspect.getfile(_ORIGINAL_POPEN) == subprocess.__file__
assert Path(subprocess.__file__).resolve() == Path(sysconfig.get_path("stdlib")) / "subprocess.py"

_SSH_ARGV = [
    "/usr/bin/ssh", "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oForwardAgent=no",
    "-oClearAllForwardings=yes", "-oConnectTimeout=15", "-oConnectionAttempts=1",
    "-oServerAliveInterval=15", "-oServerAliveCountMax=3", "stdio-test.invalid",
    "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/root synthetic-stdin-read",
]
_CHILD = """
import hashlib,json,os,signal,sys,time
signal.alarm(10)
time.sleep(1.25)
while not os.path.exists("read-go"):
    time.sleep(0.01)
data=sys.stdin.buffer.read()
print(json.dumps({"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),
                  "eof":sys.stdin.buffer.read(1)==b""}),flush=True)
"""


@pytest.fixture
def delivery(tmp_path, monkeypatch, pytestconfig, refuse_external_operations):
    """Replace only Popen with an argv-closed adapter after default refusals."""
    assert os.name == "posix" and sys.platform == "linux"
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert pytestconfig.inipath.resolve() == Path(__file__).parents[1] / "pytest.ini"
    spec = importlib.util.spec_from_file_location(
        "hosted_management_stdio_subject", Path(__file__).with_name("management_stdio_subject.py")
    )
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    subject.BASE = tmp_path
    subject.SSH = {"web": "stdio-test.invalid"}
    processes = []
    state = {"timeouts": 0, "tamper": False, "spawn_offsets": [], "released": False}

    class ObservedChild:
        def __init__(self, child, input_path):
            self.child = child
            self.input_path = input_path
            self.pid = child.pid

        @property
        def returncode(self):
            return self.child.returncode

        def wait(self, timeout):
            assert timeout == 1
            try:
                result = self.child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                state["timeouts"] += 1
                if not state["released"]:
                    marker = os.open(
                        tmp_path / "read-go",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600,
                    )
                    os.close(marker)
                    state["released"] = True
                raise
            if state["tamper"]:
                state["tamper"] = False
                with self.input_path.open("r+b", buffering=0) as retained:
                    retained.write(b"!")
                    os.fsync(retained.fileno())
            return result

    def closed_popen(argv, **kwargs):
        assert argv == _SSH_ARGV
        assert set(kwargs) == {
            "stdin", "stdout", "stderr", "shell", "close_fds", "start_new_session", "preexec_fn"
        }
        assert kwargs["shell"] is False
        assert kwargs["close_fds"] is True and kwargs["start_new_session"] is True
        assert kwargs["preexec_fn"] is subject.child_limits
        for stream, suffix in (("stdin", "stdin.json"), ("stdout", "stdout.json"), ("stderr", "stderr.log")):
            meta = os.fstat(kwargs[stream].fileno())
            assert stat.S_ISREG(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o600
            assert meta.st_uid == os.getuid() and meta.st_nlink == 1
            assert subject.file_identity(meta) == subject.file_identity(
                (tmp_path / ("web-v2-deliver." + suffix)).stat()
            )
        assert kwargs["stdin"].tell() == 0
        assert os.lseek(kwargs["stdin"].fileno(), 0, os.SEEK_CUR) == 0
        state["spawn_offsets"].append(0)
        child = _ORIGINAL_POPEN(  # Fixed isolated local child; no supplied argv or environment.
            [sys.executable, "-I", "-S", "-B", "-c", _CHILD],
            stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"],
            shell=False, close_fds=True, start_new_session=True,
            preexec_fn=subject.child_limits, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            cwd=tmp_path,
        )
        processes.append(child)
        return ObservedChild(child, tmp_path / "web-v2-deliver.stdin.json")

    monkeypatch.setattr(subprocess, "Popen", closed_popen)
    try:
        yield subject, state, processes
    finally:
        for child in processes:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=6)
            assert child.poll() is not None


def _invoke(subject, payload):
    with subject.exclusive("journal.jsonl") as journal:
        return subject.invoke("web", "deliver", ["synthetic-stdin-read"], journal, payload)


def _events(directory):
    return [json.loads(line) for line in (directory / "journal.jsonl").read_bytes().splitlines()]


@pytest.mark.parametrize("size", [64, 1_048_576])
def test_file_stdin_delivers_full_payload_after_wait_timeout(delivery, size):
    subject, state, processes = delivery
    payload = (b"0123456789abcdef" * (size // 16))
    expected_sha = hashlib.sha256(payload).hexdigest()
    result = _invoke(subject, payload)
    assert result == {"bytes": size, "sha256": expected_sha, "eof": True}
    assert state["timeouts"] >= 1 and state["released"] is True and state["spawn_offsets"] == [0]
    assert len(processes) == 1 and processes[0].returncode == 0
    retained = subject.BASE / "web-v2-deliver.stdin.json"
    assert retained.read_bytes() == payload
    assert json.loads((subject.BASE / "web-v2-deliver.stdout.json").read_bytes()) == result
    assert (subject.BASE / "web-v2-deliver.stderr.log").read_bytes() == b""
    assert {path.name for path in subject.BASE.iterdir()} == {
        "journal.jsonl", "read-go", "web-v2-deliver.stdin.json", "web-v2-deliver.stdout.json",
        "web-v2-deliver.stderr.log"
    }
    for path in subject.BASE.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    events = _events(subject.BASE)
    assert [item["phase"] for item in events] == [
        "deliver_client_started", "deliver_client_terminal", "deliver_input_file_retained"
    ]
    assert events[0]["input_bytes"] == size and events[0]["input_sha256"] == expected_sha
    assert events[0]["pid"] == events[1]["pid"] == processes[0].pid
    assert events[1]["returncode"] == 0 and events[1]["held"] is False
    assert events[2]["local_read_offset"] == events[2]["input_bytes"] == size
    assert events[2]["input_sha256"] == expected_sha
    assert events[2]["meaning"] == (
        "Local file offset only; remote staging acknowledgement is still required"
    )


@pytest.mark.parametrize("suffix", ["stdout.json", "stderr.log", "stdin.json"])
def test_existing_artifact_refuses_before_child_and_preserves_bytes(delivery, suffix):
    subject, state, processes = delivery
    collision = subject.BASE / ("web-v2-deliver." + suffix)
    collision.write_bytes(b"existing artifact")
    before = collision.stat()
    with pytest.raises(FileExistsError):
        _invoke(subject, b"0123456789abcdef" * 4)
    assert collision.read_bytes() == b"existing artifact"
    assert subject.file_identity(collision.stat()) == subject.file_identity(before)
    assert processes == [] and state["spawn_offsets"] == []
    assert _events(subject.BASE) == []


def test_post_delivery_input_tamper_refuses_retained_attestation(delivery):
    subject, state, processes = delivery
    state["tamper"] = True
    with pytest.raises(subject.Hold, match="manual_reconciliation_required"):
        _invoke(subject, b"0123456789abcdef" * 4)
    assert len(processes) == 1 and processes[0].returncode == 0
    assert (subject.BASE / "web-v2-deliver.stdin.json").read_bytes().startswith(b"!")
    assert [item["phase"] for item in _events(subject.BASE)] == [
        "deliver_client_started", "deliver_client_terminal"
    ]


def test_closed_adapter_keeps_external_operation_refusals(delivery):
    _subject, _state, processes = delivery
    for argv in (["/bin/false"], [*_SSH_ARGV[:-2], "other.invalid", _SSH_ARGV[-1]]):
        with pytest.raises(AssertionError):
            subprocess.Popen(argv)  # noqa: S603 -- closed adapter must refuse these argv before spawning
    with pytest.raises(AssertionError, match="Unmocked network or process operation"):
        subprocess.run(["/bin/false"], check=True)
    with pytest.raises(AssertionError, match="Unmocked network or process operation"):
        socket.create_connection(("stdio-test.invalid", 22))
    assert processes == []

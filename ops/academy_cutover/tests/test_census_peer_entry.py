# ruff: noqa: S101 -- assertions qualify synthetic census behavior.
"""Hosted synthetic forced-command tests; no keys, hosts, real exec or stdin reads."""

import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from types import SimpleNamespace

import candidate_census_peer_entry as E
import candidate_census_transport as T
import pytest

SOURCE = b"synthetic reviewed entrypoint bytes"
ROOT = Path(__file__).parents[1]


def policy(role="web"):
    return {
        "schema": "AcademyCensusPeerEntryPolicy.v1", "role": role, "hostname": E.HOSTS[role],
        "receiving_uid": 0 if role == "web" else 1000,
        "producer": {"path": "/root/.packet/candidate_external_census.py", "sha256": "a" * 64},
        "peer_packet_root": "/root/.packet/current", "entrypoint_sha256": hashlib.sha256(SOURCE).hexdigest(),
    }


class ExecCalled(BaseException):
    pass


@pytest.fixture
def receiver(monkeypatch):
    value = policy()
    calls = []
    reads = []
    errors = []
    environment = {"SSH_ORIGINAL_COMMAND": next(iter(E.commands(value)))}
    runtime = SimpleNamespace(
        platform="linux", version_info=(3, 12), argv=[E.ENTRYPOINT],
        flags=SimpleNamespace(isolated=True, no_site=True, dont_write_bytecode=True),
    )

    class NoStdin:
        @staticmethod
        def read(*args):
            del args
            raise AssertionError("stdin must remain untouched")

        buffer = property(lambda self: self)

    runtime.stdin = NoStdin()

    def protected(path):
        reads.append(path)
        assert path in (E.ENTRYPOINT, E.POLICY)
        return SOURCE if path == E.ENTRYPOINT else json.dumps(value).encode()

    def execute(path, argv, env):
        calls.append((path, argv, env))
        raise ExecCalled

    monkeypatch.setattr(E, "__file__", E.ENTRYPOINT)
    monkeypatch.setattr(E, "sys", runtime)
    monkeypatch.setattr(E, "os", SimpleNamespace(
        getuid=lambda: value["receiving_uid"], geteuid=lambda: value["receiving_uid"],
        environ=environment, execve=execute, write=lambda descriptor, raw: errors.append((descriptor, raw)),
    ))
    monkeypatch.setattr(E, "pwd", SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=1000)))
    monkeypatch.setattr(E, "socket", SimpleNamespace(gethostname=lambda: value["hostname"]))
    monkeypatch.setattr(E, "_protected", protected)
    return value, environment, runtime, calls, reads, errors


@pytest.mark.parametrize("operation,role", list(E.OPERATIONS.items()))
def test_all_three_commands_are_byte_exact_existing_transport_wire_contract(operation, role):
    value = policy(role)
    reference = {"path": "/root/.ssh/synthetic", "sha256": "b" * 64}
    profile = {
        "schema": "AcademyCensusTransportProfile.v2", "caller_hostname": "synthetic-caller",
        "role": role, "hostname": value["hostname"], "endpoint": "peer.invalid", "port": 22,
        "user": "root" if role == "web" else "dotmac", "identity": reference, "known_hosts": reference,
        "peer_producer": value["producer"], "peer_packet_root": value["peer_packet_root"],
        "local_packet_root": "/root/local",
    }
    inputs = value["peer_packet_root"] + "/current-" + operation + "-inputs.json"
    command = T._argv(profile, inputs)[-1]
    assert command in E.commands(value)
    assert command == " ".join(E.commands(value)[command])
    assert len(E.commands(value)) == (2 if role == "web" else 1)


@pytest.mark.parametrize("role", ["web", "lab"])
def test_actual_dispatch_uses_only_fixed_argv_clean_environment_and_preserves_stdin(receiver, role):
    value, environment, _, calls, reads, _ = receiver
    value.update(policy(role))
    command, expected = next(iter(E.commands(value).items()))
    environment.update(SSH_ORIGINAL_COMMAND=command, PATH="/attacker", PYTHONPATH="/attacker",
                       LD_PRELOAD="/attacker", HOME="/attacker", BASH_ENV="/attacker")
    with pytest.raises(ExecCalled):
        E.dispatch()
    assert calls == [(expected[0], expected, {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})]
    assert reads == [E.ENTRYPOINT, E.POLICY]
    assert "/root/.packet/candidate_external_census.py" not in reads


@pytest.mark.parametrize("alter", [
    lambda command: "", lambda command: command + " ", lambda command: command + "\n",
    lambda command: " " + command, lambda command: command.replace(" -B ", " "),
    lambda command: command + "; id", lambda command: command + " && id",
    lambda command: command + " | sh", lambda command: "sh -c '" + command + "'",
    lambda command: command.replace("--current-request-stdin", "--help"),
    lambda command: command.replace("/root/.packet/current/", "/root/.packet/current/../"),
    lambda command: command.replace("current-gate-web-inputs", "current-stopped-lab-inputs"),
    lambda command: command.replace("/usr/bin/python3.12", "python3.12"),
    lambda command: "internal-sftp", lambda command: "sftp", lambda command: "$(id)",
    lambda command: "x" * 4097,
])
def test_altered_shell_subsystem_options_whitespace_and_paths_never_exec(receiver, alter):
    _, environment, _, calls, _, _ = receiver
    environment["SSH_ORIGINAL_COMMAND"] = alter(environment["SSH_ORIGINAL_COMMAND"])
    with pytest.raises(ValueError, match="peer_entry_refused"):
        E.dispatch()
    assert calls == []


def test_missing_original_command_refused(receiver):
    _, environment, _, calls, _, _ = receiver
    environment.clear()
    with pytest.raises(ValueError, match="peer_entry_refused"):
        E.dispatch()
    assert not calls


@pytest.mark.parametrize("field,value", [
    ("platform", "darwin"), ("version_info", (3, 13)), ("argv", [E.ENTRYPOINT, "--policy=/attacker"]),
    ("argv", ["/alias/entry.py"]),
])
def test_runtime_platform_version_and_argv_are_fixed(receiver, field, value):
    _, _, runtime, calls, reads, _ = receiver
    setattr(runtime, field, value)
    with pytest.raises(ValueError):
        E.dispatch()
    assert not calls and not reads


@pytest.mark.parametrize("flag", ["isolated", "no_site", "dont_write_bytecode"])
def test_all_three_python_flags_required(receiver, flag):
    _, _, runtime, calls, reads, _ = receiver
    setattr(runtime.flags, flag, False)
    with pytest.raises(ValueError):
        E.dispatch()
    assert not calls and not reads


@pytest.mark.parametrize("field", ["getuid", "geteuid"])
def test_actual_receiving_uid_must_match_no_setuid_transition(receiver, monkeypatch, field):
    _, _, _, calls, _, _ = receiver
    monkeypatch.setattr(E.os, field, lambda: 1001)
    with pytest.raises(ValueError):
        E.dispatch()
    assert not calls


def test_lab_receiving_uid_must_be_actual_named_dotmac_user(receiver, monkeypatch):
    value, environment, _, calls, _, _ = receiver
    value.update(policy("lab"))
    environment["SSH_ORIGINAL_COMMAND"] = next(iter(E.commands(value)))
    monkeypatch.setattr(E.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1001))
    with pytest.raises(ValueError):
        E.dispatch()
    assert not calls


def test_actual_hostname_and_fixed_wrapper_path_required(receiver, monkeypatch):
    _, _, _, calls, _, _ = receiver
    monkeypatch.setattr(E.socket, "gethostname", lambda: "other-host")
    with pytest.raises(ValueError):
        E.dispatch()
    monkeypatch.setattr(E, "__file__", "/alias/entry.py")
    with pytest.raises(ValueError):
        E.dispatch()
    assert not calls


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(extra="unsupported"), lambda p: p.pop("schema"),
    lambda p: p.update(schema="AcademyCensusPeerEntryPolicy.v2"),
    lambda p: p.update(role="other"), lambda p: p.update(hostname="other"),
    lambda p: p.update(receiving_uid=True), lambda p: p.update(receiving_uid=1000),
    lambda p: p.update(entrypoint_sha256="bad"), lambda p: p["producer"].update(sha256="bad"),
    lambda p: p["producer"].update(extra="unsupported"),
    lambda p: p["producer"].update(path="/root/.packet/arbitrary.py"),
])
def test_policy_closed_fields_types_roles_and_fixed_producer(receiver, mutation):
    value, _, _, calls, _, _ = receiver
    mutation(value)
    with pytest.raises(ValueError):
        E.dispatch()
    assert not calls


@pytest.mark.parametrize("path", [
    "/root/./file", "/root/../file", "/root/.ssh/../file", "/root//file", "/root/file/", "/outside/file",
    "/root/$(id)", "/root/file;id", "/root/file name", "/root/idé", "/root", "/root/.", "/root/..",
])
def test_policy_path_grammar_rejects_aliases_shell_syntax_and_unicode(path):
    with pytest.raises(ValueError):
        E._root_path(path)


def test_source_hash_drift_refuses_without_exec(receiver):
    value, _, _, calls, _, _ = receiver
    value["entrypoint_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        E.dispatch()
    assert not calls


def test_generic_failure_has_no_original_command_policy_or_traceback(receiver):
    _, environment, _, calls, _, errors = receiver
    environment["SSH_ORIGINAL_COMMAND"] = "secret-like arbitrary untrusted request"
    assert E.main() == 111
    assert not calls
    assert errors == [(2, b"census peer entry refused\n")]


class Custody:
    """Synthetic syscall boundary for the actual anchored-file reader."""

    def __init__(self, path, fault=None):
        self.path, self.fault = path, fault
        self.raw = b"fixed synthetic bytes"
        self.opened, self.closed, self.positions = {}, [], {}
        self.read_calls = 0

    def metadata(self, path, *, after=False):
        directory = path != self.path
        mode = (stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o644)
        uid, links = 0, 2 if directory else 1
        inode = len(path) + (0 if directory else 100)
        size = 0 if directory else len(self.raw)
        if self.fault == "parent_mode" and path == "/usr/local":
            mode |= 0o020
        if self.fault == "parent_uid" and path == "/etc":
            uid = 1000
        if not directory:
            if self.fault == "mode":
                mode |= 0o020
            if self.fault == "private_mode":
                mode = stat.S_IFREG | 0o600
            if self.fault == "uid":
                uid = 1000
            if self.fault == "hardlink":
                links = 2
            if self.fault == "size":
                size = E.LIMIT + 1
            if self.fault == "short":
                size += 1
            if self.fault == "not_regular":
                mode = stat.S_IFIFO | 0o644
        if self.fault == "replacement" and after and path == self.path:
            inode += 1
        if self.fault == "parent_replacement" and after and path == "/etc":
            inode += 1
        return SimpleNamespace(st_dev=1, st_ino=inode, st_uid=uid, st_gid=0, st_mode=mode,
                               st_nlink=links, st_size=size, st_mtime_ns=1,
                               st_ctime_ns=2 if self.fault == "race" and self.read_calls else 1)

    def open(self, name, flags, *, dir_fd=None):
        assert flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK and flags & os.O_CLOEXEC
        path = name if dir_fd is None else self.opened[dir_fd].rstrip("/") + "/" + name
        if self.fault == "symlink" and path == self.path:
            raise OSError("synthetic nofollow refusal")
        if self.fault == "parent_symlink" and path in ("/usr/local", "/etc"):
            raise OSError("synthetic directory nofollow refusal")
        descriptor = 20 + len(self.opened)
        self.opened[descriptor] = path
        return descriptor

    def fstat(self, descriptor):
        return self.metadata(self.opened[descriptor])

    def stat(self, name, *, dir_fd=None, follow_symlinks):
        assert follow_symlinks is False
        path = name if dir_fd is None else self.opened[dir_fd].rstrip("/") + "/" + name
        return self.metadata(path, after=True)

    def read(self, descriptor, size):
        assert self.opened[descriptor] == self.path
        self.read_calls += 1
        offset = self.positions.get(descriptor, 0)
        raw = self.raw[offset:offset + size]
        self.positions[descriptor] = offset + len(raw)
        return raw

    def close(self, descriptor):
        assert descriptor not in self.closed
        self.closed.append(descriptor)

    def api(self):
        return SimpleNamespace(
            open=self.open, fstat=self.fstat, stat=self.stat, read=self.read, close=self.close,
            O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK,
            O_CLOEXEC=os.O_CLOEXEC, O_DIRECTORY=os.O_DIRECTORY,
        )


@pytest.mark.parametrize("path", [E.ENTRYPOINT, E.POLICY])
def test_actual_custody_reader_anchors_fixed_file_and_closes_every_fd(path, monkeypatch):
    fs = Custody(path)
    monkeypatch.setattr(E, "os", fs.api())
    assert E._protected(path) == fs.raw
    assert sorted(fs.closed) == sorted(fs.opened)
    assert fs.opened[min(fs.opened)] == "/"


@pytest.mark.parametrize("path,fault", [
    (E.ENTRYPOINT, "parent_mode"), (E.POLICY, "parent_uid"), (E.ENTRYPOINT, "parent_symlink"),
    (E.POLICY, "parent_symlink"), (E.POLICY, "parent_replacement"),
    *[(E.ENTRYPOINT, name) for name in ("symlink", "mode", "private_mode", "uid", "hardlink", "size",
                                      "short", "not_regular", "race", "replacement")],
])
def test_actual_custody_refuses_symlink_permission_size_link_and_race_failures(path, fault, monkeypatch):
    fs = Custody(path, fault)
    monkeypatch.setattr(E, "os", fs.api())
    with pytest.raises((ValueError, OSError)):
        E._protected(path)
    assert sorted(fs.closed) == sorted(fs.opened)


def test_file_reader_cannot_be_selected_by_cli_or_environment(monkeypatch):
    fs = Custody(E.POLICY)
    monkeypatch.setattr(E, "os", fs.api())
    with pytest.raises(ValueError):
        E._protected("/attacker/policy.json")
    assert not fs.opened


def test_duplicate_policy_keys_refused(receiver, monkeypatch):
    _, _, _, calls, _, _ = receiver
    monkeypatch.setattr(
        E, "_protected", lambda path: SOURCE if path == E.ENTRYPOINT else b'{"role":"web","role":"lab"}',
    )
    with pytest.raises(ValueError):
        E.dispatch()
    assert not calls


def test_policy_schema_and_runtime_path_grammar_are_consistent():
    schema = json.loads((ROOT / "census-peer-entry-policy.schema.json").read_text())
    assert set(schema["required"]) == set(E.FIELDS)
    assert schema["additionalProperties"] is False
    pattern = schema["properties"]["peer_packet_root"]["pattern"]
    for path in ("/root/.ssh/key", "/root/.packet/current", "/root/.../item", "/root/a-b_c.1"):
        assert E._root_path(path) == path
        assert re.fullmatch(pattern, path)
    for path in ("/root/.", "/root/..", "/root/./item", "/root/../item", "/root//item", "/root/x;id"):
        assert not re.fullmatch(pattern, path)
    value = copy.deepcopy(policy())
    value["producer"]["path"] = "/root/.ssh/candidate_external_census.py"
    assert E.validate_policy(value) == value

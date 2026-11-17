# ruff: noqa: S101 -- assertions qualify synthetic cron source observations.
"""Actual protected loader and observer; only POSIX/clock boundaries are synthetic."""

import builtins
import copy
import json
import os
import signal
import stat
from pathlib import Path
from types import ModuleType, SimpleNamespace

import candidate_census_domains as D
import pytest
from jsonschema import Draft202012Validator
from test_census_domains import Common
from test_systemd_template_definitions import SyntheticFS

CANARY = b"CRON_CANARY_COMMAND_ACCOUNT_ENV_SECRET_NEVER_EXPORT"


def connected(monkeypatch, role="web", configure=None, event=None):
    filesystem = SyntheticFS()
    filesystem.add("/etc/cron.d", "directory")
    filesystem.add("/etc/crontab", data=CANARY)
    filesystem.add("/etc/cron.d/academy", data=CANARY)
    if configure:
        configure(filesystem)
    clock = [0]
    handlers = {signal.SIGHUP: signal.SIG_DFL, signal.SIGINT: signal.SIG_DFL, signal.SIGTERM: signal.SIG_DFL}
    modules = []
    real_import = builtins.__import__

    def syscall(operation, *args, **kwargs):
        if event:
            event(operation, args, kwargs, filesystem, clock, handlers, modules)
        return filesystem.syscall(operation, *args, **kwargs)

    synthetic_os = SimpleNamespace(**{name: getattr(os, name) for name in (
        "O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK", "fsencode")},
        **{name: (lambda *args, _operation=name, **kwargs: syscall(_operation, *args, **kwargs))
           for name in ("open", "close", "stat", "fstat", "scandir", "read")})

    def install(number, handler):
        previous = handlers[number]
        handlers[number] = handler
        return previous

    synthetic_signal = SimpleNamespace(SIGHUP=signal.SIGHUP, SIGINT=signal.SIGINT,
                                       SIGTERM=signal.SIGTERM, signal=install)
    synthetic_time = SimpleNamespace(time=lambda: 100 + clock[0], monotonic=lambda: clock[0])

    def import_boundary(name, *args, **kwargs):
        if name == "os":
            return synthetic_os
        if name == "time":
            return synthetic_time
        if name == "signal":
            return synthetic_signal
        return real_import(name, *args, **kwargs)

    def module_factory(name):
        module = ModuleType(name)
        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": import_boundary}
        modules.append(module)
        return module

    # Source pinning, source execution, observe, validation and encoding remain real.
    monkeypatch.setattr(D, "types", SimpleNamespace(ModuleType=module_factory))
    monkeypatch.setattr(D, "sys", SimpleNamespace(platform="linux", version_info=(3, 12),
                        flags=SimpleNamespace(isolated=True, no_site=True, dont_write_bytecode=True)))
    monkeypatch.setattr(D, "os", SimpleNamespace(geteuid=lambda: 0))
    # Use the pinned collector's declared host identity rather than inventing it.
    import candidate_authority_discovery as discovery

    hostname = discovery.HOSTS[role]
    monkeypatch.setattr(D, "socket", SimpleNamespace(gethostname=lambda: hostname))
    root = Path(D.__file__).parent
    m = {"candidate": "a" * 40, "tree": "b" * 40,
         "roles": {role: {"hostname": hostname}},
         "self_sha256": Common.digest((root / "candidate_execute.py").read_bytes()),
         "helpers": {"census_domains": Common.digest((root / "candidate_census_domains.py").read_bytes()),
                     "census_discovery": D.DISCOVERY_SHA256}}
    scope = {"candidate": m["candidate"], "tree": m["tree"], "hosts": {role: hostname}}
    return SimpleNamespace(fs=filesystem, clock=clock, modules=modules, handlers=handlers,
                           m=m, scope=scope, role=role)


def produce(fixture):
    return D.collect_domain(Common, fixture.m, fixture.role, D.CRON_DOMAIN)


def validate(fixture, proof):
    return D.validate_cron_observation(Common, fixture.scope, fixture.role, proof, manifest=fixture.m)


def schema(proof):
    path = Path(D.__file__).with_name("cron-census-domain-proof.schema.json")
    Draft202012Validator(json.loads(path.read_bytes())).validate(proof)


def test_actual_source_and_schema_are_pinned():
    root = Path(D.__file__).parent
    assert Common.digest((root / "candidate_census_cron.py").read_bytes()) == D.CRON_ADAPTER_SHA256
    assert Common.digest((root / "cron-census-domain-proof.schema.json").read_bytes()) == D.CRON_SCHEMA_SHA256


@pytest.mark.parametrize("role", ["web", "lab"])
@pytest.mark.parametrize("layout", ["stable", "empty", "absent"])
def test_real_connected_producer_preserves_partial_unknown_and_hashes_only(monkeypatch, role, layout):
    def configure(fs):
        if layout != "stable":
            del fs.nodes["/etc/cron.d/academy"]
            del fs.nodes["/etc/crontab"]
        if layout == "absent":
            del fs.nodes["/etc/cron.d"]
    fixture = connected(monkeypatch, role, configure)
    proof = produce(fixture)
    assert validate(fixture, proof)
    schema(proof)
    raw = fixture.modules[1].encode(Common, proof)
    assert CANARY not in raw and b'"academy"' not in raw
    assert not proof["coverage_complete"] and not proof["classification_complete"]
    assert all(row["classification"] == "unknown" and row["authority_refs"] == [] for row in proof["objects"])
    assert all(row["source_stable"] for row in proof["objects"])
    assert set(fixture.modules[1].MANDATORY_GAPS) <= set(proof["unresolved_gaps"])
    assert not fixture.fs.fds
    assert fixture.handlers == {number: signal.SIG_DFL
                                for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)}
    with pytest.raises(ValueError, match="cron_campaign_scope_or_controls_unresolved"):
        D.validate_domain_proof(Common, fixture.scope, role, D.CRON_DOMAIN, proof, manifest=fixture.m)


@pytest.mark.parametrize("kind", ["credential", "name", "symlink", "fifo", "owner", "mode"])
def test_rejected_entry_never_reads_body_and_is_retained_unknown(monkeypatch, kind):
    filename = {"credential": "api_token", "name": "ignored.conf"}.get(kind, "academy")
    path = "/etc/cron.d/" + filename

    def configure(fs):
        del fs.nodes["/etc/cron.d/academy"]
        fs.add(path, "symlink" if kind == "symlink" else "regular", data=CANARY,
               uid=1 if kind == "owner" else 0, writable=kind == "mode")
        if kind == "fifo":
            fs.nodes[path]["mode"] = stat.S_IFIFO | 0o644
    fixture = connected(monkeypatch, configure=configure)
    proof = produce(fixture)
    assert validate(fixture, proof)
    row = next(r for r in proof["objects"] if r["source"] == "etc_cron_d")
    expected = {"credential": "credential", "name": "name", "symlink": "type", "fifo": "type"}.get(kind, kind)
    assert row["reads"][0]["status"] == "rejected_" + expected
    assert not row["source_stable"]
    assert not any(name == path for name, _ in fixture.fs.reads)
    assert CANARY not in Common.canonical(proof)


@pytest.mark.parametrize("kind", ["replacement", "same_size", "membership", "read_failure"])
def test_races_and_failures_remain_visible(monkeypatch, kind):
    opened = [0]
    changed = [False]

    def event(operation, args, kwargs, fs, *_rest):
        if operation == "open" and args[0] == "etc":
            opened[0] += 1
        if opened[0] >= 3 and not changed[0]:
            changed[0] = True
            node = fs.nodes["/etc/cron.d/academy"]
            if kind == "replacement":
                node["ino"] += 1000
            elif kind == "same_size":
                node["data"] = b"X" * len(CANARY)
            elif kind == "membership":
                fs.add("/etc/cron.d/new-job", data=CANARY)
            else:
                fs.denied.add("/etc/cron.d/academy")
    fixture = connected(monkeypatch, event=event)
    proof = produce(fixture)
    assert validate(fixture, proof)
    assert "source_passes_changed" in proof["unresolved_gaps"]
    assert any(not row["source_stable"] for row in proof["objects"])
    assert CANARY not in Common.canonical(proof)


def test_overflow_bytes_are_charged_without_body_export(monkeypatch):
    fixture = connected(monkeypatch, configure=lambda fs: fs.add("/etc/cron.d/academy", data=b"X" * 65537))
    proof = produce(fixture)
    assert validate(fixture, proof)
    row = next(r for r in proof["objects"] if r["source"] == "etc_cron_d")
    assert [r["captured_bytes"] for r in row["reads"]] == [65537, 65537]
    assert all(r["body_sha256"] is None and r["status"] == "unavailable" for r in row["reads"])
    assert proof["accounting"]["captured_payload_bytes"] == 2 * (65537 + len(CANARY))


@pytest.mark.parametrize("kind", ["objects", "aggregate", "work", "deadline", "signal", "sighup", "ledger"])
def test_resource_and_cancellation_refusals_are_closed_and_cleaned(monkeypatch, kind):
    def configure(fs):
        if kind == "objects":
            for index in range(1024):
                fs.add(f"/etc/cron.d/job{index}", data=b"")
        elif kind == "aggregate":
            for index in range(260):
                fs.add(f"/etc/cron.d/job{index}", data=b"X" * 65536)

    tripped = [False]

    def event(operation, args, kwargs, fs, clock, handlers, modules):
        del args, kwargs, fs
        if operation == "read" and not tripped[0]:
            tripped[0] = True
            if kind == "deadline":
                clock[0] = 61
            elif kind in ("signal", "sighup"):
                number = signal.SIGHUP if kind == "sighup" else signal.SIGTERM
                handlers[number](number, None)
            elif kind == "ledger":
                modules[0].Discovery.record = lambda *_args: False
            elif kind == "work":
                modules[1]._ACTIVE.work = 32768
    fixture = connected(monkeypatch, configure=configure, event=event)
    with pytest.raises(ValueError, match="cron_") as error:
        produce(fixture)
    assert CANARY.decode() not in str(error.value)
    assert not fixture.fs.fds
    assert fixture.handlers == {number: signal.SIG_DFL
                                for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)}


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(coverage_complete=True),
    lambda p: p.update(classification_complete=True),
    lambda p: p.update(control_state="fenced"),
    lambda p: p.update(raw_cron=CANARY.decode()),
    lambda p: p["objects"][0].update(classification="non_sender"),
    lambda p: p["objects"][0].update(authority_refs=["a" * 64]),
    lambda p: p["objects"][0].update(source_stable=False),
    lambda p: p["objects"].pop(),
    lambda p: p["passes"][0]["entries"].append(copy.deepcopy(p["passes"][0]["entries"][0])),
    lambda p: p["passes"][0]["entries"][0].update(captured_bytes=True),
    lambda p: p["passes"][0]["entries"][0].update(body=CANARY.decode()),
    lambda p: p["accounting"].update(captured_payload_bytes=0),
    lambda p: p["accounting"].update(retained_json_bytes=1),
    lambda p: p["accounting"].update(filesystem_work=True),
    lambda p: p["accounting"].update(filesystem_work=32768, work_events={"1": 32768}),
    lambda p: p["profile"].update(overflow_probe_bytes=True),
    lambda p: p["sources"][0].update(sha256="0" * 64),
    lambda p: p.update(unresolved_gaps=[]),
    lambda p: p["enumerated_object_ids"].reverse(),
    lambda p: p.update(observed_unix_started=True),
])
def test_strict_reconstruction_rejects_tampering(monkeypatch, mutation):
    fixture = connected(monkeypatch)
    proof = produce(fixture)
    mutation(proof)
    with pytest.raises(ValueError):
        validate(fixture, proof)


def test_output_bound_and_shared_validation_deadline(monkeypatch):
    fixture = connected(monkeypatch)
    proof = produce(fixture)
    adapter = fixture.modules[1]
    bad = copy.deepcopy(proof)
    bad["oversize"] = "X" * 8388609
    with pytest.raises(ValueError, match="cron_proof_encoding_bound"):
        adapter.encode(Common, bad)
    fixture.clock[0] = 61
    with pytest.raises(ValueError, match="cron_deadline"):
        adapter.validate(Common, fixture.scope, fixture.role, proof, sources=proof["sources"])


@pytest.mark.parametrize("when", ["pre", "post"])
def test_source_pin_drift_is_refused_on_actual_loader_path(monkeypatch, when):
    fixture = connected(monkeypatch)
    path = Path(D.__file__).with_name("candidate_census_cron.py")
    original = Common.read_bytes
    reads = [0]

    def pinned_read(name, **kwargs):
        if Path(name) == path:
            reads[0] += 1
            if when == "pre" or reads[0] >= 2:
                return b"source drift"
        return original(name, **kwargs)
    monkeypatch.setattr(Common, "read_bytes", staticmethod(pinned_read))
    with pytest.raises(ValueError, match="census_domain_actual_source_hash"):
        produce(fixture)
    assert not fixture.fs.fds


@pytest.mark.parametrize("kind", ["replacement", "disappearance"])
def test_actual_directory_anchor_replacement_or_disappearance_is_not_stability(monkeypatch, kind):
    tripped = [False]

    def configure(fs):
        if kind == "disappearance":
            del fs.nodes["/etc/cron.d/academy"]

    def event(operation, args, kwargs, fs, *_rest):
        del args, kwargs
        if operation == "scandir" and not tripped[0]:
            tripped[0] = True
            if kind == "replacement":
                # Replace the named node while the open FD retains the original node.
                fs.add("/etc/cron.d", "directory")
            else:
                del fs.nodes["/etc/cron.d"]
    fixture = connected(monkeypatch, configure=configure, event=event)
    if kind == "disappearance":
        with pytest.raises(ValueError, match="cron_acquisition_failed"):
            produce(fixture)
    else:
        proof = produce(fixture)
        assert validate(fixture, proof)
        schema(proof)
        assert proof["passes"][0]["cron_d_status"] == "changed"
        assert "source_anchor_changed" in proof["unresolved_gaps"]
        assert all(not row["source_stable"] for row in proof["objects"])
    assert not fixture.fs.fds
    assert fixture.handlers == {number: signal.SIG_DFL
                                for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)}


@pytest.mark.parametrize("stage", ["admission", "replacement"])
def test_retention_is_admitted_before_body_and_failure_stops_all_later_reads(monkeypatch, stage):
    installed = [False]

    def event(operation, args, kwargs, fs, clock, handlers, modules):
        del args, kwargs, fs, clock, handlers
        if operation == "fstat" and not installed[0]:
            installed[0] = True
            if stage == "admission":
                modules[0].Discovery.record = lambda *_args: False
            else:
                modules[0].Discovery.replace_record_facts = lambda *_args: False
    fixture = connected(monkeypatch, event=event)
    with pytest.raises(ValueError, match="cron_retention_"):
        produce(fixture)
    if stage == "admission":
        assert fixture.fs.reads == []
    else:
        assert fixture.fs.reads and all(path == "/etc/crontab" for path, _ in fixture.fs.reads)
    assert not fixture.fs.fds
    assert fixture.handlers == {number: signal.SIG_DFL
                                for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)}

# ruff: noqa: S101 -- assertions qualify synthetic resource boundaries.
"""Hosted-only guards: all input, children and delivery endpoints are synthetic."""

import copy
import io
import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import candidate_authority_discovery as D
import pytest
from jsonschema import Draft202012Validator, ValidationError
from test_systemd_graph_discovery import SyntheticDiscovery, graph


def profile(monkeypatch, **limits):
    monkeypatch.setattr(D, "RESOURCE_PROFILE", dict(D.RESOURCE_PROFILE, **limits))


@pytest.mark.parametrize("remaining", [0, 1, 7, 8])
def test_payload_allowances_are_positive_and_exact(monkeypatch, remaining):
    discovery = D.Discovery("web")
    cap = D.RESOURCE_PROFILE["captured_payload_bytes"]
    discovery.captured_payload_bytes = cap - remaining
    requests = []

    def read(_fd, request):
        requests.append(request)
        return b"x" * request

    monkeypatch.setattr(D.os, "read", read)
    if remaining:
        assert discovery.read_payload(5, 8, "processes") == b"x" * remaining
    else:
        with pytest.raises(D.ResourceLimitError):
            discovery.read_payload(5, 8, "processes")
    assert requests == ([remaining] if remaining else [])
    assert discovery.captured_payload_bytes == cap
    with pytest.raises(D.ResourceLimitError):
        discovery.read_payload(5, 1, "processes")
    assert discovery.run(["list-units"], "processes") is None
    assert discovery.commands == 0


@pytest.mark.parametrize("stop", ["signal", "deadline", "sticky"])
def test_read_gate_checks_every_operation(monkeypatch, stop):
    discovery = D.Discovery("web")
    if stop == "signal":
        discovery.pending_signal = 2
    elif stop == "deadline":
        discovery.deadline = 0
    else:
        discovery.resource_stopped = True
    monkeypatch.setattr(D.os, "read", lambda *_: pytest.fail("read after stop"))
    with pytest.raises(D.ResourceLimitError):
        discovery.read_payload(4, 1, "processes")


def metadata(mode, size=0):
    return SimpleNamespace(st_dev=3, st_ino=7, st_uid=0, st_gid=0, st_mode=mode,
                           st_size=size, st_mtime_ns=1700000000000000000, st_ctime_ns=1700000000000000000)


@pytest.mark.parametrize("proc", [False, True])
@pytest.mark.parametrize("length", [3, 4, 5])
def test_file_and_proc_reads_charge_declared_probe(monkeypatch, proc, length):
    discovery = D.Discovery("web")
    file_meta = metadata(stat.S_IFREG | 0o600)
    directory_meta = metadata(stat.S_IFDIR | 0o755)
    payload = bytearray(b"x" * length)
    requests, closed = [], []
    monkeypatch.setattr(D.os, "open", lambda *_a, **_k: 12)
    monkeypatch.setattr(D.os, "close", closed.append)
    monkeypatch.setattr(D.os, "fstat", lambda fd: file_meta if fd == 12 else directory_meta)
    monkeypatch.setattr(D.os, "stat", lambda name, **_k: directory_meta if name in ("/proc", "123") else file_meta)

    def read(_fd, request):
        requests.append(request)
        result = bytes(payload[:request])
        del payload[:request]
        return result

    monkeypatch.setattr(D.os, "read", read)
    if proc:
        # cmdline's fixed local cap is narrowed only by the global test profile.
        profile(monkeypatch, captured_payload_bytes=5)
        result = discovery.read_proc_file(10, 11, "123", "cmdline", 3, "processes", [])
    else:
        result = discovery.read_file(11, "synthetic", 0, "processes", limit=4)
    assert discovery.captured_payload_bytes == length
    assert max(requests) <= 5
    assert closed == [12]
    assert (result is None) == (length == 5)


class Buffer:
    def __init__(self, size):
        self.raw = bytes(size)


@pytest.mark.parametrize("returned", [0, 1, 7, 8, -1])
def test_sized_readlink_charges_before_completeness(monkeypatch, returned):
    discovery = D.Discovery("web")
    profile(monkeypatch, captured_payload_bytes=8, readlink_bytes=8)
    calls = []

    def adapter(directory, name, buffer, size):
        calls.append((directory, name, size))
        buffer.raw = b"x" * size
        return returned

    discovery._readlink_adapter = (SimpleNamespace(create_string_buffer=Buffer), adapter, None)
    monkeypatch.setattr(D.os, "readlink", lambda *_a, **_k: pytest.fail("unbounded fallback"))
    if returned < 0 or returned == 8:
        with pytest.raises(D.ResourceLimitError):
            discovery.read_link(9, "exe", "processes")
    else:
        assert discovery.read_link(9, "exe", "processes") == b"x" * returned
    assert discovery.captured_payload_bytes == max(0, returned)
    assert calls == [(9, b"exe", 8)]
    with pytest.raises(D.ResourceLimitError):
        discovery.read_link(9, "environ", "processes")
    assert len(calls) == 1


def test_readlink_adapter_is_lazy_and_has_explicit_abi(monkeypatch):
    calls = []

    def adapter(_directory, _name, _buffer, _size):
        return 0

    def load(path, **kwargs):
        calls.append((path, kwargs))
        return SimpleNamespace(readlinkat=adapter)

    fake = SimpleNamespace(CDLL=load, c_int="int", c_char_p="char*", c_void_p="void*",
                           c_size_t="size", c_ssize_t="signed-size", create_string_buffer=Buffer)
    monkeypatch.setitem(sys.modules, "ctypes", fake)
    discovery = D.Discovery("web")
    assert calls == []
    assert discovery.read_link(3, "cwd", "processes") == b""
    assert calls == [(None, {"use_errno": True})]
    assert adapter.argtypes == ["int", "char*", "void*", "size"]
    assert adapter.restype == "signed-size"


def test_readlink_loader_failure_has_fixed_gap(monkeypatch):
    def unavailable(*_a, **_k):
        raise OSError("never disclose this")

    monkeypatch.setitem(sys.modules, "ctypes", SimpleNamespace(CDLL=unavailable))
    discovery = D.Discovery("web")
    with pytest.raises(D.ResourceLimitError):
        discovery.read_link(3, "cwd", "processes")
    assert discovery.domain("processes")["gaps"] == ["userspace_process_link_unavailable"]
    assert discovery.captured_payload_bytes == 0


class Selector:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def register(self, *_args):
        return None

    def select(self, *_args):
        return [True]


@pytest.mark.parametrize("global_cap,local_cap,expected", [(4, 100, 4), (100, 4, 5)])
def test_mid_child_limit_charges_then_cleans_up(monkeypatch, global_cap, local_cap, expected):
    discovery = D.Discovery("web")
    profile(monkeypatch, captured_payload_bytes=global_cap)
    monkeypatch.setattr(D, "MAX_COMMAND_BYTES", local_cap)
    events = []
    stdout = SimpleNamespace(fileno=lambda: 6, close=lambda: events.append("close"))
    child = SimpleNamespace(pid=1234, stdout=stdout, wait=lambda **_k: events.append("reap"))
    monkeypatch.setattr(D.subprocess, "Popen", lambda *_a, **_k: child)
    monkeypatch.setattr(D.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(D.os, "read", lambda _fd, request: b"x" * request)
    monkeypatch.setattr(D.os, "waitid", lambda *_a: None)

    def kill(_pid, sig):
        events.append(("signal", sig))
        if sig == 0:
            raise ProcessLookupError

    monkeypatch.setattr(D.os, "killpg", kill)
    assert discovery.run(["list-units"], "systemd_loaded") is None
    assert discovery.captured_payload_bytes == expected
    assert events == [("signal", D.signal.SIGKILL), "reap", ("signal", 0), "close"]
    assert discovery.child_metadata["spawned"] == discovery.child_metadata["reaped"] == 1
    assert discovery.child_metadata["group_cleanup_confirmed"] == 1
    if global_cap == 4:
        assert discovery.run(["list-units"], "systemd_loaded") is None
        assert discovery.commands == 1


@pytest.mark.parametrize("value", ["quote\"\\\n\t\b\f\r\x00\x1f\x7f\u0080\uffff\U0001f600", 2**127,
                                   -(2**127), 1.25, True, None, (1, "x"), {"a": ["x", 1]}])
def test_canonical_size_matches_encoder(value):
    encoded = json.dumps(value, **D.JSON_OPTIONS).encode("ascii")
    assert D.canonical_size(value, len(encoded)) == len(encoded)
    with pytest.raises(D.ResourceLimitError):
        D.canonical_size(value, len(encoded) - 1)
    assert D.stage_json(value, len(encoded) + 1).read() == encoded + b"\n"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -(float("inf")), 2**129,
                                   b"raw", {1: "wrong key"}, {"x" * 257: 0}, "x" * (2 * D.MIB + 1)])
def test_primitive_validation_precedes_encoder(value, monkeypatch):
    monkeypatch.setattr(D.json, "JSONEncoder", lambda **_k: pytest.fail("encoder reached"))
    with pytest.raises(D.ResourceLimitError):
        D.stage_json(value, 63 * D.MIB)


def test_cycles_depth_entries_and_nodes_are_bounded(monkeypatch):
    cycle = []
    cycle.append(cycle)
    with pytest.raises(D.ResourceLimitError):
        D.canonical_size(cycle, D.MIB)
    profile(monkeypatch, json_depth=2, json_container_entries=2, json_nodes=3)
    for tree in ([1, 2, 3], [[[[]]]], {"a": [1, 2]}):
        with pytest.raises(D.ResourceLimitError):
            D.canonical_size(tree, D.MIB)


def test_record_and_atomic_replacement_refusal_preserve_prior_facts(monkeypatch):
    discovery = D.Discovery("web")
    facts = {"nested": {"old": True}}
    assert discovery.record("systemd_loaded", "a.service", facts)
    before = copy.deepcopy(discovery.domain("systemd_loaded")["records"][0])
    size = discovery.ordinary_record_json_bytes
    profile(monkeypatch, record_json_bytes=size)
    assert not discovery.replace_record_facts(facts, {"nested": {"new": "x" * size}})
    assert discovery.domain("systemd_loaded")["records"][0] == before
    assert discovery.ordinary_record_json_bytes == size
    assert discovery.observation_retention_incomplete
    assert not discovery.record("systemd_loaded", "b.service", {"large": "x" * size})
    assert len(discovery.domain("systemd_loaded")["records"]) == 1
    assert discovery.domain("systemd_loaded")["complete"] == 1
    assert discovery.domain("systemd_loaded")["skipped"] == 2


def test_atomic_replacement_delta_and_identity(monkeypatch):
    discovery = D.Discovery("web")
    facts = {"old": True}
    assert discovery.record("systemd_loaded", "a.service", facts)
    original = id(facts)
    profile(monkeypatch, ordinary_record_json_bytes=discovery.ordinary_record_json_bytes)
    assert discovery.replace_record_facts(facts, {})
    assert id(facts) == original and facts == {}
    assert discovery.ordinary_record_json_bytes == D.canonical_size(
        discovery.domain("systemd_loaded")["records"][0], 2 * D.MIB)


def test_rejected_parsed_graph_is_not_retained_or_complete(monkeypatch):
    discovery = SyntheticDiscovery()
    raw = graph("a.service", Wants="b.service b.service")
    initial = discovery.collect_unit_graph(raw, D.GRAPH_PROPERTIES)
    facts = discovery.retain_unit_graph("a.service", {"a.service"}, {"a.service"}, initial)
    previous = copy.deepcopy(facts)
    repeated = discovery.collect_unit_graph(raw, D.GRAPH_PROPERTIES, graph_only=True)
    profile(monkeypatch, ordinary_record_json_bytes=discovery.ordinary_record_json_bytes)
    assert not discovery.replace_record_facts(facts, dict(facts, repeated=repeated))
    assert facts == previous
    discovery.resource_stopped = True
    discovery.recount_retained_graph()
    counters = discovery.domain("systemd_unit_graph")["endpoint_accounting"]
    assert counters["total"]["endpoint_count"] == 8
    assert counters["initial"]["retained_endpoint_count"] == 4
    assert counters["repeated"]["retained_endpoint_count"] == 0
    assert counters["total"]["retained_endpoint_count"] == 4
    assert not counters["total"]["unparsed_tail"]
    assert discovery.domain("systemd_unit_graph")["complete"] == 0


def validator():
    schema = json.loads((Path(__file__).parents[1] / "discovery.schema.json").read_text())
    return Draft202012Validator(schema)


def report(discovery):
    return json.loads(discovery.seal().read())


def test_normal_v2_closed_schema_and_exact_framing():
    discovery = SyntheticDiscovery()
    discovery.systemd()
    staged = discovery.seal().read()
    result = json.loads(staged)
    assert result["schema"] == "AcademyAuthorityDiscovery.v2"
    assert staged == json.dumps(result, **D.JSON_OPTIONS).encode("ascii") + b"\n"
    validator().validate(result)
    forged = dict(result, normal_evidence_not_emitted=True)
    with pytest.raises(ValidationError):
        validator().validate(forged)


def test_failure_variant_is_distinct_closed_and_preserves_counters(monkeypatch):
    discovery = D.Discovery("web")
    discovery.commands = 7
    discovery.files = 3
    discovery.captured_payload_bytes = 91
    discovery.domain("collector")["gaps"] = ["x" * (D.MIB + 1)]
    result = report(discovery)
    assert result["schema"] == "AcademyAuthorityDiscoveryFailure.v2"
    assert result["domains"] == {} and result["normal_evidence_not_emitted"]
    assert result["commands_attempted"] == 7 and result["files_attempted"] == 3
    assert result["resource_accounting"]["captured_payload_bytes"] == 91
    assert len(json.dumps(result, **D.JSON_OPTIONS)) + 1 <= D.MIB
    validator().validate(result)
    with pytest.raises(ValidationError):
        validator().validate(dict(result, schema="AcademyAuthorityDiscovery.v2"))
    with pytest.raises(ValidationError):
        validator().validate(dict(result, raw_error="forged"))


@pytest.mark.parametrize("limit", ["ordinary_record_json_bytes", "record_json_bytes"])
def test_ordinary_admission_limit_is_inclusive(monkeypatch, limit):
    first = D.Discovery("web")
    assert first.record("systemd_loaded", "a.service", {})
    exact = first.ordinary_record_json_bytes
    profile(monkeypatch, **{limit: exact})
    discovery = D.Discovery("web")
    assert discovery.record("systemd_loaded", "a.service", {})
    profile(monkeypatch, **{limit: exact - 1})
    discovery = D.Discovery("web")
    assert not discovery.record("systemd_loaded", "a.service", {})


def test_metadata_commas_and_final_newline_are_budgeted(monkeypatch):
    discovery = D.Discovery("web")
    assert discovery.record("systemd_loaded", "a.service", {})
    assert discovery.record("systemd_loaded", "b.service", {})
    envelope = discovery.envelope()
    metadata = dict(envelope, domains={name: dict(domain, records=[]) for name, domain in discovery.domains.items()})
    base = D.canonical_size(metadata, D.MIB)
    # Profile contents affect metadata too, so use a generous margin then force failure.
    profile(monkeypatch, metadata_json_bytes=base - 100)
    assert report(discovery)["normal_evidence_not_emitted"]


def test_definition_reserve_is_exclusive_and_counts_whole_domain(monkeypatch):
    discovery = D.Discovery("web")
    profile(monkeypatch, ordinary_record_json_bytes=0, definition_domain_json_bytes=1024)
    assert not discovery.record("systemd_loaded", "a.service", {})
    assert discovery.record(D.DEFINITION_DOMAIN, "a.service", {})
    assert discovery.ordinary_record_json_bytes == 0
    definition = discovery.domain(D.DEFINITION_DOMAIN)
    result = report(discovery)
    assert result["schema"] == "AcademyAuthorityDiscovery.v2"
    assert len(result["domains"][D.DEFINITION_DOMAIN]["records"]) == 1
    definition["source_reads"] = ["x" * 1500]
    assert report(discovery)["normal_evidence_not_emitted"]


def test_normal_document_bound_fails_before_delivery(monkeypatch):
    discovery = D.Discovery("web")
    profile(monkeypatch, normal_json_bytes=1)
    output = io.BytesIO()
    discovery.emit(output)
    assert json.loads(output.getvalue())["normal_evidence_not_emitted"]
    assert output.getvalue().count(b"\n") == 1


def test_partial_stdout_delivery_never_appends_fallback():
    discovery = D.Discovery("web")

    class Partial:
        def __init__(self):
            self.data = bytearray()
            self.calls = 0

        def write(self, block):
            self.calls += 1
            if self.calls > 1:
                raise BrokenPipeError
            self.data.extend(block[:9])
            return 9

        def flush(self):
            pytest.fail("flush after failed delivery")

    output = Partial()
    with pytest.raises(BrokenPipeError):
        discovery.emit(output)
    assert output.calls == 2
    assert len(output.data) == 9
    assert b"Failure" not in output.data


@pytest.mark.parametrize("value", [
    "".join(chr(code) for code in range(128)),
    "\u0080\u07ff\u0800\ud7ff\ud800\udfff\ue000\uffff\U00010000\U0010ffff",
    {"\x7f\ud800\U0010ffff": (("\x7f",), ["\udfff", {"nested": "\U0001f600"}])},
])
def test_full_ascii_unicode_surrogate_and_tuple_canonical_parity(value):
    encoded = json.dumps(value, **D.JSON_OPTIONS).encode("ascii")
    assert D.canonical_size(value, len(encoded)) == len(encoded)
    assert D.stage_json(value, len(encoded) + 1).read() == encoded + b"\n"


def test_del_exact_boundary_includes_escape_and_newline():
    assert D.canonical_size("\x7f", 8) == 8
    assert D.stage_json("\x7f", 9).read() == b'"\\u007f"\n'
    with pytest.raises(D.ResourceLimitError):
        D.canonical_size("\x7f", 7)
    with pytest.raises(D.ResourceLimitError):
        D.stage_json("\x7f", 8)


def test_escaped_primitive_is_refused_before_encoder(monkeypatch):
    monkeypatch.setattr(D.json, "JSONEncoder", lambda **_k: pytest.fail("encoder reached"))
    with pytest.raises(D.ResourceLimitError):
        D.stage_json("\x00" * (D.MIB // 2), 2 * D.MIB)


def test_retention_refusal_stops_new_reads_and_children_with_truthful_reason(monkeypatch):
    discovery = D.Discovery("web")
    profile(monkeypatch, record_json_bytes=1)
    assert not discovery.record("systemd_loaded", "a.service", {})
    monkeypatch.setattr(D.os, "read", lambda *_a: pytest.fail("read after retention refusal"))
    assert discovery.resource_stopped
    assert discovery.resource_stop_reason == "observation_retention_limit"
    with pytest.raises(D.ResourceLimitError):
        discovery.read_payload(5, 1, "processes")
    assert discovery.run(["list-units"], "systemd_loaded") is None
    assert discovery.commands == 0
    assert discovery.domain("processes")["gaps"] == ["observation_retention_limit"]
    assert discovery.captured_payload_bytes == 0
    assert discovery.recount_retained_graph() is None


def test_metadata_limit_exactly_accounts_record_commas_and_newline(monkeypatch):
    discovery = D.Discovery("web")
    assert discovery.record("systemd_loaded", "a.service", {})
    assert discovery.record("systemd_loaded", "b.service", {})
    profile(monkeypatch, metadata_json_bytes=4096)
    for _ in range(4):
        envelope = discovery.envelope()
        metadata = dict(envelope, domains={name: dict(domain, records=[])
                                          for name, domain in discovery.domains.items()})
        exact = D.canonical_size(metadata, D.MIB) + 2  # One record comma and the final newline.
        if exact == D.RESOURCE_PROFILE["metadata_json_bytes"]:
            break
        profile(monkeypatch, metadata_json_bytes=exact)
    assert report(discovery)["schema"] == "AcademyAuthorityDiscovery.v2"
    profile(monkeypatch, metadata_json_bytes=exact - 1)
    assert report(discovery)["normal_evidence_not_emitted"]


def test_definition_domain_limit_is_inclusive_without_ordinary_charging(monkeypatch):
    discovery = D.Discovery("web")
    profile(monkeypatch, ordinary_record_json_bytes=0)
    assert discovery.record(D.DEFINITION_DOMAIN, "a.service", {})
    exact = D.canonical_size(discovery.domain(D.DEFINITION_DOMAIN), 16 * D.MIB)
    profile(monkeypatch, definition_domain_json_bytes=exact)
    assert report(discovery)["schema"] == "AcademyAuthorityDiscovery.v2"
    assert discovery.ordinary_record_json_bytes == 0
    profile(monkeypatch, definition_domain_json_bytes=exact - 1)
    assert report(discovery)["normal_evidence_not_emitted"]


def test_normal_limit_exactly_accounts_final_newline(monkeypatch):
    discovery = D.Discovery("web")
    profile(monkeypatch, normal_json_bytes=4096)
    for _ in range(4):
        exact = D.canonical_size(discovery.envelope(), D.MIB) + 1
        if exact == D.RESOURCE_PROFILE["normal_json_bytes"]:
            break
        profile(monkeypatch, normal_json_bytes=exact)
    assert report(discovery)["schema"] == "AcademyAuthorityDiscovery.v2"
    profile(monkeypatch, normal_json_bytes=exact - 1)
    assert report(discovery)["normal_evidence_not_emitted"]


def test_domain_and_gap_metadata_are_bounded_with_finalization_slot():
    discovery = D.Discovery("web")
    for index in range(31):
        discovery.domain("synthetic_" + str(index))
    with pytest.raises(D.ResourceLimitError):
        discovery.domain("extra")
    discovery.gap("collector", "unexpected_failure")
    assert len(discovery.domains) == 32
    for index in range(128):
        discovery.gap("synthetic_0", "gap_" + str(index))
    with pytest.raises(D.ResourceLimitError):
        discovery.gap("synthetic_0", "overflow")


def test_duplicate_facts_identity_is_refused_without_ledger_change():
    discovery = D.Discovery("web")
    facts = {"old": True}
    assert discovery.record("systemd_loaded", "a.service", facts)
    ledger = dict(discovery.record_ledger)
    size = discovery.ordinary_record_json_bytes
    assert not discovery.record("systemd_loaded", "b.service", facts)
    assert discovery.record_ledger == ledger
    assert discovery.ordinary_record_json_bytes == size
    assert len(discovery.domain("systemd_loaded")["records"]) == 1
    assert facts == {"old": True}


@pytest.mark.parametrize("container", ["dict", "list", "tuple", "same"])
def test_replacement_cannot_create_post_commit_self_cycle(container):
    discovery = D.Discovery("web")
    facts = {"old": True}
    assert discovery.record("systemd_loaded", "a.service", facts)
    ledger = dict(discovery.record_ledger)
    size = discovery.ordinary_record_json_bytes
    nested = {"dict": {"nested": facts}, "list": {"nested": [facts]},
              "tuple": {"nested": (facts,)}, "same": facts}[container]
    assert not discovery.replace_record_facts(facts, nested)
    assert discovery.record_ledger == ledger
    assert discovery.ordinary_record_json_bytes == size
    assert facts == {"old": True}


def test_replacement_cannot_alias_another_record_facts():
    discovery = D.Discovery("web")
    first, second = {"first": True}, {"second": True}
    assert discovery.record("systemd_loaded", "a.service", first)
    assert discovery.record("systemd_loaded", "b.service", second)
    assert not discovery.replace_record_facts(first, {"aliased": second})
    assert first == {"first": True} and second == {"second": True}


@pytest.mark.parametrize("exhaustion", ["domain", "gap", "domain_name", "gap_code"])
def test_metadata_refusal_has_nonrecursive_single_failure_delivery(exhaustion):
    discovery = D.Discovery("web")
    with pytest.raises(D.ResourceLimitError):
        if exhaustion == "domain":
            for index in range(32):
                discovery.domain("synthetic_" + str(index))
        elif exhaustion == "gap":
            for index in range(129):
                discovery.gap("synthetic", "gap_" + str(index))
        elif exhaustion == "domain_name":
            discovery.domain("x" * 65)
        else:
            discovery.gap("synthetic", "x" * 129)
    discovery.gap("collector", "unexpected_failure")
    discovery.interrupted("collector")
    output = io.BytesIO()
    discovery.emit(output)
    data = output.getvalue()
    result = json.loads(data)
    assert len(data) <= D.MIB and data.count(b"\n") == 1
    assert result["schema"] == "AcademyAuthorityDiscoveryFailure.v2"
    assert result["domains"] == {} and result["normal_evidence_not_emitted"]
    assert result["resource_accounting"]["resource_stop_reason"] == "observation_retention_limit"
    validator().validate(result)


def test_gap_dedup_does_not_consume_capacity_or_mutate_code():
    discovery = D.Discovery("web")
    for index in range(128):
        discovery.gap("synthetic", "gap_" + str(index))
    discovery.gap("synthetic", "gap_0")
    assert len(discovery.domain("synthetic")["gaps"]) == 128
    assert not discovery.resource_stopped


@pytest.mark.parametrize("field,limit", [("stat", 16384), ("status", 65536),
                                         ("cgroup", 65536), ("cmdline", D.MAX_BYTES)])
def test_proc_local_overflow_probe_is_exactly_one_charged_byte(monkeypatch, field, limit):
    discovery = D.Discovery("web")
    file_meta = metadata(stat.S_IFREG | 0o600)
    directory_meta = metadata(stat.S_IFDIR | 0o755)
    remaining = limit + 1
    requests, closed = [], []
    monkeypatch.setattr(D.os, "open", lambda *_a, **_k: 12)
    monkeypatch.setattr(D.os, "close", closed.append)
    monkeypatch.setattr(D.os, "fstat", lambda fd: file_meta if fd == 12 else directory_meta)
    monkeypatch.setattr(D.os, "stat", lambda name, **_k: directory_meta if name in ("/proc", "123") else file_meta)

    def read(_fd, request):
        nonlocal remaining
        requests.append(request)
        size = min(request, remaining)
        remaining -= size
        return b"x" * size

    monkeypatch.setattr(D.os, "read", read)
    assert discovery.read_proc_file(10, 11, "123", field, 3, "processes", []) is None
    assert discovery.captured_payload_bytes == limit + 1
    assert sum(requests) == limit + 1
    assert max(requests) <= 65536
    assert "procfs_file_byte_bound" in discovery.domain("processes")["gaps"]
    assert closed == [12]

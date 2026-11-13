# ruff: noqa: S101 -- assertions qualify synthetic graph observations.
"""Hosted-only graph qualification; commands and host data are synthetic."""

import json

import candidate_authority_discovery as D
import pytest


def graph(name, **changes):
    values = dict.fromkeys(D.Discovery.graph_properties(name), "")
    values.update(Id=name, Names=name)
    values.update(changes)
    return b"".join(key.encode() + b"=" + value.encode() + b"\n" for key, value in values.items())


def observe(raw, name="a.service", **kwargs):
    return D.Discovery.parse_unit_graph(raw, D.Discovery.graph_properties(name), **kwargs)


class SyntheticDiscovery(D.Discovery):
    def __init__(self, names=("a.service",), *, final=None, initial_raw=None, repeated_raw=None,
                 failed_listing=None):
        super().__init__("web")
        self.names = names
        self.final = names if final is None else final
        self.initial_raw = initial_raw
        self.repeated_raw = repeated_raw
        self.failed_listing = failed_listing
        self.calls = []

    def run(self, args, domain, **_kwargs):
        self.calls.append((args, domain))
        if domain == self.failed_listing:
            self.gap(domain, "synthetic_command_failure")
            return None
        if args[0] == "list-jobs":
            return b""
        if args[0].startswith("list-"):
            names = self.final if domain.endswith("_final") else self.names
            if args[0] in ("list-timers", "list-jobs"):
                names = ()
            key = "unit_file" if args[0] == "list-unit-files" else "unit"
            return json.dumps([{key: name} for name in names]).encode()
        assert args[0] == "show"
        name = args[-1]
        if domain == "systemd_unit_graph":
            if self.repeated_raw is not None:
                return self.repeated_raw(name)
            return graph(name)
        if self.initial_raw is not None:
            return self.initial_raw(name)
        fields = args[2].removeprefix("--property=").split(",")
        values = dict.fromkeys(fields, "")
        values.update(Id=name, Names=name)
        return b"".join(key.encode() + b"=" + value.encode() + b"\n" for key, value in values.items())


def rows(discovery):
    return discovery.domain("systemd_unit_graph")["records"]


def test_endpoint_order_duplicates_and_original_projections():
    raw = graph("a.service", Wants="b.service b.service a.service") + b"ExecStart=sensitive-command\n"
    result = observe(raw)
    assert result["gaps"] == []
    item = result["fields"]["Wants"]
    assert item["endpoint_sha256"] == [D.digest(x.encode()) for x in ("b.service", "b.service", "a.service")]
    assert item["projection"] == D.projection(b"b.service b.service a.service")
    assert "sensitive-command" not in json.dumps(result)
    assert "unexpected_graph_key" in observe(raw, graph_only=True)["gaps"]


@pytest.mark.parametrize("field", ["Names", "Triggers", "TriggeredBy", "Requires", "Wants", "Before", "After"])
def test_native_backslash_identity_decodes_one_cli_layer_in_every_array(field):
    native = rb"example\x2dnode.service"
    rendered = b'"example\\\\x2dnode.service"'
    value = b"a.service " + rendered + b" " + rendered
    result = observe(graph("a.service", **{field: value.decode("ascii")}))
    assert result["gaps"] == []
    assert result["fields"][field] == {
        "projection": D.projection(value),
        "endpoint_sha256": [D.digest(b"a.service"), D.digest(native), D.digest(native)],
        "valid": True,
    }
    assert D.digest(native) != D.digest(b"example-node.service")


def test_native_quoted_names_join_enumeration_without_unknown_identity_disclosure():
    native = r"example\x2dnode.service"
    rendered = '"example\\\\x2dnode.service"'
    discovery = SyntheticDiscovery((native,))
    discovery.initial_raw = lambda name: graph(name, Names=rendered, After=rendered)
    discovery.repeated_raw = discovery.initial_raw
    discovery.systemd()
    row = rows(discovery)[0]
    facts = row["facts"]
    assert row["identity_sha256"] == D.digest(native.encode())
    assert row["identity"] is None and row["unknown_identity"]
    assert facts["gaps"] == [] and facts["graph_fields_unchanged"]
    assert facts["unresolved_endpoint_sha256"] == []
    assert facts["classification"] == "unknown" and facts["authority_refs"] == []
    assert native not in json.dumps(row)


def test_scalar_id_and_conditional_unit_remain_raw_native_bytes():
    native = r"example\x2dnode.service"
    timer = r"example\x2dnode.timer"
    result = observe(graph(timer, Names='"example\\\\x2dnode.timer"', Unit=native), timer)
    assert result["gaps"] == []
    for field, value in (("Id", timer), ("Unit", native)):
        assert result["fields"][field] == {
            "projection": D.projection(value.encode()),
            "endpoint_sha256": [D.digest(value.encode())], "valid": True,
        }
    for field in ("Id", "Unit"):
        result = observe(graph("a.timer", **{field: '"example\\\\x2dnode.service"'}), "a.timer")
        assert not result["fields"][field]["valid"]
        assert "unsupported_graph_value" in result["gaps"]


@pytest.mark.parametrize("value", [
    b'"a.service"', b"'a.service'", rb"example\x2dnode.service",
    rb'"example\x2dnode.service"', rb'"example\nnode.service"',
    rb'"example\qnode.service"', rb'"example\$node.service"',
    rb'"example\`node.service"', rb'"example\"node.service"',
    b'"example\\\\node.service', b'"example\\', b'""',
    b'"example\\\\node".service', b'example"\\\\node.service"',
    b'"example\\\\node.service""other.service"', b"$(other.service)",
    b'"example\\\\node service"', b" a.service", b"a.service ", b"a.service  b.service",
    b'"example\\\\node/invalid.service"', b'"example\\\\\xff.service"',
])
def test_array_rejects_noncanonical_quotes_escapes_concatenation_and_nonunits(value):
    result = observe(graph("a.service").replace(b"After=\n", b"After=" + value + b"\n"))
    item = result["fields"]["After"]
    assert not item["valid"]
    assert "unsupported_graph_value" in result["gaps"]
    assert item["projection"] == D.projection(value)


@pytest.mark.parametrize("size,valid", [(255, True), (256, False)])
def test_native_array_token_length_bound_applies_after_cli_decoding(size, valid):
    native = b"a" * (size - 1) + b"\\"
    rendered = b'"' + native.replace(b"\\", b"\\\\") + b'"'
    result = observe(graph("a.service", After=rendered.decode()))
    assert result["fields"]["After"]["valid"] is valid
    if valid:
        assert result["fields"]["After"]["endpoint_sha256"] == [D.digest(native)]
    else:
        assert "unsupported_graph_value" in result["gaps"]


def test_array_budget_bounds_token_allocation_and_preserves_whole_field_refusal(monkeypatch):
    original = D.Discovery.systemctl_unit_array_tokens
    attempts = []

    def counted(value):
        for token in original(value):
            attempts.append(len(token))
            yield token

    monkeypatch.setattr(D.Discovery, "systemctl_unit_array_tokens", staticmethod(counted))
    value = b" ".join([b'"example\\\\x2dnode.service"'] * 20000)
    result = observe(graph("a.service", After=value.decode()), endpoint_budget=3)
    assert attempts == [9, 23, 23]  # Names, then remaining+1 After tokens.
    assert result["endpoint_count"] == 2
    assert "graph_endpoint_budget" in result["gaps"]
    assert result["fields"]["After"] == {
        "projection": D.projection(value), "endpoint_sha256": [], "valid": False,
    }


def test_large_space_and_line_inputs_refuse_without_unbounded_token_splitting():
    value = " " * D.MAX_BYTES
    result = observe(graph("a.service", After=value), endpoint_budget=3)
    assert result["endpoint_count"] == 3
    assert "unsupported_graph_value" in result["gaps"]
    assert not result["fields"]["After"]["valid"]
    assert result["fields"]["After"]["projection"] == D.projection(value.encode())
    raw = b"\n" * (D.MAX_ROWS + 1)
    result = observe(raw)
    assert result["gaps"] == ["graph_line_bound"] and result["endpoint_count"] == 0
    assert result["original_output"] == D.projection(raw)


def test_interruption_while_decoding_array_cannot_mark_prefix_valid():
    checks = 0

    def stopped():
        nonlocal checks
        checks += 1
        return checks >= 3

    result = D.Discovery.parse_unit_graph(
        b"After=a.service b.service\n", ("After",), stopped=stopped
    )
    assert "graph_work_interrupted_or_deadline" in result["gaps"]
    assert result["endpoint_count"] == 0
    assert result["fields"]["After"]["endpoint_sha256"] == []
    assert not result["fields"]["After"]["valid"]


@pytest.mark.parametrize("suffix", [
    b"Id=other.service\n", b"After=a.service\tb.service\n", b"After=a.service  b.service\n",
    b"After=\xff.service\n", b"Id=\n", b"Id=a.service b.service\n", b"Names=bad/name\n",
])
def test_duplicate_or_unsupported_graph_fields(suffix):
    result = observe(graph("a.service") + suffix)
    assert result["gaps"]
    assert "duplicate_graph_key" in result["gaps"]


@pytest.mark.parametrize("value", ["a.service\tb.service", "a.service  b.service", "bad/name", "a.service\r"])
def test_unsupported_list_values(value):
    result = observe(graph("a.service", After=value))
    assert "unsupported_graph_value" in result["gaps"]
    assert result["fields"]["After"]["projection"] == D.projection(value.encode())


def test_missing_malformed_and_conditional_scalar():
    assert "missing_graph_fields" in observe(b"Id=a.service\n")["gaps"]
    assert "line_missing_equals" in observe(graph("a.service") + b"broken\n")["gaps"]
    assert observe(graph("a.timer"), "a.timer")["gaps"] == []
    assert "unsupported_graph_value" in observe(graph("a.timer", Unit="a.service b.service"), "a.timer")["gaps"]
    assert observe(None)["fields"]["Id"] is None


def test_old_projections_counters_and_unknown_classification_preserved():
    discovery = SyntheticDiscovery()
    discovery.systemd()
    old = discovery.domain("systemd_unit_properties")
    assert (old["enumerated"], old["inspected"], old["complete"]) == (1, 1, 1)
    assert old["records"][0]["facts"]["properties"]["Id"] == D.projection(b"a.service")
    target = discovery.domain("systemd_unit_graph")
    assert target["enumeration_complete"] and target["complete"] == 1
    assert not target["classification_complete"]
    facts = rows(discovery)[0]["facts"]
    assert facts["graph_fields_unchanged"]
    assert facts["classification"] == "unknown" and facts["authority_refs"] == []
    show_calls = [domain for args, domain in discovery.calls if args[0] == "show"]
    assert show_calls == ["systemd_unit_properties", "systemd_unit_graph"]
    assert discovery.domain("systemd_installed_final")["enumeration_complete"]
    assert discovery.domain("systemd_loaded_final")["enumeration_complete"]
    for name, count in (("systemd_installed", 1), ("systemd_loaded", 1), ("systemd_timers", 0),
                        ("systemd_jobs", 0), ("systemd_unit_properties", 1)):
        original = discovery.domain(name)
        assert (original["enumerated"], original["inspected"], original["complete"]) == (count, count, count)
        assert original["raced"] == original["skipped"] == 0
        assert original["enumeration_complete"] and not original["classification_complete"]
        assert original["gaps"] == []
    assert discovery.domain("systemd_jobs")["empty_pending_jobs_snapshot"]
    for domain, key in (("systemd_installed", "unit_file"), ("systemd_loaded", "unit")):
        assert discovery.domain(domain)["records"][0]["facts"]["row_projection"] == D.projection(
            json.dumps({key: "a.service"}, sort_keys=True).encode()
        )
    original_facts = old["records"][0]["facts"]
    expected = {field: D.projection(b"a.service" if field in ("Id", "Names") else b"")
                for field in (*D.COMMON_PROPERTIES, *D.EXEC_CONTEXT_PROPERTIES, *D.SERVICE_PROPERTIES)}
    assert original_facts["properties"] == expected
    assert original_facts["missing_properties"] == []
    assert original_facts["property_retry_output"] == original_facts["property_retry_failure"] == {}


def test_aliases_templates_cycles_and_dangling_endpoints_remain_separate():
    names = ("alias.service", "canonical.service", "task@.service")
    discovery = SyntheticDiscovery(names)
    def relationships(name):
        return graph(name, Id="canonical.service", Names="alias.service canonical.service",
                     After="alias.service", Wants="missing.service")

    discovery.initial_raw = lambda name: relationships(name) + b"EnvironmentFiles=\nExecStart=\n"
    discovery.repeated_raw = relationships
    discovery.systemd()
    assert len(rows(discovery)) == 3
    assert len({row["identity_sha256"] for row in rows(discovery)}) == 3
    assert rows(discovery)[2]["facts"]["name_shape"]["shape"] == "template"
    for row in rows(discovery):
        facts = row["facts"]
        assert facts["graph_fields_unchanged"]
        assert facts["unresolved_endpoint_sha256"] == [D.digest(b"missing.service")]
        assert facts["classification"] == "unknown" and facts["authority_refs"] == []
    assert "missing.service" not in json.dumps(rows(discovery))


def test_final_only_and_removed_nodes_and_explicit_memberships():
    discovery = SyntheticDiscovery(final=("b.service",))
    discovery.systemd()
    by_hash = {row["identity_sha256"]: row["facts"] for row in rows(discovery)}
    before = by_hash[D.digest(b"a.service")]
    after = by_hash[D.digest(b"b.service")]
    assert before["membership_after"] == {"installed": False, "loaded": False}
    assert after["membership_before"] == {"installed": False, "loaded": False}
    assert after["initial"]["fields"]["Id"] is None
    assert "enumeration_membership_changed" in discovery.domain("systemd_unit_graph")["gaps"]
    assert discovery.loaded_units == {"a.service"}  # Original process enumeration is preserved.


@pytest.mark.parametrize("listing", ["systemd_installed", "systemd_loaded", "systemd_installed_final",
                                     "systemd_loaded_final"])
def test_failed_enumerations_are_not_successful_empty(listing):
    discovery = SyntheticDiscovery(failed_listing=listing)
    discovery.systemd()
    target = discovery.domain("systemd_unit_graph")
    assert not target["enumeration_complete"]
    assert target["complete"] == 0
    assert "enumeration_boundary_unavailable" in target["gaps"]
    if listing.endswith("_final"):
        key = "installed" if "installed" in listing else "loaded"
        assert rows(discovery)[0]["facts"]["membership_after"][key] is None


def test_successful_empty_graph_still_has_no_classification():
    discovery = SyntheticDiscovery(())
    discovery.systemd()
    target = discovery.domain("systemd_unit_graph")
    assert target["enumeration_complete"] and target["enumerated"] == 0
    assert not target["classification_complete"]


@pytest.mark.parametrize("repeat", [None, b"Id=a.service\n", graph("a.service", After="a.service")])
def test_missing_or_changed_repeated_fields_are_gaps(repeat):
    discovery = SyntheticDiscovery(repeated_raw=lambda _name: repeat)
    discovery.systemd()
    target = discovery.domain("systemd_unit_graph")
    assert target["complete"] == 0
    assert not rows(discovery)[0]["facts"]["graph_fields_unchanged"]
    assert "graph_fields_changed_or_unavailable" in target["gaps"]


def test_graph_union_cap_and_deadline_remain_partial(monkeypatch):
    discovery = SyntheticDiscovery()
    initial = observe(graph("a.service"))
    for name in ("systemd_installed", "systemd_loaded"):
        discovery.domain(name)["enumeration_complete"] = True
    discovery.listing = lambda *_args: {"a.service", "b.service", "c.service"}
    monkeypatch.setattr(D, "MAX_ROWS", 2)
    facts = discovery.retain_unit_graph("a.service", {"a.service"}, set(), initial)
    facts["repeated"] = initial
    discovery.finish_unit_graph({"a.service"}, set(), {"a.service": facts})
    target = discovery.domain("systemd_unit_graph")
    assert target["enumerated"] == 3 and target["inspected"] == 2 and target["skipped"] == 1
    assert "union_units_truncated" in target["gaps"]
    discovery = SyntheticDiscovery()
    discovery.deadline = 0
    discovery.finish_unit_graph({"a.service"}, set(), {})
    assert discovery.domain("systemd_unit_graph")["skipped"] == 1
    assert "graph_work_interrupted_or_deadline" in discovery.domain("systemd_unit_graph")["gaps"]


def test_whole_output_hashes_survive_duplicate_and_malformed_input():
    raw = graph("a.service") + b"Id=b.service\nmalformed\n"
    result = observe(raw, graph_only=True)
    assert result["original_output"] == D.projection(raw)
    assert result["gaps"]
    discovery = SyntheticDiscovery(repeated_raw=lambda _name: raw)
    discovery.systemd()
    facts = rows(discovery)[0]["facts"]
    assert facts["initial"]["original_output"] is not None
    assert facts["repeated"]["original_output"] == D.projection(raw)


def test_shared_endpoint_budget_is_charged_across_both_reads_and_units():
    discovery = SyntheticDiscovery()
    discovery.graph_endpoint_remaining = 3
    fields = discovery.graph_properties("a.service")
    first = discovery.collect_unit_graph(graph("a.service"), fields)
    second = discovery.collect_unit_graph(graph("a.service"), fields, graph_only=True)
    third = discovery.collect_unit_graph(graph("b.service"), fields)
    assert first["endpoint_count"] == 2 and second["endpoint_count"] == 1
    assert third["endpoint_count"] == 0 and discovery.graph_endpoint_remaining == 0
    assert "graph_endpoint_budget" in second["gaps"] and "graph_endpoint_budget" in third["gaps"]
    assert third["original_output"] == D.projection(graph("b.service"))
    assert sum(item["endpoint_count"] for item in (first, second, third)) == 3


def test_parser_stops_on_shared_interruption():
    result = D.Discovery.parse_unit_graph(graph("a.service"), D.GRAPH_PROPERTIES, stopped=lambda: True)
    assert "graph_work_interrupted_or_deadline" in result["gaps"]
    assert result["endpoint_count"] == 0
    assert result["original_output"] == D.projection(graph("a.service"))


def test_runner_cleanup_failure_cannot_create_stable_success(monkeypatch):
    discovery = SyntheticDiscovery()
    original = discovery.run

    def run(args, domain, **kwargs):
        if domain == "systemd_unit_graph":
            discovery.gap(domain, "prior_child_cleanup_unconfirmed")
            return None
        return original(args, domain, **kwargs)

    monkeypatch.setattr(discovery, "run", run)
    discovery.systemd()
    assert discovery.domain("systemd_unit_graph")["complete"] == 0
    assert not rows(discovery)[0]["facts"]["graph_fields_unchanged"]
    assert "prior_child_cleanup_unconfirmed" in discovery.domain("systemd_unit_graph")["gaps"]


@pytest.mark.parametrize("stop", ["deadline", "signal"])
def test_late_stop_retains_captured_pairs_and_never_calls_runner_again(monkeypatch, stop):
    discovery = SyntheticDiscovery(("a.service", "b.service", "c.service"))
    original_run = discovery.run
    stopped_at = []

    def run(args, domain, **kwargs):
        assert not stopped_at, "runner invoked after shared stop"
        result = original_run(args, domain, **kwargs)
        if domain == "systemd_unit_graph" and args[-1] == "b.service":
            stopped_at.append(len(discovery.calls))
            if stop == "deadline":
                discovery.deadline = 0
            else:
                discovery.pending_signal = 15
        return result

    monkeypatch.setattr(discovery, "run", run)
    discovery.systemd()
    target = discovery.domain("systemd_unit_graph")
    assert target["enumerated"] == 3 and target["inspected"] == 2 and target["skipped"] == 1
    assert target["complete"] == 0 and not target["classification_complete"]
    assert not target["enumeration_complete"]
    assert len(discovery.calls) == stopped_at[0]
    assert "graph_finalization_unavailable" in target["gaps"]
    for row in rows(discovery):
        facts = row["facts"]
        assert facts["initial"]["original_output"] is not None
        assert facts["repeated"]["original_output"] is not None
        assert facts["membership_after"] == {"installed": None, "loaded": None}
        assert facts["unresolved_endpoint_sha256"] is None
        assert not facts["graph_fields_unchanged"]
        assert "graph_finalization_unavailable" in facts["gaps"]
    assert rows(discovery)[0]["facts"]["initial"]["fields"]["Id"]["endpoint_sha256"] == [D.digest(b"a.service")]
    assert "graph_work_interrupted_or_deadline" in rows(discovery)[1]["facts"]["repeated"]["gaps"]


def test_stop_after_initial_read_retains_projection_and_skips_repeat(monkeypatch):
    discovery = SyntheticDiscovery()
    original_run = discovery.run

    def run(args, domain, **kwargs):
        assert discovery.pending_signal is None
        result = original_run(args, domain, **kwargs)
        if args[0] == "show":
            discovery.pending_signal = 15
        return result

    monkeypatch.setattr(discovery, "run", run)
    discovery.systemd()
    facts = rows(discovery)[0]["facts"]
    assert facts["initial"]["original_output"] is not None
    assert facts["repeated"]["original_output"] is None
    assert "graph_work_interrupted_or_deadline" in facts["initial"]["gaps"]
    assert discovery.domain("systemd_unit_graph")["complete"] == 0
    assert [domain for args, domain in discovery.calls if args[0] == "show"] == ["systemd_unit_properties"]

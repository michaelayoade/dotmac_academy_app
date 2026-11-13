# ruff: noqa: S101 -- hosted synthetic qualification assertions.
"""Runtime v255 endpoint catalogue: no host commands or inferred activation."""

import copy
import json
from pathlib import Path

import candidate_authority_discovery as D
import pytest
from jsonschema import Draft202012Validator, ValidationError
from test_systemd_graph_discovery import SyntheticDiscovery, graph, observe, rows

ADDED = (
    "Requisite", "BindsTo", "PartOf", "Upholds", "RequiredBy", "RequisiteOf", "WantedBy", "BoundBy",
    "UpheldBy", "ConsistsOf", "Conflicts", "ConflictedBy", "OnSuccess", "OnSuccessOf", "OnFailure",
    "OnFailureOf", "PropagatesReloadTo", "ReloadPropagatedFrom", "PropagatesStopTo", "StopPropagatedFrom",
    "JoinsNamespaceOf", "SliceOf",
)
HISTORICAL = ("Id", "Names", "Triggers", "TriggeredBy", "Requires", "Wants", "Before", "After")


def validator():
    return Draft202012Validator(json.loads((Path(__file__).parents[1] / "discovery.schema.json").read_text()))


def collected():
    discovery = SyntheticDiscovery()
    discovery.systemd()
    return discovery, json.loads(discovery.seal().read())


def test_catalogue_hash_source_signatures_and_unchanged_budgets():
    catalogue = D.SYSTEMD_RUNTIME_RELATION_CATALOGUE
    actual_hash = D.digest(json.dumps(catalogue, **D.JSON_OPTIONS).encode("ascii"))
    assert actual_hash == D.SYSTEMD_RUNTIME_RELATION_CATALOGUE_SHA256
    assert catalogue["source_version"] == "systemd.v255"
    assert len(ADDED) == 22 and set(ADDED) <= set(D.GRAPH_PROPERTIES)
    assert catalogue["activation_complete_claimed"] is False
    assert catalogue["default_target_inference"] == "forbidden"
    assert catalogue["inverse_scope"] == "exported_unit_properties"
    namespace = catalogue["properties"]["JoinsNamespaceOf"]
    assert namespace["inverse"] == "JoinsNamespaceOf" and namespace["direction"] == "symmetric"
    slice_of = catalogue["properties"]["SliceOf"]
    assert slice_of["inverse"] is None and slice_of["internal_inverse"] == "UNIT_IN_SLICE"
    assert slice_of["internal_inverse_exported"] is False
    assert "InSlice" not in D.GRAPH_PROPERTIES
    assert "https://github.com/systemd/systemd/blob/v255/src/core/unit.c#L2901-L2932" in catalogue["sources"]
    assert catalogue["unsupported_path_requirements"] == {
        "Unit.RequiresMountsFor": {"signature": "as", "reason": "paths_not_unit_endpoints"},
        "Path.Paths": {"signature": "a(ss)", "reason": "paths_not_unit_endpoints"},
    }
    assert (D.SYSTEMD_ENDPOINT_PROFILE["field_attempts"], D.SYSTEMD_ENDPOINT_PROFILE["unit_read_attempts"],
            D.SYSTEMD_ENDPOINT_PROFILE["initial_pass_attempts"], D.SYSTEMD_ENDPOINT_PROFILE["repeated_pass_attempts"],
            D.SYSTEMD_ENDPOINT_PROFILE["total_attempts"]) == (4096, 8192, 65536, 65536, 131072)


def test_every_field_requested_in_both_fixed_show_reads():
    discovery = SyntheticDiscovery(("a.service", "b.timer", "c.path"))
    discovery.systemd()
    for name in discovery.names:
        calls = [args for args, _domain in discovery.calls if args[0] == "show" and args[-1] == name]
        assert len(calls) == 2
        for call in calls:
            requested = call[2].removeprefix("--property=").split(",")
            assert set((*HISTORICAL, *ADDED, "Following")) <= set(requested)
            assert "RequiresMountsFor" not in requested and "Paths" not in requested
            assert ("Unit" in requested) == name.endswith((".timer", ".path"))


@pytest.mark.parametrize("field", [*ADDED, "Names", "Triggers", "TriggeredBy", "Requires", "Wants", "Before", "After"])
def test_each_array_preserves_one_cli_layer_order_and_duplicates(field):
    native = rb"native\x2dname.service"
    value = b'a.service "native\\\\x2dname.service" "native\\\\x2dname.service"'
    read = observe(graph("a.service", **{field: value.decode("ascii")}))
    assert read["gaps"] == []
    item = read["fields"][field]
    assert item["projection"] == D.projection(value)
    assert item["endpoint_sha256"] == [D.digest(b"a.service"), D.digest(native), D.digest(native)]
    assert item["endpoint_count"] == item["retained_endpoint_count"] == 3


@pytest.mark.parametrize("value,valid,count", [
    ("", True, 0), (r"native\x2dname.service", True, 1),
    ("a.service b.service", False, 1), ('"a.service"', False, 1), ("/a/path", False, 1),
])
def test_following_is_optional_raw_native_scalar(value, valid, count):
    item = observe(graph("a.service", Following=value))["fields"]["Following"]
    assert item["valid"] is valid and item["endpoint_count"] == count
    assert item["endpoint_sha256"] == ([D.digest(value.encode())] if valid and value else [])
    assert item["projection"] == D.projection(value.encode())


@pytest.mark.parametrize("field", ADDED)
def test_new_fields_missing_duplicate_invalid_and_caps_refuse(field):
    raw = graph("a.service")
    missing = b"\n".join(line for line in raw.split(b"\n") if not line.startswith(field.encode() + b"="))
    assert "missing_graph_fields" in observe(missing)["gaps"]
    duplicate = observe(raw + field.encode() + b"=a.service\n")
    assert "duplicate_graph_key" in duplicate["gaps"]
    assert not duplicate["fields"][field]["valid"]
    invalid = observe(graph("a.service", **{field: "/path/not-a-unit"}))
    assert invalid["fields"][field]["endpoint_sha256"] == []
    capped = observe(graph("a.service", **{field: " ".join(["a.service"] * 4097)}))
    assert "graph_endpoint_field_budget" in capped["gaps"]
    assert capped["fields"][field]["endpoint_count"] == 4096
    assert capped["fields"][field]["unparsed_tail"] and capped["fields"][field]["endpoint_sha256"] == []


def test_v3_sealed_global_guard_accounting_and_no_invented_targets():
    discovery, report = collected()
    validator().validate(report)
    facts = rows(discovery)[0]["facts"]
    assert facts["schema"] == "AcademySystemdUnitGraphFacts.v3"
    assert facts["classification"] == "unknown" and facts["authority_refs"] == []
    assert facts["activation_complete_claimed"] is False
    assert facts["initial"]["fields"]["Following"]["endpoint_sha256"] == []
    assert discovery.domain("systemd_unit_graph")["endpoint_accounting"]["total"]["retained_endpoint_count"] == 4
    assert report["resource_profile"] == D.RESOURCE_PROFILE
    assert D.canonical_size(report, D.RESOURCE_PROFILE["normal_json_bytes"]) + 1 == len(discovery.seal().read())


@pytest.mark.parametrize("scope,key,value", [
    ("domain", "runtime_relation_catalogue_sha256", "0" * 64),
    ("facts", "runtime_relation_catalogue_sha256", "0" * 64),
    ("read", "runtime_relation_catalogue_sha256", "0" * 64),
    ("facts", "activation_complete_claimed", True),
    ("facts", "schema", "AcademySystemdUnitGraphFacts.v2"),
    ("catalogue", "activation_complete_claimed", True),
    ("property", "signature", "s"),
    ("property", "direction", "inverse"),
])
def test_v3_closed_catalogue_and_version_binding(scope, key, value):
    _discovery, report = collected()
    domain = report["domains"]["systemd_unit_graph"]
    facts = domain["records"][0]["facts"]
    targets = {"domain": domain, "facts": facts, "read": facts["initial"],
               "catalogue": domain["runtime_relation_catalogue"],
               "property": domain["runtime_relation_catalogue"]["properties"]["Requisite"]}
    targets[scope][key] = value
    with pytest.raises(ValidationError):
        validator().validate(report)


def historical_v2(report):
    """Explicit historical fixture, with the original eight graph fields only."""
    report = copy.deepcopy(report)
    domain = report["domains"]["systemd_unit_graph"]
    domain.pop("runtime_relation_catalogue")
    domain.pop("runtime_relation_catalogue_sha256")
    for record in domain["records"]:
        facts = record["facts"]
        facts["schema"] = "AcademySystemdUnitGraphFacts.v2"
        facts.pop("runtime_relation_catalogue_sha256")
        facts.pop("activation_complete_claimed")
        for phase in ("initial", "repeated"):
            read = facts[phase]
            read.pop("runtime_relation_catalogue_sha256")
            read["fields"] = {key: value for key, value in read["fields"].items() if key in HISTORICAL}
    return report


def test_historical_v2_accepted_but_cannot_mix_v3_read_or_catalogue():
    _discovery, current = collected()
    old = historical_v2(current)
    validator().validate(old)
    mixed = copy.deepcopy(old)
    mixed["domains"]["systemd_unit_graph"]["records"][0]["facts"]["initial"] = (
        current["domains"]["systemd_unit_graph"]["records"][0]["facts"]["initial"]
    )
    with pytest.raises(ValidationError):
        validator().validate(mixed)
    old["domains"]["systemd_unit_graph"]["runtime_relation_catalogue"] = D.SYSTEMD_RUNTIME_RELATION_CATALOGUE
    with pytest.raises(ValidationError):
        validator().validate(old)


def test_following_missing_duplicate_and_unit_read_cap_remain_partial():
    raw = graph("a.service", Following=r"native\x2dname.service")
    missing = raw.replace(b"Following=native\\x2dname.service\n", b"")
    assert "missing_graph_fields" in observe(missing)["gaps"]
    duplicate = observe(raw + b"Following=a.service\n")
    assert "duplicate_graph_key" in duplicate["gaps"]
    assert duplicate["fields"]["Following"]["endpoint_count"] == 2
    assert duplicate["fields"]["Following"]["endpoint_sha256"] == []
    value = " ".join(["a.service"] * 4096)
    capped = observe(graph("a.service", Requisite=value, BindsTo=value, Upholds="a.service"))
    assert capped["endpoint_count"] == 8192
    assert "graph_endpoint_unit_budget" in capped["gaps"] and capped["unparsed_tail"]
    for phase in ("initial", "repeated"):
        result = observe(raw, phase=phase, pass_remaining=2)
        assert result["endpoint_count"] == 2
        assert "graph_endpoint_" + phase + "_pass_budget" in result["gaps"]
    result = observe(raw, total_remaining=2)
    assert "graph_endpoint_total_budget" in result["gaps"] and result["endpoint_count"] == 2


@pytest.mark.parametrize("attempts,hashes,retained", [
    (2, [], 0), (1, [], 0), (0, ["a" * 64], 1),
])
def test_valid_following_counters_cannot_disagree(attempts, hashes, retained):
    _discovery, report = collected()
    item = report["domains"]["systemd_unit_graph"]["records"][0]["facts"]["initial"]["fields"]["Following"]
    item.update(valid=True, endpoint_count=attempts, endpoint_sha256=hashes, retained_endpoint_count=retained)
    with pytest.raises(ValidationError):
        validator().validate(report)


@pytest.mark.parametrize("value,attempts", [("", 0), ("b.service", 1)])
def test_valid_following_empty_and_nonempty_schema_cases(value, attempts):
    discovery = SyntheticDiscovery()
    discovery.initial_raw = lambda name: graph(name, Following=value) + b"EnvironmentFiles=\nExecStart=\n"
    discovery.repeated_raw = lambda name: graph(name, Following=value)
    discovery.systemd()
    report = json.loads(discovery.seal().read())
    for phase in ("initial", "repeated"):
        item = report["domains"]["systemd_unit_graph"]["records"][0]["facts"][phase]["fields"]["Following"]
        assert item["valid"] and item["endpoint_count"] == item["retained_endpoint_count"] == attempts
        assert len(item["endpoint_sha256"]) == attempts
    validator().validate(report)


def test_invalid_following_keeps_duplicate_attempt_counters_without_hashes():
    discovery = SyntheticDiscovery(
        repeated_raw=lambda name: graph(name, Following="b.service") + b"Following=c.service\n",
    )
    discovery.systemd()
    report = json.loads(discovery.seal().read())
    item = report["domains"]["systemd_unit_graph"]["records"][0]["facts"]["repeated"]["fields"]["Following"]
    assert not item["valid"] and item["endpoint_count"] == 2
    assert item["retained_endpoint_count"] == 0 and item["endpoint_sha256"] == []
    validator().validate(report)

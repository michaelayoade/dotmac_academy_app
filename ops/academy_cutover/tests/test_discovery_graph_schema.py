# ruff: noqa: S101 -- assertions qualify the structural graph schema.
"""Hosted-only validation of synthetic collector output against the public schema."""

import copy
import json
from pathlib import Path

import candidate_authority_discovery as D
import pytest
from jsonschema import Draft202012Validator, ValidationError
from test_systemd_graph_discovery import SyntheticDiscovery, graph


@pytest.fixture
def schema():
    return json.loads((Path(__file__).parents[1] / "discovery.schema.json").read_text())


@pytest.fixture
def validator(schema):
    return Draft202012Validator(schema)


def envelope(discovery):
    return json.loads(discovery.seal().read())


@pytest.fixture
def observed():
    discovery = SyntheticDiscovery()
    discovery.systemd()
    return envelope(discovery)


def facts(observed):
    return observed["domains"]["systemd_unit_graph"]["records"][0]["facts"]


def test_schema_is_valid_draft_2020_12(schema):
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("names,final", [
    (("a.service",), None),
    ((), None),
    (("a.timer", "b.path", "worker@.service"), None),
    (("a.service",), ("b.service",)),
])
def test_actual_synthetic_output_is_accepted(validator, names, final):
    discovery = SyntheticDiscovery(names, final=final)
    discovery.systemd()
    validator.validate(envelope(discovery))


@pytest.mark.parametrize("raw", [
    b"Id=a.service\n",  # Missing fields remain explicit nulls.
    graph("a.service") + b"Id=alias.service\nmalformed\n",
    graph("a.service", Wants="missing.service missing.service"),
    None,
])
def test_incomplete_parser_output_is_accepted(validator, raw):
    discovery = SyntheticDiscovery(repeated_raw=lambda _name: raw)
    discovery.systemd()
    validator.validate(envelope(discovery))


def test_pending_row_is_accepted_without_finalization(validator):
    discovery = SyntheticDiscovery()
    initial = discovery.collect_unit_graph(graph("a.service"), D.GRAPH_PROPERTIES)
    pending = discovery.retain_unit_graph("a.service", {"a.service"}, {"a.service"}, initial)
    assert pending["unresolved_endpoint_sha256"] is None
    assert pending["membership_after"] == {"installed": None, "loaded": None}
    assert not pending["graph_fields_unchanged"]
    assert discovery.domain("systemd_unit_graph")["complete"] == 0
    validator.validate(envelope(discovery))


def test_final_diagnostic_deadline_gap_uses_legacy_facts(validator, observed):
    diagnostic = observed["domains"]["systemd_installed_final"]
    diagnostic["gaps"].append("graph_work_interrupted_or_deadline")
    validator.validate(observed)
    diagnostic["records"][0]["facts"] = copy.deepcopy(facts(observed))
    with pytest.raises(ValidationError):
        validator.validate(observed)


@pytest.mark.parametrize("key,value", [
    ("classification", "non_sender"),
    ("authority_refs", ["forged-authority"]),
    ("plaintext", "raw-unit-name.service"),
    ("requested_identity_sha256", "not-a-hash"),
    ("gaps", ["forged_gap"]),
    ("unresolved_endpoint_sha256", ["bad-hash"]),
    ("unresolved_endpoint_sha256", ["a" * 64, "a" * 64]),
    ("name_shape", {"shape": "forged", "template_name_sha256": None}),
    ("membership_before", {"installed": None, "loaded": True}),
])
def test_rejects_forged_or_unbounded_graph_facts(validator, observed, key, value):
    facts(observed)[key] = value
    with pytest.raises(ValidationError):
        validator.validate(observed)


@pytest.mark.parametrize("scope,key,value", [
    ("read", "plaintext", "sensitive-command"),
    ("read", "endpoint_count", 8193),
    ("read", "gaps", ["forged_gap"]),
    ("field", "endpoint_sha256", ["bad-hash"]),
    ("field", "endpoint_sha256", ["a" * 64] * 8193),
    ("field", "plaintext", "unredacted.service"),
    ("projection", "sha256", "f" * 63),
    ("projection", "bytes", 8388609),
    ("projection", "plaintext", "unredacted.service"),
])
def test_rejects_invalid_graph_reads(validator, observed, scope, key, value):
    read = facts(observed)["initial"]
    field = read["fields"]["Id"]
    target = {"read": read, "field": field, "projection": field["projection"]}[scope]
    target[key] = value
    with pytest.raises(ValidationError):
        validator.validate(observed)


def test_rejects_missing_fields_and_unknown_graph_keys(validator, observed):
    malformed = copy.deepcopy(observed)
    del facts(malformed)["initial"]["fields"]["Id"]
    with pytest.raises(ValidationError):
        validator.validate(malformed)
    facts(observed)["initial"]["fields"]["ExecStart"] = None
    with pytest.raises(ValidationError):
        validator.validate(observed)


@pytest.mark.parametrize("scope,key,value", [
    ("envelope", "coverage_complete", True),
    ("envelope", "campaign_authority_claimed", True),
    ("envelope", "classification_complete", True),
    ("domain", "classification_complete", True),
    ("domain", "gaps", ["forged_gap"]),
    ("record", "identity", "unreviewed.service"),
    ("record", "authority_id", "bad-hash"),
    ("record", "relevance", "sender"),
])
def test_rejects_authority_upgrades(validator, observed, scope, key, value):
    domain = observed["domains"]["systemd_unit_graph"]
    target = {"envelope": observed, "domain": domain, "record": domain["records"][0]}[scope]
    target[key] = value
    with pytest.raises(ValidationError):
        validator.validate(observed)


def test_graph_facts_cannot_bypass_explicit_domain(validator, observed):
    observed["domains"]["unreviewed_domain"] = observed["domains"].pop("systemd_unit_graph")
    with pytest.raises(ValidationError):
        validator.validate(observed)


def test_explicit_endpoint_profile_is_exact_and_bound_to_both_observations(validator, observed):
    domain = observed["domains"]["systemd_unit_graph"]
    assert domain["endpoint_profile"] == D.SYSTEMD_ENDPOINT_PROFILE
    assert facts(observed)["schema"] == "AcademySystemdUnitGraphFacts.v3"
    assert facts(observed)["endpoint_profile_sha256"] == domain["endpoint_profile_sha256"]
    for phase in ("initial", "repeated"):
        read = facts(observed)[phase]
        assert read["phase"] == phase
        assert read["endpoint_profile_sha256"] == domain["endpoint_profile_sha256"]
        assert read["endpoint_count"] == read["retained_endpoint_count"] == 2
        assert not read["unparsed_tail"]
    assert domain["endpoint_accounting"]["total"] == {
        "endpoint_count": 4, "retained_endpoint_count": 4, "unparsed_tail": False,
    }
    validator.validate(observed)


@pytest.mark.parametrize("scope,key,value", [
    ("profile", "field_attempts", 4097),
    ("profile", "total_attempts", 131073),
    ("profile", "enumerated_names", 8192),  # Enumeration is outside the endpoint profile.
    ("profile", "scope", "complete_acquisition"),
    ("profile", "extra", True),
    ("domain", "endpoint_profile_sha256", "a" * 64),
    ("facts", "endpoint_profile_sha256", "a" * 64),
    ("read", "endpoint_profile_sha256", "a" * 64),
    ("read", "phase", "repeated"),
    ("field", "endpoint_count", 4097),
    ("field", "retained_endpoint_count", 4097),
    ("field", "endpoint_sha256", ["a" * 64] * 4097),
    ("field", "unparsed_tail", "unknown"),
    ("initial", "endpoint_count", 65537),
    ("repeated", "endpoint_count", 65537),
    ("total", "endpoint_count", 131073),
    ("total", "retained_endpoint_count", 131073),
    ("total", "extra", 1),
])
def test_closed_v2_profile_and_counters_reject_forgery(validator, observed, scope, key, value):
    domain = observed["domains"]["systemd_unit_graph"]
    read = facts(observed)["initial"]
    targets = {
        "profile": domain["endpoint_profile"], "domain": domain, "facts": facts(observed),
        "read": read, "field": read["fields"]["Id"], **domain["endpoint_accounting"],
    }
    targets[scope][key] = value
    with pytest.raises(ValidationError):
        validator.validate(observed)


def test_invalid_v2_field_cannot_retain_prefix_hashes(validator, observed):
    field = facts(observed)["initial"]["fields"]["Id"]
    field["valid"] = False
    with pytest.raises(ValidationError):
        validator.validate(observed)


def test_resource_refusal_schema_matches_actual_partial_collector(validator):
    discovery = SyntheticDiscovery()
    after = " ".join(["a.service"] * 4097)
    discovery.initial_raw = lambda name: graph(name, After=after) + b"EnvironmentFiles=\nExecStart=\n"
    discovery.repeated_raw = lambda name: graph(name, After=after)
    discovery.systemd()
    report = envelope(discovery)
    item = facts(report)["initial"]["fields"]["After"]
    assert item["endpoint_count"] == 4096 and item["retained_endpoint_count"] == 0
    assert item["unparsed_tail"] and not item["valid"] and item["endpoint_sha256"] == []
    assert "graph_endpoint_field_budget" in facts(report)["gaps"]
    validator.validate(report)


def historical_v1_report(observed):
    """Synthetic frozen v1 shape, retained under its original legacy envelope."""
    report = copy.deepcopy(observed)
    report["schema"] = "AcademyAuthorityDiscovery.v1"
    for key in ("resource_profile", "resource_profile_sha256", "resource_accounting"):
        report.pop(key)
    domain = report["domains"]["systemd_unit_graph"]
    for key in ("endpoint_profile", "endpoint_profile_sha256", "endpoint_accounting",
                "runtime_relation_catalogue", "runtime_relation_catalogue_sha256"):
        domain.pop(key)
    fields = {}
    for field in ("Id", "Names", "Triggers", "TriggeredBy", "Requires", "Wants", "Before", "After"):
        value = b"a.service" if field in ("Id", "Names") else b""
        fields[field] = {
            "projection": D.projection(value), "endpoint_sha256": [D.digest(value)] if value else [], "valid": True,
        }
    read = {"fields": fields, "gaps": [], "endpoint_count": 2, "original_output": D.projection(graph("a.service"))}
    domain["records"][0]["facts"] = {
        "schema": "AcademySystemdUnitGraphFacts.v1", "requested_identity_sha256": D.digest(b"a.service"),
        "name_shape": {"shape": "plain", "template_name_sha256": None},
        "membership_before": {"installed": True, "loaded": True},
        "membership_after": {"installed": True, "loaded": True},
        "initial": read, "repeated": copy.deepcopy(read), "graph_fields_unchanged": True,
        "unresolved_endpoint_sha256": [], "gaps": [], "classification": "unknown", "authority_refs": [],
    }
    return report


def test_historical_v1_stays_closed_and_cannot_mix_with_v2(validator, observed):
    historical = historical_v1_report(observed)
    validator.validate(historical)
    mixed = copy.deepcopy(historical)
    mixed["domains"]["systemd_unit_graph"]["records"][0]["facts"] = copy.deepcopy(facts(observed))
    with pytest.raises(ValidationError):
        validator.validate(mixed)
    mixed = copy.deepcopy(observed)
    mixed["domains"]["systemd_unit_graph"]["records"][0]["facts"] = facts(historical)
    with pytest.raises(ValidationError):
        validator.validate(mixed)
    facts(historical)["initial"]["retained_endpoint_count"] = 2
    with pytest.raises(ValidationError):
        validator.validate(historical)

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
    return {
        "schema": "AcademyAuthorityDiscovery.v1",
        "role": "web",
        "host": discovery.host,
        "coverage_complete": False,
        "campaign_authority_claimed": False,
        "classification_complete": False,
        "purpose": "readonly_discovery_facts_only",
        "domains": discovery.domains,
        "commands_attempted": discovery.commands,
        "files_attempted": discovery.files,
        "child_lifecycle": discovery.child_metadata,
        "signal_interrupted": discovery.pending_signal is not None,
    }


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
    discovery.graph_endpoint_remaining = D.MAX_ROWS
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

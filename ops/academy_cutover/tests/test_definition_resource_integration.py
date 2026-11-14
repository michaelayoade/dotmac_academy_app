# ruff: noqa: S101 -- hosted-only qualification of the combined collector boundaries.
"""Synthetic definition I/O must consume the same guard as ordinary observations."""

import json
from pathlib import Path

import candidate_authority_discovery as D
import pytest
from jsonschema import Draft202012Validator
from test_systemd_template_definitions import SyntheticDefinitions, base_fs, facts, observe


def test_definition_body_capture_is_charged_and_guarded_envelope_is_valid():
    filesystem = base_fs()
    discovery = observe(filesystem)
    assert facts(discovery)["source_acquisition_complete"]
    captured = sum(size for _path, size in filesystem.reads)
    assert captured > 0
    assert discovery.captured_payload_bytes == captured
    result = json.loads(discovery.seal().read())
    assert result["schema"] == "AcademyAuthorityDiscovery.v3"
    assert result["resource_accounting"]["captured_payload_bytes"] == captured
    schema = json.loads((Path(__file__).parents[1] / "discovery.schema.json").read_text())
    Draft202012Validator(schema).validate(result)


@pytest.mark.parametrize("operation", ["read", "readlink"])
def test_no_definition_syscall_after_global_payload_allowance_is_exhausted(operation):
    filesystem = base_fs()
    discovery = SyntheticDefinitions(filesystem)
    discovery.definition_state()
    discovery.captured_payload_bytes = D.RESOURCE_PROFILE["captured_payload_bytes"]
    with pytest.raises(D.DefinitionRefusedError):
        if operation == "read":
            discovery.definition_io("read", 123, 1)
        else:
            discovery.definition_io("readlink", "worker@.service", dir_fd=123)
    assert operation not in filesystem.calls
    assert discovery.resource_stopped
    assert discovery.definition_state()["unparsed_tail"]


def test_truncated_definition_link_is_charged_before_refusal(monkeypatch):
    discovery = SyntheticDefinitions(base_fs())
    discovery.definition_state()
    discovery.captured_payload_bytes = D.RESOURCE_PROFILE["captured_payload_bytes"] - 3
    calls = []

    def sized_link(operation, name, *, dir_fd, maximum):
        calls.append((operation, name, dir_fd, maximum))
        assert maximum == 3
        return b"abc"

    monkeypatch.setattr(discovery, "definition_syscall", sized_link)
    with pytest.raises(D.DefinitionRefusedError):
        discovery.definition_io("readlink", "worker@.service", dir_fd=123)
    assert calls == [("readlink", "worker@.service", 123, 3)]
    assert discovery.captured_payload_bytes == D.RESOURCE_PROFILE["captured_payload_bytes"]
    assert discovery.resource_stopped


def test_no_child_can_start_without_capture_capacity(monkeypatch):
    discovery = D.Discovery("web")
    discovery.captured_payload_bytes = D.RESOURCE_PROFILE["captured_payload_bytes"]
    calls = []

    def forbidden_child(*args, **kwargs):
        calls.append((args, kwargs))
        pytest.fail("child started without capture allowance")

    monkeypatch.setattr(D.subprocess, "Popen", forbidden_child)
    assert discovery.run(["list-units", "--all", "--output=json"], "systemd_loaded") is None
    assert calls == []
    assert discovery.child_metadata["spawned"] == 0
    assert discovery.resource_stopped

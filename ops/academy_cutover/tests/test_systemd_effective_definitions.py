# ruff: noqa: S101 -- hosted synthetic effective-definition qualification.
"""Plain and mixed definitions use synthetic manager/filesystem inputs only."""

import copy
import json
from pathlib import Path

import candidate_authority_discovery as D
import pytest
from jsonschema import Draft202012Validator, ValidationError
from test_systemd_graph_discovery import SyntheticDiscovery
from test_systemd_template_definitions import (
    LOW,
    ROOT,
    SyntheticDefinitions,
    SyntheticFS,
    domain,
    facts,
    relations,
)


def acquire(filesystem, *, installed=(), loaded=(), final_installed=None, final_loaded=None,
            failed=(), **kwargs):
    discovery = SyntheticDefinitions(filesystem, **kwargs)
    discovery.installed_units = set(installed)
    discovery.loaded_units = set(loaded)
    discovery.final_installed_units = set(installed if final_installed is None else final_installed)
    discovery.final_loaded_units = set(loaded if final_loaded is None else final_loaded)
    for label in failed:
        discovery.domain(label)["enumeration_complete"] = False
    discovery.template_definitions()
    return discovery


def schema():
    return json.loads((Path(__file__).parents[1] / "discovery.schema.json").read_text())


def validate(discovery):
    result = json.loads(discovery.seal().read())
    Draft202012Validator(schema()).validate(result)
    return result


def test_mixed_targets_include_four_observed_sets_and_only_lookup_abstract_templates():
    filesystem = SyntheticFS()
    for name in ("installed.service", "loaded.socket", "late.timer", "last.path", "worker@.service",
                 "worker@one.service", "unobserved.service", "worker@fiction.service"):
        filesystem.add(ROOT + "/" + name, data=b"[Unit]\nRequires=base.service\n")
    discovery = acquire(filesystem, installed=("installed.service", "worker@one.service"),
                        loaded=("loaded.socket",), final_installed=("late.timer",), final_loaded=("last.path",))
    expected = {"installed.service", "loaded.socket", "late.timer", "last.path", "worker@.service",
                "worker@one.service"}
    assert domain(discovery)["enumerated"] == domain(discovery)["inspected"] == len(expected)
    assert {row["identity_sha256"] for row in domain(discovery)["records"]} == {
        D.digest(name.encode()) for name in expected
    }
    assert not any(path.endswith(("unobserved.service", "worker@fiction.service")) for path, _ in filesystem.reads)
    assert not domain(discovery)["enumeration_complete"]
    assert "definition_enumeration_membership_changed" in domain(discovery)["gaps"]
    assert all(not facts(discovery, name)["source_acquisition_complete"] for name in expected)
    validate(discovery)


@pytest.mark.parametrize("membership", ["installed", "loaded"])
def test_installed_only_and_loaded_only_plain_definitions(membership):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\nWants=other.service\n")
    discovery = acquire(filesystem, **{membership: ("plain.service",)})
    result = facts(discovery, "plain.service")
    assert result["schema"] == "AcademySystemdEffectiveDefinitionFacts.v1"
    assert result["source_kind"] == "effective_unit_definition"
    assert result["name_shape"] == {"shape": "plain", "template_name_sha256": None}
    assert result["source_acquisition_complete"] and domain(discovery)["enumeration_complete"]
    assert result["classification"] == "unknown" and result["authority_refs"] == []
    assert not result["activation_semantics_complete"]
    validate(discovery)


@pytest.mark.parametrize("failed", ["systemd_installed", "systemd_loaded", "systemd_installed_final",
                                    "systemd_loaded_final"])
def test_each_unavailable_boundary_retains_plain_source_but_refuses_completeness(failed):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\n")
    discovery = acquire(filesystem, loaded=("plain.service",), failed=(failed,))
    assert domain(discovery)["inspected"] == 1
    assert not domain(discovery)["enumeration_complete"]
    result = facts(discovery, "plain.service")
    assert not result["source_acquisition_complete"]
    assert "definition_enumeration_boundary_unavailable" in result["unresolved_requirements"]
    validate(discovery)


def test_final_only_name_is_retained_and_actual_final_listing_sets_are_saved():
    discovery = SyntheticDiscovery(names=("first.service",), final=("late.service",))
    discovery.systemd()
    assert discovery.installed_units == discovery.loaded_units == {"first.service"}
    assert discovery.final_installed_units == discovery.final_loaded_units == {"late.service"}
    failed = SyntheticDiscovery(names=("first.service",), failed_listing="systemd_loaded_final")
    failed.systemd()
    assert failed.final_installed_units == {"first.service"} and failed.final_loaded_units == set()
    assert not failed.domain("systemd_loaded_final")["enumeration_complete"]


def test_fragmentless_runtime_definition_is_incomplete_without_invented_defaults():
    filesystem = SyntheticFS()
    filesystem.add(ROOT, "directory")
    discovery = acquire(filesystem, loaded=("runtime.scope",))
    result = facts(discovery, "runtime.scope")
    assert result["fragment_kind"] is None and result["sources"] == []
    assert "definition_fragment_absent" in result["unresolved_requirements"]
    assert "activation_semantics_incomplete" in result["unresolved_requirements"]
    assert not result["source_acquisition_complete"] and relations(discovery, "runtime.scope") == []
    assert filesystem.reads == []
    validate(discovery)


def test_plain_alias_rechecks_root_precedence_and_shared_body_is_charged_once_per_pass():
    body = b"[Unit]\nRequires=winner.service\n"
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=body)
    filesystem.add(LOW + "/plain.service", data=b"[Unit]\nRequires=shadowed.service\n")
    filesystem.add(ROOT + "/alias.service", "symlink", LOW + "/plain.service")
    discovery = acquire(filesystem, installed=("plain.service", "alias.service"), roots=(ROOT, LOW))
    assert facts(discovery, "alias.service")["canonical_identity_sha256"] == D.digest(b"plain.service")
    assert facts(discovery, "alias.service")["source_acquisition_complete"]
    assert [row["value_sha256"] for row in relations(discovery, "alias.service")] == [D.digest(b"winner.service")]
    assert len(filesystem.reads) == 2
    assert {path for path, _ in filesystem.reads} == {ROOT + "/plain.service"}
    assert domain(discovery)["definition_accounting"]["body_bytes"] == 2 * len(body)
    assert discovery.captured_payload_bytes >= 2 * len(body)
    assert domain(discovery)["definition_accounting"]["distinct_bodies"] == 1
    validate(discovery)


@pytest.mark.parametrize("kind", ["cycle", "dangling"])
def test_plain_alias_failures(kind):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", "symlink", "other.service")
    if kind == "cycle":
        filesystem.add(ROOT + "/other.service", "symlink", "plain.service")
    discovery = acquire(filesystem, installed=("plain.service",))
    assert "definition_alias_" + kind in facts(discovery, "plain.service")["unresolved_requirements"]
    assert not facts(discovery, "plain.service")["source_acquisition_complete"]
    assert filesystem.reads == []


@pytest.mark.parametrize("source,target", [("plain.service", "other.timer"), ("plain.service", "other@.service"),
                                           ("plain.mount", "other.mount"), ("plain.automount", "other.automount"),
                                           ("plain.swap", "other.swap"), ("plain.slice", "other.slice"),
                                           ("plain.scope", "other.scope")])
def test_incompatible_plain_aliases_do_not_shadow_lower_regular_source(source, target):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/" + source, "symlink", LOW + "/" + target)
    filesystem.add(LOW + "/" + source, data=b"[Unit]\nRequires=lower.service\n")
    discovery = acquire(filesystem, installed=(source,), roots=(ROOT, LOW))
    assert facts(discovery, source)["source_acquisition_complete"]
    assert any(row["kind"] == "ignored_incompatible_alias" for row in domain(discovery)["path_observations"])
    assert [row["value_sha256"] for row in relations(discovery, source)] == [D.digest(b"lower.service")]


@pytest.mark.parametrize("mask", ["empty", "null"])
def test_plain_masks_retain_unknown_authority_without_reading_device(mask):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", "regular" if mask == "empty" else "symlink",
                   b"" if mask == "empty" else "/dev/null")
    discovery = acquire(filesystem, installed=("plain.service",))
    result = facts(discovery, "plain.service")
    assert result["mask"] and result["source_acquisition_complete"]
    assert result["classification"] == "unknown" and result["authority_refs"] == []
    assert not result["activation_semantics_complete"]
    assert filesystem.reads == []
    validate(discovery)


def test_plain_dropin_exact_dash_prefix_type_and_alias_winners():
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/foo-bar.service", data=b"[Unit]\nRequires=fragment.service\n")
    filesystem.add(ROOT + "/alias.service", "symlink", "foo-bar.service")
    for directory, basename, value in (
        ("foo-bar.service.d", "10.conf", "exact"), ("foo-.service.d", "10.conf", "shadowed-prefix"),
        ("service.d", "10.conf", "shadowed-type"), ("foo-.service.d", "20.conf", "prefix"),
        ("service.d", "30.conf", "type"), ("alias.service.d", "40.conf", "alias"),
    ):
        filesystem.add(ROOT + "/" + directory + "/" + basename,
                       data=("[Unit]\nRequires=" + value + ".service\n").encode())
    filesystem.add(LOW + "/foo-bar.service.d/10.conf", data=b"[Unit]\nRequires=shadowed-root.service\n")
    discovery = acquire(filesystem, installed=("foo-bar.service",), roots=(ROOT, LOW))
    assert facts(discovery, "foo-bar.service")["source_acquisition_complete"]
    assert [row["value_sha256"] for row in relations(discovery, "foo-bar.service")] == [
        D.digest((value + ".service").encode()) for value in ("fragment", "exact", "prefix", "type", "alias")
    ]
    assert all(not path.endswith(("foo-.service.d/10.conf", "/service.d/10.conf"))
               for path, _ in filesystem.reads)
    assert all(not path.startswith(LOW) for path, _ in filesystem.reads)


@pytest.mark.parametrize("unit_type", sorted(D.DEFINITION_UNIT_TYPES))
def test_plain_types_section_filtering_and_default_activation_stays_unresolved(unit_type):
    name = "plain." + unit_type
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/" + name,
                   data=b"[Unit]\nRequires=visible.service\n[WrongSection]\nRequires=hidden.service\n")
    discovery = acquire(filesystem, loaded=(name,))
    result = facts(discovery, name)
    assert [row["value_sha256"] for row in relations(discovery, name)] == [D.digest(b"visible.service")]
    assert "activation_semantics_incomplete" in result["unresolved_requirements"]
    assert not result["activation_semantics_complete"]
    assert result["authority_refs"] == []
    validate(discovery)


def test_1025_mixed_targets_refuse_before_any_selected_body_read():
    filesystem = SyntheticFS()
    names = ["plain" + str(index) + ".service" for index in range(1023)]
    for name in [*names, "worker@.service", "worker@one.service"]:
        filesystem.add(ROOT + "/" + name, data=b"[Unit]\n")
    discovery = acquire(filesystem, installed=names, loaded=("worker@one.service",))
    assert domain(discovery)["enumerated"] == domain(discovery)["skipped"] == 1025
    assert domain(discovery)["inspected"] == 0 and filesystem.reads == []
    assert "definition_target_bound" in domain(discovery)["gaps"]
    validate(discovery)


def test_unsupported_observed_unit_is_counted_and_refused_before_body_read():
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\n")
    discovery = acquire(filesystem, installed=("plain.service", "invalid.unknown"))
    assert domain(discovery)["enumerated"] == domain(discovery)["skipped"] == 2
    assert "definition_unit_name_unsupported" in domain(discovery)["gaps"]
    assert filesystem.reads == []
    validate(discovery)


@pytest.mark.parametrize("failure", ["changed", "denied", "linked"])
def test_plain_source_changes_denials_and_unprofiled_links_remain_incomplete(failure):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\n")
    kwargs = {}
    if failure == "changed":
        def mutate(fs):
            fs.nodes[ROOT + "/plain.service"]["stamp"] += 1
        kwargs["mutate"] = mutate
    elif failure == "denied":
        filesystem.denied.add(ROOT)
    else:
        filesystem.add(ROOT + "/plain.service", "symlink", LOW + "/outside.service")
        filesystem.add(LOW + "/outside.service", data=b"[Unit]\n")
    discovery = acquire(filesystem, installed=("plain.service",), **kwargs)
    assert (not domain(discovery)["enumeration_complete"]
            or not facts(discovery, "plain.service")["source_acquisition_complete"])
    if failure != "changed":
        assert filesystem.reads == []
    validate(discovery)


def test_plain_exec_environment_and_credentials_are_hash_only_without_external_reads(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("synthetic definition attempted an external action")
    monkeypatch.setattr(D.subprocess, "Popen", forbidden)
    monkeypatch.setattr(D.os, "getenv", forbidden)
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=(
        b"[Service]\nExecStart=/secret/command --token=private\nEnvironment=PASSWORD=private\n"
        b"EnvironmentFile=/secret/environment\nLoadCredential=key:/secret/key\n"
    ))
    discovery = acquire(filesystem, loaded=("plain.service",))
    assert {path for path, _ in filesystem.reads} == {ROOT + "/plain.service"}
    result = validate(discovery)
    encoded = json.dumps(result)
    assert "private" not in encoded and "/secret" not in encoded
    assert not facts(discovery, "plain.service")["activation_semantics_complete"]


def test_sealed_effective_schema_versions_are_closed_and_reject_mixing_and_authority_upgrades():
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\n")
    discovery = acquire(filesystem, loaded=("plain.service",))
    result = validate(discovery)
    validator = Draft202012Validator(schema())
    domain_path = result["domains"][D.DEFINITION_DOMAIN]
    assert domain_path["definition_profile"]["target_selection"] == "observed_initial_final_units_and_lookup_templates"
    for mutation in ("old_facts", "old_domain_profile", "old_fact_profile", "activation", "authority", "extra"):
        changed = copy.deepcopy(result)
        target = changed["domains"][D.DEFINITION_DOMAIN]
        item = target["records"][0]["facts"]
        if mutation == "old_facts":
            item["schema"] = "AcademySystemdTemplateDefinitionFacts.v1"
        elif mutation == "old_domain_profile":
            target["definition_profile"]["schema"] = "AcademySystemdDefinitionProfile.v1"
        elif mutation == "old_fact_profile":
            item["definition_profile"]["schema"] = "AcademySystemdDefinitionProfile.v1"
        elif mutation == "activation":
            item["activation_semantics_complete"] = True
        elif mutation == "authority":
            item["authority_refs"] = ["f" * 64]
        else:
            item["unrecognized"] = True
        with pytest.raises(ValidationError):
            validator.validate(changed)


def test_historical_definition_versions_remain_closed_and_supported_in_v2_envelope():
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/worker@.service", data=b"[Unit]\n")
    result = validate(acquire(filesystem))
    target = result["domains"][D.DEFINITION_DOMAIN]
    old_hash = "713859b6fdc5043a963a7463c0182a47ab0668416dc916019e0a88de7c6f60ab"
    historical_profile = {key: value["const"]
                          for key, value in schema()["$defs"]["definition_profile"]["properties"].items()}
    assert historical_profile["definition_targets"] == 128
    for holder in (target, target["records"][0]["facts"]):
        holder["definition_profile"] = copy.deepcopy(historical_profile)
        holder["definition_profile_sha256"] = old_hash
    item = target["records"][0]["facts"]
    item["schema"] = "AcademySystemdTemplateDefinitionFacts.v1"
    item["source_kind"] = "template_definition"
    del item["name_shape"]
    result["schema"] = "AcademyAuthorityDiscovery.v2"
    historical = schema()["$defs"]["normal_v2"]["properties"]
    result["resource_profile"] = copy.deepcopy(historical["resource_profile"]["const"])
    result["resource_profile_sha256"] = historical["resource_profile_sha256"]["const"]
    for key in ("ordinary_filesystem_work", "definition_filesystem_work", "cumulative_filesystem_work",
                "reserved_definition_filesystem_work"):
        del result["resource_accounting"][key]
    del target["definition_accounting"]["alias_resolution_attempts"]
    del target["definition_accounting"]["candidate_selection_attempts"]
    validator = Draft202012Validator(schema())
    validator.validate(result)
    item["name_shape"] = {"shape": "template", "template_name_sha256": D.digest(b"worker@.service")}
    with pytest.raises(ValidationError):
        validator.validate(result)


def test_plain_competing_alias_dropins_remain_ambiguous_and_unread():
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\n")
    for alias in ("left.service", "right.service"):
        filesystem.add(ROOT + "/" + alias, "symlink", "plain.service")
        filesystem.add(ROOT + "/" + alias + ".d/10.conf", data=b"[Unit]\nWants=other.service\n")
    discovery = acquire(filesystem, installed=("plain.service",))
    assert "definition_alias_order_ambiguous" in facts(discovery, "plain.service")["unresolved_requirements"]
    assert not facts(discovery, "plain.service")["source_acquisition_complete"]
    assert all(not path.endswith(".conf") for path, _ in filesystem.reads)
    validate(discovery)


def test_effective_enumeration_representation_bound_does_not_expand_record_capacity():
    filesystem = SyntheticFS()
    filesystem.add(ROOT, "directory")
    names = tuple("plain" + str(index) + ".service" for index in range(1025))
    result = validate(acquire(filesystem, loaded=names))
    target = result["domains"][D.DEFINITION_DOMAIN]
    assert target["records"] == [] and target["inspected"] == 0
    target["enumerated"] = target["skipped"] = 40960
    validator = Draft202012Validator(schema())
    validator.validate(result)
    target["enumerated"] = target["skipped"] = 40961
    with pytest.raises(ValidationError):
        validator.validate(result)
    definitions = schema()["$defs"]
    assert definitions["resource_effective_definition_domain"]["properties"]["inspected"]["maximum"] == 1024
    assert definitions["resource_effective_definition_domain"]["properties"]["records"]["maxItems"] == 1024
    assert definitions["resource_definition_domain"]["properties"]["enumerated"]["maximum"] == 24576
    assert "name_shape" not in definitions["definition_facts"]["properties"]
    assert "target_selection" not in definitions["definition_profile"]["properties"]


@pytest.mark.parametrize("roots", [(ROOT, LOW), D.SYSTEMD_DEFINITION_ROOTS], ids=["two-roots", "all-13-roots"])
def test_capacity_1024_records_and_distinct_bodies_with_alias_instance_and_dropins(roots):
    filesystem = SyntheticFS()
    for root in roots:
        filesystem.add(root, "directory")
    names = []
    fragment_paths = {}
    # 1021 plain fragments + one template, one inherited instance, one alias.
    for number in range(1021):
        name = "plain" + str(number) + ".service"
        names.append(name)
        fragment_paths[name] = roots[(number + 1) % len(roots)] + "/" + name
        filesystem.add(fragment_paths[name], data=b"[Unit]\n")
    filesystem.add(ROOT + "/worker@.service", data=b"[Unit]\n")
    filesystem.add(ROOT + "/alias.service", "symlink", fragment_paths["plain1.service"])
    filesystem.add(ROOT + "/plain0.service.d/10.conf", data=b"# first dropin\n")
    filesystem.add(LOW + "/plain2.service.d/20.conf", data=b"# second dropin\n")
    discovery = acquire(filesystem, installed=(*names, "alias.service"), loaded=("worker@one.service",),
                        roots=roots)
    target = domain(discovery)
    assert target["enumerated"] == target["inspected"] == target["complete"] == 1024
    assert target["enumeration_complete"] and target["gaps"] == []
    assert len({path for path, _ in filesystem.reads}) == 1024
    assert len(filesystem.reads) == len(target["source_reads"]) == 2048
    assert all(sum(1 for observed, _ in filesystem.reads if observed == path) == 2
               for path in {path for path, _ in filesystem.reads})
    assert target["definition_accounting"]["distinct_bodies"] == 1024
    selection_attempts = target["definition_accounting"]["candidate_selection_attempts"]
    assert 0 < selection_attempts <= D.SYSTEMD_DEFINITION_PROFILE["candidate_selection_attempts"] == 1048576
    assert {str(Path(path).parent) for path in fragment_paths.values()} == set(roots)
    if len(roots) == 13:
        assert selection_attempts > 638976  # includes aliases, the template and inherited instance.
    assert all(row["facts"]["source_acquisition_complete"] for row in target["records"])
    assert all(row["facts"]["classification"] == "unknown" and row["facts"]["authority_refs"] == []
               and not row["facts"]["activation_semantics_complete"] for row in target["records"])
    result = validate(discovery)
    assert result["schema"] == "AcademyAuthorityDiscovery.v3"
    work = result["resource_accounting"]
    assert work["ordinary_filesystem_work"] == 0
    assert work["definition_filesystem_work"] == work["cumulative_filesystem_work"] == discovery.files
    assert work["reserved_definition_filesystem_work"] == 0
    assert work["definition_filesystem_work"] <= 262144 and not filesystem.fds
    assert not result["coverage_complete"] and not result["campaign_authority_claimed"]


def test_ordinary_work_prior_to_definition_acquisition_remains_separately_charged():
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\n")
    discovery = SyntheticDefinitions(filesystem, names=("plain.service",))
    discovery.files = D.MAX_FILES
    discovery.template_definitions()
    assert facts(discovery, "plain.service")["source_acquisition_complete"]
    result = validate(discovery)
    work = result["resource_accounting"]
    assert work["ordinary_filesystem_work"] == D.MAX_FILES
    assert work["definition_filesystem_work"] == domain(discovery)["definition_accounting"]["filesystem_work"]
    assert work["cumulative_filesystem_work"] == work["ordinary_filesystem_work"] + work["definition_filesystem_work"]
    assert work["cumulative_filesystem_work"] == result["files_attempted"]
    assert discovery.read_file(123, "never-opened", 0, "synthetic") is None


def test_current_phase_candidate_scans_once_and_missing_candidates_use_root_observation(monkeypatch):
    filesystem = SyntheticFS()
    for name in ("plain.service", "other.service"):
        filesystem.add(ROOT + "/" + name, data=b"[Unit]\n")
    filesystem.add(ROOT + "/service.d/10.conf", data=b"# shared\n")
    discovery = SyntheticDefinitions(filesystem, names=("plain.service", "other.service"))
    scans = []
    original = discovery.definition_scan

    def scan(path, scope="root"):
        scans.append((discovery.definition_state()["phase"], path, scope))
        return original(path, scope)

    monkeypatch.setattr(discovery, "definition_scan", scan)
    discovery.template_definitions()
    assert scans == [("initial", ROOT, "root"), ("initial", ROOT + "/service.d", "dropin"),
                     ("repeated", ROOT, "root"), ("repeated", ROOT + "/service.d", "dropin")]
    assert len(filesystem.reads) == 6  # two fragments and one common body, twice each.
    assert not any(row["kind"] == "absent" for row in domain(discovery)["path_observations"])
    assert discovery.definition_state()["candidate_scans"] == {}
    assert discovery.definition_state()["root_snapshots"] == {}
    validate(discovery)


@pytest.mark.parametrize("change", ["missing_appears", "present_removed", "candidate_metadata", "body", "ancestor"])
def test_phase_cache_never_hides_root_candidate_body_or_ancestor_changes(change):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\n")
    if change != "missing_appears":
        filesystem.add(ROOT + "/plain.service.d/10.conf", data=b"# original\n")

    def mutate(fs):
        if change == "missing_appears":
            fs.add(ROOT + "/plain.service.d/10.conf", data=b"# new\n")
        elif change == "present_removed":
            del fs.nodes[ROOT + "/plain.service.d/10.conf"]
        elif change == "candidate_metadata":
            fs.nodes[ROOT + "/plain.service.d"]["stamp"] += 1
        elif change == "body":
            fs.nodes[ROOT + "/plain.service.d/10.conf"]["data"] = b"# replaced\n"
            fs.nodes[ROOT + "/plain.service.d/10.conf"]["stamp"] += 1
        else:
            fs.nodes["/etc"]["stamp"] += 1

    discovery = acquire(filesystem, installed=("plain.service",), mutate=mutate)
    assert not facts(discovery, "plain.service")["source_acquisition_complete"]
    assert not domain(discovery)["enumeration_complete"]
    assert {"definition_snapshot_changed", "definition_selected_sources_changed"} & set(domain(discovery)["gaps"])
    assert not filesystem.fds
    validate(discovery)


@pytest.mark.parametrize("stop", ["deadline", "cancel", "attempt_cap"])
def test_alias_cpu_work_checks_inside_reverse_candidates_and_failed_hops(monkeypatch, stop):
    discovery = SyntheticDefinitions(SyntheticFS())
    mapping = {"plain.service": {"kind": "regular", "path": ROOT + "/plain.service"}}
    for number in range(30):
        mapping["missing" + str(number) + ".service"] = {
            "kind": "alias", "destination": "absent.service", "path": ROOT + "/missing" + str(number),
        }
    original = discovery.definition_alias_step
    steps = []

    def step():
        steps.append(True)
        if len(steps) == 10:
            if stop == "deadline":
                discovery.deadline = 0
            elif stop == "cancel":
                discovery.pending_signal = 15
            else:
                limit = D.SYSTEMD_DEFINITION_PROFILE["alias_resolution_attempts"]
                discovery.definition_state()["alias_attempts"] = limit
        original()

    monkeypatch.setattr(discovery, "definition_alias_step", step)
    expected = "definition_alias_resolution_bound" if stop == "attempt_cap" else "definition_interrupted"
    with pytest.raises(D.DefinitionRefusedError, match=expected):
        discovery.resolve_template_fragment("plain.service", mapping)
    assert len(steps) == 10 and discovery.fs.calls == []
    assert expected in domain(discovery)["gaps"]


def test_source_read_maximum_shape_and_exact_table_budget_fit_admission_limit():
    limits = D.SYSTEMD_DEFINITION_PROFILE
    worst = {
        "phase": "repeated", "path_reference": limits["path_records"] - 1, "body_sha256": "f" * 64,
        "bytes": limits["body_bytes_per_read"], "before_sha256": "f" * 64, "after_sha256": "f" * 64,
        "mask": False,
    }
    assert len(json.dumps(worst, **D.JSON_OPTIONS).encode("ascii")) <= limits["source_read_record_bytes"] == 512
    total = (limits["definition_targets"] * (limits["definition_header_bytes"] + 1)
             + limits["path_records"] * (limits["path_record_bytes"] + 1)
             + limits["source_read_records"] * (limits["source_read_record_bytes"] + 1)
             + limits["relation_attempts_total"] * (limits["relation_record_bytes"] + 1)
             + limits["manager_commands"] * (limits["manager_record_bytes"] + 1))
    assert total == 15224836
    assert limits["evidence_bytes"] - D.MIB - total == 503804


def test_definition_and_cumulative_limits_reserve_descriptor_cleanup(monkeypatch):
    filesystem = SyntheticFS()
    discovery = SyntheticDefinitions(filesystem)
    state = discovery.definition_state()
    state["work"] = D.SYSTEMD_DEFINITION_PROFILE["filesystem_work"] - 2
    discovery.files = discovery.definition_files = state["work"]
    fd = discovery.definition_open("/", D.os.O_RDONLY | D.os.O_DIRECTORY | D.os.O_NOFOLLOW)
    assert state["work"] + state["reserved_work"] == D.SYSTEMD_DEFINITION_PROFILE["filesystem_work"]
    with pytest.raises(D.DefinitionRefusedError, match="definition_filesystem_work_bound"):
        discovery.definition_io("fstat", fd)
    discovery.pending_signal = 15
    discovery.definition_close_pass()
    assert state["work"] == discovery.definition_files == discovery.files == 262144
    assert state["reserved_work"] == 0 and not filesystem.fds
    assert discovery.fs.calls == ["open", "close"]
    assert discovery.resource_accounting()["ordinary_filesystem_work"] == 0

    discovery = SyntheticDefinitions(SyntheticFS())
    monkeypatch.setattr(D, "RESOURCE_PROFILE", dict(D.RESOURCE_PROFILE, definition_filesystem_work=1))
    with pytest.raises(D.DefinitionRefusedError, match="definition_filesystem_work_bound"):
        discovery.definition_open("/", D.os.O_RDONLY | D.os.O_DIRECTORY | D.os.O_NOFOLLOW)
    assert discovery.fs.calls == []


def primed_selection(present):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\n")
    if present:
        filesystem.add(ROOT + "/service.d", "directory")
    discovery = SyntheticDefinitions(filesystem)
    discovery.snapshot_unit_roots((ROOT,))
    if present:
        discovery.definition_candidate_scan(ROOT, "service.d", "dropin")
    resolution = {"canonical": "plain.service", "aliases": {"alias.service"}, "failure": None,
                  "fragment": {"path": ROOT + "/plain.service", "kind": "regular", "metadata": {}}}
    return discovery, resolution


@pytest.mark.parametrize("present", [False, True], ids=["all-negative", "cached-present"])
@pytest.mark.parametrize("stop", ["deadline", "cancel"])
def test_selection_stop_inside_negative_and_cached_candidate_loops_has_no_new_io(monkeypatch, present, stop):
    discovery, resolution = primed_selection(present)
    state = discovery.definition_state()
    baseline = state["selection_attempts"]
    calls_before = len(discovery.fs.calls)
    original = discovery.definition_selection_step
    attempts = []

    def step():
        attempts.append(True)
        # canonical, alias, and type groups each charge root/visit/scan entry.
        # The ninth guard is the cached-present or index-negative type scan.
        if len(attempts) == 9:
            if stop == "deadline":
                discovery.deadline = 0
            else:
                discovery.pending_signal = 15
        original()

    monkeypatch.setattr(discovery, "definition_selection_step", step)
    with pytest.raises(D.DefinitionRefusedError, match="definition_interrupted"):
        discovery.select_definition_sources(resolution, (ROOT,))
    assert len(attempts) == 9 and state["selection_attempts"] == baseline + 8
    assert len(discovery.fs.calls) == calls_before
    discovery.definition_close_pass()
    assert all(operation == "close" for operation in discovery.fs.calls[calls_before:])
    assert not discovery.fs.fds


@pytest.mark.parametrize("present", [False, True], ids=["index-negative", "cached-present"])
def test_direct_candidate_scan_zero_cpu_allowance_refuses_before_cache_or_negative_return(monkeypatch, present):
    discovery, _resolution = primed_selection(present)
    state = discovery.definition_state()
    state["selection_attempts"] = 0
    monkeypatch.setattr(D, "SYSTEMD_DEFINITION_PROFILE", dict(D.SYSTEMD_DEFINITION_PROFILE,
                                                            candidate_selection_attempts=0))
    before = len(discovery.fs.calls)
    with pytest.raises(D.DefinitionRefusedError, match="definition_candidate_selection_bound"):
        discovery.definition_candidate_scan(ROOT, "service.d", "dropin")
    assert state["selection_attempts"] == 0 and len(discovery.fs.calls) == before
    discovery.definition_close_pass()
    assert not discovery.fs.fds


def test_selection_zero_allowance_checks_before_candidate_directory_construction(monkeypatch):
    discovery, resolution = primed_selection(False)
    state = discovery.definition_state()
    state["selection_attempts"] = 0
    monkeypatch.setattr(D, "SYSTEMD_DEFINITION_PROFILE", dict(D.SYSTEMD_DEFINITION_PROFILE,
                                                            candidate_selection_attempts=0))
    constructed = []

    def candidate_dirs(name):
        constructed.append(name)
        pytest.fail("candidate directories constructed after selection budget exhaustion")

    monkeypatch.setattr(discovery, "definition_candidate_dirs", candidate_dirs)
    before = len(discovery.fs.calls)
    with pytest.raises(D.DefinitionRefusedError, match="definition_candidate_selection_bound"):
        discovery.select_definition_sources(resolution, (ROOT,))
    assert constructed == [] and state["selection_attempts"] == 0
    assert len(discovery.fs.calls) == before
    discovery.definition_close_pass()


def test_selection_duplicate_visited_paths_are_charged_and_cap_is_exact(monkeypatch):
    discovery, resolution = primed_selection(False)
    resolution["aliases"] = set()
    before = len(discovery.fs.calls)
    discovery.select_definition_sources(resolution, (ROOT, ROOT))
    # Four suffixes * two groups * (two root setups + two candidate visits
    # + one scan entry). The duplicate path is charged before visited lookup.
    state = discovery.definition_state()
    assert state["selection_attempts"] == 40 and len(discovery.fs.calls) == before
    monkeypatch.setattr(D, "SYSTEMD_DEFINITION_PROFILE", dict(D.SYSTEMD_DEFINITION_PROFILE,
                                                            candidate_selection_attempts=41))
    discovery.definition_candidate_scan(ROOT, "service.d", "dropin")
    assert state["selection_attempts"] == 41
    with pytest.raises(D.DefinitionRefusedError, match="definition_candidate_selection_bound"):
        discovery.definition_candidate_scan(ROOT, "service.d", "dropin")
    assert state["selection_attempts"] == 41 and len(discovery.fs.calls) == before
    discovery.definition_close_pass()


def test_selection_exhaustion_is_a_closed_current_gap_and_retained_fact_requirement():
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\n")
    discovery = SyntheticDefinitions(filesystem, names=("plain.service",))
    limit = D.SYSTEMD_DEFINITION_PROFILE["candidate_selection_attempts"]
    # One initial plain target uses 4 suffixes * 2 groups * 3 charges.
    discovery.definition_state()["selection_attempts"] = limit - 24
    discovery.template_definitions()
    assert domain(discovery)["definition_accounting"]["candidate_selection_attempts"] == limit
    assert "definition_candidate_selection_bound" in domain(discovery)["gaps"]
    result = facts(discovery, "plain.service")
    assert "definition_candidate_selection_bound" in result["unresolved_requirements"]
    assert not result["source_acquisition_complete"] and len(filesystem.reads) == 1
    validate(discovery)

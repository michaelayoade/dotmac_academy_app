# ruff: noqa: S101 -- hosted synthetic adapter qualification only.
"""Connected systemd evidence retains every unknown and refuses full authority."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import candidate_census_domains as D
import candidate_maintenance as M
import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from test_census_domains import Common
from test_maintenance_identity_projection import identity_case
from test_systemd_graph_discovery import SyntheticDiscovery as GraphDiscovery
from test_systemd_template_definitions import ROOT, SyntheticDefinitions, SyntheticFS


class ConnectedDiscovery(SyntheticDefinitions):
    def __init__(self, filesystem, names, *, final=None, initial_raw=None, repeated_raw=None):
        super().__init__(filesystem, names=names)
        # Standalone definition fixtures prime these flags; connected acquisition must prove each boundary itself.
        for label in D.SYSTEMD_LISTINGS:
            self.domain(label)["enumeration_complete"] = False
        self.host = "vmi2490731"
        self.names = names
        self.final = names if final is None else final
        self.failed_listing = None
        self.initial_raw = initial_raw
        self.repeated_raw = repeated_raw
        self.calls = []
        self.graph_change = {}

    def run(self, args, domain, **kwargs):
        if args[0] == "get-property":
            if domain == "systemd_template_definitions":
                return super().run(args, domain, **kwargs)
            return None  # Missing typed property remains an explicit legacy-property gap.
        raw = GraphDiscovery.run(self, args, domain, **kwargs)
        if args[0] == "show" and raw is not None:
            if args[-1].endswith(".timer"):
                target = args[-1].removesuffix(".timer") + ".service"
                raw = raw.replace(b"Unit=\n", b"Unit=" + target.encode() + b"\n")
            for key, value in self.graph_change.items():
                raw = raw.replace(key.encode() + b"=\n", key.encode() + b"=" + value.encode() + b"\n")
        return raw


def source_refs():
    return [{"path": str(Path(D.__file__).with_name(name)),
             "sha256": Common.digest(Path(D.__file__).with_name(name).read_bytes())}
            for name in ("candidate_census_domains.py", "candidate_authority_discovery.py", "candidate_execute.py")]


def make_proof(case, discovery, *, mode="original", before=None, after=None, controls=(None, None)):
    with discovery.seal() as sealed:
        report = json.loads(sealed.read())
    assert report["schema"] == "AcademyAuthorityDiscovery.v3"
    refs = [*source_refs(), {"path": str(Path(D.__file__).with_name("discovery.schema.json")),
                             "sha256": D.DISCOVERY_SCHEMA_SHA256}]
    m = {**case.m, "self_sha256": refs[2]["sha256"], "roles": {"web": {"hostname": "vmi2490731"}},
         "helpers": {"census_domains": refs[0]["sha256"], "census_discovery": refs[1]["sha256"],
                     "maintenance": {"path": "/synthetic/candidate_maintenance.py", "sha256": "d" * 64}},
         "maintenance": {"path": "/synthetic/maintenance.json", "sha256": "e" * 64}}
    case.component["plan"] = {"path": "/synthetic/maintenance-plan.json", "sha256": "f" * 64}
    maintenance_refs = [m["maintenance"], m["helpers"]["maintenance"], case.component["plan"]]
    if before is None:
        before = {Common.digest(unit.encode()): M.original_identity_expected(case.component, "web", unit)
                  for unit in case.component["hosts"]["web"]["units"]}
    after = copy.deepcopy(before) if after is None else after
    membership = {label: sorted(Common.digest(name.encode()) for name in names) for label, names in zip(
        D.SYSTEMD_LISTINGS, (discovery.installed_units, discovery.loaded_units,
                            discovery.final_installed_units, discovery.final_loaded_units), strict=True)}
    stable = controls[0] is not None and controls[0] == controls[1]
    objects = D._systemd_objects(Common, m, M, case.component, "web", report, membership, before, after, mode, stable)
    proof = {"schema": "AcademySystemdCensusDomainObservation.v1", "candidate": m["candidate"], "tree": m["tree"],
             "role": "web", "hostname": "vmi2490731", "domain": D.SYSTEMD_DOMAIN, "sources": refs,
             "maintenance_sources": maintenance_refs, "observed_unix_started": 100, "observed_unix_finished": 101,
             "mode": mode, "named_before": before, "named_after": after,
             "control_before": controls[0], "control_after": controls[1], "discovery": report,
             "unit_membership": membership, "objects": objects,
             "maintenance_lifecycle": {"attempted": 0, "cleanup_confirmed": 0, "records": [],
                                       "records_sha256": Common.digest(Common.canonical([])),
                                       "spawning": False, "pending_signal": False},
             "adapter_accounting": {"capture_reconstruction_work_before_validation": 0, "work_limit": 1_048_576,
                                    "proof_byte_limit": discovery.envelope()["resource_profile"]["normal_json_bytes"]},
             "enumerated_object_ids": [row["object_id"] for row in objects],
             "unresolved_gaps": D._systemd_gaps(report, objects, before, after, mode, stable),
             "coverage_complete": False}
    scope = {"candidate": m["candidate"], "tree": m["tree"], "hosts": {"web": "vmi2490731"},
             "domains": {D.SYSTEMD_DOMAIN: {"discovery_refs": refs}}}
    return m, scope, proof


def observation(monkeypatch, *, extra=(), final=None, mutate=None, graph_change=None, all_named=False):
    case = identity_case(monkeypatch)
    if all_named:
        template = case.spec
        case.component["hosts"]["web"]["units"] = {}
        for unit in M.TARGETS["web"]:
            spec = copy.deepcopy(template)
            spec["original_files"][0]["path"] = ROOT + "/" + unit
            if unit.endswith(".timer"):
                spec["observed_command_sha256"] = M.sha(b"")
            case.component["hosts"]["web"]["units"][unit] = spec
    filesystem = SyntheticFS()
    names = (*case.component["hosts"]["web"]["units"], *extra)
    for name in set(names) | set(final or ()):
        filesystem.add(ROOT + "/" + name, data=case.body)
    if mutate is not None:
        mutate(filesystem, case)
    discovery = ConnectedDiscovery(filesystem, names, final=final)
    discovery.graph_change = graph_change or {}
    discovery.systemd()
    discovery.template_definitions()
    m, scope, proof = make_proof(case, discovery)
    monkeypatch.setattr(M, "validate_component", lambda *_args: case.component)
    C = type("SystemdCommon", (Common,), {"maintenance_module": staticmethod(lambda _m: M)})
    return SimpleNamespace(case=case, discovery=discovery, m=m, scope=scope, proof=proof, C=C)


def named(proof, unit):
    return next(row for row in proof["objects"] if row["unit_sha256"] == Common.digest(unit.encode()))


def validate_schema(proof):
    base = Path(D.__file__).parent
    schema = json.loads((base / "systemd-census-domain-proof.schema.json").read_bytes())
    schema["$id"] = "https://synthetic.invalid/systemd.json"
    discovery = json.loads((base / "discovery.schema.json").read_bytes())
    registry = Registry().with_resource("https://synthetic.invalid/discovery.schema.json",
                                        Resource.from_contents(discovery, default_specification=DRAFT202012))
    Draft202012Validator(schema, registry=registry).validate(proof)


def test_named_source_graph_and_bodies_connect_without_sender_or_bucket_claim(monkeypatch):
    fixture = observation(monkeypatch, extra=("unmatched.service", "idle.timer"))
    row = named(fixture.proof, fixture.case.unit)
    assert row["classification"] == "named_execution_authority" and len(row["authority_refs"]) == 1
    assert row["campaign_bucket"] == "unresolved" and not row["activation_complete"]
    for unit in ("unmatched.service", "idle.timer"):
        assert named(fixture.proof, unit)["classification"] == "unknown"
        assert named(fixture.proof, unit)["authority_refs"] == []
    assert D.validate_systemd_observation(fixture.C, fixture.scope, "web", fixture.proof, manifest=fixture.m)
    validate_schema(fixture.proof)
    with pytest.raises(ValueError, match="membership_activation_or_control_unresolved"):
        D.validate_domain_proof(fixture.C, fixture.scope, "web", D.SYSTEMD_DOMAIN, fixture.proof, manifest=fixture.m)


@pytest.mark.parametrize("kind", ["changed-body", "extra-dropin", "alias", "dependency"])
def test_named_target_alone_does_not_override_body_dropin_alias_or_dependency_mismatch(monkeypatch, kind):
    def mutate(filesystem, case):
        if kind == "changed-body":
            filesystem.nodes[ROOT + "/" + case.unit]["data"] = b"[Unit]\nDescription=changed\n"
        elif kind == "extra-dropin":
            filesystem.add(ROOT + "/" + case.unit + ".d/10-extra.conf", data=b"[Unit]\n")
        elif kind == "alias":
            filesystem.add(ROOT + "/other.service", data=case.body)
            filesystem.add(ROOT + "/" + case.unit, "symlink", "other.service")

    fixture = observation(monkeypatch, mutate=mutate,
                          graph_change={"Requires": "other.service"} if kind == "dependency" else None)
    row = named(fixture.proof, fixture.case.unit)
    assert row["classification"] == "unknown" and row["authority_refs"] == []
    assert not fixture.proof["coverage_complete"]
    D.validate_systemd_observation(fixture.C, fixture.scope, "web", fixture.proof, manifest=fixture.m)


def test_final_only_units_omitted_definition_and_templates_are_retained_unknown(monkeypatch):
    fixture = observation(monkeypatch, extra=("task@.service",), final=("late.service",))
    units = {row["unit_sha256"] for row in fixture.proof["objects"]}
    assert {Common.digest(unit.encode()) for unit in (fixture.case.unit, "late.service", "task@.service")} <= units
    assert named(fixture.proof, "late.service")["classification"] == "unknown"
    omitted = copy.deepcopy(fixture.proof)
    omitted["objects"].pop()
    with pytest.raises(ValueError, match="exact_object_union"):
        D.validate_systemd_observation(fixture.C, fixture.scope, "web", omitted, manifest=fixture.m)


def test_forged_source_classification_completion_and_recipe_are_reconstructed(monkeypatch):
    fixture = observation(monkeypatch)
    for field, value, reason in (("classification", "unknown", "exact_object_union"),
                                  ("campaign_bucket", "legacy", "exact_object_union"),
                                  ("control_state", "named_fenced", "exact_object_union")):
        proof = copy.deepcopy(fixture.proof)
        named(proof, fixture.case.unit)[field] = value
        with pytest.raises(ValueError, match=reason):
            D.validate_systemd_observation(fixture.C, fixture.scope, "web", proof, manifest=fixture.m)
    proof = copy.deepcopy(fixture.proof)
    proof["named_before"][Common.digest(fixture.case.unit.encode())]["effective_config_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="identity_recipe"):
        D.validate_systemd_observation(fixture.C, fixture.scope, "web", proof, manifest=fixture.m)
    proof = copy.deepcopy(fixture.proof)
    proof["coverage_complete"] = True
    with pytest.raises(ValueError, match="completion_or_mode"):
        D.validate_systemd_observation(fixture.C, fixture.scope, "web", proof, manifest=fixture.m)


def test_explicit_primary_service_suffix_join_preserves_existing_stable_ids():
    for role in ("web", "lab"):
        for unit in Common.services(role):
            assert D.systemd_authority_id(Common, role, "synthetic", unit + ".service") == D.authority_id(
                Common, role, "synthetic", unit)
    unit = "named-job.timer"
    assert D.systemd_authority_id(Common, "lab", "synthetic", unit) == Common.digest(Common.canonical({
        "schema": "AcademySystemdUnitAuthority.v1", "hostname": "synthetic", "role": "lab", "unit": unit}))
    assert D.systemd_authority_id(Common, "web", "synthetic", unit) != D.systemd_authority_id(
        Common, "lab", "synthetic", unit)


@pytest.mark.parametrize("context", [(None, {}, "fenced"), (object(), None, "fenced"),
                                     (object(), {}, None), (object(), {}, "resumed")])
def test_mixed_or_resumed_control_context_refuses(context):
    with pytest.raises(ValueError, match=r"control_context_incomplete|control_status"):
        D._systemd_mode(Common, *context)


def controlled_fixture(monkeypatch):
    fixture = observation(monkeypatch, all_named=True)
    approval = {"attempt": "synthetic-attempt"}
    evidence = SimpleNamespace(get=lambda *_args: None)
    current_units = {}
    for unit, spec in fixture.case.component["hosts"]["web"]["units"].items():
        original = M.original_identity_expected(fixture.case.component, "web", unit)
        current_units[unit] = {"effective_config_sha256": spec["expected_config_sha256"]["fenced"],
                               "original_files_sha256": original["original_files_sha256"],
                               "owned_files_sha256": M.sha(M.canonical({str(M.own_path(fixture.m, unit, True)):
                                                                       M.sha(M.fence_bytes(unit))})),
                               "cgroup_path_sha256": M.sha(b"empty_cgroup_path"), "main_pid": "0", "control_pid": "0",
                               "active_state": "inactive", "sub_state": "dead"}
        fixture.discovery.fs.add(str(M.own_path(fixture.m, unit, True)), data=M.fence_bytes(unit))
    configuration = {unit: row["effective_config_sha256"] for unit, row in current_units.items()}
    processes = {unit: ["0", "0", row["cgroup_path_sha256"]] for unit, row in current_units.items()}
    timers = {unit: ["inactive", "dead"] for unit in current_units if unit.endswith(".timer")}
    current = {"units": current_units, "configuration_sha256": M.sha(M.canonical(configuration)),
               "process_census_sha256": M.sha(M.canonical(processes)),
               "pending_jobs_sha256": M.sha(M.canonical([])), "timer_states_sha256": M.sha(M.canonical(timers))}
    retained = {"status": "fenced", "observation_sha256": "a" * 64, "retained_receipt_sha256": "b" * 64,
                "observed_unix_started": 90.5, "observed_unix_finished": 91.5, "remote_current_state_proven": False}
    calls = []

    def verify_retained(_C, m, e, a, role, status):
        Common.require(m == fixture.m and e is evidence and a == approval and role == "web" and status == "fenced",
                       "synthetic_genuine_authority_binding")
        calls.append("retained")
        return copy.deepcopy(retained)

    # Existing verify_observation remains real: it must call retained verification and current reproduction.
    monkeypatch.setattr(M, "verify_retained", verify_retained)
    monkeypatch.setattr(M.socket, "gethostname", lambda: M.HOSTS["web"])
    monkeypatch.setattr(M, "current", lambda *_args, **_kwargs: calls.append("current") or copy.deepcopy(current))
    fixture.current = current
    fixture.evidence, fixture.approval, fixture.control_calls = evidence, approval, calls
    return fixture


def test_control_verifier_demands_genuine_context_and_current_not_retained_hashes(monkeypatch):
    fixture = controlled_fixture(monkeypatch)
    control = D._systemd_control(fixture.C, fixture.m, M, fixture.case.component, fixture.evidence,
                                fixture.approval, "web", "fenced", M.time.monotonic() + 20)
    assert fixture.control_calls == ["retained", "current"]
    assert control["attempt"] == fixture.approval["attempt"]
    assert control["proof"]["host_local_current_state_proven"] is True
    with pytest.raises(ValueError, match="genuine_control_context"):
        D._systemd_control(fixture.C, fixture.m, M, fixture.case.component, object(), fixture.approval,
                           "web", "fenced", M.time.monotonic() + 20)
    with pytest.raises(ValueError, match="control_role_status"):
        D._systemd_control(fixture.C, fixture.m, M, fixture.case.component, fixture.evidence, fixture.approval,
                           "web", "adopted_and_fenced", M.time.monotonic() + 20)


@pytest.mark.parametrize("mutation", [
    lambda value: value["units"][M.TARGETS["web"][0]].update(main_pid="23"),
    lambda value: value["units"][M.TARGETS["web"][0]].update(active_state="active"),
    lambda value: value["units"][M.TARGETS["web"][0]].update(cgroup_path_sha256="0" * 64),
    lambda value: value["units"][M.TARGETS["web"][0]].update(effective_config_sha256="0" * 64),
    lambda value: value.update(pending_jobs_sha256="0" * 64),
])
def test_active_jobs_cgroups_or_current_config_drift_cannot_become_fenced(monkeypatch, mutation):
    fixture = controlled_fixture(monkeypatch)
    mutation(fixture.current)
    with pytest.raises(M.Refusal):
        D._systemd_control(fixture.C, fixture.m, M, fixture.case.component, fixture.evidence, fixture.approval,
                           "web", "fenced", M.time.monotonic() + 20)


def test_systemd_dispatch_connected_six_others_and_complete_producer_still_refuse(monkeypatch):
    calls = []
    monkeypatch.setattr(D, "observe_systemd", lambda *args, **kwargs: calls.append(kwargs) or {"partial": True})
    assert D.collect_domain(Common, {}, "web", D.SYSTEMD_DOMAIN) == {"partial": True}
    assert calls == [{"evidence": None, "approval": None, "maintenance_status": None}]
    for domain in D.DOMAINS:
        if domain not in (D.PROCESS_DOMAIN, D.SYSTEMD_DOMAIN):
            with pytest.raises(ValueError, match="adapter_unimplemented"):
                D.collect_domain(Common, {}, "web", domain)
    # The existing hard refusal is retained even if every dictionary validator is mocked to return references.
    monkeypatch.setattr(D, "validate_domain_proof", lambda *_args, **_kwargs: set())
    scope = {"hosts": {"web": "vmi2490731", "lab": "synthetic-lab"},
             "authority_membership": {role: {bucket: [] for bucket in D.BUCKETS} for role in ("web", "lab")}}
    authored = {domain: {role: {"coverage_complete": True} for role in ("web", "lab")} for domain in D.DOMAINS}
    with pytest.raises(ValueError, match="adapter_unimplemented"):
        D.require_complete_scope(Common, scope, authored)


def connected_control_proof(monkeypatch):
    fixture = controlled_fixture(monkeypatch)
    control = D._systemd_control(fixture.C, fixture.m, M, fixture.case.component, fixture.evidence,
                                fixture.approval, "web", "fenced", M.time.monotonic() + 20)
    names = tuple(fixture.case.component["hosts"]["web"]["units"])
    discovery = ConnectedDiscovery(fixture.discovery.fs, names)
    discovery.systemd()
    discovery.template_definitions()
    identities = {Common.digest(unit.encode()): D._systemd_expected_identity(
        M, fixture.C, fixture.m, fixture.case.component, "web", unit, "fenced") for unit in names}
    fixture.m, fixture.scope, fixture.proof = make_proof(fixture.case, discovery, mode="fenced", before=identities,
                                                       controls=(control, copy.deepcopy(control)))
    return fixture


def test_fresh_control_joins_exact_named_sources_and_graph_without_completing_campaign(monkeypatch):
    fixture = connected_control_proof(monkeypatch)
    assert all(row["classification"] == "named_execution_authority" and row["control_state"] == "named_fenced"
               for row in fixture.proof["objects"])
    result = D.verify_systemd_named_controls(fixture.C, fixture.m, fixture.evidence, fixture.approval,
                                             "web", "fenced", fixture.proof)
    assert result == fixture.proof["control_before"]
    assert not fixture.proof["coverage_complete"]
    assert "systemd_campaign_membership_unresolved" in fixture.proof["unresolved_gaps"]
    validate_schema(fixture.proof)


@pytest.mark.parametrize("field,value", [("role", "lab"), ("status", "adopted_and_fenced"),
                                        ("attempt", "different-attempt"), ("helper_sha256", "0" * 64)])
def test_control_role_status_attempt_and_source_bindings_cannot_be_forged(monkeypatch, field, value):
    fixture = connected_control_proof(monkeypatch)
    fixture.proof["control_before"][field] = value
    with pytest.raises(ValueError, match="control_binding"):
        D.validate_systemd_observation(fixture.C, fixture.scope, "web", fixture.proof, manifest=fixture.m,
                                       evidence=fixture.evidence, approval=fixture.approval)


def test_retained_only_flag_and_changed_current_body_cannot_satisfy_control(monkeypatch):
    fixture = connected_control_proof(monkeypatch)
    fixture.proof["control_before"]["proof"]["host_local_current_state_proven"] = False
    with pytest.raises(ValueError, match="actual_retained_control"):
        D.validate_systemd_observation(fixture.C, fixture.scope, "web", fixture.proof, manifest=fixture.m,
                                       evidence=fixture.evidence, approval=fixture.approval)


def test_failed_listing_prefix_is_retained_unknown_with_unavailable_membership_gap(monkeypatch):
    fixture = observation(monkeypatch)
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/prefix.service", data=b"[Unit]\n")
    discovery = ConnectedDiscovery(filesystem, ())
    original = discovery.run

    def listing(args, domain, **kwargs):
        if args[0] == "list-unit-files" and domain == "systemd_installed":
            return b'[{"unit_file":"prefix.service"},{"unit_file":"not a unit"}]'
        return original(args, domain, **kwargs)

    discovery.run = listing
    discovery.systemd()
    discovery.template_definitions()
    m, scope, proof = make_proof(fixture.case, discovery)
    assert proof["unit_membership"]["systemd_installed"] == []
    assert named(proof, "prefix.service")["classification"] == "unknown"
    assert "systemd_listing_membership_unavailable" in proof["unresolved_gaps"]
    D.validate_systemd_observation(fixture.C, scope, "web", proof, manifest=m)
    validate_schema(proof)


@pytest.mark.parametrize("fault", ["cleanup", "cancel", "deadline"])
def test_maintenance_terminal_failures_are_not_downgraded_or_followed_by_more_units(fault):
    calls = []
    discovery = SimpleNamespace(pending_signal=None, resource_stopped=False)
    maintenance = SimpleNamespace(COMMANDS=[], SPAWNING=False, PENDING=False,
                                  read_timeout=M.read_timeout, Refusal=M.Refusal)
    budget = {"work": 0, "deadline": M.time.monotonic() + 20, "discovery": discovery,
              "maintenance": maintenance, "command_start": 0, "phase": "discovery"}

    def project(*_args, **_kwargs):
        calls.append(True)
        if fault == "cleanup":
            maintenance.COMMANDS.append({"cleanup": {"confirmed": False, "spawn_handle_unavailable": True}})
        elif fault == "cancel":
            discovery.pending_signal = 15
        else:
            budget["deadline"] = 0
        raise M.Refusal("ordinary_metadata_refusal")

    maintenance.original_identity_projection = project
    component = {"hosts": {"web": {"units": {"first.service": {}, "second.service": {}}}}}
    with pytest.raises(D.SystemdObservationHold):
        D._systemd_named_snapshot(Common, {}, maintenance, component, "web", "original",
                                  budget["deadline"], None, budget)
    assert calls == [True] and budget["phase"] == "discovery"


def test_signal_dispatch_never_raises_across_discovery_spawn_or_hup_cleanup(monkeypatch):
    discovery = ConnectedDiscovery(SyntheticFS(), ())
    monkeypatch.setattr(M, "PENDING", False)
    monkeypatch.setattr(M, "SPAWNING", True)
    budget = {"phase": "discovery"}
    D._systemd_signal(discovery, M, budget, D.signal.SIGTERM, None)
    assert discovery.pending_signal == D.signal.SIGTERM and M.PENDING is False
    budget["phase"] = "maintenance"
    D._systemd_signal(discovery, M, budget, D.signal.SIGINT, None)
    assert M.PENDING is True
    monkeypatch.setattr(M, "SPAWNING", False)
    for _ in range(2):
        D._systemd_signal(discovery, M, budget, D.signal.SIGHUP, None)
    assert discovery.pending_signal == D.signal.SIGHUP and M.PENDING is True


@pytest.mark.parametrize("change,reason", [
    (lambda proof: proof["discovery"].update(resource_profile_sha256="0" * 64), "resource_profile"),
    (lambda proof: proof["discovery"]["child_lifecycle"].update(spawned=1), "child_cleanup"),
    (lambda proof: proof["discovery"]["resource_accounting"].update(cumulative_filesystem_work=0),
     "resource_accounting"),
    (lambda proof: proof["discovery"]["domains"]["systemd_unit_graph"]["records"][0]["facts"].update(
        graph_fields_unchanged=False), "repeated_stability"),
    (lambda proof: proof["discovery"]["domains"]["systemd_template_definitions"]["records"][0]["facts"]["sources"][0]
     .update(initial_read=99999), "read_reference"),
])
def test_nested_source_profiles_lifecycle_graph_and_reference_joins_are_validated(monkeypatch, change, reason):
    fixture = observation(monkeypatch)
    change(fixture.proof)
    with pytest.raises(ValueError, match=rf"discovery_schema_mismatch|{reason}"):
        D.validate_systemd_observation(fixture.C, fixture.scope, "web", fixture.proof, manifest=fixture.m)


def fixed_schema():
    return json.loads(Path(D.__file__).with_name("discovery.schema.json").read_bytes())


def structural_accepts(schema, value):
    budget = {"work": 0, "deadline": D.time.monotonic() + 300}
    validator = D._FixedDiscoveryValidator(Common, schema, budget)
    try:
        validator.validate_normal(value)
    except ValueError:
        return False
    return True


def reference_accepts(schema, value):
    entry = {"$ref": "#/$defs/normal_v3", "$defs": schema["$defs"]}
    return not list(Draft202012Validator(entry).iter_errors(value))


@pytest.mark.parametrize("mutation", [
    lambda value: value["domains"]["systemd_template_definitions"]["path_observations"][0].update(unused_extra=True),
    lambda value: value["domains"]["systemd_template_definitions"]["manager_observations"][0].update(unused_extra=True),
    lambda value: value["domains"]["systemd_template_definitions"]["source_reads"][0].update(phase="invented"),
    lambda value: value["domains"]["systemd_template_definitions"]["relations"].append({"unused_extra": True}),
    lambda value: value["domains"]["systemd_unit_properties"]["records"][0].update(unused_extra=True),
    lambda value: value["domains"]["systemd_unit_graph"]["records"][0]["facts"]["initial"]["fields"]["Requires"]
    .update(endpoint_count=True),
])
def test_full_fixed_schema_matches_jsonschema_for_unused_nested_mutations(monkeypatch, mutation):
    fixture = observation(monkeypatch)
    schema = fixed_schema()
    report = fixture.proof["discovery"]
    assert structural_accepts(schema, report) and reference_accepts(schema, report)
    invalid = copy.deepcopy(report)
    mutation(invalid)
    assert not reference_accepts(schema, invalid)
    assert not structural_accepts(schema, invalid)


@pytest.mark.parametrize("node,value,expected", [
    ({"const": True}, 1, False),
    ({"const": {"nested": [False]}}, {"nested": [0]}, False),
    ({"type": "integer"}, True, False),
    ({"type": "integer"}, 1.0, True),
    ({"type": ["boolean", "null"]}, None, True),
    ({"anyOf": [{"type": "boolean"}, {"type": "integer"}]}, 2, True),
    ({"oneOf": [{"type": "integer"}, {"minimum": 0}]}, 1, False),
    ({"type": "array", "items": {"enum": [False, 0]}, "uniqueItems": True}, [False, 0], True),
    ({"type": "array", "items": {"type": "number"}, "uniqueItems": True}, [1, 1.0], False),
    ({"$ref": "#/$defs/base", "maximum": 2}, 3, False),
    ({"if": {"type": "integer"}, "then": {"minimum": 2}, "else": {"type": "boolean"}}, 1, False),
    ({"if": {"type": "integer"}, "then": {"minimum": 2}, "else": {"type": "boolean"}}, True, True),
])
def test_supported_vocabulary_differential_bool_unions_conditions_and_ref_siblings(node, value, expected):
    schema = {"$defs": {"normal_v3": node, "base": {"type": "integer", "minimum": 1}}}
    assert structural_accepts(schema, value) is expected
    assert reference_accepts(schema, value) is expected


@pytest.mark.parametrize("node", [{"not": {}}, {"pattern": ".*"}, {"$ref": "https://invalid/schema"},
                                  {"$ref": "#/$defs/missing"}, {"$ref": "#/$defs/normal_v3"}])
def test_fixed_schema_compile_refuses_unknown_vocabulary_resolvers_and_cycles(node):
    with pytest.raises(ValueError, match="schema_"):
        D._FixedDiscoveryValidator(Common, {"$defs": {"normal_v3": node}},
                                    {"work": 0, "deadline": D.time.monotonic() + 300})


def test_union_cannot_convert_budget_exhaustion_into_an_allowed_branch():
    budget = {"work": 0, "deadline": D.time.monotonic() + 300}
    validator = D._FixedDiscoveryValidator(Common, {"$defs": {"normal_v3": {"anyOf": [False, True]}}}, budget)
    budget["work"] = 1_048_576
    with pytest.raises(D.SystemdObservationHold):
        validator.validate_normal({})


def test_schema_is_exact_pinned_adjacent_file_and_only_systemd_adds_fourth_source(monkeypatch):
    fixture = observation(monkeypatch)
    path = Path(D.__file__).with_name("discovery.schema.json")
    assert Common.digest(path.read_bytes()) == D.DISCOVERY_SCHEMA_SHA256
    module, refs = D._systemd_module(fixture.C, fixture.m)
    assert module._systemd_normal_schema == fixed_schema()
    assert refs == [*source_refs(), {"path": str(path), "sha256": D.DISCOVERY_SCHEMA_SHA256}]
    assert len(D._sources(fixture.C, fixture.m)[1]) == 3
    original = fixture.C.read_bytes
    monkeypatch.setattr(fixture.C, "read_bytes", staticmethod(
        lambda name, **kwargs: b"schema drift" if Path(name) == path else original(name, **kwargs)))
    with pytest.raises(ValueError, match="actual_source_hash"):
        D._systemd_module(fixture.C, fixture.m)


def producer_case(monkeypatch, fault=None):
    """Real dispatcher/producer; only protected loaders, host and I/O leaves are synthetic."""
    fixture = controlled_fixture(monkeypatch)
    events = []
    instances = []
    original_loader = D._systemd_module
    original_control = D._systemd_control
    original_named = D._systemd_named_snapshot
    original_structural = D._FixedDiscoveryValidator.validate_normal
    original_semantic = D._validate_systemd_report
    original_current = M.current
    loader_calls = []
    monkeypatch.setattr(M, "COMMANDS", [])
    monkeypatch.setattr(M, "SPAWNING", False)
    monkeypatch.setattr(M, "PENDING", False)
    monkeypatch.setattr(D, "sys", SimpleNamespace(platform="linux", version_info=(3, 12),
                        flags=SimpleNamespace(isolated=True, no_site=True, dont_write_bytecode=True)))
    monkeypatch.setattr(D, "os", SimpleNamespace(geteuid=lambda: 0, WNOWAIT=1))
    monkeypatch.setattr(D, "socket", SimpleNamespace(gethostname=lambda: "vmi2490731"))

    class ProducerDiscovery(ConnectedDiscovery):
        def __init__(self, role):
            assert role == "web"
            super().__init__(fixture.discovery.fs, tuple(fixture.case.component["hosts"][role]["units"]))
            instances.append(self)

        def systemd(self):
            events.append("systemd")
            if fault == "discovery-cancel":
                D.signal.getsignal(D.signal.SIGTERM)(D.signal.SIGTERM, None)
            return super().systemd()

        def template_definitions(self):
            events.append("definitions")
            result = super().template_definitions()
            if fault == "unused-table":
                self.domain("systemd_template_definitions")["manager_observations"][0]["unused_extra"] = True
            return result

        def definition_close_pass(self):
            events.append("close")
            super().definition_close_pass()
            if fault == "close":
                raise RuntimeError("synthetic_close_failure")

        def seal(self):
            events.append("seal")
            if fault == "seal":
                import io
                return io.BytesIO(Common.canonical(self.envelope(failure=True)))
            return super().seal()

    def loader(C, manifest):
        loader_calls.append(True)
        events.append("source-recheck")
        if fault == "source-drift" and len(loader_calls) == 2:
            raise ValueError("census_domain_actual_source_hash")
        module, refs = original_loader(C, manifest)
        module.Discovery = ProducerDiscovery
        module.HOSTS = {"web": "vmi2490731", "lab": "synthetic-lab"}
        original_encode = module.stage_json

        def encode(*args):
            events.append("encode")
            return original_encode(*args)

        module.stage_json = encode
        return module, refs

    def current(*args, **kwargs):
        events.append("current")
        if fault == "maintenance-cancel":
            D.signal.getsignal(D.signal.SIGINT)(D.signal.SIGINT, None)
        if fault in ("cleanup", "spawn-unavailable"):
            M.COMMANDS.append({"cleanup": {"confirmed": False, "spawn_handle_unavailable": True}})
        return original_current(*args, **kwargs)

    def control(*args, **kwargs):
        events.append("control")
        return original_control(*args, **kwargs)

    def named_snapshot(*args, **kwargs):
        events.append("named")
        return original_named(*args, **kwargs)

    def structural(self, value):
        events.append("structural")
        return original_structural(self, value)

    def semantic(*args):
        events.append("semantic")
        return original_semantic(*args)

    monkeypatch.setattr(D, "_systemd_module", loader)
    monkeypatch.setattr(D, "_systemd_control", control)
    monkeypatch.setattr(D, "_systemd_named_snapshot", named_snapshot)
    monkeypatch.setattr(D._FixedDiscoveryValidator, "validate_normal", structural)
    monkeypatch.setattr(D, "_validate_systemd_report", semantic)
    monkeypatch.setattr(M, "current", current)
    if fault in ("work", "deadline"):
        original_check = D._systemd_check

        def check(C, budget):
            if budget is not None and "discovery" in budget:
                budget["work"] = 1_048_576 if fault == "work" else budget["work"]
                budget["deadline"] = 0 if fault == "deadline" else budget["deadline"]
            return original_check(C, budget)

        monkeypatch.setattr(D, "_systemd_check", check)
    fixture.events, fixture.instances, fixture.loader_calls = events, instances, loader_calls
    return fixture


def invoke_producer(fixture):
    return D.collect_domain(fixture.C, fixture.m, "web", D.SYSTEMD_DOMAIN, evidence=fixture.evidence,
                            approval=fixture.approval, maintenance_status="fenced")


def test_real_dispatcher_producer_runs_control_acquisition_validation_and_bounded_encode(monkeypatch):
    fixture = producer_case(monkeypatch)
    handlers = {number: D.signal.getsignal(number) for number in (D.signal.SIGTERM, D.signal.SIGHUP, D.signal.SIGINT)}
    proof = invoke_producer(fixture)
    selected = [event for event in fixture.events if event in
                ("control", "named", "systemd", "definitions", "seal", "structural", "semantic", "encode")]
    assert selected == ["control", "named", "systemd", "definitions", "control", "named", "seal",
                        "structural", "semantic", "encode"]
    assert len(fixture.loader_calls) == 3
    assert "close" in fixture.events and fixture.instances[0].fs.fds == {}
    assert proof["adapter_accounting"]["capture_reconstruction_work_before_validation"] > 0
    assert all(D.signal.getsignal(number) == handler for number, handler in handlers.items())
    validate_schema(proof)


@pytest.mark.parametrize("fault,error", [
    ("maintenance-cancel", D.SystemdObservationHold), ("discovery-cancel", D.SystemdObservationHold),
    ("cleanup", D.SystemdObservationHold), ("spawn-unavailable", D.SystemdObservationHold),
    ("work", D.SystemdObservationHold), ("deadline", D.SystemdObservationHold),
    ("seal", ValueError), ("unused-table", ValueError), ("source-drift", ValueError), ("close", RuntimeError),
])
def test_real_producer_faults_restore_handlers_and_never_return_completed_prefix(monkeypatch, fault, error):
    fixture = producer_case(monkeypatch, fault)
    handlers = {number: D.signal.getsignal(number) for number in (D.signal.SIGTERM, D.signal.SIGHUP, D.signal.SIGINT)}
    with pytest.raises(error):
        invoke_producer(fixture)
    assert all(D.signal.getsignal(number) == handler for number, handler in handlers.items())
    assert "encode" not in fixture.events
    if fault in ("maintenance-cancel", "cleanup", "spawn-unavailable", "work", "deadline"):
        assert "systemd" not in fixture.events
    assert all(not instance.fs.fds for instance in fixture.instances)


@pytest.mark.parametrize("elapsed", [290, 301])
def test_standalone_verification_validation_and_current_share_one_deadline(monkeypatch, elapsed):
    fixture = connected_control_proof(monkeypatch)
    clock = [0]
    monkeypatch.setattr(D.time, "monotonic", lambda: clock[0])
    original_validate = D.validate_systemd_observation
    original_current = M.current
    observed = []

    def validate(*args, **kwargs):
        result = original_validate(*args, **kwargs)
        clock[0] = elapsed
        return result

    def current(*args, deadline=None, **kwargs):
        observed.append(deadline)
        return original_current(*args, deadline=deadline, **kwargs)

    monkeypatch.setattr(D, "validate_systemd_observation", validate)
    monkeypatch.setattr(M, "current", current)
    if elapsed > 300:
        with pytest.raises(D.SystemdObservationHold):
            D.verify_systemd_named_controls(fixture.C, fixture.m, fixture.evidence, fixture.approval,
                                            "web", "fenced", fixture.proof)
        assert observed == []
    else:
        D.verify_systemd_named_controls(fixture.C, fixture.m, fixture.evidence, fixture.approval,
                                        "web", "fenced", fixture.proof)
        assert observed == [300]


@pytest.mark.parametrize("mutation,reason", [
    (lambda jobs: jobs.update(unexpected_extra=True), "discovery_schema_mismatch"),
    (lambda jobs: jobs.update(enumerated=1), "empty_jobs_snapshot"),
    (lambda jobs: jobs.update(enumeration_complete=False), "empty_jobs_snapshot"),
])
def test_empty_jobs_variant_remains_closed_and_cannot_conflict_with_observed_counters(monkeypatch, mutation, reason):
    fixture = observation(monkeypatch)
    jobs = fixture.proof["discovery"]["domains"]["systemd_jobs"]
    assert jobs["empty_pending_jobs_snapshot"] is True
    mutation(jobs)
    with pytest.raises(ValueError, match=reason):
        D.validate_systemd_observation(fixture.C, fixture.scope, "web", fixture.proof, manifest=fixture.m)


def test_unexpected_identity_helper_failure_is_terminal_and_does_not_visit_next_unit():
    calls = []
    maintenance = SimpleNamespace(COMMANDS=[], SPAWNING=False, PENDING=False,
                                  read_timeout=M.read_timeout, Refusal=M.Refusal)
    budget = {"work": 0, "deadline": M.time.monotonic() + 20,
              "discovery": SimpleNamespace(pending_signal=None, resource_stopped=False),
              "maintenance": maintenance, "command_start": 0, "phase": "discovery"}

    def project(*_args, **_kwargs):
        calls.append(True)
        raise AttributeError("synthetic_unexpected_helper_failure")

    maintenance.original_identity_projection = project
    component = {"hosts": {"web": {"units": {"first.service": {}, "second.service": {}}}}}
    with pytest.raises(AttributeError, match="unexpected_helper_failure"):
        D._systemd_named_snapshot(Common, {}, maintenance, component, "web", "original",
                                  budget["deadline"], None, budget)
    assert calls == [True] and budget["phase"] == "discovery"

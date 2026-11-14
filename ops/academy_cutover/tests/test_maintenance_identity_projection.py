# ruff: noqa: S101 -- hosted synthetic maintenance qualification only.
"""Identity observation is separate from maintenance action readiness."""

import copy
import stat
from types import SimpleNamespace

import candidate_maintenance as M
import pytest


class IdentityCommon:
    configured_start = staticmethod(lambda text: text)
    stable_exec_start = staticmethod(lambda text: text)
    retained_environment_target = staticmethod(lambda _m, _role: "/synthetic/retained.env")


def identity_case(monkeypatch, unit="academy-admin-report.service", *, service_type="oneshot"):
    body = b"[Unit]\n"
    command = "synthetic-python -m synthetic.job" if unit.endswith(".service") else "synthetic timer text"
    fields = (*M.COMMON_CONFIG, *(M.SERVICE_CONFIG if unit.endswith(".service") else M.TIMER_CONFIG))
    values = dict.fromkeys(fields, "")
    values.update(Id=unit, Names=unit, LoadState="loaded", FragmentPath="/etc/systemd/system/" + unit,
                  RefuseManualStop="no", AllowIsolate="no")
    for key in ("FailureAction", "SuccessAction", "JobTimeoutAction", "StartLimitAction"):
        values[key] = "none"
    if unit.endswith(".service"):
        values.update(Type=service_type, User="dotmac", Group="dotmac", DynamicUser="no", PrivateUsers="no",
                      RestartMode="normal", ExecStart=command)
    info = SimpleNamespace(st_dev=1, st_ino=2, st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o644,
                           st_nlink=1, st_size=len(body), st_mtime_ns=1, st_ctime_ns=1)
    ref = {"path": values["FragmentPath"], "sha256": M.sha(body), **dict(zip(
        ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns"), M.identity(info), strict=True))}
    config_sha = M.normalized_config(IdentityCommon, values)
    spec = {"original_files": [ref], "enablement_links": [], "original_unit_text_sha256": M.sha(command.encode()),
            "expected_config_sha256": dict.fromkeys(("original", *M.STATUSES), config_sha),
            "dependencies": {key: [] for key in M.DEPS}, "originally_active": True,
            "observed_command_sha256": M.sha(command.encode()) if unit.endswith(".service") else M.sha(b""),
            "environment_sha256": M.sha(b"")}
    manifest = {"candidate": "a" * 40, "tree": "b" * 40, "source": "/synthetic/source", "venv": "/synthetic/venv"}
    component = {"inert_program_sha256": M.sha(b"inert"),
                 "hosts": {"web": {"hostname": "vmi2490731", "uid": 1000, "gid": 1000, "units": {unit: spec}}}}
    case = SimpleNamespace(C=IdentityCommon, m=manifest, component=component, unit=unit, spec=spec,
                           values=values, body=body, text=command, info=info, show_calls=[],
                           live={"ActiveState": "inactive", "SubState": "dead"}, owned=False)

    def read(path, **_kwargs):
        if str(path) == ref["path"]:
            return case.body, case.info
        if str(path) == "/usr/bin/false":
            return b"inert", info
        if case.owned:
            return b"owned", info
        raise FileNotFoundError

    def show(_unit, config=True, *, deadline=None):
        M.read_timeout(deadline)
        case.show_calls.append(config)
        return copy.deepcopy(case.values if config else case.live)

    monkeypatch.setattr(M, "read_file", read)
    monkeypatch.setattr(M, "show", show)
    monkeypatch.setattr(M, "read_command", lambda _args, _deadline=None: case.text)
    monkeypatch.setattr(M, "conf_inventory", lambda *_args: None)
    monkeypatch.setattr(M, "manager_environment", lambda *_args: None)
    monkeypatch.setattr(M, "activation_links", lambda *_args: None)
    monkeypatch.setattr(M, "pending_jobs", lambda *_args: M.sha(M.canonical([])))
    monkeypatch.setattr(M, "run", lambda _args: "systemd 255 synthetic\n")
    monkeypatch.setattr(M.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1000, pw_gid=1000))
    return case


def test_identity_projection_reads_exact_originals_without_action_readiness(monkeypatch):
    case = identity_case(monkeypatch, service_type="simple")
    case.live.update(ActiveState="active", SubState="running")
    value = M.original_identity_projection(case.C, case.m, case.component, "web", case.unit)
    assert value == M.original_identity_expected(case.component, "web", case.unit)
    assert case.show_calls == [True]
    assert "synthetic-python" not in str(value) and "/etc/systemd/system" not in str(value)
    with pytest.raises(M.Refusal, match="active_legacy_daemon_hold"):
        M.preflight_original(case.C, case.m, case.component, "web")


@pytest.mark.parametrize("change,reason", [
    (lambda c: setattr(c, "body", b"changed"), "immutable_original_preimage"),
    (lambda c: c.values.update(Id="alias.service"), "original_alias_generator"),
    (lambda c: c.values.update(Names=c.unit + " alias.service"), "original_alias_generator"),
    (lambda c: c.values.update(SourcePath="/run/generator/synthetic"), "original_alias_generator"),
    (lambda c: c.values.update(FragmentPath="/etc/systemd/system/other.service"), "original_file_coverage"),
    (lambda c: c.values.update(DropInPaths="/etc/systemd/system/extra.conf"), "original_file_coverage"),
    (lambda c: c.values.update(Requires="other.service"), "original_dependencies_drift"),
    (lambda c: c.values.update(WorkingDirectory="/different"), "original_effective_configuration"),
    (lambda c: setattr(c, "text", "changed command"), "original_unit_text_drift"),
])
def test_identity_drift_is_not_replaced_by_target_name_or_inactivity(monkeypatch, change, reason):
    case = identity_case(monkeypatch)
    change(case)
    with pytest.raises(M.Refusal, match=reason):
        M.original_identity_projection(case.C, case.m, case.component, "web", case.unit)


def test_original_preflight_keeps_owned_override_refusal(monkeypatch):
    case = identity_case(monkeypatch)
    case.owned = True
    with pytest.raises(M.Refusal, match="existing_owned_dropin_no_reuse"):
        M.preflight_original(case.C, case.m, case.component, "web")


def test_original_preflight_keeps_timer_state_and_action_readiness(monkeypatch):
    case = identity_case(monkeypatch, "academy-email-digest.timer")
    with pytest.raises(M.Refusal, match="original_timer_state_changed"):
        M.preflight_original(case.C, case.m, case.component, "web")
    case.live.update(ActiveState="active", SubState="waiting")
    case.values["RefuseManualStop"] = "yes"
    case.spec["expected_config_sha256"]["original"] = M.normalized_config(case.C, case.values)
    with pytest.raises(M.Refusal, match="unsupported_original_actions"):
        M.preflight_original(case.C, case.m, case.component, "web")


def test_original_preflight_success_keeps_same_result_contract(monkeypatch):
    case = identity_case(monkeypatch)
    expected = M.original_identity_expected(case.component, "web", case.unit)
    result = M.preflight_original(case.C, case.m, case.component, "web")
    assert result == {"original_files_sha256": M.sha(M.canonical({case.unit: expected["original_files_sha256"]})),
                      "permitted_oneshot_services": [case.unit]}
    assert case.show_calls == [True, False]


def test_projection_deadline_refuses_before_file_or_manager_access(monkeypatch):
    case = identity_case(monkeypatch)
    with pytest.raises(M.Refusal, match="natural_job_drain_unconfirmed"):
        M.original_identity_projection(case.C, case.m, case.component, "web", case.unit, deadline=0)
    assert case.show_calls == []


def test_existing_verifier_reproduces_current_after_retained_check_and_forwards_deadline(monkeypatch):
    calls = []
    monkeypatch.setattr(M.socket, "gethostname", lambda: M.HOSTS["web"])
    monkeypatch.setattr(M, "verify_retained", lambda *_args: calls.append("retained") or {"status": "fenced"})
    monkeypatch.setattr(M, "validate_component", lambda *_args: {"synthetic": True})

    def current(*_args, deadline=None):
        calls.append(("current", deadline))
        return {"synthetic_current": True}

    monkeypatch.setattr(M, "current", current)
    deadline = M.time.monotonic() + 10
    result = M.verify_observation(None, {}, object(), {}, "web", "fenced", deadline=deadline)
    assert calls == ["retained", ("current", deadline)]
    assert result["host_local_current_state_proven"] is True and result["current"] == {"synthetic_current": True}


def test_pending_cancellation_refuses_read_command_before_spawn(monkeypatch):
    calls = []
    monkeypatch.setattr(M, "PENDING", True)
    monkeypatch.setattr(M, "run", lambda *_args, **_kwargs: calls.append(True))
    with pytest.raises(M.Refusal, match="interrupted"):
        M.read_command(["/usr/bin/systemctl", "--version"])
    assert calls == []

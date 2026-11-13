"""Hosted-only legacy ownership qualification using synthetic unit and proc data."""

import hashlib
import importlib.util
import unittest
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "synthetic_legacy_unit_owner", Path(__file__).parents[1] / "candidate_execute.py"
)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class SyntheticProcPath:
    """A lexical path with a fake proc-owner boundary; no filesystem methods."""

    def __init__(self, value, owner_stat):
        self.value = PurePosixPath(value)
        self.owner_stat = owner_stat

    def __truediv__(self, part):
        return SyntheticProcPath(self.value / part, self.owner_stat)

    def __str__(self):
        return str(self.value)

    def stat(self):
        return self.owner_stat(str(self))


class LegacyOwner(unittest.TestCase):
    def setUp(self):
        self.runtime = {"source": "/synthetic/legacy-source", "venv": "/synthetic/legacy-venv"}
        self.state = {"MainPID": "4242", "ActiveState": "active", "SubState": "running"}
        self.uid = 1001
        self.ticks = ["12345", "12345"]
        self.argv = self.runtime["venv"].encode() + b"/bin/python\0-m\0synthetic_app\0"
        self.links = {
            "/proc/4242/exe": "/synthetic/interpreter",
            "/proc/4242/cwd": self.runtime["source"],
        }
        self.realpaths = {
            self.runtime["venv"] + "/bin/python": "/synthetic/interpreter",
            "/bin/sh": "/synthetic/shell",
        }
        self.owner_stat = Mock(side_effect=self.stat_owner)
        self.proc_bytes = Mock(side_effect=self.read_proc)
        self.properties = Mock(side_effect=lambda *_: dict(self.state))
        self.baseline = Mock(return_value={
            "units": {unit: dict(self.runtime) for role in ("web", "lab") for unit in P.services(role)}
        })
        self.readlink = Mock(side_effect=lambda path: self.links[str(path)])
        self.realpath = Mock(side_effect=lambda path: self.realpaths[str(path)])
        self.read_command = Mock(side_effect=AssertionError("unexpected command read"))
        self.m = {"roles": {role: {"uid": 1001, "baseline": {"units": {}}} for role in ("web", "lab")}}
        self.configured_start = Mock(wraps=P.configured_start)
        self.render_override = Mock(wraps=P.render_override)
        for name, value in (
            ("Path", lambda *parts: SyntheticProcPath(PurePosixPath(*parts), self.owner_stat)),
            ("os", SimpleNamespace(readlink=self.readlink, path=SimpleNamespace(realpath=self.realpath))),
            ("properties", self.properties), ("proc_bytes", self.proc_bytes),
            ("baseline_runtime", self.baseline), ("read_command", self.read_command),
            ("configured_start", self.configured_start), ("render_override", self.render_override),
            ("SOURCE", "/synthetic/candidate-source"), ("VENV", "/synthetic/candidate-venv"),
        ):
            patcher = patch.object(P, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def stat_owner(self, path):
        self.assertEqual(path, "/proc/4242")
        return SimpleNamespace(st_uid=self.uid)

    def read_proc(self, path, limit=1_000_000):
        if str(path) == "/proc/4242/cmdline":
            self.assertEqual(limit, 1_000_000)
            return self.argv
        self.assertEqual(str(path), "/proc/4242/stat")
        self.assertEqual(limit, 65536)
        # Linux stat fields after comm: state is index0, starttime is index19.
        fields = ["S", *(["0"] * 18), self.ticks.pop(0)]
        return b"4242 (synthetic worker) " + " ".join(fields).encode()

    def observe(self, unit="academy-v2-web", role="web"):
        return P.old_unit_inventory(unit, self.m, role)

    def hr_wrapper(self):
        unit = "academy-v2-hr-report"
        inner = (
            self.runtime["venv"] + "/bin/python -m app.cli hr-report --to "
            "${ACADEMY_HR_RECIPIENTS:-hr@dotmac.ng}"
        )
        command = "/bin/sh -c '" + inner + "'"
        expected_hash = hashlib.sha256(command.encode()).hexdigest()
        self.m["roles"]["web"]["baseline"]["units"][unit] = {"command_sha256": expected_hash}
        self.read_command.side_effect = None
        self.read_command.return_value = "[Service]\nExecStart=" + command + "\n"
        self.argv = b"\0".join(arg.encode() for arg in ("/bin/sh", "-c", inner)) + b"\0"
        self.links["/proc/4242/exe"] = "/synthetic/shell"
        patcher = patch.object(P, "HR_HASHES", {self.runtime["venv"]: expected_hash})
        patcher.start()
        self.addCleanup(patcher.stop)
        return unit, command

    def test_primary_identity_uses_baseline_uid_source_and_interpreter(self):
        result = self.observe()
        self.assertEqual(result["start_ticks"], "12345")
        self.assertEqual(result["argv_sha256"], hashlib.sha256(self.argv).hexdigest())
        self.assertEqual(result["unit_state"], self.state)
        self.assertEqual(result["planned_action"], "stop_primary")
        self.assertEqual(result["gate_awareness"], "legacy_gate_unaware")
        self.baseline.assert_called_once_with(self.m, "web")
        self.realpath.assert_called_once_with(self.runtime["venv"] + "/bin/python")
        self.owner_stat.assert_called_once_with("/proc/4242")
        self.assertEqual(self.properties.call_count, 2)
        self.assertEqual(self.ticks, [])
        self.read_command.assert_not_called()

    def test_lab_primary_is_checked_against_its_own_baseline(self):
        result = self.observe("academy-v2-lab-worker", "lab")
        self.assertEqual(result["planned_action"], "stop_primary")
        self.baseline.assert_called_once_with(self.m, "lab")

    def test_sender_has_drain_plan_and_each_supported_argv0_is_baseline_bound(self):
        for name in ("python", "python3", "uvicorn", "gunicorn"):
            with self.subTest(name=name):
                self.ticks = ["12345", "12345"]
                self.argv = (self.runtime["venv"] + "/bin/" + name).encode() + b"\0synthetic-arg\0"
                result = self.observe("academy-v2-email-digest")
                self.assertEqual(result["planned_action"], "drain_only")
                self.assertEqual(result["argv_sha256"], hashlib.sha256(self.argv).hexdigest())

    def test_pid_zero_returns_unset_process_evidence_without_reading_proc_or_baseline(self):
        self.state.update(MainPID="0", ActiveState="inactive", SubState="dead")
        result = self.observe()
        self.assertIsNone(result["start_ticks"])
        self.assertIsNone(result["argv_sha256"])
        self.assertEqual(result["planned_action"], "stop_primary")
        self.baseline.assert_not_called()
        self.proc_bytes.assert_not_called()
        self.readlink.assert_not_called()
        self.owner_stat.assert_not_called()

    def test_timer_zero_has_timer_plan_and_does_not_infer_sender_ownership(self):
        self.state["MainPID"] = "0"
        result = self.observe("academy-v2-email-digest.timer")
        self.assertEqual(result["planned_action"], "stop_timer")
        self.assertEqual(result["gate_awareness"], "timer_only")
        self.assertIsNone(result["start_ticks"])
        self.assertIsNone(result["argv_sha256"])
        self.baseline.assert_not_called()
        self.proc_bytes.assert_not_called()

    def test_timer_with_sender_pid_refuses_before_any_process_read(self):
        with self.assertRaisesRegex(ValueError, "timer_cannot_own_sender_pid"):
            self.observe("academy-v2-email-digest.timer")
        self.proc_bytes.assert_not_called()
        self.baseline.assert_not_called()

    def test_invalid_pid_text_and_reserved_pid_refuse_before_proc_read(self):
        for pid, reason in (("-1", "preinventory_mainpid"), ("", "preinventory_mainpid"),
                            ("42x", "preinventory_mainpid"), (" 4242", "preinventory_mainpid"),
                            ("1", "preinventory_sender_pid")):
            with self.subTest(pid=pid):
                self.state["MainPID"] = pid
                with self.assertRaisesRegex(ValueError, reason):
                    self.observe()
        self.proc_bytes.assert_not_called()
        self.readlink.assert_not_called()

    def test_argv0_outside_baseline_interpreters_refuses(self):
        for argv in (b"/synthetic/candidate-venv/bin/python\0", b"python\0", b"/bin/sh\0",
                     self.runtime["venv"].encode() + b"/bin/python-unapproved\0", b"", b"\0"):
            with self.subTest(argv=argv):
                self.ticks = ["12345", "12345"]
                self.argv = argv
                with self.assertRaisesRegex(ValueError, "preinventory_actual_interpreter"):
                    self.observe()
        self.owner_stat.assert_not_called()

    def test_actual_executable_cannot_substitute_for_matching_argv0(self):
        self.links["/proc/4242/exe"] = "/synthetic/candidate-interpreter"
        with self.assertRaisesRegex(ValueError, "preinventory_actual_interpreter"):
            self.observe()
        self.owner_stat.assert_not_called()

    def test_owner_mismatch_refuses_even_with_valid_command_and_executable(self):
        self.uid = 0
        with self.assertRaisesRegex(ValueError, "preinventory_actual_legacy_process_identity"):
            self.observe()
        self.assertEqual(self.properties.call_count, 1)

    def test_cwd_must_be_the_baseline_source_not_candidate_or_other_source(self):
        for cwd in ("/synthetic/candidate-source", "/synthetic/other-source"):
            with self.subTest(cwd=cwd):
                self.ticks = ["12345", "12345"]
                self.links["/proc/4242/cwd"] = cwd
                with self.assertRaisesRegex(ValueError, "preinventory_actual_legacy_process_identity"):
                    self.observe()

    def test_pid_reuse_between_snapshots_refuses(self):
        self.ticks = ["12345", "12346"]
        with self.assertRaisesRegex(ValueError, "preinventory_pid_ticks_stable"):
            self.observe()
        self.assertEqual(self.properties.call_count, 1)

    def test_unit_pid_active_or_substate_change_between_snapshots_refuses(self):
        for changed in ({"MainPID": "4243"}, {"ActiveState": "deactivating"}, {"SubState": "stop-sigterm"}):
            with self.subTest(changed=changed):
                self.ticks = ["12345", "12345"]
                self.properties.side_effect = [dict(self.state), dict(self.state, **changed)]
                with self.assertRaisesRegex(ValueError, "preinventory_pid_ticks_stable"):
                    self.observe()

    def test_process_disappearance_during_owner_check_propagates(self):
        self.owner_stat.side_effect = ProcessLookupError("synthetic process disappeared")
        with self.assertRaisesRegex(ProcessLookupError, "disappeared"):
            self.observe()
        self.assertEqual(self.properties.call_count, 1)

    def test_hr_exact_wrapper_uses_configured_start_renderer_and_real_shell_target(self):
        unit, command = self.hr_wrapper()
        result = self.observe(unit)
        self.assertEqual(result["planned_action"], "drain_only")
        self.assertEqual(result["argv_sha256"], hashlib.sha256(self.argv).hexdigest())
        self.read_command.assert_called_once_with(["/usr/bin/systemctl", "cat", unit])
        self.configured_start.assert_called_once_with(self.read_command.return_value)
        self.render_override.assert_called_once_with(
            unit, command, hashlib.sha256(command.encode()).hexdigest(), self.runtime
        )
        self.realpath.assert_called_once_with("/bin/sh")

    def test_hr_actual_wrapper_arguments_must_exactly_match_configured_command(self):
        unit, _ = self.hr_wrapper()
        self.argv = b"/bin/sh\0-c\0synthetic-unapproved-command\0"
        with self.assertRaisesRegex(ValueError, "preinventory_actual_hr_wrapper"):
            self.observe(unit)
        self.render_override.assert_called_once()
        self.owner_stat.assert_not_called()

    def test_hr_matching_argv_still_requires_the_real_shell_executable(self):
        unit, _ = self.hr_wrapper()
        self.links["/proc/4242/exe"] = "/synthetic/other-shell"
        with self.assertRaisesRegex(ValueError, "preinventory_actual_hr_wrapper"):
            self.observe(unit)

    def test_hr_configured_command_drift_is_rejected_by_actual_renderer(self):
        unit, _ = self.hr_wrapper()
        self.m["roles"]["web"]["baseline"]["units"][unit]["command_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "configured_command_drift"):
            self.observe(unit)
        self.render_override.assert_called_once()
        self.readlink.assert_not_called()

    def test_hr_duplicate_execstart_is_rejected_by_actual_configured_start_parser(self):
        unit, command = self.hr_wrapper()
        self.read_command.return_value += "ExecStart=" + command + "\n"
        with self.assertRaisesRegex(ValueError, "single_effective_execstart_required"):
            self.observe(unit)
        self.render_override.assert_not_called()

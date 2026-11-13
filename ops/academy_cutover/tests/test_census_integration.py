"""Hosted-only synthetic integration; no hosts, credentials or runtime inputs."""

import copy
import hashlib
import importlib.util
import io
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "synthetic_census_integration", Path(__file__).parents[1] / "candidate_external_census.py"
)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
HASH = "a" * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields), "closed_fields")


class Integration(unittest.TestCase):
    def setUp(self):
        self.files = {}
        self.C = SimpleNamespace(
            require=require, exact=exact, canonical=canonical, decode=json.loads,
            digest=lambda raw: hashlib.sha256(raw).hexdigest(),
            hexvalue=lambda value: require(type(value) is str and len(value) == 64, "hash"),
            read_bytes=Mock(side_effect=lambda path, **kw: self.files[str(path)]),
            approval=Mock(), stamp=Mock(), gate_ready=Mock(return_value={"hold_id": HASH}),
        )
        self.m = {
            "candidate": "b" * 40, "tree": "c" * 40,
            "helpers": {"external_census": HASH, "census_transport": HASH},
            "roles": {r: {"hostname": "synthetic-" + r} for r in ("web", "lab")},
            "census_transport": {r: {"path": "/synthetic/" + r, "sha256": HASH} for r in ("web", "lab")},
        }
        self.approval = {
            "attempt": "synthetic", "approval_record_path": "/synthetic/human", "approval_record_sha256": HASH,
            "approved_unix": 1, "expires_unix": 300,
        }
        self.active = {
            "kind": "execution", "phase": "quiesce", "manifest": self.store("manifest", self.m),
            "approval": self.store("approval", self.approval),
        }
        self.E = SimpleNamespace(
            a=self.approval, m=self.m, manifest_hash=self.active["manifest"]["sha256"],
            approval_hash=self.active["approval"]["sha256"], active_authority=self.active,
            used={}, sha256=HASH,
            phase=Mock(return_value={"observations": {"stop_completed_unix": 90, "gate": {"hold_id": HASH}}}),
        )
        self.T = SimpleNamespace(
            archived_source_ref=Mock(), request_current=Mock(return_value={"request": {"binding": {"nonce": "test"}}}),
            verify_current=Mock(), observe_local_leaf=Mock(return_value={"synthetic": True}), _request=Mock(),
        )
        for target, value in (("load_scope", ({}, HASH)), ("_authority", self.approval), ("_transport", self.T)):
            patcher = patch.object(P, target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for target, value in (("gethostname", "synthetic-lab"),):
            patcher = patch.object(P.socket, target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(P.os, "geteuid", return_value=0)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(P.time, "time", return_value=200)
        patcher.start()
        self.addCleanup(patcher.stop)

    def store(self, name, value):
        path = "/synthetic/" + name
        raw = canonical(value)
        self.files[path] = raw
        return {"path": path, "sha256": hashlib.sha256(raw).hexdigest()}

    def packet(self, name="gate-web"):
        role = name.rsplit("-", 1)[1]
        if name == "gate-web":
            facts = dict.fromkeys(("hold_id", "owner_record_sha256", "gate_approval_sha256", "state_sha256"), HASH)
            facts.update(supervisor_pid=10, supervisor_start_ticks="20", lock_inode=[1, 2], lock_kernel_row="synthetic")
        else:
            facts = {
                "units": [], "application_pids": [], "preserved": [], "quiesce_receipt_sha256": HASH,
                "stop_completed_unix": 90, "gate_epoch": HASH,
            }
            self.E.used["quiesce-" + role] = {"sha256": HASH}
        source = {
            "schema": "AcademyLocalCensusSource.v1", "adapter": name.split("-")[0],
            "candidate": self.m["candidate"], "tree": self.m["tree"], "attempt": "synthetic", "role": role,
            "hostname": "synthetic-" + role, "producer_sha256": HASH,
            "observed_unix_started": 100, "observed_unix_finished": 101, "facts": facts,
        }
        mirror = self.store("mirror/raw-" + name + ".json", source)
        original = {"path": "/synthetic/peer/raw-" + name + ".json", "sha256": mirror["sha256"]}
        self.files[original["path"]] = self.files[mirror["path"]]
        receipt = {
            "schema": "AcademyRootGateObservation.v1" if name == "gate-web" else "AcademyRootStoppedObservation.v1",
            "candidate": self.m["candidate"], "tree": self.m["tree"], "attempt": "synthetic",
            "hostname": "synthetic-" + role,
        }
        if name == "gate-web":
            receipt.update(observed_unix_started=100, **facts)
        else:
            receipt.update(observed_unix=100, **{k: facts[k] for k in (
                "units", "application_pids", "preserved", "quiesce_receipt_sha256"
            )}, process_census_sha256=self.C.digest(canonical(facts)))
        bundle = {
            "schema": "AcademyCensusSourceBundle.v1", "receipt_name": name, "receipt_sha256": HASH,
            **{k: source[k] for k in (
                "candidate", "tree", "attempt", "role", "hostname", "producer_sha256",
                "observed_unix_started", "observed_unix_finished"
            )},
            "execution_manifest_sha256": self.E.manifest_hash, "execution_approval_sha256": self.E.approval_hash,
            "authority_scope_sha256": HASH, "active_authority": self.active, "gate_epoch": HASH,
            "sources": {"local_observation": original},
        }
        self.E._get_raw = Mock(return_value=bundle)
        self.E.used[name] = {"observed_unix": 100}
        self.E.used["sources-" + name] = {"observed_unix": 101}
        self.T.archived_source_ref.return_value = mirror
        self.T.verify_current.return_value = facts if name == "gate-web" else {
            k: facts[k] for k in ("units", "application_pids", "preserved")
        }
        return bundle, source, receipt

    def verify(self, name, receipt, fresh=True):
        return P.verify_receipt_sources(self.C, self.m, self.E, name, receipt, HASH, fresh)

    def test_peer_gate_reconstructs_original_receipt(self):
        bundle, _, receipt = self.packet()
        with patch.object(P, "_gate", side_effect=AssertionError("remote physical observer")):
            self.assertEqual(self.verify("gate-web", receipt), bundle)
        self.T.request_current.assert_called_once()
        self.T.verify_current.assert_called_once()
        self.assertEqual(self.T.request_current.call_args.args[5], bundle["sources"]["local_observation"])
        self.assertEqual(self.T.request_current.call_args.kwargs["output"], Path("/synthetic/mirror"))

    def test_peer_stopped_joins_original_stop_and_actual_gate_role(self):
        P.socket.gethostname.return_value = "synthetic-web"
        _, _, receipt = self.packet("stopped-lab")
        with patch.object(P, "_stopped", side_effect=AssertionError("recursive peer stop")):
            self.verify("stopped-lab", receipt)
        self.E.phase.assert_called_once_with("quiesce-lab", "lab", "quiesce", fresh=False)
        self.C.gate_ready.assert_called_once_with(self.E, self.m, self.E.a, "web")

    def test_peer_stop_epoch_or_original_join_refuses_before_rpc(self):
        for field in ("gate_epoch", "stop_completed_unix", "quiesce_receipt_sha256"):
            with self.subTest(field=field):
                P.socket.gethostname.return_value = "synthetic-web"
                _, source, receipt = self.packet("stopped-lab")
                source["facts"][field] = 91 if field == "stop_completed_unix" else "d" * 64
                mirror = self.store("mirror/raw-stopped-lab.json", source)
                self.T.archived_source_ref.return_value = mirror
                with self.assertRaises(ValueError):
                    self.verify("stopped-lab", receipt)
                self.T.request_current.assert_not_called()

    def test_wrong_host_future_stale_and_fake_json_refuse(self):
        bundle, source, receipt = self.packet()
        P.socket.gethostname.return_value = "workstation"
        with self.assertRaisesRegex(ValueError, "actual_verifier_host"):
            self.verify("gate-web", receipt)
        P.socket.gethostname.return_value = "synthetic-lab"
        bundle["observed_unix_finished"] = 201
        with self.assertRaisesRegex(ValueError, "source_interval"):
            self.verify("gate-web", receipt)
        bundle["observed_unix_finished"] = 101
        self.C.stamp.side_effect = ValueError("stale")
        with self.assertRaisesRegex(ValueError, "stale"):
            self.verify("gate-web", receipt)
        self.C.stamp.side_effect = None
        source["hostname"] = "copied-fake"
        self.T.archived_source_ref.return_value = self.store("mirror/raw-gate-web.json", source)
        with self.assertRaisesRegex(ValueError, "underlying_source_identity"):
            self.verify("gate-web", receipt)
        self.T.request_current.assert_not_called()

    def test_remote_uncertainty_propagates_once(self):
        _, _, receipt = self.packet()
        self.T.request_current.side_effect = TimeoutError("remote cleanup uncertain")
        with self.assertRaisesRegex(TimeoutError, "cleanup uncertain"):
            self.verify("gate-web", receipt)
        self.T.request_current.assert_called_once()
        self.T.verify_current.assert_not_called()
        self.C.gate_ready.assert_not_called()

    def test_live_or_receipt_drift_refuses(self):
        _, _, receipt = self.packet()
        self.T.verify_current.return_value = {"authored": True}
        with self.assertRaisesRegex(ValueError, "peer_live_source_drift"):
            self.verify("gate-web", receipt)
        self.packet()
        receipt["hostname"] = "fake"
        with self.assertRaisesRegex(ValueError, "exact_receipt_source_semantics"):
            self.verify("gate-web", receipt)

    def test_local_path_unchanged(self):
        P.socket.gethostname.return_value = "synthetic-web"
        _, source, receipt = self.packet()
        with patch.object(P, "_gate", return_value=source["facts"]) as physical:
            self.verify("gate-web", receipt)
        physical.assert_called_once_with(self.C, self.m, self.E, "web")
        self.T.request_current.assert_not_called()
        self.T.archived_source_ref.assert_not_called()

    def test_full_domain_peer_refuses(self):
        bundle, _, receipt = self.packet()
        name = "pre-quiescence-web"
        bundle["receipt_name"] = name
        self.E.used[name] = self.E.used["gate-web"]
        self.E.used["sources-" + name] = self.E.used["sources-gate-web"]
        with self.assertRaisesRegex(ValueError, "coverage_gap_unimplemented"):
            self.verify(name, receipt)
        self.T.request_current.assert_not_called()

    def test_cli_actual_inputs_index_and_authority_guard(self):
        inputs = {
            "role": "web", "observation": "gate", "evidence_index": "/synthetic/index", **self.active,
        }
        binding = {
            "peer_inputs": {"path": "/synthetic/inputs", "sha256": self.C.digest(b"actual")},
            "peer_evidence_index": {"path": "/synthetic/index", "sha256": HASH},
            "role": "web", "operation": "gate-web", "active_authority": self.active,
        }
        self.T._request.return_value = binding
        ctx = {"synthetic": True}
        with patch.object(P, "_context", return_value=(self.C, self.m, self.E, "web", {}, HASH)):
            self.assertEqual(P._current_request(ctx, inputs, "/synthetic/inputs", b"actual", io.BytesIO(b"{}")),
                             {"synthetic": True})
            for field in ("peer_inputs", "peer_evidence_index", "active_authority"):
                changed = copy.deepcopy(binding)
                changed[field] = dict(changed[field])
                changed[field]["sha256" if field != "active_authority" else "phase"] = "wrong"
                self.T._request.return_value = changed
                self.T.observe_local_leaf.reset_mock()
                with self.assertRaises(ValueError):
                    P._current_request(ctx, inputs, "/synthetic/inputs", b"actual", io.BytesIO(b"{}"))
                self.T.observe_local_leaf.assert_not_called()
            with self.assertRaisesRegex(ValueError, "request_bound"):
                P._current_request(ctx, inputs, "/synthetic/inputs", b"actual", io.BytesIO(b"x" * 16_385))

    def test_peer_stopped_web_uses_actual_lab_gate_dag(self):
        _, _, receipt = self.packet("stopped-web")
        self.verify("stopped-web", receipt)
        self.C.gate_ready.assert_called_once_with(self.E, self.m, self.E.a, "lab")

    def test_current_gate_change_refuses_before_stopped_rpc(self):
        _, _, receipt = self.packet("stopped-web")
        self.C.gate_ready.return_value = {"hold_id": "e" * 64}
        with self.assertRaisesRegex(ValueError, "current_gate_epoch"):
            self.verify("stopped-web", receipt)
        self.T.request_current.assert_not_called()

    def test_source_raw_hash_mismatch_refuses_before_rpc(self):
        _, _, receipt = self.packet()
        self.files["/synthetic/mirror/raw-gate-web.json"] += b" "
        with self.assertRaisesRegex(ValueError, "protected_source_hash"):
            self.verify("gate-web", receipt)
        self.T.request_current.assert_not_called()

    def test_both_consumers_call_shared_verifier_and_cli_returns_before_dispatch(self):
        root = Path(__file__).parents[1]
        for name in ("candidate_execute.py", "candidate_promote.py"):
            source = (root / name).read_text()
            self.assertIn("census_module(self.m).verify_receipt_sources(", source)
        source = (root / "candidate_external_census.py").read_text()
        branch = source[source.index("    if args.current_request_stdin:"):]
        self.assertLess(branch.index("        return"), branch.index('    if inputs["observation"] == "exclusion":'))


class TransportLoader(unittest.TestCase):
    def test_pinned_instance_cached_and_changed_pin_reloads(self):
        raw = b"_ISSUED = {}\n"
        C = SimpleNamespace(
            exact=exact, require=require, hexvalue=lambda value: None,
            digest=lambda value: hashlib.sha256(value).hexdigest(), read_bytes=Mock(return_value=raw),
        )
        m = {"helpers": {"census_transport": C.digest(raw)}}
        with patch.dict(P._TRANSPORT_CACHE, {}, clear=True):
            first = P._transport(C, m)
            first._ISSUED["synthetic"] = HASH
            self.assertIs(P._transport(C, m), first)
            self.assertEqual(P._transport(C, m)._ISSUED["synthetic"], HASH)
            raw = b"_ISSUED = {}\n# successor\n"
            C.read_bytes.return_value = raw
            m["helpers"]["census_transport"] = C.digest(raw)
            self.assertIsNot(P._transport(C, m), first)
            C.read_bytes.return_value = b"changed without pin"
            with self.assertRaisesRegex(ValueError, "protected_source_hash"):
                P._transport(C, m)


if __name__ == "__main__":
    unittest.main()

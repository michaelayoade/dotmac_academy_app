"""Synthetic-only protocol and lifecycle checks; never contact a host or read keys."""

import copy
import hashlib
import importlib.util
import json
import signal
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "synthetic_transport", Path(__file__).parents[1] / "candidate_census_transport.py"
)
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)
HASH = "a" * 64


def reference(name="input"):
    return {"path": "/root/synthetic/" + name, "sha256": HASH}


def profile():
    return {
        "schema": "AcademyCensusTransportProfile.v2",
        "caller_hostname": "synthetic-lab",
        "role": "web",
        "hostname": "synthetic-web",
        "endpoint": "peer.invalid",
        "port": 22,
        "user": "root",
        **{name: reference(name) for name in ("identity", "known_hosts")},
        "peer_producer": reference("candidate_external_census.py"),
        "peer_packet_root": "/root/peer-packet",
        "local_packet_root": "/root/local-packet",
    }


def request(operation="gate-web"):
    binding = dict.fromkeys(T.BINDING_FIELDS, HASH)
    binding.update(
        {
            "candidate": "b" * 40,
            "tree": "c" * 40,
            "attempt": "synthetic-attempt",
            "role": T.OPERATIONS[operation],
            "hostname": "synthetic-" + T.OPERATIONS[operation],
            "operation": operation,
            "original_source": reference("source"),
            "peer_inputs": reference(),
            "peer_evidence_index": reference("seed-index"),
            "gate_epoch": HASH,
            "original_stop_ref": None if operation == "gate-web" else reference("stop"),
            "active_authority": {
                "kind": "execution",
                "phase": "quiesce",
                "manifest": reference(),
                "approval": reference(),
            },
        }
    )
    return {
        "schema": "AcademyCensusCurrentRequest.v1",
        "nonce": "d" * 64,
        "issued_unix": 100,
        "expires_unix": 130,
        "binding": binding,
    }


def response(req):
    return {
        "schema": "AcademyCensusCurrentLeaf.v1",
        "request": copy.deepcopy(req),
        "observed_unix_started": 101,
        "observed_unix_finished": 102,
        "facts": {},
    }


class Protocol(unittest.TestCase):
    def tearDown(self):
        T._ISSUED.clear()
        T._UNCERTAIN_CHILDREN.clear()

    def test_challenge_echo_and_deadline(self):
        req = request()
        self.assertEqual(T._response(req, response(req), 105), {})
        for mutate in (
            lambda r: r["request"].update(nonce="e" * 64),
            lambda r: r.update(observed_unix_finished=131),
            lambda r: r.update(observed_unix_started=True),
        ):
            value = response(req)
            mutate(value)
            with self.assertRaises(ValueError):
                T._response(req, value, 105)
        for now in (130, 131):
            with self.assertRaises(ValueError):
                T._request(req, now)

    def test_closed_DAG_and_original_source(self):
        for operation, role in T.OPERATIONS.items():
            self.assertEqual(T._request(request(operation), 105)["role"], role)
        req = request()
        req["binding"]["operation"] = "exclusion-web"
        with self.assertRaises(ValueError):
            T._request(req, 105)
        req = request()
        req["binding"]["role"] = "lab"
        with self.assertRaises(ValueError):
            T._request(req, 105)
        req = request()
        req["binding"]["original_source"]["sha256"] = "forged"
        with self.assertRaises(ValueError):
            T._request(req, 105)

    def test_paths_and_endpoint_injection(self):
        for path in ("/root/x/../y", "/root/x;id", "/root/x y", "/outside/x", "/root/$(id)"):
            with self.assertRaises(ValueError):
                T._path(path)
        for endpoint in ("-oProxyCommand=id", "host;id", "a b", "$(id)"):
            value = profile()
            value["endpoint"] = endpoint
            with self.assertRaises(ValueError):
                T._argv(value, "/root/peer-packet/current-gate-web-inputs.json")
        args = T._argv(profile(), "/root/peer-packet/current-gate-web-inputs.json")
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("ForwardAgent=no", args)
        self.assertIn("ProxyCommand=none", args)
        self.assertIn("-B -I -S", args[-1])

    def test_missing_or_wrong_profile_does_not_read_credentials(self):
        common = Mock()
        with self.assertRaises(ValueError):
            T._profile(common, {}, "web", reference("profile"))
        common.read_bytes.assert_not_called()
        value = profile()
        value["caller_hostname"] = "other-caller"
        common.decode.return_value = value
        m = {
            "census_transport": {"web": reference("profile")},
            "roles": {"web": {"hostname": "synthetic-web"}, "lab": {"hostname": "synthetic-lab"}},
        }
        with (
            patch.object(T, "_pin", return_value=b"{}") as pin,
            patch.object(T.socket, "gethostname", return_value="synthetic-caller"),
        ):
            with self.assertRaises(ValueError):
                T._profile(common, m, "web", reference("profile"))
            self.assertEqual(pin.call_count, 1)  # only profile, no key/trust reads

    def test_v2_profile_has_no_future_artifact_hashes_and_static_validation_reads_no_keys(self):
        value = profile()
        m = {
            "census_transport": {"web": reference("profile")},
            "roles": {"web": {"hostname": "synthetic-web"}, "lab": {"hostname": "synthetic-lab"}},
            "helpers": {"external_census": HASH},
        }
        common = Mock()
        common.decode.return_value = value
        with patch.object(T, "_pin", return_value=b"{}") as pin:
            self.assertEqual(T.validate_profile(common, m, "web", reference("profile")), value)
            self.assertEqual(pin.call_count, 1)
        self.assertNotIn("peer_inputs", value)
        self.assertNotIn("peer_source", value)
        for old in (dict(value, schema="AcademyCensusTransportProfile.v1"), dict(value, peer_inputs=reference())):
            common.decode.return_value = old
            with patch.object(T, "_pin", return_value=b"{}"), self.assertRaises(ValueError):
                T.validate_profile(common, m, "web", reference("profile"))

    def test_dynamic_bootstrap_binds_actual_index_bytes_without_frozen_future_hash(self):
        req = request()
        req["binding"]["original_source"]["path"] = "/root/peer-packet/raw-gate-web.json"
        value = {
            "schema": "AcademyCensusInputs.v1",
            "kind": "execution",
            "phase": "quiesce",
            "role": "web",
            "observation": "gate",
            "common": reference("candidate_execute.py"),
            "manifest": req["binding"]["active_authority"]["manifest"],
            "approval": req["binding"]["active_authority"]["approval"],
            "evidence_index": "/root/peer-packet/seed-index.json",
            "output": "/root/peer-packet",
        }
        raw_bootstrap = json.dumps(value).encode()
        old_index = b'{"entries":{},"created_unix":100}'
        new_index = b'{"entries":{},"created_unix":101}'
        common = Mock()
        common.decode.side_effect = json.loads
        common.read_bytes.side_effect = [raw_bootstrap, old_index]
        first = T._dynamic_inputs(common, {"self_sha256": HASH}, profile(), "gate-web", req["binding"])
        common.read_bytes.side_effect = [raw_bootstrap, new_index]
        second = T._dynamic_inputs(common, {"self_sha256": HASH}, profile(), "gate-web", req["binding"])
        self.assertEqual(first[0], second[0])  # unchanged bootstrap
        self.assertNotEqual(first[1], second[1])  # changed index is explicitly bound
        bound = dict(req["binding"], peer_evidence_index=first[1])
        for wrong in (
            dict(value, role="lab"),
            dict(value, phase="promote"),
            dict(value, approval=reference("wrong-approval")),
        ):
            with self.assertRaises(ValueError):
                T._validate_bootstrap(common, {"self_sha256": HASH}, wrong, bound, first[0]["path"])
        common.read_bytes.side_effect = None
        common.read_bytes.return_value = new_index
        with self.assertRaisesRegex(ValueError, "source_hash"):
            T._pin(common, first[3])
        with self.assertRaises(ValueError):
            T._mirror(profile(), "/root/outside/seed-index.json")
        with self.assertRaises(ValueError):
            T._seed_index(common, b'{"entries":{"gate-web":{"path":"/root/peer-packet/raw-gate-web.json"}}}')

    def test_unissued_forged_JSON_and_replay_refuse(self):
        req = request()
        common = Mock()
        common.canonical.side_effect = lambda value: json.dumps(value, sort_keys=True).encode()
        common.decode.side_effect = lambda raw: json.loads(raw)
        source = {"facts": {"hold_id": HASH}}
        source_ref = reference("source")
        raw_source = common.canonical(source)
        source_ref["sha256"] = hashlib.sha256(raw_source).hexdigest()
        req["binding"]["original_source"] = source_ref
        value = {
            "schema": "AcademyCensusTransportEvidence.v1",
            "intent": reference("intent"),
            "request": req,
            "response": response(req),
            "cleanup_confirmed": True,
        }
        raw_request = common.canonical(req)
        with (
            patch.object(T, "_trusted", return_value=Mock()),
            patch.object(
                T, "_pin", side_effect=lambda _c, ref, *_: raw_request if ref["path"].endswith("intent") else raw_source
            ),
            patch.object(T, "_authority", return_value=Mock()),
            patch.object(T, "_response", return_value={}),
            patch.object(T, "_leaf_facts", return_value={}),
            patch.object(T, "archived_source_ref", return_value=source_ref),
        ):
            with self.assertRaisesRegex(ValueError, "not_issued_or_replayed"):
                T.verify_current(
                    common,
                    {"census_transport": {"web": reference("profile")}},
                    Mock(),
                    req["binding"],
                    source_ref,
                    value,
                )
            T._ISSUED[req["nonce"]] = hashlib.sha256(common.canonical(value)).hexdigest()
            self.assertEqual(
                T.verify_current(
                    common,
                    {"census_transport": {"web": reference("profile")}},
                    Mock(),
                    req["binding"],
                    source_ref,
                    value,
                ),
                {},
            )
            with self.assertRaisesRegex(ValueError, "not_issued_or_replayed"):
                T.verify_current(
                    common,
                    {"census_transport": {"web": reference("profile")}},
                    Mock(),
                    req["binding"],
                    source_ref,
                    value,
                )

    def test_nonce_is_locally_minted_and_intent_is_durable_before_SSH(self):
        common = Mock()
        common.canonical.side_effect = lambda value: json.dumps(value, sort_keys=True).encode()
        common.decode.side_effect = json.loads
        req = request()
        approved_profile = profile()
        evidence = Mock()

        def remote(_argv, payload, expires):
            self.assertEqual(expires, 125)
            minted = json.loads(payload)
            self.assertEqual(minted["nonce"], "07" * 32)
            self.assertEqual(common.write_new.call_count, 1)
            self.assertEqual(common.write_new.call_args.args[1], minted)
            return common.canonical(
                {
                    "schema": "AcademyCensusCurrentLeaf.v1",
                    "request": minted,
                    "observed_unix_started": 100,
                    "observed_unix_finished": 100,
                    "facts": {},
                }
            )

        with (
            patch.object(T, "_trusted", return_value=Mock()),
            patch.object(T, "_authority", return_value=evidence),
            patch.object(T, "_profile", return_value=approved_profile),
            patch.object(T, "_binding", return_value=req["binding"]),
            patch.object(T, "_leaf_facts", return_value={}),
            patch.object(T, "_pin", return_value=b'{"expires_unix":125}'),
            patch.object(T, "archived_source_ref", return_value=reference("source")),
            patch.object(
                T,
                "_dynamic_inputs",
                return_value=(
                    req["binding"]["peer_inputs"],
                    req["binding"]["peer_evidence_index"],
                    reference("local-inputs"),
                    reference("local-index"),
                ),
            ),
            patch.object(T.time, "time", return_value=100),
            patch.object(T.os, "urandom", return_value=bytes([7]) * 32) as entropy,
            patch.object(T._Child, "run", side_effect=remote),
        ):
            result = T.request_current(
                common,
                {"census_transport": {"web": reference("profile")}},
                evidence,
                "web",
                "gate-web",
                reference("source"),
                {"approval": reference("approval")},
                reference("profile"),
                "/root/synthetic/output",
            )
        entropy.assert_called_once_with(32)
        self.assertEqual(common.write_new.call_count, 2)
        self.assertIn(result["request"]["nonce"], T._ISSUED)

    def test_source_hash_mismatch_and_cleanup_forgery_refuse(self):
        common = Mock()
        common.read_bytes.return_value = b"forged-json"
        with self.assertRaisesRegex(ValueError, "source_hash"):
            T._pin(common, reference())
        with patch.object(T, "_trusted", return_value=Mock()):
            value = {
                "schema": "AcademyCensusTransportEvidence.v1",
                "intent": reference(),
                "request": request(),
                "response": response(request()),
                "cleanup_confirmed": False,
            }
            with self.assertRaisesRegex(ValueError, "transport_evidence"):
                T.verify_current(common, {}, Mock(), {}, reference(), value)

    def test_stopped_peer_does_not_call_gate_or_receipt_lookup(self):
        req = request("stopped-lab")
        b = req["binding"]
        source = {name: b[name] for name in ("candidate", "tree", "attempt", "role", "hostname", "producer_sha256")}
        source.update(schema="AcademyLocalCensusSource.v1", adapter="stopped")
        source["facts"] = {
            "quiesce_receipt_sha256": HASH,
            "gate_epoch": HASH,
            "units": {"x": "inactive"},
            "application_pids": [],
            "preserved": {"route": HASH},
        }
        m = {
            "candidate": b["candidate"],
            "tree": b["tree"],
            "roles": {"lab": {"hostname": b["hostname"]}},
            "helpers": {"external_census": HASH, "census_transport": HASH},
            "self_sha256": HASH,
        }
        evidence = Mock(a={"attempt": b["attempt"]}, manifest_hash=HASH, approval_hash=HASH, sha256=HASH)
        common = Mock()
        common.decode.side_effect = [
            source,
            {"common": {"path": str(Path(T.__file__).absolute().with_name("candidate_execute.py")), "sha256": HASH}},
        ]
        common.stopped.return_value = {"units": {"x": "inactive"}, "matching_application_pids": []}
        common.preserved.return_value = {"route": HASH}
        producer = Mock()
        producer.load_scope.return_value = ({}, HASH)
        with (
            patch.object(T, "_trusted", return_value=producer),
            patch.object(T, "_authority"),
            patch.object(T, "_validate_bootstrap"),
            patch.object(T, "_seed_index"),
            patch.object(T, "_pin", return_value=b"{}"),
            patch.object(T.socket, "gethostname", return_value=b["hostname"]),
            patch.object(T.time, "time", return_value=105),
        ):
            result = T.observe_local_leaf(common, m, evidence, req)
            evidence.sha256 = "f" * 64
            common.decode.side_effect = [
                source,
                {
                    "common": {
                        "path": str(Path(T.__file__).absolute().with_name("candidate_execute.py")),
                        "sha256": HASH,
                    }
                },
            ]
            with self.assertRaisesRegex(ValueError, "actual_peer_E_index_hash"):
                T.observe_local_leaf(common, m, evidence, req)
        self.assertEqual(result["facts"]["application_pids"], [])
        producer._gate.assert_not_called()
        evidence.phase.assert_not_called()
        evidence.get.assert_not_called()
        common.stopped.assert_called_once_with("lab", m)


class Lifecycle(unittest.TestCase):
    def test_timeout_during_spawn_defers_signal_and_kills_before_reap(self):
        child = Mock(pid=123456)
        child.stdin = Mock()
        child.stdout = Mock()
        child.stdin.fileno.return_value = 11
        child.stdout.fileno.return_value = 12
        events = []
        run = T._Child()

        def spawn(*_args, **_kwargs):
            self.assertEqual(run.phase, "spawning")
            run.interrupt(signal.SIGTERM, None)
            return child

        def waitid(*_args):
            events.append("reserve")
            return None

        def killpg(_pid, number):
            events.append("kill" if number else "probe")
            if number == 0:
                raise ProcessLookupError

        child.wait.side_effect = lambda **_: events.append("reap")
        with (
            patch.object(T.subprocess, "Popen", side_effect=spawn),
            patch.object(T.signal, "getsignal", return_value=signal.SIG_DFL),
            patch.object(T.signal, "signal", return_value=signal.SIG_DFL),
            patch.object(T.os, "set_blocking"),
            patch.object(T.os, "waitid", side_effect=waitid),
            patch.object(T.os, "killpg", side_effect=killpg),
            patch.object(T.selectors, "DefaultSelector") as selector,
        ):
            selector.return_value.__enter__.return_value.get_map.return_value = {1: True}
            with self.assertRaisesRegex(ValueError, "cleanup_unconfirmed"):
                run.run(["synthetic-never-executed"], b"{}", 10**12)
        self.assertEqual(events, ["reserve", "kill", "reap", "probe"])
        self.assertTrue(run.cleanup_confirmed)
        child.stdin.close.assert_called_once()
        child.stdout.close.assert_called_once()

    def test_timeout_is_bounded_and_still_cleans_owned_group(self):
        child = Mock(pid=123456)
        run = T._Child()
        with (
            patch.object(T.subprocess, "Popen", return_value=child),
            patch.object(T.signal, "getsignal", return_value=signal.SIG_DFL),
            patch.object(T.signal, "signal", return_value=signal.SIG_DFL),
            patch.object(T.os, "set_blocking"),
            patch.object(T.os, "waitid", return_value=None),
            patch.object(T.os, "killpg", side_effect=[None, ProcessLookupError]),
            patch.object(T.time, "monotonic", side_effect=[0, 0, 100]),
            patch.object(T.selectors, "DefaultSelector") as selector,
        ):
            selector.return_value.__enter__.return_value.get_map.return_value = {1: True}
            with self.assertRaises(ValueError):
                run.run(["synthetic-never-executed"], b"{}", 10**12)
        child.wait.assert_called_once_with(timeout=1)
        self.assertTrue(run.cleanup_confirmed)

    def test_uncertain_cleanup_never_reaps_or_retries_after_lost_reservation(self):
        child = Mock(pid=123456)
        run = T._Child()
        with (
            patch.object(T.subprocess, "Popen", return_value=child),
            patch.object(T.signal, "getsignal", return_value=signal.SIG_DFL),
            patch.object(T.signal, "signal", return_value=signal.SIG_DFL),
            patch.object(T.os, "set_blocking", side_effect=OSError),
            patch.object(T.os, "waitid", side_effect=ChildProcessError),
            patch.object(T.os, "killpg") as kill,
        ):
            with self.assertRaises(ValueError):
                run.run(["synthetic-never-executed"], b"{}", 10**12)
        self.assertFalse(run.cleanup_confirmed)
        child.wait.assert_not_called()
        kill.assert_not_called()
        self.assertIn(child, T._UNCERTAIN_CHILDREN)


if __name__ == "__main__":
    unittest.main()

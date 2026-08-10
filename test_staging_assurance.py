import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from staging_assurance import evaluate_live_gates, load_assurance_policy, run_offline_assurance


ROOT = Path(__file__).resolve().parent
POLICY = ROOT / "config" / "staging-assurance.example.json"
ALERTS = [
    {
        "schema_version": "security_alert.v1",
        "source": "logwatcher",
        "source_event_id": "LW-BRUTE-001",
        "observed_at": "2026-07-03T02:14:25Z",
        "asset_id": "WIN-DC01",
        "kind": "brute_force",
        "severity": "high",
        "title": "Five failed logons from one source within five minutes",
        "risk_owner": "security-ops",
        "event_code": 4625,
        "source_ip": "203.0.113.45",
        "target_user": "administrator",
        "evidence_refs": ["sample://logwatcher/alerts/brute-force-001"],
    },
    {
        "schema_version": "security_alert.v1",
        "source": "logwatcher",
        "source_event_id": "LW-LOCKOUT-001",
        "observed_at": "2026-07-03T08:03:02Z",
        "asset_id": "WIN-DC01",
        "kind": "account_lockout",
        "severity": "medium",
        "title": "Account jsmith was locked out",
        "risk_owner": "security-ops",
        "event_code": 4740,
        "source_ip": None,
        "target_user": "jsmith",
        "evidence_refs": ["sample://logwatcher/alerts/lockout-001"],
    },
    {
        "schema_version": "security_alert.v1",
        "source": "logwatcher",
        "source_event_id": "LW-PRIV-001",
        "observed_at": "2026-07-03T11:47:22Z",
        "asset_id": "WIN-FILE02",
        "kind": "privilege_escalation",
        "severity": "critical",
        "title": "Unexpected elevated-privilege logon by guest",
        "risk_owner": "security-ops",
        "event_code": 4672,
        "source_ip": None,
        "target_user": "guest",
        "evidence_refs": ["sample://logwatcher/alerts/privilege-001"],
    },
]


class StagingAssuranceTests(unittest.TestCase):
    def test_offline_package_proves_contract_replay_lifecycle_and_outbox(self):
        with tempfile.TemporaryDirectory() as temp:
            alerts = Path(temp) / "alerts.jsonl"
            alerts.write_text(
                "\n".join(json.dumps(item, sort_keys=True) for item in ALERTS) + "\n",
                encoding="utf-8",
            )
            report = run_offline_assurance(str(POLICY), str(alerts))
        self.assertEqual(report["mode"], "offline_no_azure")
        self.assertFalse(report["azure_mutation_performed"])
        self.assertEqual(report["alert_count"], 3)
        self.assertEqual(report["offline_decision"], "READY_FOR_MANUAL_AZURE_STAGING")
        self.assertTrue(all(report["offline_gates"].values()))
        self.assertEqual(report["live_validation"]["decision"], "NO_GO")
        self.assertEqual(report["production_decision"], "NO_GO")

    def test_offline_assurance_uses_one_explicit_runtime_root(self):
        with tempfile.TemporaryDirectory() as temp:
            alerts = Path(temp) / "alerts.jsonl"
            alerts.write_text(
                "\n".join(json.dumps(item, sort_keys=True) for item in ALERTS) + "\n",
                encoding="utf-8",
            )
            with mock.patch(
                "scripts.staging_logwatcher.os.path.commonpath",
                side_effect=AssertionError("runtime root inference must not run"),
            ):
                report = run_offline_assurance(str(POLICY), str(alerts))
        self.assertEqual(report["offline_decision"], "READY_FOR_MANUAL_AZURE_STAGING")

    def test_policy_rejects_secret_fields_and_unsafe_thresholds(self):
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        cases = []
        secret = json.loads(json.dumps(policy))
        secret["thresholds"]["client_secret"] = "must-not-be-here"
        cases.append(secret)
        unsafe = json.loads(json.dumps(policy))
        unsafe["thresholds"]["outbox_worker_max_age_seconds"] = 0
        cases.append(unsafe)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.json"
            for payload in cases:
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.subTest(payload=payload), self.assertRaises(ValueError):
                    load_assurance_policy(str(path))

    def test_live_gate_is_exact_fail_closed_and_does_not_claim_production(self):
        policy = load_assurance_policy(str(POLICY))
        evidence = {name: True for name in policy["required_live_gates"]}
        self.assertEqual(
            evaluate_live_gates(policy, evidence)["decision"],
            "GO_LIMITED_STAGING_PILOT",
        )
        evidence[policy["required_live_gates"][0]] = False
        self.assertEqual(evaluate_live_gates(policy, evidence)["decision"], "NO_GO")
        evidence["unexpected"] = True
        with self.assertRaises(ValueError):
            evaluate_live_gates(policy, evidence)


if __name__ == "__main__":
    unittest.main()

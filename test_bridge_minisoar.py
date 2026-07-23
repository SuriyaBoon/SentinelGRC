import json
import tempfile
import unittest
from pathlib import Path

from scripts.bridge_minisoar import run_minisoar_bridge
from state_store import SQLiteStateStore


def write_bundle(root: Path, *, status="closed", passed=True, kind="brute_force", environment="synthetic-lab"):
    (root / "finding.json").write_text(json.dumps({
        "finding_id": "FND-TESTBUNDLE01",
        "title": "Five failed logons within five minutes",
        "risk_owner": "asset-owner-01",
        "severity": "high",
        "status": status,
        "playbook_id": "PB-BF-001",
        "playbook_version": 1,
    }), encoding="utf-8")
    (root / "alert.json").write_text(json.dumps({
        "alert_id": "ALT-TESTBUNDLE01",
        "asset_id": "WIN-DC01",
        "kind": kind,
        "severity": "high",
        "risk_owner": "asset-owner-01",
        "environment": environment,
    }), encoding="utf-8")
    (root / "verification.json").write_text(json.dumps({
        "finding_id": "FND-TESTBUNDLE01",
        "passed": passed,
        "notes": "simulated post-conditions",
    }), encoding="utf-8")


class MiniSoarBridgeTests(unittest.TestCase):
    def test_closed_and_verified_incident_creates_governance_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root)
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))
            self.assertTrue(result["bundle_read"])
            self.assertTrue(result["finding_created"])
            self.assertEqual(result["errors"], 0)
            self.assertTrue(result["sentinel_finding_id"].startswith("SEC-IR-"))

    def test_replaying_bundle_reassesses_existing_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root)
            db = str(root / "governance.db")
            first = run_minisoar_bridge(str(root), db)
            replay = run_minisoar_bridge(str(root), db)
            self.assertTrue(first["finding_created"])
            self.assertTrue(replay["finding_reassessed"])
            self.assertEqual(first["sentinel_finding_id"], replay["sentinel_finding_id"])
            stored = SQLiteStateStore(db).get_external_finding(first["sentinel_finding_id"])
            self.assertEqual(stored["reassessment_count"], 1)

    def test_unverified_incident_is_skipped_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, passed=False)
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))
            self.assertTrue(result["bundle_read"])
            self.assertFalse(result["finding_created"])
            self.assertIn("verified", result["skipped_reason"])

    def test_unverified_incident_can_be_explicitly_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, passed=False)
            result = run_minisoar_bridge(
                str(root), str(root / "governance.db"), require_verification_pass=False,
            )
            self.assertTrue(result["finding_created"])

    def test_open_incident_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, status="pending_verification")
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))
            self.assertFalse(result["finding_created"])
            self.assertEqual(result["errors"], 0)

    def test_non_synthetic_incident_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, environment="production")
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))
            self.assertFalse(result["finding_created"])
            self.assertEqual(result["errors"], 0)

    def test_missing_bundle_is_reported_without_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_minisoar_bridge(str(root / "missing"), str(root / "governance.db"))
            self.assertFalse(result["bundle_read"])
            self.assertEqual(result["errors"], 1)


if __name__ == "__main__":
    unittest.main()

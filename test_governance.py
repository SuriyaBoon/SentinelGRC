import json
import unittest
from datetime import date, timedelta
from pathlib import Path

from scripts import governance


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
        self.posture = json.loads(Path("sample_posture.json").read_text(encoding="utf-8"))
        self.assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))

    def test_queue_uses_registered_asset_metadata(self):
        queue = governance.build_remediation_queue(
            self.controls, self.posture, self.assets
        )
        self.assertEqual(queue["asset_id"], "WS-001")
        self.assertGreater(queue["risk_score"], 0)
        self.assertEqual(
            queue["findings"][0]["asset"]["business_service"],
            "Financial reporting",
        )

    def test_unknown_asset_is_rejected(self):
        with self.assertRaises(ValueError):
            governance.build_remediation_queue(
                self.controls, {**self.posture, "asset_id": "UNKNOWN"}, self.assets
            )

    def test_exception_requires_approval_and_future_expiry(self):
        queue = governance.build_remediation_queue(
            self.controls, self.posture, self.assets
        )
        finding_id = queue["findings"][0]["finding_id"]
        expiry = (date.today() + timedelta(days=30)).isoformat()
        updated = governance.approve_exception(
            queue,
            finding_id,
            "security-manager",
            "Compensating control deployed",
            expiry,
        )
        self.assertEqual(updated["findings"][0]["status"], "accepted-risk")
        self.assertEqual(
            updated["findings"][0]["exception"]["approver"], "security-manager"
        )

    def test_expired_exception_is_rejected(self):
        queue = governance.build_remediation_queue(
            self.controls, self.posture, self.assets
        )
        with self.assertRaises(ValueError):
            governance.approve_exception(
                queue,
                queue["findings"][0]["finding_id"],
                "manager",
                "reason",
                date.today().isoformat(),
            )

    def test_expired_exception_reopens_finding(self):
        queue = governance.build_remediation_queue(self.controls, self.posture, self.assets)
        finding_id = queue["findings"][0]["finding_id"]
        governance.approve_exception(queue, finding_id, "manager", "temporary control", (date.today() + timedelta(days=1)).isoformat())
        queue["findings"][0]["exception"]["expires_on"] = date.today().isoformat()
        governance.expire_exceptions(queue)
        self.assertEqual(queue["findings"][0]["status"], "open")
        self.assertEqual(queue["findings"][0]["exception_status"], "expired")

if __name__ == "__main__":
    unittest.main()

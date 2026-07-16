import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

import workflow


class WorkflowTests(unittest.TestCase):
    def test_generates_control_and_stale_privileged_tickets(self):
        remediation = {
            "findings": [
                {
                    "finding_id": "WS-001:END-001",
                    "status": "open",
                    "asset": {
                        "asset_id": "WS-001",
                        "hostname": "finance-laptop-01",
                        "business_service": "Financial reporting",
                        "criticality": "high",
                    },
                    "control": {
                        "control_name": "System volume encryption",
                        "severity": "high",
                        "owner": "Endpoint Security",
                    },
                }
            ]
        }
        access_review = {
            "reviewed_at": "2026-07-16T12:00:00Z",
            "users": [
                {
                    "sam_account_name": "legacy-admin",
                    "stale": True,
                    "enabled": True,
                    "privileged": True,
                }
            ],
        }
        result = workflow.generate_tickets(
            remediation,
            access_review,
            datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(len(result["tickets"]), 2)
        self.assertEqual(result["tickets"][0]["response_due_at"], "2026-07-16T12:30:00Z")
        self.assertEqual(result["tickets"][1]["priority"], "critical")
        self.assertFalse(result["auto_remediation"])
        self.assertTrue(all(ticket["auto_remediation"] is False for ticket in result["tickets"]))

    def test_closed_or_accepted_findings_do_not_create_tickets(self):
        result = workflow.generate_tickets(
            {"findings": [{"finding_id": "x", "status": "accepted-risk"}]},
            {"users": [{"sam_account_name": "u", "stale": False}]},
        )
        self.assertEqual(result["tickets"], [])


if __name__ == "__main__":
    unittest.main()

import json
import unittest
from pathlib import Path

from portfolio_contracts import (
    ASSET_ALLOWED,
    ASSET_REQUIRED,
    TICKET_ALLOWED,
    TICKET_REQUIRED,
    normalize_asset_context_v1,
    normalize_remediation_ticket_v1,
)
from scripts.ingestion_api import validate_posture


ROOT = Path(__file__).parent


class PortfolioContractTests(unittest.TestCase):
    def asset(self):
        return {"schema_version": "asset_context.v1", "source": "home-lab-v5", "source_asset_id": "INV-1", "observed_at": "2026-08-19T00:00:00Z", "asset_id": "WIN-01", "hostname": "win-01", "owner": "owner-01", "criticality": "high", "status": "active", "evidence_refs": ["sample://inventory/INV-1"]}

    def ticket(self):
        return {"schema_version": "remediation_ticket.v1", "source": "helpdesk", "source_ticket_id": "HD-1", "finding_id": "F-1", "asset_id": "WIN-01", "owner": "analyst-01", "status": "assigned", "priority": "P2", "created_at": "2026-08-19T00:00:00Z", "updated_at": "2026-08-19T00:01:00Z", "due_at": "2026-08-19T08:00:00Z", "evidence_refs": ["https://helpdesk.invalid/tickets/HD-1"]}

    def test_schema_and_runtime_fields_match(self):
        asset_schema = json.loads((ROOT / "schemas/asset-context.v1.schema.json").read_text())
        ticket_schema = json.loads((ROOT / "schemas/remediation-ticket.v1.schema.json").read_text())
        self.assertEqual(set(asset_schema["properties"]), ASSET_ALLOWED)
        self.assertEqual(set(asset_schema["required"]), ASSET_REQUIRED)
        self.assertEqual(set(ticket_schema["properties"]), TICKET_ALLOWED)
        self.assertEqual(set(ticket_schema["required"]), TICKET_REQUIRED)

    def test_asset_context_is_stable_and_strict(self):
        first = normalize_asset_context_v1(self.asset())
        changed = self.asset(); changed["criticality"] = "critical"
        second = normalize_asset_context_v1(changed)
        self.assertEqual(first["context_id"], second["context_id"])
        invalid = self.asset(); invalid["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            normalize_asset_context_v1(invalid)

    def test_asset_context_rejects_bad_business_context_and_evidence(self):
        for field, value in (("owner", "bad owner"), ("criticality", "urgent"), ("observed_at", "2026-08-19"), ("evidence_refs", ["file:///secret"])):
            with self.subTest(field=field):
                invalid = self.asset(); invalid[field] = value
                with self.assertRaises(ValueError):
                    normalize_asset_context_v1(invalid)

    def test_ticket_is_stable_and_strict(self):
        first = normalize_remediation_ticket_v1(self.ticket())
        changed = self.ticket(); changed["status"] = "in_progress"
        second = normalize_remediation_ticket_v1(changed)
        self.assertEqual(first["ticket_context_id"], second["ticket_context_id"])
        invalid = self.ticket(); invalid["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            normalize_remediation_ticket_v1(invalid)

    def test_ticket_rejects_invalid_sla_context(self):
        cases = (("priority", "P0"), ("status", "deleted"), ("updated_at", "2026-08-18T00:00:00Z"), ("due_at", "naive"))
        for field, value in cases:
            with self.subTest(field=field):
                invalid = self.ticket(); invalid[field] = value
                with self.assertRaises(ValueError):
                    normalize_remediation_ticket_v1(invalid)

    def test_posture_optional_fields_follow_schema(self):
        payload = {"schema_version": "1.0", "collected_at": "2026-08-19T00:00:00Z", "asset_id": "WIN-01", "hostname": "win-01", "bitlocker_system_drive": True, "firewall_all_profiles_enabled": True, "defender_realtime_enabled": True, "days_since_last_update": 1, "os": "Windows", "os_version": "11", "domain": True, "owner": "owner-01", "criticality": "high", "checks": [{"name": "firewall", "passed": True, "value": "enabled", "error": None}]}
        validate_posture(payload)
        for field, value in (("domain", "yes"), ("owner", ""), ("criticality", "urgent"), ("checks", [{"name": "x", "passed": "yes", "value": None, "error": None}])):
            with self.subTest(field=field):
                invalid = dict(payload); invalid[field] = value
                with self.assertRaises(ValueError):
                    validate_posture(invalid)


if __name__ == "__main__":
    unittest.main()

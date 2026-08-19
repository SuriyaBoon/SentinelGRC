import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None
    FormatChecker = None

from portfolio_contracts import (
    ASSET_ALLOWED,
    ASSET_REQUIRED,
    EVIDENCE_REFERENCE_PATTERN,
    TICKET_ALLOWED,
    TICKET_REQUIRED,
    normalize_asset_context_v1,
    normalize_remediation_ticket_v1,
)
from scripts.ingestion_api import validate_posture


ROOT = Path(__file__).parent


class PortfolioContractTests(unittest.TestCase):
    @staticmethod
    def asset():
        return {
            "schema_version": "asset_context.v1",
            "source": "home-lab-v5",
            "source_asset_id": "INV-1",
            "observed_at": "2026-08-19T00:00:00Z",
            "asset_id": "WIN-01",
            "hostname": "win-01",
            "owner": "owner-01",
            "criticality": "high",
            "status": "active",
            "evidence_refs": ["sample://inventory/INV-1"],
        }

    @staticmethod
    def ticket():
        return {
            "schema_version": "remediation_ticket.v1",
            "source": "helpdesk",
            "source_ticket_id": "HD-1",
            "finding_id": "F-1",
            "asset_id": "WIN-01",
            "owner": "analyst-01",
            "status": "assigned",
            "priority": "P2",
            "created_at": "2026-08-19T00:00:00Z",
            "updated_at": "2026-08-19T00:01:00Z",
            "due_at": "2026-08-19T08:00:00Z",
            "evidence_refs": ["https://helpdesk.invalid/tickets/HD-1"],
        }

    @staticmethod
    def posture():
        return {
            "schema_version": "1.0",
            "collected_at": "2026-08-19T00:00:00Z",
            "asset_id": "WIN-01",
            "hostname": "win-01",
            "bitlocker_system_drive": True,
            "firewall_all_profiles_enabled": True,
            "defender_realtime_enabled": True,
            "days_since_last_update": 1,
            "os": "Windows",
            "os_version": "11",
            "domain": True,
            "owner": "owner-01",
            "criticality": "high",
            "checks": [
                {
                    "name": "firewall",
                    "passed": True,
                    "value": "enabled",
                    "error": None,
                }
            ],
        }

    @staticmethod
    def load_schema(name):
        return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))

    def test_schema_and_runtime_fields_match(self):
        asset_schema = self.load_schema("asset-context.v1.schema.json")
        ticket_schema = self.load_schema("remediation-ticket.v1.schema.json")
        self.assertEqual(set(asset_schema["properties"]), ASSET_ALLOWED)
        self.assertEqual(set(asset_schema["required"]), ASSET_REQUIRED)
        self.assertEqual(set(ticket_schema["properties"]), TICKET_ALLOWED)
        self.assertEqual(set(ticket_schema["required"]), TICKET_REQUIRED)

    def test_schema_and_runtime_share_evidence_reference_pattern(self):
        asset_schema = self.load_schema("asset-context.v1.schema.json")
        ticket_schema = self.load_schema("remediation-ticket.v1.schema.json")
        asset_pattern = asset_schema["properties"]["evidence_refs"]["items"]["pattern"]
        ticket_pattern = ticket_schema["properties"]["evidence_refs"]["items"]["pattern"]
        self.assertEqual(asset_pattern, EVIDENCE_REFERENCE_PATTERN)
        self.assertEqual(ticket_pattern, EVIDENCE_REFERENCE_PATTERN)

    def test_asset_context_is_stable_and_strict(self):
        first = normalize_asset_context_v1(self.asset())
        changed = self.asset()
        changed["criticality"] = "critical"
        second = normalize_asset_context_v1(changed)
        self.assertEqual(first["context_id"], second["context_id"])
        invalid = self.asset()
        invalid["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            normalize_asset_context_v1(invalid)

    def test_asset_context_rejects_bad_business_context_and_evidence(self):
        cases = (
            ("owner", "bad owner"),
            ("criticality", "urgent"),
            ("criticality", "HIGH"),
            ("status", "Active"),
            ("observed_at", "2026-08-19"),
            ("evidence_refs", ["file:///secret"]),
            ("evidence_refs", ["https:///missing-authority"]),
            ("evidence_refs", ["https://user:secret@example.invalid/evidence"]),
            ("evidence_refs", [" sample://inventory/INV-1"]),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                invalid = self.asset()
                invalid[field] = value
                with self.assertRaises(ValueError):
                    normalize_asset_context_v1(invalid)

    def test_ticket_is_stable_and_strict(self):
        first = normalize_remediation_ticket_v1(self.ticket())
        changed = self.ticket()
        changed["status"] = "in_progress"
        second = normalize_remediation_ticket_v1(changed)
        self.assertEqual(first["ticket_context_id"], second["ticket_context_id"])
        invalid = self.ticket()
        invalid["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            normalize_remediation_ticket_v1(invalid)

    def test_ticket_rejects_invalid_sla_context(self):
        cases = (
            ("priority", "P0"),
            ("priority", "p2"),
            ("status", "Assigned"),
            ("status", "deleted"),
            ("updated_at", "2026-08-18T00:00:00Z"),
            ("due_at", "naive"),
            ("evidence_refs", ["file:///ticket"]),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                invalid = self.ticket()
                invalid[field] = value
                with self.assertRaises(ValueError):
                    normalize_remediation_ticket_v1(invalid)

    def test_posture_optional_fields_follow_schema(self):
        payload = self.posture()
        validate_posture(payload)
        for field in ("owner", "checks"):
            missing = dict(payload)
            del missing[field]
            validate_posture(missing)
        for field in ("os", "os_version", "domain", "days_since_last_update"):
            nullable = dict(payload)
            nullable[field] = None
            validate_posture(nullable)
        cases = (
            ("domain", "yes"),
            ("owner", ""),
            ("owner", None),
            ("criticality", "urgent"),
            ("checks", None),
            ("checks", [{"name": "x", "passed": "yes", "value": None, "error": None}]),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                invalid = dict(payload)
                invalid[field] = value
                with self.assertRaises(ValueError):
                    validate_posture(invalid)

    @unittest.skipUnless(
        Draft202012Validator is not None and FormatChecker is not None,
        "requires hash-locked jsonschema qualification dependency",
    )
    def test_schema_date_time_formats_are_executable(self):
        definitions = (
            ("asset-context.v1.schema.json", self.asset, ("observed_at",)),
            (
                "remediation-ticket.v1.schema.json",
                self.ticket,
                ("created_at", "updated_at", "due_at"),
            ),
        )
        for schema_name, fixture, fields in definitions:
            validator = Draft202012Validator(
                self.load_schema(schema_name),
                format_checker=FormatChecker(),
            )
            self.assertEqual(list(validator.iter_errors(fixture())), [])
            for field in fields:
                for invalid_value in ("not-a-timestamp", "2026-08-19T00:00:00"):
                    with self.subTest(schema=schema_name, field=field, value=invalid_value):
                        invalid = fixture()
                        invalid[field] = invalid_value
                        self.assertTrue(list(validator.iter_errors(invalid)))


if __name__ == "__main__":
    unittest.main()

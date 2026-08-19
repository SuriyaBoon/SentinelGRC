import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None
    FormatChecker = None

from contract_validation import CANONICAL_TEXT_PATTERN
from portfolio_contracts import (
    ASSET_ALLOWED,
    ASSET_REQUIRED,
    EVIDENCE_REFERENCE_PATTERN,
    RFC3339_PATTERN,
    SOURCE_IDENTIFIER_PATTERN,
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

    def test_source_identity_is_canonical_and_collision_safe(self):
        for fixture, normalizer in (
            (self.asset, normalize_asset_context_v1),
            (self.ticket, normalize_remediation_ticket_v1),
        ):
            canonical = fixture()
            normalizer(canonical)
            noncanonical = fixture()
            noncanonical["source"] = canonical["source"].upper()
            with self.subTest(schema=canonical["schema_version"]):
                with self.assertRaisesRegex(ValueError, "canonical lowercase"):
                    normalizer(noncanonical)

        for schema_name in (
            "asset-context.v1.schema.json",
            "remediation-ticket.v1.schema.json",
        ):
            schema = self.load_schema(schema_name)
            self.assertEqual(
                schema["properties"]["source"]["pattern"],
                SOURCE_IDENTIFIER_PATTERN,
            )

    def test_runtime_rejects_non_rfc3339_timestamp_forms(self):
        definitions = (
            (self.asset, normalize_asset_context_v1, ("observed_at",)),
            (
                self.ticket,
                normalize_remediation_ticket_v1,
                ("created_at", "updated_at", "due_at"),
            ),
        )
        for fixture, normalizer, fields in definitions:
            for field in fields:
                for invalid_value in (
                    "2026-08-19 00:00:00+00:00",
                    "2026-08-19T00:00:00",
                    "2026-08-19t00:00:00z",
                ):
                    with self.subTest(field=field, value=invalid_value):
                        payload = fixture()
                        payload[field] = invalid_value
                        with self.assertRaises(ValueError):
                            normalizer(payload)

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


    def test_input_and_normalized_schemas_enforce_trust_boundary(self):
        definitions = (
            (
                "asset-context.v1.schema.json",
                "asset-context-normalized.v1.schema.json",
                self.asset,
                normalize_asset_context_v1,
                "context_id",
            ),
            (
                "remediation-ticket.v1.schema.json",
                "remediation-ticket-normalized.v1.schema.json",
                self.ticket,
                normalize_remediation_ticket_v1,
                "ticket_context_id",
            ),
        )
        for source_name, normalized_name, fixture, normalizer, derived in definitions:
            source = self.load_schema(source_name)
            normalized = self.load_schema(normalized_name)
            self.assertNotIn(derived, source["properties"])
            self.assertEqual(
                source["properties"],
                {key: value for key, value in normalized["properties"].items() if key != derived},
            )
            poisoned = fixture()
            poisoned[derived] = "ATTACKER-CONTROLLED"
            with self.assertRaisesRegex(ValueError, "unknown fields"):
                normalizer(poisoned)
            if Draft202012Validator is not None:
                source_validator = Draft202012Validator(source)
                normalized_validator = Draft202012Validator(normalized)
                record = normalizer(fixture())
                self.assertEqual(list(source_validator.iter_errors(fixture())), [])
                self.assertTrue(list(source_validator.iter_errors(record)))
                self.assertEqual(list(normalized_validator.iter_errors(record)), [])

    def test_evidence_authority_is_hostname_only_without_ports(self):
        valid = (
            "https://example.invalid/path",
            "azblob://archive.invalid/container/blob",
            "sample://inventory/INV-1",
            "urn:sentinel:evidence:1",
        )
        invalid = (
            "https://?evidence=1",
            "https://#fragment",
            "azblob://:443/path",
            "https://user@example.invalid/path",
            "https://user:secret@example.invalid/path",
            "https://example.invalid:0/path",
            "https://example.invalid:8443/path",
            "https://example.invalid:65535/path",
            "https://example.invalid:99999/path",
        )
        definitions = (
            (
                "asset-context.v1.schema.json",
                self.asset,
                lambda value: value,
            ),
            (
                "asset-context-normalized.v1.schema.json",
                self.asset,
                normalize_asset_context_v1,
            ),
            (
                "remediation-ticket.v1.schema.json",
                self.ticket,
                lambda value: value,
            ),
            (
                "remediation-ticket-normalized.v1.schema.json",
                self.ticket,
                normalize_remediation_ticket_v1,
            ),
        )
        for reference in valid:
            with self.subTest(reference=reference):
                payload = self.asset()
                payload["evidence_refs"] = [reference]
                normalize_asset_context_v1(payload)
        for reference in invalid:
            with self.subTest(reference=reference):
                payload = self.asset()
                payload["evidence_refs"] = [reference]
                with self.assertRaises(ValueError):
                    normalize_asset_context_v1(payload)
        if Draft202012Validator is not None:
            for schema_name, fixture, transform in definitions:
                schema = self.load_schema(schema_name)
                pattern = schema["properties"]["evidence_refs"]["items"]["pattern"]
                self.assertEqual(pattern, EVIDENCE_REFERENCE_PATTERN)
                validator = Draft202012Validator(schema)
                # Normalize a valid baseline before injecting a schema-only defect.
                valid_record = transform(fixture())
                for reference in valid:
                    payload = dict(valid_record)
                    payload["evidence_refs"] = [reference]
                    self.assertEqual(
                        list(validator.iter_errors(payload)),
                        [],
                        (schema_name, reference),
                    )
                for reference in invalid:
                    payload = dict(valid_record)
                    payload["evidence_refs"] = [reference]
                    self.assertTrue(
                        list(validator.iter_errors(payload)),
                        (schema_name, reference),
                    )

    def test_canonical_text_rejects_controls_and_boundary_whitespace(self):
        invalid = (
            " leading",
            "trailing ",
            "\u00a0leading",
            "trailing\u2003",
            "\u2028leading",
            "trailing\u2029",
            "win\x0001",
            "win\t01",
            "win\n01",
            "win\x7f01",
        )
        for value in invalid:
            with self.subTest(value=repr(value)):
                payload = self.asset()
                payload["hostname"] = value
                with self.assertRaises(ValueError):
                    normalize_asset_context_v1(payload)
                posture = self.posture()
                posture["os"] = value
                with self.assertRaises(ValueError):
                    validate_posture(posture)
        payload = self.asset()
        payload["hostname"] = "Windows workstation"
        self.assertEqual(
            normalize_asset_context_v1(payload)["hostname"],
            "Windows workstation",
        )

    def test_posture_exploit_payload_is_rejected(self):
        payload = self.posture()
        payload["collected_at"] = "2026-08-19 00:00:00+00:00"
        payload["os"] = "Windows\n11"
        payload["checks"][0]["name"] = "fire\nwall"
        with self.assertRaises(ValueError):
            validate_posture(payload)

    def test_posture_schema_and_runtime_share_text_and_timestamp_contracts(self):
        schema = self.load_schema("posture.schema.json")
        self.assertEqual(schema["properties"]["collected_at"]["pattern"], RFC3339_PATTERN)
        for name in ("asset_id", "hostname", "os", "os_version", "owner"):
            self.assertEqual(schema["properties"][name]["pattern"], CANONICAL_TEXT_PATTERN)
        check_properties = schema["properties"]["checks"]["items"]["properties"]
        self.assertEqual(check_properties["name"]["pattern"], CANONICAL_TEXT_PATTERN)
        self.assertEqual(check_properties["error"]["pattern"], CANONICAL_TEXT_PATTERN)
        if Draft202012Validator is not None:
            validator = Draft202012Validator(schema)
            exploit = self.posture()
            exploit["collected_at"] = "2026-08-19 00:00:00+00:00"
            exploit["os"] = "Windows\n11"
            exploit["checks"][0]["name"] = "fire\nwall"
            self.assertTrue(list(validator.iter_errors(exploit)))
        for field, value in (
            ("os", "Windows\n11"),
            ("owner", " owner"),
        ):
            payload = self.posture()
            payload[field] = value
            with self.assertRaises(ValueError):
                validate_posture(payload)
        for field, value in (("name", "fire\nwall"), ("error", "bad\x7ferror")):
            payload = self.posture()
            payload["checks"][0][field] = value
            with self.assertRaises(ValueError):
                validate_posture(payload)

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
            schema = self.load_schema(schema_name)
            validator = Draft202012Validator(
                schema,
                format_checker=FormatChecker(),
            )
            for field in fields:
                self.assertEqual(schema["properties"][field]["pattern"], RFC3339_PATTERN)
            self.assertEqual(list(validator.iter_errors(fixture())), [])
            for field in fields:
                for invalid_value in (
                    "not-a-timestamp",
                    "2026-08-19T00:00:00",
                    "2026-08-19 00:00:00+00:00",
                    "2026-08-19t00:00:00z",
                ):
                    with self.subTest(schema=schema_name, field=field, value=invalid_value):
                        invalid = fixture()
                        invalid[field] = invalid_value
                        self.assertTrue(list(validator.iter_errors(invalid)))


if __name__ == "__main__":
    unittest.main()

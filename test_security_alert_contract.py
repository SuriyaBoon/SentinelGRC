import copy
import json
import unittest
from pathlib import Path

from contract_validation import (
    CANONICAL_TEXT_PATTERN,
    EVIDENCE_REFERENCE_PATTERN,
    RFC3339_PATTERN,
)
from security_alert_contract import ALLOWED_FIELDS, REQUIRED_FIELDS, normalize_security_alert_v1

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:  # pragma: no cover - exercised by minimal runtime installs
    Draft202012Validator = None
    FormatChecker = None


def alert():
    return {
        "schema_version": "security_alert.v1",
        "source": "logwatcher",
        "source_event_id": "LW-4625-001",
        "observed_at": "2026-07-03T02:14:25Z",
        "asset_id": "WIN-DC01",
        "kind": "brute_force",
        "severity": "high",
        "title": "Five failed logons from one source",
        "risk_owner": "security-ops",
        "event_code": 4625,
        "source_ip": "203.0.113.45",
        "target_user": "administrator",
        "evidence_refs": ["sample://logwatcher/alerts/001"],
    }


class SecurityAlertContractTests(unittest.TestCase):
    @staticmethod
    def schema():
        return json.loads(
            (Path(__file__).parent / "schemas" / "security-alert.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )

    def test_json_schema_and_runtime_boundary_have_the_same_fields(self):
        schema = self.schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["properties"]), ALLOWED_FIELDS)
        self.assertEqual(set(schema["required"]), REQUIRED_FIELDS)
        self.assertEqual(
            schema["properties"]["observed_at"]["pattern"], RFC3339_PATTERN
        )
        self.assertEqual(
            schema["properties"]["title"]["pattern"], CANONICAL_TEXT_PATTERN
        )
        self.assertEqual(
            schema["properties"]["target_user"]["pattern"],
            CANONICAL_TEXT_PATTERN,
        )
        self.assertEqual(
            schema["properties"]["evidence_refs"]["items"]["pattern"],
            EVIDENCE_REFERENCE_PATTERN,
        )

    def test_contract_derives_stable_identity_from_immutable_source_fields(self):
        first = normalize_security_alert_v1(alert())
        changed = alert()
        changed["title"] = "Updated analyst description"
        changed["severity"] = "critical"
        second = normalize_security_alert_v1(changed)
        self.assertEqual(first["finding_id"], second["finding_id"])
        self.assertEqual(second["severity"], "critical")
        self.assertEqual(second["details"]["schema_version"], "security_alert.v1")

    def test_contract_rejects_unknown_missing_and_mismatched_fields(self):
        cases = []
        unknown = alert()
        unknown["approved_by"] = "caller-controlled"
        cases.append(unknown)
        missing = alert()
        del missing["asset_id"]
        cases.append(missing)
        mismatched = alert()
        mismatched["event_code"] = 4672
        cases.append(mismatched)
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                normalize_security_alert_v1(payload)

    def test_contract_validation_order_is_stable(self):
        payload = alert()
        payload["approved_by"] = "caller-controlled"
        del payload["asset_id"]
        payload["schema_version"] = "unsupported"
        with self.assertRaisesRegex(
            ValueError,
            "^security alert contains unknown fields: approved_by$",
        ):
            normalize_security_alert_v1(payload)

        del payload["approved_by"]
        with self.assertRaisesRegex(
            ValueError,
            "^security alert missing fields: asset_id$",
        ):
            normalize_security_alert_v1(payload)

        payload = alert()
        payload["source"] = "invalid source"
        payload["kind"] = "unsupported"
        with self.assertRaisesRegex(
            ValueError,
            "^security alert source is invalid$",
        ):
            normalize_security_alert_v1(payload)

    def test_contract_requires_timezone_ip_and_approved_evidence_reference(self):
        for field, value in (
            ("observed_at", "2026-07-03T02:14:25"),
            ("source_ip", "999.1.1.1"),
            ("evidence_refs", ["file:///C:/Users/example/secret.txt"]),
        ):
            payload = copy.deepcopy(alert())
            payload[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                normalize_security_alert_v1(payload)

    def test_contract_rejects_noncanonical_text_timestamp_and_authority(self):
        for field, value in (
            ("title", " padded "),
            ("title", "bad\nvalue"),
            ("target_user", "admin\u200b"),
            ("observed_at", "2026-07-03 02:14:25+00:00"),
            ("observed_at", "2026-07-03T02:14:25.1234567Z"),
            ("source", "LogWatcher"),
            ("evidence_refs", ["https://:443/path"]),
            ("evidence_refs", ["https://example.invalid/a\u00a0b"]),
            ("evidence_refs", ["https://example.invalid/path\ufeff"]),
        ):
            payload = copy.deepcopy(alert())
            payload[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                normalize_security_alert_v1(payload)

    def test_contract_normalizes_valid_offset_timestamp_to_utc(self):
        payload = alert()
        payload["observed_at"] = "2026-07-03T09:14:25+07:00"
        normalized = normalize_security_alert_v1(payload)
        self.assertEqual(
            normalized["details"]["observed_at"], "2026-07-03T02:14:25Z"
        )

    def test_contract_rejects_non_string_field_names_without_sorting(self):
        payload = alert()
        payload[1] = "caller-controlled"
        with self.assertRaisesRegex(
            ValueError, "security alert field names must be strings"
        ):
            normalize_security_alert_v1(payload)

    @unittest.skipUnless(
        Draft202012Validator is not None,
        "jsonschema assessment dependency is required",
    )
    def test_schema_rejects_runtime_exploit_payloads_and_kind_code_mismatch(self):
        validator = Draft202012Validator(
            self.schema(), format_checker=FormatChecker()
        )
        self.assertTrue(validator.is_valid(alert()))
        cases = (
            ("title", "bad\nvalue"),
            ("target_user", "admin\u200b"),
            ("observed_at", "2026-07-03 02:14:25+00:00"),
            ("source", "LogWatcher"),
            ("source_ip", "999.1.1.1"),
            ("evidence_refs", ["https://:443/path"]),
            ("evidence_refs", ["https://example.invalid/a\u00a0b"]),
            ("event_code", 4740),
        )
        for field, value in cases:
            payload = copy.deepcopy(alert())
            payload[field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(validator.is_valid(payload))


if __name__ == "__main__":
    unittest.main()

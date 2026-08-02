import copy
import json
import unittest
from pathlib import Path

from security_alert_contract import ALLOWED_FIELDS, REQUIRED_FIELDS, normalize_security_alert_v1


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
    def test_json_schema_and_runtime_boundary_have_the_same_fields(self):
        schema = json.loads(
            (Path(__file__).parent / "schemas" / "security-alert.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["properties"]), ALLOWED_FIELDS)
        self.assertEqual(set(schema["required"]), REQUIRED_FIELDS)

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


if __name__ == "__main__":
    unittest.main()

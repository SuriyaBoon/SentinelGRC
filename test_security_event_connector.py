import unittest

from security_event_connector import normalize_security_event


class SecurityEventConnectorTests(unittest.TestCase):
    def test_failed_logon_becomes_stable_finding(self):
        event = {
            "event_code": 4625, "event_id": "EVT-1", "asset_id": "DC-01",
            "timestamp": "2026-07-19T12:00:00Z", "account": "admin",
            "source_ip": "10.0.0.5", "privileged": True,
        }
        first = normalize_security_event(event)
        second = normalize_security_event(event)
        self.assertEqual(first["finding_id"], second["finding_id"])
        self.assertEqual(first["severity"], "critical")
        self.assertEqual(first["control_id"], "SEC-AUTH-001")

    def test_irrelevant_or_closed_event_is_ignored(self):
        self.assertIsNone(normalize_security_event({"event_code": 4624}))
        self.assertIsNone(normalize_security_event({
            "event_code": 4625, "status": "closed",
        }))

    def test_malformed_event_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_security_event({"event_code": 4625, "event_id": "EVT-1"})

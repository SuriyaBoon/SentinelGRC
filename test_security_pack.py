import unittest

from security_pack import build_security_findings


class SecurityPackTests(unittest.TestCase):
    def test_normalizes_multiple_sources_to_deduplicable_findings(self):
        posture = {
            "asset_id": "WS-001",
            "owner": "Endpoint Team",
            "criticality": "high",
            "checks": [{"name": "bitlocker", "passed": False, "value": False, "error": None}],
        }
        access = {
            "reviewed_at": "2026-07-19T00:00:00Z",
            "users": [{"sam_account_name": "svc-old", "stale": True, "enabled": True, "privileged": True}],
        }
        result = build_security_findings(
            posture, access,
            [{"id": "V-1", "title": "Critical CVE", "severity": "critical", "cve": "CVE-2026-1"}],
            [{"id": "E-1", "exposed": True, "endpoint": "10.0.0.1", "port": 3389}],
        )
        self.assertEqual(len(result), 4)
        self.assertEqual(len({item["finding_id"] for item in result}), 4)
        self.assertEqual({item["source"] for item in result},
                         {"endpoint_posture", "ad_access_review", "vulnerability_scanner", "network_exposure"})

    def test_ignores_passed_or_closed_observations(self):
        posture = {"asset_id": "WS-001", "checks": [{"name": "firewall", "passed": True}]}
        result = build_security_findings(
            posture,
            vulnerabilities=[{"id": "V-1", "status": "closed"}],
            exposures=[{"id": "E-1", "exposed": False}],
        )
        self.assertEqual(result, [])

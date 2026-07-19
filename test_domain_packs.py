import unittest

from domain_packs import build_domain_findings, normalize_observation


class DomainPackTests(unittest.TestCase):
    def test_all_enterprise_packs_emit_one_shared_contract(self):
        cases = {
            "privacy": "data_owner",
            "bcm": "service_owner",
            "itsm": "service_owner",
            "vendor": "vendor_owner",
            "cloud": "cloud_owner",
            "data": "data_owner",
        }
        for pack, owner_field in cases.items():
            with self.subTest(pack=pack):
                finding = normalize_observation(pack, {
                    "observation_id": "OBS-1",
                    "control_id": "CTRL-1",
                    "asset_id": "ASSET-1",
                    "title": "Control gap",
                    "severity": "high",
                    owner_field: "owner-1",
                    "status": "open",
                })
                self.assertEqual(finding["domain"], pack)
                self.assertEqual(finding["risk_owner"], "owner-1")
                self.assertTrue(finding["finding_id"])

    def test_resolved_observations_are_not_reopened(self):
        self.assertEqual(build_domain_findings("privacy", [{
            "observation_id": "OBS-1", "control_id": "CTRL-1",
            "asset_id": "DATA-1", "title": "Resolved", "severity": "low",
            "data_owner": "owner", "status": "closed",
        }]), [])

    def test_contract_rejects_missing_owner_and_invalid_pack(self):
        with self.assertRaises(ValueError):
            normalize_observation("vendor", {
                "observation_id": "OBS-1", "control_id": "CTRL-1",
                "asset_id": "V-1", "title": "Missing owner", "severity": "high",
            })
        with self.assertRaises(ValueError):
            normalize_observation("unknown", {})

    def test_identical_observations_are_idempotent(self):
        observation = {
            "observation_id": "OBS-1", "control_id": "CTRL-1",
            "asset_id": "CLOUD-1", "title": "Public bucket",
            "severity": "critical", "cloud_owner": "owner",
        }
        first = normalize_observation("cloud", observation)
        second = normalize_observation("cloud", observation)
        self.assertEqual(first["finding_id"], second["finding_id"])

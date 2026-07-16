import json
import tempfile
import unittest
from pathlib import Path

import sentinelgrc


class SentinelGRCTests(unittest.TestCase):
    def setUp(self):
        self.controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
        self.posture = json.loads(Path("sample_posture.json").read_text(encoding="utf-8"))

    def test_failed_control_has_risk_score_scaled_by_asset_criticality(self):
        result = sentinelgrc.evaluate_control(self.controls[0], self.posture)
        self.assertFalse(result["passed"])
        self.assertEqual(result["risk_score"], 18)

    def test_passing_control_has_zero_risk(self):
        result = sentinelgrc.evaluate_control(self.controls[1], self.posture)
        self.assertTrue(result["passed"])
        self.assertEqual(result["risk_score"], 0)

    def test_hash_chained_evidence_detects_tampering(self):
        results = [
            sentinelgrc.evaluate_control(control, self.posture)
            for control in self.controls
        ]
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.jsonl"
            evidence = sentinelgrc.build_evidence(
                self.posture, results, sentinelgrc.GENESIS_HASH
            )
            sentinelgrc.append_evidence(str(ledger), evidence)
            self.assertTrue(sentinelgrc.verify_ledger(str(ledger))[0])
            record = json.loads(ledger.read_text(encoding="utf-8"))
            record["asset"]["hostname"] = "tampered-host"
            ledger.write_text(json.dumps(record) + "\n", encoding="utf-8")
            self.assertFalse(sentinelgrc.verify_ledger(str(ledger))[0])


if __name__ == "__main__":
    unittest.main()

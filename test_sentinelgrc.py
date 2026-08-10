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

    def test_json_input_is_confined_to_runtime_root(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "runtime"
            root.mkdir()
            inside = root / "inside.json"
            outside = base / "outside.json"
            inside.write_text('{"scope":"inside"}', encoding="utf-8")
            outside.write_text('{"scope":"outside"}', encoding="utf-8")

            self.assertEqual(
                sentinelgrc.load_json(inside, runtime_root=root),
                {"scope": "inside"},
            )
            for unsafe in ("../outside.json", outside.resolve()):
                with self.subTest(path=unsafe), self.assertRaisesRegex(
                    ValueError, "must remain under"
                ):
                    sentinelgrc.load_json(unsafe, runtime_root=root)

    def test_json_input_rejects_symlink_escape_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "runtime"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "secret.json").write_text("{}", encoding="utf-8")
            link = root / "escape"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks are unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "must remain under"):
                sentinelgrc.load_json(
                    link / "secret.json", runtime_root=root
                )


if __name__ == "__main__":
    unittest.main()

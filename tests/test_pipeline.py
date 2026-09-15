import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts import pipeline


class PipelineTests(unittest.TestCase):
    def test_pipeline_connects_governance_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = pipeline.run_pipeline(
                json.loads(Path("sample_posture.json").read_text(encoding="utf-8")),
                json.loads(Path("controls.json").read_text(encoding="utf-8")),
                json.loads(Path("assets.json").read_text(encoding="utf-8")),
                str(root / "ledger.jsonl"),
                str(root / "remediation.json"),
                str(root / "tickets.json"),
                str(root / "report.json"),
                str(root / "state.db"),
                json.loads(Path("sample_ad_access_review.json").read_text(encoding="utf-8")),
                datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(result["status"], "accepted")
            self.assertEqual(result["controls_failed"], 2)
            self.assertEqual(result["tickets_created"], 3)
            report = json.loads((root / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["risk_score"], 27)
            self.assertEqual(len((root / "ledger.jsonl").read_text(encoding="utf-8").splitlines()), 1)

            duplicate = pipeline.run_pipeline(
                json.loads(Path("sample_posture.json").read_text(encoding="utf-8")),
                json.loads(Path("controls.json").read_text(encoding="utf-8")),
                json.loads(Path("assets.json").read_text(encoding="utf-8")),
                str(root / "ledger.jsonl"),
                str(root / "remediation.json"),
                str(root / "tickets.json"),
                str(root / "report.json"),
                str(root / "state.db"),
                json.loads(Path("sample_ad_access_review.json").read_text(encoding="utf-8")),
                datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(duplicate["status"], "duplicate")
            self.assertEqual(len((root / "ledger.jsonl").read_text(encoding="utf-8").splitlines()), 1)

    def test_pipeline_can_dual_write_open_findings_to_governance_core(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = pipeline.run_pipeline(
                json.loads(Path("sample_posture.json").read_text(encoding="utf-8")),
                json.loads(Path("controls.json").read_text(encoding="utf-8")),
                json.loads(Path("assets.json").read_text(encoding="utf-8")),
                str(root / "ledger.jsonl"), str(root / "remediation.json"),
                str(root / "tickets.json"), str(root / "report.json"),
                str(root / "state.db"),
                governance_db=str(root / "governance.db"),
            )
            self.assertEqual(result["status"], "accepted")
            import sqlite3
            from contextlib import closing
            with closing(sqlite3.connect(root / "governance.db")) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 2)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM risk_records").fetchone()[0], 0)

    def test_governance_storage_mode_makes_sqlite_the_primary_write_path(self):
        import os
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {
                "SENTINEL_STORAGE": "governance",
                "SENTINEL_GOVERNANCE_DB": str(root / "governance.db"),
            }, clear=False):
                result = pipeline.run_pipeline(
                    json.loads(Path("sample_posture.json").read_text(encoding="utf-8")),
                    json.loads(Path("controls.json").read_text(encoding="utf-8")),
                    json.loads(Path("assets.json").read_text(encoding="utf-8")),
                    str(root / "ledger.jsonl"), str(root / "remediation.json"),
                    str(root / "tickets.json"), str(root / "report.json"),
                    str(root / "state.db"),
                )
            self.assertEqual(result["status"], "accepted")
            self.assertTrue((root / "governance.db").exists())

    def test_unregistered_asset_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                pipeline.run_pipeline(
                    {"asset_id": "UNKNOWN", "hostname": "unknown"},
                    [],
                    [],
                    str(Path(directory) / "ledger.jsonl"),
                    str(Path(directory) / "remediation.json"),
                    str(Path(directory) / "tickets.json"),
                    str(Path(directory) / "report.json"),
                    str(Path(directory) / "state.db"),
                )


if __name__ == "__main__":
    unittest.main()

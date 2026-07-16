import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

import pipeline
from ingestion_api import validate_posture
from state_store import SQLiteStateStore


class EnterpriseSafetyTests(unittest.TestCase):
    def test_pipeline_claim_is_single_winner(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStateStore(str(Path(directory) / "state.db"))
            results = []
            barrier = threading.Barrier(2)
            def claim():
                barrier.wait()
                results.append(store.claim_pipeline_run("same-input"))
            threads = [threading.Thread(target=claim) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sorted(results), [False, True])

    def test_stale_pipeline_run_can_be_reclaimed(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStateStore(str(Path(directory) / "state.db"))
            self.assertTrue(store.claim_pipeline_run("stale", now=1000, lease_seconds=10))
            self.assertFalse(store.claim_pipeline_run("stale", now=1005, lease_seconds=10))
            self.assertTrue(store.claim_pipeline_run("stale", now=1011, lease_seconds=10))
    def test_failed_output_recovers_without_duplicate_ledger_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            posture = json.loads(Path("sample_posture.json").read_text(encoding="utf-8"))
            controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
            assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))
            bad_report = root / "report-dir"
            bad_report.mkdir()
            with self.assertRaises(OSError):
                pipeline.run_pipeline(posture, controls, assets, str(root / "ledger.jsonl"), str(root / "remediation.json"), str(root / "tickets.json"), str(bad_report), str(root / "state.db"))
            result = pipeline.run_pipeline(posture, controls, assets, str(root / "ledger.jsonl"), str(root / "remediation.json"), str(root / "tickets.json"), str(root / "report.json"), str(root / "state.db"), created_at=datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc))
            self.assertEqual(result["status"], "accepted")
            self.assertEqual(len((root / "ledger.jsonl").read_text(encoding="utf-8").splitlines()), 1)

    def test_sample_posture_matches_ingestion_contract(self):
        validate_posture(json.loads(Path("sample_posture.json").read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
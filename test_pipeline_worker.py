import json
import tempfile
import unittest
from pathlib import Path

from scripts import pipeline_worker


class PipelineWorkerTests(unittest.TestCase):
    def test_worker_processes_inbox_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            (inbox / "evidence-001.json").write_text(
                Path("sample_posture.json").read_text(encoding="utf-8"), encoding="utf-8"
            )
            controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
            assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))
            review = json.loads(Path("sample_ad_access_review.json").read_text(encoding="utf-8"))
            first = pipeline_worker.process_inbox_once(
                str(inbox), controls, assets, str(root / "ledger.jsonl"),
                str(root / "state.db"), str(root / "remediation"),
                str(root / "tickets"), str(root / "reports"), review
            )
            second = pipeline_worker.process_inbox_once(
                str(inbox), controls, assets, str(root / "ledger.jsonl"),
                str(root / "state.db"), str(root / "remediation"),
                str(root / "tickets"), str(root / "reports"), review
            )
            self.assertEqual(first[0]["status"], "accepted")
            self.assertEqual(second, [])
            self.assertTrue((root / "reports" / "evidence-001.json").exists())
            self.assertEqual(len((root / "ledger.jsonl").read_text(encoding="utf-8").splitlines()), 1)


    def test_worker_runtime_prefixed_default_output_directories_are_allowlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "evidence-inbox"
            inbox.mkdir()
            (inbox / "evidence-defaults.json").write_text(
                Path("sample_posture.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
            assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))
            review = json.loads(
                Path("sample_ad_access_review.json").read_text(encoding="utf-8")
            )

            result = pipeline_worker.process_inbox_once(
                str(inbox),
                controls,
                assets,
                str(root / "evidence-ledger.jsonl"),
                str(root / "sentinelgrc-state.db"),
                "runtime/remediation",
                "runtime/tickets",
                "runtime/reports",
                review,
            )

            self.assertEqual(result[0]["status"], "accepted")
            self.assertTrue(
                (root / "runtime" / "remediation" / "evidence-defaults.json").exists()
            )
            self.assertTrue(
                (root / "runtime" / "tickets" / "evidence-defaults.json").exists()
            )
            self.assertTrue(
                (root / "runtime" / "reports" / "evidence-defaults.json").exists()
            )


if __name__ == "__main__":
    unittest.main()

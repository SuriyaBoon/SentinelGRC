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


    def test_worker_storage_root_is_independent_from_inbox_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "incoming" / "evidence-inbox"
            storage = root / "storage"
            inbox.mkdir(parents=True)
            storage.mkdir()
            (inbox / "evidence-separated.json").write_text(
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
                str(storage / "evidence-ledger.jsonl"),
                str(storage / "sentinelgrc-state.db"),
                "runtime/remediation",
                "runtime/tickets",
                "runtime/reports",
                review,
                audit_path=str(storage / "runtime" / "audit-log.jsonl"),
                runtime_root=storage,
                governance_db=str(storage / "runtime" / "governance.db"),
            )

            self.assertEqual(result[0]["status"], "accepted")
            self.assertTrue(
                (storage / "runtime" / "remediation" / "evidence-separated.json").exists()
            )
            self.assertTrue(
                (storage / "runtime" / "tickets" / "evidence-separated.json").exists()
            )
            self.assertTrue(
                (storage / "runtime" / "reports" / "evidence-separated.json").exists()
            )

    def test_invalid_storage_configuration_fails_before_queue_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "incoming"
            storage = root / "storage"
            outside = root / "outside"
            inbox.mkdir()
            storage.mkdir()
            outside.mkdir()
            controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
            assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))

            with self.assertRaisesRegex(ValueError, "governance database path must remain under"):
                pipeline_worker.process_inbox_once(
                    str(inbox),
                    controls,
                    assets,
                    str(storage / "evidence-ledger.jsonl"),
                    str(storage / "sentinelgrc-state.db"),
                    "runtime/remediation",
                    "runtime/tickets",
                    "runtime/reports",
                    runtime_root=storage,
                    governance_db=str(outside / "governance.db"),
                )

            self.assertFalse((storage / "sentinelgrc-state.db").exists())


if __name__ == "__main__":
    unittest.main()

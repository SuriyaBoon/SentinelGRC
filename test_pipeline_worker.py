import inspect
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from job_queue import SQLiteJobQueue
from scripts import pipeline_worker
class PipelineWorkerTests(unittest.TestCase):
    def test_worker_options_keep_processing_boundary_below_parameter_limit(self):
        parameters = inspect.signature(pipeline_worker.process_inbox_once).parameters
        self.assertLessEqual(len(parameters), 13)
        self.assertIn("options", parameters)
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
                options=pipeline_worker.WorkerRunOptions(
                    audit_path=str(storage / "runtime" / "audit-log.jsonl"),
                    runtime_root=storage,
                    governance_db=str(storage / "runtime" / "governance.db"),
                ),
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
            worker_args = (
                str(inbox),
                controls,
                assets,
                str(storage / "evidence-ledger.jsonl"),
                str(storage / "sentinelgrc-state.db"),
                "runtime/remediation",
                "runtime/tickets",
                "runtime/reports",
            )
            options = pipeline_worker.WorkerRunOptions(
                runtime_root=storage,
                governance_db=str(outside / "governance.db"),
            )
            with self.assertRaisesRegex(ValueError, "governance database path must remain under"):
                pipeline_worker.process_inbox_once(*worker_args, options=options)
            self.assertFalse((storage / "sentinelgrc-state.db").exists())
    def test_invalid_inbox_filename_fails_before_queue_or_business_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            (inbox / "unsafe evidence.json").write_text(
                Path("sample_posture.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
            assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))
            options = pipeline_worker.WorkerRunOptions(
                governance_db=str(root / "governance.db")
            )
            args = (
                str(inbox), controls, assets, str(root / "ledger.jsonl"),
                str(root / "state.db"), "remediation", "tickets", "reports",
            )
            with self.assertRaisesRegex(ValueError, "inbox evidence ID"):
                pipeline_worker.process_inbox_once(*args, options=options)
            for forbidden in (
                "state.db", "governance.db", "ledger.jsonl",
                "remediation", "tickets", "reports",
            ):
                with self.subTest(forbidden=forbidden):
                    self.assertFalse((root / forbidden).exists())
    def test_tampered_queued_path_is_permanently_rejected_before_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            state_db = root / "state.db"
            outside = root / "outside.json"
            outside.write_text(
                Path("sample_posture.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            queue = SQLiteJobQueue(str(state_db))
            queue.enqueue(str(outside))
            controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
            assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))
            result = pipeline_worker.process_inbox_once(
                str(inbox), controls, assets, str(root / "ledger.jsonl"),
                str(state_db), "remediation", "tickets", "reports",
            )
            self.assertEqual(result[0]["status"], "error")
            self.assertEqual(result[0]["queue_status"], "dead")
            self.assertEqual(SQLiteJobQueue(str(state_db)).metadata()["dead"], 1)
            self.assertFalse((root / "ledger.jsonl").exists())
            self.assertFalse((root / "remediation").exists())
    def test_failpoint_replay_preserves_exactly_once_pipeline_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            (inbox / "evidence-crash.json").write_text(
                Path("sample_posture.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            command = [
                sys.executable,
                "-m",
                "scripts.pipeline_worker",
                "once",
                "--inbox",
                str(inbox),
                "--runtime-root",
                str(root),
                "--controls",
                str(Path("controls.json").resolve()),
                "--assets",
                str(Path("assets.json").resolve()),
                "--access-review",
                str(Path("sample_ad_access_review.json").resolve()),
                "--ledger",
                str(root / "evidence-ledger.jsonl"),
                "--state-db",
                str(root / "sentinelgrc-state.db"),
                "--audit-log",
                str(root / "runtime" / "audit-log.jsonl"),
                "--governance-db",
                str(root / "runtime" / "governance.db"),
                "--lease-seconds",
                "1",
            ]
            crash_environment = {
                **os.environ,
                "SENTINEL_ENV": "lab",
                "SENTINEL_ENABLE_TEST_FAILPOINTS": "true",
                "SENTINEL_FAILPOINT": pipeline_worker.FAILPOINT_AFTER_PIPELINE_COMMIT,
            }
            crashed = subprocess.run(
                command,
                cwd=Path.cwd(),
                env=crash_environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(crashed.returncode, pipeline_worker.FAILPOINT_EXIT_CODE)
            protected_paths = [
                root / "evidence-ledger.jsonl",
                root / "runtime" / "audit-log.jsonl",
                root / "runtime" / "remediation" / "evidence-crash.json",
                root / "runtime" / "tickets" / "evidence-crash.json",
                root / "runtime" / "reports" / "evidence-crash.json",
            ]
            committed_content = {
                path: path.read_bytes()
                for path in protected_paths
            }
            time.sleep(1.1)
            replayed = subprocess.run(
                command,
                cwd=Path.cwd(),
                env={
                    key: value
                    for key, value in os.environ.items()
                    if key not in {
                        "SENTINEL_ENABLE_TEST_FAILPOINTS",
                        "SENTINEL_FAILPOINT",
                    }
                },
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(replayed.returncode, 0, replayed.stderr)
            self.assertIn('"status": "duplicate"', replayed.stdout)
            for path, content in committed_content.items():
                self.assertEqual(path.read_bytes(), content, str(path))
    def test_failpoint_configuration_is_rejected_before_queue_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
            assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))
            original = os.environ.copy()
            try:
                os.environ["SENTINEL_FAILPOINT"] = pipeline_worker.FAILPOINT_AFTER_PIPELINE_COMMIT
                os.environ.pop("SENTINEL_ENABLE_TEST_FAILPOINTS", None)
                with self.assertRaisesRegex(RuntimeError, "requires"):
                    pipeline_worker.process_inbox_once(
                        str(inbox), controls, assets,
                        str(root / "ledger.jsonl"), str(root / "state.db"),
                        "runtime/remediation", "runtime/tickets", "runtime/reports",
                    )
            finally:
                os.environ.clear()
                os.environ.update(original)
            self.assertFalse((root / "state.db").exists())
    def test_failpoint_is_rejected_outside_lab_before_queue_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
            assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))
            original = os.environ.copy()
            try:
                os.environ["SENTINEL_ENV"] = "staging"
                os.environ["SENTINEL_ENABLE_TEST_FAILPOINTS"] = "true"
                os.environ["SENTINEL_FAILPOINT"] = (
                    pipeline_worker.FAILPOINT_AFTER_PIPELINE_COMMIT
                )
                with self.assertRaisesRegex(RuntimeError, "only in SENTINEL_ENV=lab"):
                    pipeline_worker.process_inbox_once(
                        str(inbox), controls, assets,
                        str(root / "ledger.jsonl"), str(root / "state.db"),
                        "runtime/remediation", "runtime/tickets", "runtime/reports",
                    )
            finally:
                os.environ.clear()
                os.environ.update(original)
            self.assertFalse((root / "state.db").exists())
if __name__ == "__main__":
    unittest.main()

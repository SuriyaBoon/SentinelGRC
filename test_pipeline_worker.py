import inspect
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from argparse import Namespace
from unittest.mock import patch
from pathlib import Path
from job_queue import SQLiteJobQueue
from scripts import pipeline_worker
from state_store import SQLiteStateStore
class PipelineWorkerTests(unittest.TestCase):
    def test_worker_options_keep_processing_boundary_below_parameter_limit(self):
        parameters = inspect.signature(pipeline_worker.process_inbox_once).parameters
        self.assertLessEqual(len(parameters), 13)
        self.assertIn("options", parameters)
    def test_worker_ignores_pending_ingestion_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            evidence_id = "a" * 24
            (inbox / f"{evidence_id}.json").write_text(
                Path("sample_posture.json").read_text(encoding="utf-8"), encoding="utf-8"
            )
            store = SQLiteStateStore(root / "state.db", storage_root=root)
            store.begin_payload("hash-pending", evidence_id)
            args = (
                str(inbox), json.loads(Path("controls.json").read_text()),
                json.loads(Path("assets.json").read_text()), str(root / "ledger.jsonl"),
                str(root / "state.db"), str(root / "remediation"), str(root / "tickets"),
                str(root / "reports"),
            )
            self.assertEqual(pipeline_worker.process_inbox_once(*args), [])
            store.commit_payload("hash-pending", evidence_id)
            self.assertEqual(pipeline_worker.process_inbox_once(*args)[0]["status"], "accepted")

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
                "--config-root",
                str(Path.cwd()),
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

    @staticmethod
    def _worker_namespace(
        runtime_root: Path,
        controls: str,
        assets: str,
        *,
        config_root: str | None = None,
        access_review: str | None = None,
    ) -> Namespace:
        return Namespace(
            runtime_root=str(runtime_root),
            config_root=config_root,
            controls=controls,
            assets=assets,
            access_review=access_review,
            max_attempts=3,
            retry_delay=60,
            audit_log="runtime/audit-log.jsonl",
            lease_seconds=300,
            governance_db=None,
        )

    def test_configuration_defaults_to_non_default_runtime_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "controls.json").write_text("[]", encoding="utf-8")
            (root / "assets.json").write_text("[]", encoding="utf-8")
            args = self._worker_namespace(root, "controls.json", "assets.json")
            config_root, runtime_root = pipeline_worker.resolve_worker_roots(args)
            configuration = pipeline_worker.load_worker_configuration(args, config_root)
            self.assertEqual(config_root, root.resolve())
            self.assertEqual(runtime_root, root.resolve())
            self.assertEqual(configuration.controls, [])
            self.assertEqual(configuration.assets, [])

    def test_configuration_outside_declared_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self._worker_namespace(
                root,
                str(Path("controls.json").resolve()),
                str(Path("assets.json").resolve()),
            )
            config_root, _ = pipeline_worker.resolve_worker_roots(args)
            with self.assertRaisesRegex(ValueError, "control catalogue must remain under"):
                pipeline_worker.load_worker_configuration(args, config_root)

    def test_explicit_separate_configuration_root_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime_root = root / "runtime"
            config_root = root / "configuration"
            runtime_root.mkdir()
            config_root.mkdir()
            (config_root / "controls.json").write_text("[]", encoding="utf-8")
            (config_root / "assets.json").write_text("[]", encoding="utf-8")
            args = self._worker_namespace(
                runtime_root,
                "controls.json",
                "assets.json",
                config_root=str(config_root),
            )
            resolved_config, resolved_runtime = pipeline_worker.resolve_worker_roots(args)
            configuration = pipeline_worker.load_worker_configuration(
                args, resolved_config
            )
            self.assertEqual(resolved_config, config_root.resolve())
            self.assertEqual(resolved_runtime, runtime_root.resolve())
            self.assertEqual(configuration.controls, [])
            self.assertEqual(configuration.assets, [])

    def test_main_loads_worker_configuration_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            argv = [
                "pipeline_worker",
                "once",
                "--inbox",
                str(inbox),
                "--runtime-root",
                str(root),
                "--controls",
                "controls.json",
                "--assets",
                "assets.json",
            ]
            with patch.object(sys, "argv", argv), patch.object(
                pipeline_worker, "load_json", side_effect=[[], []]
            ) as mocked_load:
                self.assertEqual(pipeline_worker.main(), 0)
            self.assertEqual(mocked_load.call_count, 2)

if __name__ == "__main__":
    unittest.main()

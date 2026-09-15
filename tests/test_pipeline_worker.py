import hashlib
import inspect
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from argparse import Namespace
from contextlib import closing, redirect_stderr
from io import StringIO
from unittest.mock import Mock, patch
from pathlib import Path
from job_queue import SQLiteJobQueue
import publication_reconciliation
from scripts import pipeline_worker
from state_store import SQLITE_LOCK_TIMEOUT_SECONDS, SQLiteStateStore
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
            payload = Path("sample_posture.json").read_bytes()
            payload_hash = hashlib.sha256(payload).hexdigest()
            evidence_id = payload_hash[:24]
            (inbox / f"{evidence_id}.json").write_bytes(payload)
            store = SQLiteStateStore(root / "state.db", storage_root=root)
            store.begin_payload(payload_hash, evidence_id)
            self.assertGreater(
                publication_reconciliation.RECONCILIATION_GRACE_SECONDS, 0
            )
            args = (
                str(inbox), json.loads(Path("controls.json").read_text()),
                json.loads(Path("assets.json").read_text()), str(root / "ledger.jsonl"),
                str(root / "state.db"), str(root / "remediation"), str(root / "tickets"),
                str(root / "reports"),
            )
            self.assertEqual(pipeline_worker.process_inbox_once(*args), [])
            store.commit_payload(payload_hash, evidence_id)
            self.assertEqual(pipeline_worker.process_inbox_once(*args)[0]["status"], "accepted")

    def test_worker_processes_no_row_hex_named_file_as_unmanaged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            payload = Path("sample_posture.json").read_bytes()
            evidence_id = hashlib.sha256(payload).hexdigest()[:24]
            (inbox / f"{evidence_id}.json").write_bytes(payload)
            store = SQLiteStateStore(root / "state.db", storage_root=root)
            self.assertIsNone(store.find_payload_by_evidence_id(evidence_id))
            args = (
                str(inbox), json.loads(Path("controls.json").read_text()),
                json.loads(Path("assets.json").read_text()), str(root / "ledger.jsonl"),
                str(root / "state.db"), str(root / "remediation"), str(root / "tickets"),
                str(root / "reports"),
            )
            result = pipeline_worker.process_inbox_once(*args)
            self.assertEqual(result[0]["status"], "accepted")
            self.assertTrue((root / "reports" / f"{evidence_id}.json").exists())

    def test_worker_skips_pending_publication_with_non_hex_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            payload = Path("sample_posture.json").read_bytes()
            evidence_id = "manual-pub-report"
            (inbox / f"{evidence_id}.json").write_bytes(payload)
            store = SQLiteStateStore(root / "state.db", storage_root=root)
            store.begin_payload(hashlib.sha256(payload).hexdigest(), evidence_id)
            # Reconciliation cannot heal this record on its own either, so the
            # skip below comes purely from the publication-state lookup.
            args = (
                str(inbox), json.loads(Path("controls.json").read_text()),
                json.loads(Path("assets.json").read_text()), str(root / "ledger.jsonl"),
                str(root / "state.db"), str(root / "remediation"), str(root / "tickets"),
                str(root / "reports"),
            )
            self.assertEqual(pipeline_worker.process_inbox_once(*args), [])
            self.assertEqual(
                store.find_payload_by_evidence_id(evidence_id)["status"], "pending"
            )

    def test_worker_reads_no_row_hex_named_entry_through_regular_file_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            evidence_id = hashlib.sha256(b"unused").hexdigest()[:24]
            (inbox / f"{evidence_id}.json").mkdir()
            args = (
                str(inbox), json.loads(Path("controls.json").read_text()),
                json.loads(Path("assets.json").read_text()), str(root / "ledger.jsonl"),
                str(root / "state.db"), str(root / "remediation"), str(root / "tickets"),
                str(root / "reports"),
            )
            with patch.object(pipeline_worker.pipeline, "run_pipeline") as run:
                result = pipeline_worker.process_inbox_once(*args)
            self.assertEqual(result[0]["status"], "error")
            self.assertIn("regular readable file", result[0]["error"])
            run.assert_not_called()

    def test_worker_provenance_does_not_use_filename_heuristic(self):
        self.assertFalse(hasattr(pipeline_worker, "is_evidence_filename"))
        self.assertNotIn("is_evidence_filename", inspect.getsource(pipeline_worker))

    def test_worker_rejects_replaced_committed_evidence_before_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            original = Path("sample_posture.json").read_bytes()
            payload_hash = hashlib.sha256(original).hexdigest()
            evidence_id = payload_hash[:24]
            store = SQLiteStateStore(root / "state.db", storage_root=root)
            store.begin_payload(payload_hash, evidence_id)
            store.commit_payload(payload_hash, evidence_id)
            replacement = json.loads(original)
            replacement["hostname"] = "substituted-host"
            (inbox / f"{evidence_id}.json").write_text(
                json.dumps(replacement), encoding="utf-8"
            )
            args = (
                str(inbox), json.loads(Path("controls.json").read_text()),
                json.loads(Path("assets.json").read_text()), str(root / "ledger.jsonl"),
                str(root / "state.db"), str(root / "remediation"), str(root / "tickets"),
                str(root / "reports"),
            )
            with patch.object(pipeline_worker.pipeline, "run_pipeline") as run:
                result = pipeline_worker.process_inbox_once(*args)
            self.assertEqual(result[0]["status"], "error")
            self.assertIn("hash verification", result[0]["error"])
            run.assert_not_called()

    def test_transient_evidence_read_error_uses_bounded_retry_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            payload = Path("sample_posture.json").read_bytes()
            payload_hash = hashlib.sha256(payload).hexdigest()
            evidence_id = payload_hash[:24]
            (inbox / f"{evidence_id}.json").write_bytes(payload)
            store = SQLiteStateStore(root / "state.db", storage_root=root)
            store.begin_payload(payload_hash, evidence_id)
            store.commit_payload(payload_hash, evidence_id)
            args = (
                str(inbox), json.loads(Path("controls.json").read_text()),
                json.loads(Path("assets.json").read_text()), str(root / "ledger.jsonl"),
                str(root / "state.db"), str(root / "remediation"), str(root / "tickets"),
                str(root / "reports"), None,
                pipeline_worker.WorkerRunOptions(max_attempts=3, retry_delay=0),
            )
            with patch("publication_reconciliation.os.open", side_effect=PermissionError):
                result = pipeline_worker.process_inbox_once(*args)
            self.assertEqual(
                [item["queue_status"] for item in result],
                ["pending", "pending", "dead"],
            )
            self.assertEqual(SQLiteJobQueue(root / "state.db").metadata()["dead"], 1)
            self.assertIn("temporarily unavailable", result[0]["error"])

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
            # The crashed job's lease is expired deterministically instead of
            # sleeping out a real lease: the CLI now enforces a lease safety
            # floor far above one second.
            with closing(sqlite3.connect(root / "sentinelgrc-state.db")) as connection:
                connection.execute(
                    "UPDATE pipeline_jobs SET locked_until = 0 WHERE status = 'running'"
                )
                connection.commit()
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

    def test_main_exits_nonzero_when_lease_is_lost(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            argv = [
                "pipeline_worker", "once", "--inbox", str(inbox),
                "--runtime-root", str(root), "--controls", "controls.json",
                "--assets", "assets.json",
            ]
            with patch.object(sys, "argv", argv), patch.object(
                pipeline_worker, "load_json", side_effect=[[], []]
            ), patch.object(
                pipeline_worker, "process_inbox_once",
                return_value=[{"file": "evidence.json", "status": "lease_lost"}],
            ):
                self.assertEqual(pipeline_worker.main(), 1)

    def test_one_shot_exit_code_accepts_only_completed_results(self):
        successful_results = (
            [],
            [{"status": "accepted"}],
            [{"status": "duplicate"}],
            [{"status": "accepted"}, {"status": "duplicate"}],
        )
        for results in successful_results:
            with self.subTest(results=results):
                self.assertEqual(pipeline_worker._one_shot_exit_code(results), 0)

    def test_one_shot_exit_code_fails_closed(self):
        failed_results = (
            [{"status": "lease_lost"}],
            [{"status": "error"}],
            [{"status": "unknown"}],
            [{"status": ""}],
            [{}],
            ["malformed"],
        )
        for results in failed_results:
            with self.subTest(results=results):
                self.assertEqual(pipeline_worker._one_shot_exit_code(results), 1)

    def _blocked_read_lease_fixture(self, root, queue, lease_seconds=3):
        """Enqueue and claim one managed-evidence job for worker-a."""
        inbox = root / "inbox"
        inbox.mkdir(exist_ok=True)
        payload = Path("sample_posture.json").read_bytes()
        payload_hash = hashlib.sha256(payload).hexdigest()
        evidence_id = payload_hash[:24]
        payload_path = inbox / f"{evidence_id}.json"
        payload_path.write_bytes(payload)
        queue.enqueue(str(payload_path))
        job = queue.claim("worker-a", lease_seconds=lease_seconds)
        publication_state = Mock(
            **{
                "find_payload_by_evidence_id.return_value": {
                    "status": "committed",
                    "payload_hash": payload_hash,
                }
            }
        )
        options = pipeline_worker.WorkerRunOptions(
            max_attempts=3, retry_delay=0, lease_seconds=lease_seconds
        )
        paths = pipeline_worker._resolve_worker_paths(
            str(inbox), str(root / "ledger.jsonl"), str(root / "state.db"),
            "remediation", "tickets", "reports", options,
        )
        return payload, payload_hash, job, publication_state, options, paths

    def test_immediate_renewal_sqlite_error_fails_closed_before_evidence_read(self):
        class LockedRenewQueue:
            def renew(self, *args, **kwargs):
                raise sqlite3.OperationalError("database is locked")

            def fail(self, *args, **kwargs):
                raise AssertionError("queue.fail() must not run while ownership is unknown")

            def complete(self, *args, **kwargs):
                raise AssertionError("complete() must not run while ownership is unknown")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            inbox.mkdir()
            job = {"job_id": 1, "payload_path": str(inbox / "evidence-001.json")}
            options = pipeline_worker.WorkerRunOptions(max_attempts=3, retry_delay=0)
            paths = pipeline_worker._resolve_worker_paths(
                str(inbox), str(root / "ledger.jsonl"), str(root / "state.db"),
                "remediation", "tickets", "reports", options,
            )
            with patch.object(
                pipeline_worker, "_read_claimed_payload"
            ) as read, patch.object(
                pipeline_worker.pipeline, "run_pipeline"
            ) as run:
                result = pipeline_worker._process_claimed_job(
                    LockedRenewQueue(), job, paths, Mock(),
                    [], [], None, options, "worker-a", None,
                )
            self.assertEqual(result["status"], "lease_lost")
            read.assert_not_called()
            run.assert_not_called()

    def test_one_second_lease_uses_fractional_renewal_interval(self):
        recorded_intervals = []

        class RecordingStop:
            def wait(self, timeout=None):
                recorded_intervals.append(timeout)
                return True

        queue = Mock()
        lease_lost = threading.Event()
        pipeline_worker._renew_lease_until_stopped(
            queue, RecordingStop(), lease_lost, 1, "worker-a", 1
        )
        self.assertEqual(len(recorded_intervals), 1)
        self.assertGreater(recorded_intervals[0], 0)
        self.assertLess(recorded_intervals[0], 1)
        queue.renew.assert_not_called()
        self.assertFalse(lease_lost.is_set())

    def test_heartbeat_sqlite_error_sets_lease_lost(self):
        class LockedRenewQueue:
            def renew(self, *args, **kwargs):
                raise sqlite3.OperationalError("database is locked")

        stop = threading.Event()
        lease_lost = threading.Event()
        heartbeat = threading.Thread(
            target=pipeline_worker._renew_lease_until_stopped,
            args=(LockedRenewQueue(), stop, lease_lost, 1, "worker-a", 1),
        )
        heartbeat.start()
        try:
            self.assertTrue(lease_lost.wait(timeout=5))
        finally:
            stop.set()
            heartbeat.join(timeout=5)
        self.assertFalse(heartbeat.is_alive())

    def test_heartbeat_renews_during_blocked_read_and_blocks_reclaim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            queue = SQLiteJobQueue(str(root / "state.db"))
            payload, _hash, job, publication_state, options, paths = (
                self._blocked_read_lease_fixture(root, queue)
            )
            controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
            assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))
            read_started = threading.Event()
            release_read = threading.Event()
            blocked_renewals = threading.Event()
            second_blocked_renewal = threading.Event()
            original_renew = SQLiteJobQueue.renew

            def blocked_read(path, expected_hash):
                read_started.set()
                release_read.wait(timeout=10)
                return payload

            def renewing(self, *args, **kwargs):
                result = original_renew(self, *args, **kwargs)
                if read_started.is_set() and not release_read.is_set():
                    if not blocked_renewals.is_set():
                        blocked_renewals.set()
                    else:
                        second_blocked_renewal.set()
                return result

            with patch.object(
                pipeline_worker, "read_verified_evidence", blocked_read
            ), patch.object(SQLiteJobQueue, "renew", renewing):
                with patch.object(
                    pipeline_worker.pipeline, "run_pipeline",
                    return_value={"status": "accepted"},
                ) as run:
                    result_box = {}

                    def process():
                        result_box["result"] = pipeline_worker._process_claimed_job(
                            queue, job, paths, publication_state,
                            controls, assets, None, options, "worker-a", None,
                        )

                    worker_thread = threading.Thread(target=process)
                    worker_thread.start()
                    try:
                        self.assertTrue(read_started.wait(timeout=5))
                        self.assertTrue(blocked_renewals.wait(timeout=5))
                        self.assertTrue(second_blocked_renewal.wait(timeout=5))
                        self.assertIsNone(
                            queue.claim(
                                "worker-b", lease_seconds=3, now=time.time() + 2
                            )
                        )
                    finally:
                        release_read.set()
                        worker_thread.join(timeout=10)
                    self.assertFalse(worker_thread.is_alive())
            self.assertEqual(result_box["result"]["status"], "accepted")
            run.assert_called_once()

    def test_lease_loss_during_blocked_read_prevents_pipeline_side_effects(self):
        class OneShotRenewQueue:
            """First renewal proves ownership; later renewals report loss."""

            def __init__(self):
                self.renew_calls = 0
                self.failed = False

            def renew(self, job_id, worker_id, lease_seconds):
                self.renew_calls += 1
                if self.renew_calls == 1:
                    return True
                return False

            def fail(self, *args, **kwargs):
                self.failed = True
                return "pending"

            def complete(self, *args, **kwargs):
                raise AssertionError("complete() must not run after lease loss")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_queue = OneShotRenewQueue()
            payload = Path("sample_posture.json").read_bytes()
            payload_hash = hashlib.sha256(payload).hexdigest()
            evidence_id = payload_hash[:24]
            inbox = root / "inbox"
            inbox.mkdir()
            job = {
                "job_id": 1,
                "payload_path": str(inbox / f"{evidence_id}.json"),
            }
            publication_state = Mock(
                **{
                    "find_payload_by_evidence_id.return_value": {
                        "status": "committed",
                        "payload_hash": payload_hash,
                    }
                }
            )
            options = pipeline_worker.WorkerRunOptions(
                max_attempts=3, retry_delay=0, lease_seconds=3
            )
            paths = pipeline_worker._resolve_worker_paths(
                str(inbox), str(root / "ledger.jsonl"), str(root / "state.db"),
                "remediation", "tickets", "reports", options,
            )
            read_started = threading.Event()
            release_read = threading.Event()
            captured = {}
            original_target = pipeline_worker._renew_lease_until_stopped

            def capturing_target(queue, stop, lease_lost, job_id, worker_id, lease_seconds):
                captured["lease_lost"] = lease_lost
                original_target(queue, stop, lease_lost, job_id, worker_id, lease_seconds)

            def blocked_read(path, expected_hash):
                read_started.set()
                release_read.wait(timeout=10)
                return payload

            with patch.object(
                pipeline_worker, "read_verified_evidence", blocked_read
            ), patch.object(
                pipeline_worker, "_renew_lease_until_stopped", capturing_target
            ):
                with patch.object(
                    pipeline_worker.pipeline, "run_pipeline",
                    return_value={"status": "accepted"},
                ) as run:
                    result_box = {}

                    def process():
                        result_box["result"] = pipeline_worker._process_claimed_job(
                            fake_queue, job, paths, publication_state,
                            [], [], None, options, "worker-a", None,
                        )

                    worker_thread = threading.Thread(target=process)
                    worker_thread.start()
                    try:
                        self.assertTrue(read_started.wait(timeout=5))
                        # Wait for the worker's own lease-loss event, not a
                        # fake-queue flag, so the post-read check is race-free.
                        self.assertIsNotNone(captured.get("lease_lost"))
                        self.assertTrue(captured["lease_lost"].wait(timeout=5))
                    finally:
                        release_read.set()
                        worker_thread.join(timeout=10)
                    self.assertFalse(worker_thread.is_alive())
            self.assertEqual(result_box["result"]["status"], "lease_lost")
            run.assert_not_called()
            self.assertFalse(fake_queue.failed)
            self.assertGreaterEqual(fake_queue.renew_calls, 2)

    def test_read_failure_stops_and_joins_heartbeat(self):
        captured = {}
        original_target = pipeline_worker._renew_lease_until_stopped

        def capturing_target(queue, stop, lease_lost, job_id, worker_id, lease_seconds):
            captured["thread"] = threading.current_thread()
            captured["stop"] = stop
            original_target(queue, stop, lease_lost, job_id, worker_id, lease_seconds)

        def failing_read(path, publication_state):
            raise PermissionError("blocked evidence read")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            queue = SQLiteJobQueue(str(root / "state.db"))
            _payload, _hash, job, publication_state, options, paths = (
                self._blocked_read_lease_fixture(root, queue)
            )
            with patch.object(
                pipeline_worker, "_read_claimed_payload", failing_read
            ), patch.object(
                pipeline_worker, "_renew_lease_until_stopped", capturing_target
            ):
                result = pipeline_worker._process_claimed_job(
                    queue, job, paths, publication_state,
                    [], [], None, options, "worker-a", None,
                )
            self.assertEqual(result["status"], "error")
            self.assertIn("temporarily unavailable", result["error"])
            self.assertTrue(captured["stop"].is_set())
            captured["thread"].join(timeout=5)
            self.assertFalse(captured["thread"].is_alive())

    def test_success_stops_and_joins_heartbeat(self):
        captured = {}
        original_target = pipeline_worker._renew_lease_until_stopped

        def capturing_target(queue, stop, lease_lost, job_id, worker_id, lease_seconds):
            captured["thread"] = threading.current_thread()
            captured["stop"] = stop
            original_target(queue, stop, lease_lost, job_id, worker_id, lease_seconds)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            queue = SQLiteJobQueue(str(root / "state.db"))
            _payload, _hash, job, publication_state, options, paths = (
                self._blocked_read_lease_fixture(root, queue)
            )
            with patch.object(
                pipeline_worker, "_renew_lease_until_stopped", capturing_target
            ), patch.object(
                pipeline_worker.pipeline, "run_pipeline",
                return_value={"status": "accepted"},
            ) as run:
                result = pipeline_worker._process_claimed_job(
                    queue, job, paths, publication_state,
                    [], [], None, options, "worker-a", None,
                )
            self.assertEqual(result["status"], "accepted")
            run.assert_called_once()
            self.assertTrue(captured["stop"].is_set())
            captured["thread"].join(timeout=5)
            self.assertFalse(captured["thread"].is_alive())

    def test_worker_cleanup_joins_heartbeat_without_short_timeout(self):
        queue = Mock()
        queue.renew.return_value = True
        queue.fail.return_value = "pending"
        heartbeat = Mock()
        job = {"job_id": 1, "payload_path": "evidence.json"}
        options = pipeline_worker.WorkerRunOptions()
        with patch.object(
            pipeline_worker.threading, "Thread", return_value=heartbeat
        ) as thread_factory, patch.object(
            pipeline_worker, "_validated_inbox_item", return_value=Path("evidence.json")
        ), patch.object(
            pipeline_worker, "_read_claimed_payload",
            side_effect=PermissionError("blocked evidence read"),
        ):
            result = pipeline_worker._process_claimed_job(
                queue, job, Mock(inbox=Path(".")), Mock(),
                [], [], None, options, "worker-a", None,
            )
        self.assertEqual(result["status"], "error")
        heartbeat.start.assert_called_once_with()
        heartbeat.join.assert_called_once_with()
        heartbeat_stop = thread_factory.call_args.kwargs["args"][1]
        self.assertTrue(heartbeat_stop.is_set())

    def _run_controlled_acknowledgement(self, *, lose_lease_during_join):
        queue = Mock()
        queue.renew.return_value = True
        order = []

        class ControlledHeartbeat:
            def __init__(self, *, target, args, daemon):
                self.lease_lost = args[2]

            def start(self):
                return None

            def join(self):
                order.append("join")
                if lose_lease_during_join:
                    self.lease_lost.set()

        queue.complete.side_effect = lambda *args: order.append("complete") or True
        job = {"job_id": 1, "payload_path": "evidence.json"}
        paths = Mock(
            inbox=Path("."), ledger="ledger.jsonl", remediation_dir="remediation",
            tickets_dir="tickets", reports_dir="reports", state_db="state.db",
            audit_path=None, governance_db=None, storage_root=Path("."),
        )
        with patch.object(
            pipeline_worker.threading, "Thread", ControlledHeartbeat
        ), patch.object(
            pipeline_worker, "_validated_inbox_item", return_value=Path("evidence.json")
        ), patch.object(
            pipeline_worker, "_read_claimed_payload", return_value=b"{}"
        ), patch.object(
            pipeline_worker.pipeline, "run_pipeline", return_value={"status": "accepted"}
        ):
            result = pipeline_worker._process_claimed_job(
                queue, job, paths, Mock(), [], [], None,
                pipeline_worker.WorkerRunOptions(), "worker-a", None,
            )
        return result, queue, order

    def test_heartbeat_loss_during_join_prevents_acknowledgement(self):
        result, queue, order = self._run_controlled_acknowledgement(
            lose_lease_during_join=True
        )
        self.assertEqual(result["status"], "lease_lost")
        self.assertEqual(order, ["join"])
        queue.complete.assert_not_called()

    def test_heartbeat_is_joined_before_acknowledgement(self):
        result, queue, order = self._run_controlled_acknowledgement(
            lose_lease_during_join=False
        )
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(order, ["join", "complete"])
        queue.complete.assert_called_once_with(1, "worker-a")

    def test_unexpected_validation_failure_preserves_original_error(self):
        queue = Mock()
        queue.renew.return_value = True
        queue.fail.return_value = "pending"
        heartbeat = Mock()
        job = {"job_id": 1, "payload_path": "evidence.json"}
        with patch.object(
            pipeline_worker.threading, "Thread", return_value=heartbeat
        ), patch.object(
            pipeline_worker, "_validated_inbox_item", side_effect=RuntimeError("boom")
        ):
            result = pipeline_worker._process_claimed_job(
                queue, job, Mock(inbox=Path(".")), Mock(), [], [], None,
                pipeline_worker.WorkerRunOptions(), "worker-a", None,
            )
        self.assertEqual(result["file"], "evidence.json")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "boom")
        self.assertNotIn("UnboundLocalError", result["error"])
        queue.fail.assert_called_once()
        heartbeat.join.assert_called_once_with()

    def test_min_worker_lease_derives_from_shared_lock_timeout(self):
        self.assertEqual(
            pipeline_worker.MIN_WORKER_LEASE_SECONDS,
            SQLITE_LOCK_TIMEOUT_SECONDS * 2,
        )
        self.assertGreater(
            pipeline_worker.MIN_WORKER_LEASE_SECONDS, SQLITE_LOCK_TIMEOUT_SECONDS
        )

    def test_worker_run_options_validation_floor_and_other_bounds(self):
        floor = pipeline_worker.MIN_WORKER_LEASE_SECONDS
        pipeline_worker._validate_worker_run_options(
            pipeline_worker.WorkerRunOptions(lease_seconds=floor)
        )
        pipeline_worker._validate_worker_run_options(pipeline_worker.WorkerRunOptions())
        for invalid in (
            pipeline_worker.WorkerRunOptions(lease_seconds=floor - 1),
            pipeline_worker.WorkerRunOptions(max_attempts=0),
            pipeline_worker.WorkerRunOptions(retry_delay=-1),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    pipeline_worker._validate_worker_run_options(invalid)

    def test_lease_below_floor_rejected_before_any_worker_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / "inbox"
            controls = json.loads(Path("controls.json").read_text(encoding="utf-8"))
            assets = json.loads(Path("assets.json").read_text(encoding="utf-8"))
            options = pipeline_worker.WorkerRunOptions(
                lease_seconds=pipeline_worker.MIN_WORKER_LEASE_SECONDS - 1
            )
            with patch.object(
                pipeline_worker, "SQLiteJobQueue"
            ) as queue, patch.object(
                pipeline_worker, "SQLiteStateStore"
            ) as store, patch.object(
                pipeline_worker, "reconcile_pending_publications"
            ) as reconcile, patch.object(
                pipeline_worker.pipeline, "run_pipeline"
            ) as run:
                with self.assertRaisesRegex(
                    ValueError, "lease_seconds must be at least"
                ):
                    pipeline_worker.process_inbox_once(
                        str(inbox), controls, assets, str(root / "ledger.jsonl"),
                        str(root / "state.db"), "remediation", "tickets", "reports",
                        options=options,
                    )
            queue.assert_not_called()
            store.assert_not_called()
            reconcile.assert_not_called()
            run.assert_not_called()
            self.assertFalse(inbox.exists())
            self.assertFalse((root / "state.db").exists())

    def test_cli_rejects_lease_below_floor_with_concise_parser_error(self):
        argv = [
            "pipeline_worker",
            "once",
            "--inbox",
            "evidence-inbox",
            "--runtime-root",
            ".",
            "--controls",
            "controls.json",
            "--assets",
            "assets.json",
            "--lease-seconds",
            str(pipeline_worker.MIN_WORKER_LEASE_SECONDS - 1),
        ]
        stderr = StringIO()
        with patch.object(sys, "argv", argv), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                pipeline_worker.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("lease_seconds must be at least", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_lease_loss_during_run_pipeline_prevents_successful_completion(self):
        class LossAfterFirstRenewQueue:
            def __init__(self):
                self.renew_calls = 0
                self.completed = False

            def renew(self, job_id, worker_id, lease_seconds):
                self.renew_calls += 1
                return self.renew_calls == 1

            def complete(self, *args, **kwargs):
                self.completed = True
                raise AssertionError("complete() must not run after lease loss")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_queue = LossAfterFirstRenewQueue()
            inbox = root / "inbox"
            inbox.mkdir()
            (inbox / "evidence-001.json").write_text(
                Path("sample_posture.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            job = {"job_id": 1, "payload_path": str(inbox / "evidence-001.json")}
            options = pipeline_worker.WorkerRunOptions(
                max_attempts=3, retry_delay=0, lease_seconds=3
            )
            paths = pipeline_worker._resolve_worker_paths(
                str(inbox), str(root / "ledger.jsonl"), str(root / "state.db"),
                "remediation", "tickets", "reports", options,
            )
            captured = {}
            original_target = pipeline_worker._renew_lease_until_stopped

            def capturing_target(queue, stop, lease_lost, job_id, worker_id, lease_seconds):
                captured["lease_lost"] = lease_lost
                original_target(queue, stop, lease_lost, job_id, worker_id, lease_seconds)

            def blocking_run(*run_args, **run_kwargs):
                # Hold the pipeline open until the heartbeat reports lease loss.
                if not captured["lease_lost"].wait(timeout=5):
                    raise AssertionError("lease loss was never reported")
                return {"status": "accepted"}

            with patch.object(
                pipeline_worker, "_renew_lease_until_stopped", capturing_target
            ), patch.object(
                pipeline_worker.pipeline, "run_pipeline", side_effect=blocking_run
            ):
                result = pipeline_worker._process_claimed_job(
                    fake_queue, job, paths,
                    # Provenance now consults publication state unconditionally;
                    # this test has no record, matching the unmanaged read it expects.
                    Mock(find_payload_by_evidence_id=Mock(return_value=None)),
                    [], [], None, options, "worker-a", None,
                )
            self.assertEqual(result["status"], "lease_lost")
            self.assertFalse(fake_queue.completed)
            self.assertGreaterEqual(fake_queue.renew_calls, 2)
if __name__ == "__main__":
    unittest.main()

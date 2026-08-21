import tempfile
import threading
from contextlib import closing
import unittest
import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path

from state_store import SQLiteStateStore


class StateStoreTests(unittest.TestCase):
    def test_legacy_payload_table_migrates_before_index_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "CREATE TABLE accepted_payloads ("
                    "payload_hash TEXT PRIMARY KEY, evidence_id TEXT NOT NULL, "
                    "accepted_at REAL NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO accepted_payloads(payload_hash, evidence_id, accepted_at) "
                    "VALUES (?, ?, ?)",
                    ("legacy-hash", "legacy-evidence", 1000),
                )
                connection.commit()

            first = SQLiteStateStore(database, storage_root=directory)
            self.assertEqual(first.get_evidence_id("legacy-hash"), "legacy-evidence")

            with closing(sqlite3.connect(database)) as connection:
                columns = {
                    row[1] for row in connection.execute(
                        "PRAGMA table_info(accepted_payloads)"
                    ).fetchall()
                }
                indexes = {
                    row[1] for row in connection.execute(
                        "PRAGMA index_list(accepted_payloads)"
                    ).fetchall()
                }
                status = connection.execute(
                    "SELECT status FROM accepted_payloads WHERE payload_hash = ?",
                    ("legacy-hash",),
                ).fetchone()[0]

            self.assertIn("status", columns)
            self.assertIn("idx_accepted_payloads_evidence_status", indexes)
            self.assertEqual(status, "committed")

            second = SQLiteStateStore(database, storage_root=directory)
            self.assertEqual(second.get_evidence_id("legacy-hash"), "legacy-evidence")

    def test_nonce_survives_new_store_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "state.db")
            first = SQLiteStateStore(db)
            self.assertTrue(first.reserve_nonce("nonce-123", 300, now=1000))
            second = SQLiteStateStore(db)
            self.assertFalse(second.reserve_nonce("nonce-123", 300, now=1001))

    def test_payload_requires_commit_before_worker_visibility(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStateStore(Path(directory) / "state.db", storage_root=directory)
            self.assertTrue(store.begin_payload("hash-pending", "evidence-pending"))
            self.assertIsNone(store.get_evidence_id("hash-pending"))
            self.assertFalse(store.is_evidence_committed("evidence-pending"))
            self.assertTrue(store.commit_payload("hash-pending", "evidence-pending"))
            self.assertEqual(store.get_evidence_id("hash-pending"), "evidence-pending")
            self.assertTrue(store.is_evidence_committed("evidence-pending"))

    def test_parallel_legacy_initialization_serializes_status_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "CREATE TABLE accepted_payloads (payload_hash TEXT PRIMARY KEY, "
                    "evidence_id TEXT NOT NULL, accepted_at REAL NOT NULL)"
                )
                connection.commit()
            barrier = threading.Barrier(2)
            failures = []
            def initialize():
                try:
                    barrier.wait(timeout=5)
                    SQLiteStateStore(database, storage_root=root)
                except Exception as error:
                    failures.append(error)
            threads = [threading.Thread(target=initialize) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertEqual(failures, [])
            with closing(sqlite3.connect(database)) as connection:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(accepted_payloads)")}
            self.assertIn("status", columns)

    def test_payload_identity_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStateStore(str(Path(directory) / "state.db"))
            self.assertTrue(store.remember_payload("hash-1", "evidence-1", now=1000))
            self.assertFalse(store.remember_payload("hash-1", "evidence-2", now=1001))
            self.assertEqual(store.get_evidence_id("hash-1"), "evidence-1")
            self.assertIsNone(store.get_evidence_id("hash-2"))

    def test_external_import_outbox_distinguishes_replay_and_reassessment(self):
        finding = {
            "finding_id": "F-1",
            "source": "test",
            "control_id": "C-1",
            "asset_id": "A-1",
            "title": "Finding",
            "risk_owner": "owner",
            "severity": "high",
            "details": {"version": 1},
        }
        first_hash = hashlib.sha256(b"first").hexdigest()
        second_hash = hashlib.sha256(b"second").hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStateStore(str(Path(directory) / "state.db"))
            created = store.record_external_finding_import(finding, first_hash, now=1000)
            replayed = store.record_external_finding_import(finding, first_hash, now=1001)
            finding["details"] = {"version": 2}
            reassessed = store.record_external_finding_import(
                finding, second_hash, now=1002
            )
            finding["details"] = {"version": 1}
            old_replay = store.record_external_finding_import(
                finding, first_hash, now=1003
            )
            stored = store.get_external_finding("F-1")

        self.assertEqual(created["action"], "created")
        self.assertEqual(replayed["action"], "replayed")
        self.assertEqual(reassessed["action"], "reassessed")
        self.assertEqual(old_replay["action"], "replayed")
        self.assertEqual(stored["reassessment_count"], 1)
        self.assertEqual(stored["details"], {"version": 2})


if __name__ == "__main__":
    unittest.main()

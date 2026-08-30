import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.bridge_jml import run_jml_bridge
from state_store import SQLiteStateStore


SCHEMA = """
CREATE TABLE jml_requests (
    request_id TEXT PRIMARY KEY, request_type TEXT NOT NULL,
    employee_id TEXT NOT NULL, username TEXT NOT NULL,
    first_name TEXT NOT NULL, last_name TEXT NOT NULL,
    department TEXT NOT NULL, old_department TEXT,
    job_title TEXT, manager_id TEXT NOT NULL,
    requested_by TEXT NOT NULL, effective_at TEXT NOT NULL,
    reason TEXT, status TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE verifications (
    verification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL, actor_id TEXT NOT NULL, result TEXT NOT NULL,
    checks_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE executions (
    execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL, actor_id TEXT NOT NULL, dry_run INTEGER NOT NULL,
    results_json TEXT NOT NULL, created_at TEXT NOT NULL
);
"""


def seed_request(
    connection: sqlite3.Connection,
    request_id: str,
    request_type: str,
    username: str,
    *,
    status="closed",
    verification="passed",
    requested_by="hr-01",
    execution_actor="iam-operator-01",
    verifier_actor="verifier-01",
):
    connection.execute(
        "INSERT INTO jml_requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            request_id, request_type, "EMP-1001", username, "First", "Last", "IT",
            "Sales" if request_type == "mover" else None, "Title", "manager-01", requested_by,
            "2026-08-01T09:00:00Z", "test", status, "2026-08-01T09:00:00Z", "2026-08-01T09:05:00Z",
        ),
    )
    if execution_actor is not None:
        connection.execute(
            "INSERT INTO executions(request_id, actor_id, dry_run, results_json, created_at) "
            "VALUES (?,?,?,?,?)",
            (request_id, execution_actor, 1, "[]", "2026-08-01T09:03:00Z"),
        )
    if verification is not None:
        connection.execute(
            "INSERT INTO verifications(request_id, actor_id, result, checks_json, created_at) VALUES (?,?,?,?,?)",
            (request_id, verifier_actor, verification, "{}", "2026-08-01T09:04:00Z"),
        )


def make_jml_db(path: Path, rows: list[tuple[str, str, str]], *, status="closed", verification="passed"):
    connection = sqlite3.connect(path)
    connection.executescript(SCHEMA)
    for request_id, request_type, username in rows:
        seed_request(connection, request_id, request_type, username, status=status, verification=verification)
    connection.commit()
    connection.close()


class JMLBridgeTests(unittest.TestCase):
    def test_closed_joiner_creates_governance_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_jml_db(root / "jml.db", [("JML-000001", "joiner", "jsmith")])
            result = run_jml_bridge(str(root / "jml.db"), str(root / "governance.db"))
            self.assertEqual(result["findings_created"], 1)
            self.assertEqual(result["finding_ids"], ["SEC-IAM-000001"])

    def test_replay_reassesses_without_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_jml_db(root / "jml.db", [("JML-000001", "joiner", "jsmith")])
            db = str(root / "governance.db")
            first = run_jml_bridge(str(root / "jml.db"), db)
            replay = run_jml_bridge(str(root / "jml.db"), db)
            self.assertEqual(first["findings_created"], 1)
            self.assertEqual(replay["findings_reassessed"], 1)
            self.assertEqual(SQLiteStateStore(db).get_external_finding("SEC-IAM-000001")["reassessment_count"], 1)

    def test_request_types_map_to_distinct_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_jml_db(root / "jml.db", [
                ("JML-000001", "joiner", "jsmith"),
                ("JML-000002", "mover", "adoe"),
                ("JML-000003", "leaver", "bcarter"),
            ])
            db = str(root / "governance.db")
            result = run_jml_bridge(str(root / "jml.db"), db)
            self.assertEqual(result["findings_created"], 3)
            self.assertEqual(
                {SQLiteStateStore(db).get_external_finding(finding_id)["control_id"] for finding_id in result["finding_ids"]},
                {"SEC-IAM-004", "SEC-IAM-005", "SEC-IAM-006"},
            )

    def test_not_closed_request_is_counted_as_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_jml_db(root / "jml.db", [("JML-000001", "joiner", "jsmith")], status="pending_verification", verification=None)
            result = run_jml_bridge(str(root / "jml.db"), str(root / "governance.db"))
            self.assertEqual(result["requests_read"], 1)
            self.assertEqual(result["skipped"], 1)

    def test_missing_or_failed_verification_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_jml_db(root / "jml.db", [("JML-000001", "joiner", "jsmith")], verification=None)
            result = run_jml_bridge(str(root / "jml.db"), str(root / "governance.db"))
            self.assertEqual(result["skipped"], 1)

    def test_requester_or_executor_cannot_supply_independent_verification(self):
        for verifier in ("hr-01", "iam-operator-01"):
            with self.subTest(verifier=verifier), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                connection = sqlite3.connect(root / "jml.db")
                connection.executescript(SCHEMA)
                seed_request(
                    connection,
                    "JML-000001",
                    "joiner",
                    "jsmith",
                    verifier_actor=verifier,
                )
                connection.commit()
                connection.close()

                result = run_jml_bridge(
                    str(root / "jml.db"), str(root / "governance.db")
                )

                self.assertEqual(result["skipped"], 1)
                self.assertEqual(result["findings_created"], 0)

    def test_malformed_source_identity_is_rejected_at_bridge_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_jml_db(root / "jml.db", [("../../escape", "joiner", "jsmith")])
            result = run_jml_bridge(
                str(root / "jml.db"), str(root / "governance.db")
            )

            self.assertEqual(result["errors"], 1)
            self.assertEqual(result["findings_created"], 0)

    def test_single_request_can_be_targeted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_jml_db(root / "jml.db", [("JML-000001", "joiner", "jsmith")])
            result = run_jml_bridge(str(root / "jml.db"), str(root / "governance.db"), "JML-000001")
            self.assertEqual(result["requests_read"], 1)
            self.assertEqual(result["findings_created"], 1)

    def test_missing_database_is_reported_without_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_jml_bridge(str(root / "missing.db"), str(root / "governance.db"))
            self.assertEqual(result["errors"], 1)
            self.assertEqual(result["requests_read"], 0)


if __name__ == "__main__":
    unittest.main()

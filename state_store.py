"""Small SQLite state store for replay protection and idempotent ingestion."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
import time
from pathlib import Path
from typing import Any


class SQLiteStateStore:
    def __init__(self, path: str = "sentinelgrc-state.db"):
        self.path = str(Path(path))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    nonce TEXT PRIMARY KEY,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS accepted_payloads (
                    payload_hash TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    accepted_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pipeline_runs (
                    input_hash TEXT PRIMARY KEY,
                    ledger_record_hash TEXT NOT NULL,
                    remediation_path TEXT NOT NULL,
                    tickets_path TEXT NOT NULL,
                    report_path TEXT NOT NULL,
                    processed_at REAL NOT NULL
                );
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(pipeline_runs)").fetchall()}
            if "status" not in columns:
                connection.execute("ALTER TABLE pipeline_runs ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'")
            if "last_error" not in columns:
                connection.execute("ALTER TABLE pipeline_runs ADD COLUMN last_error TEXT")
            if "run_lease_until" not in columns:
                connection.execute("ALTER TABLE pipeline_runs ADD COLUMN run_lease_until REAL NOT NULL DEFAULT 0")
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def reserve_nonce(self, nonce: str, ttl_seconds: int, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        with self._lock, closing(self._connect()) as connection:
            connection.execute("DELETE FROM replay_nonces WHERE expires_at <= ?", (current,))
            try:
                connection.execute(
                    "INSERT INTO replay_nonces(nonce, expires_at) VALUES (?, ?)",
                    (nonce, current + ttl_seconds),
                )
            except sqlite3.IntegrityError:
                return False
            connection.commit()
            return True

    def get_evidence_id(self, payload_hash: str) -> str | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT evidence_id FROM accepted_payloads WHERE payload_hash = ?",
                (payload_hash,),
            ).fetchone()
        return None if row is None else str(row["evidence_id"])

    def remember_payload(self, payload_hash: str, evidence_id: str, now: float | None = None) -> None:
        current = time.time() if now is None else now
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT OR IGNORE INTO accepted_payloads(payload_hash, evidence_id, accepted_at) VALUES (?, ?, ?)",
                (payload_hash, evidence_id, current),
            )
            connection.commit()

    def claim_pipeline_run(self, input_hash: str, now: float | None = None, lease_seconds: int = 900) -> bool:
        current = time.time() if now is None else now
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT status, COALESCE(run_lease_until, 0) AS run_lease_until FROM pipeline_runs WHERE input_hash = ?", (input_hash,)).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO pipeline_runs(input_hash, ledger_record_hash, remediation_path, tickets_path, report_path, processed_at, status, run_lease_until) VALUES (?, '', '', '', '', ?, 'running', ?)",
                    (input_hash, current, current + lease_seconds),
                )
                connection.commit()
                return True
            if row[0] == "failed" or (row[0] == "running" and (row[1] <= current)):
                connection.execute("UPDATE pipeline_runs SET status = 'running', last_error = NULL, processed_at = ?, run_lease_until = ? WHERE input_hash = ?", (current, current + lease_seconds, input_hash))
                connection.commit()
                return True
            connection.commit()
            return False

    def complete_pipeline_run(
        self, input_hash: str, ledger_record_hash: str, remediation_path: str,
        tickets_path: str, report_path: str, now: float | None = None,
    ) -> None:
        current = time.time() if now is None else now
        with closing(self._connect()) as connection:
            connection.execute(
                "UPDATE pipeline_runs SET status = 'completed', ledger_record_hash = ?, remediation_path = ?, tickets_path = ?, report_path = ?, processed_at = ?, last_error = NULL, run_lease_until = 0 WHERE input_hash = ?",
                (ledger_record_hash, remediation_path, tickets_path, report_path, current, input_hash),
            )
            connection.commit()

    def fail_pipeline_run(self, input_hash: str, error: str, now: float | None = None) -> None:
        current = time.time() if now is None else now
        with closing(self._connect()) as connection:
            connection.execute("UPDATE pipeline_runs SET status = 'failed', last_error = ?, processed_at = ?, run_lease_until = 0 WHERE input_hash = ?", (error[:2000], current, input_hash))
            connection.commit()
    def get_pipeline_run(self, input_hash: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM pipeline_runs WHERE input_hash = ?",
                (input_hash,),
            ).fetchone()
        return None if row is None else dict(row)

    def remember_pipeline_run(
        self,
        input_hash: str,
        ledger_record_hash: str,
        remediation_path: str,
        tickets_path: str,
        report_path: str,
        now: float | None = None,
    ) -> None:
        current = time.time() if now is None else now
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO pipeline_runs(
                    input_hash, ledger_record_hash, remediation_path,
                    tickets_path, report_path, processed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (input_hash, ledger_record_hash, remediation_path, tickets_path, report_path, current),
            )
            connection.commit()

    def export_metadata(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            nonce_count = connection.execute("SELECT COUNT(*) FROM replay_nonces").fetchone()[0]
            payload_count = connection.execute("SELECT COUNT(*) FROM accepted_payloads").fetchone()[0]
        return {"replay_nonce_count": nonce_count, "accepted_payload_count": payload_count}

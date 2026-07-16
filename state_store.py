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
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def reserve_nonce(self, nonce: str, ttl_seconds: int, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM replay_nonces WHERE expires_at <= ?", (current,))
            try:
                connection.execute(
                    "INSERT INTO replay_nonces(nonce, expires_at) VALUES (?, ?)",
                    (nonce, current + ttl_seconds),
                )
            except sqlite3.IntegrityError:
                return False
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

    def export_metadata(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            nonce_count = connection.execute("SELECT COUNT(*) FROM replay_nonces").fetchone()[0]
            payload_count = connection.execute("SELECT COUNT(*) FROM accepted_payloads").fetchone()[0]
        return {"replay_nonce_count": nonce_count, "accepted_payload_count": payload_count}

"""Small SQLite state store for replay protection and idempotent ingestion."""

from __future__ import annotations

import json
import hashlib
import sqlite3
import threading
from contextlib import closing
import time
from pathlib import Path
from typing import Any

from path_security import resolve_sqlite_database_under_root, select_storage_root


DEFAULT_STATE_DB = "sentinelgrc-state.db"
BEGIN_IMMEDIATE_SQL = "BEGIN IMMEDIATE"


class SQLiteStateStore:
    def __init__(
        self,
        path: str | Path = DEFAULT_STATE_DB,
        *,
        storage_root: str | Path | None = None,
    ):
        supplied = Path(path).expanduser()
        boundary = select_storage_root(supplied, storage_root)
        self.path = str(
            resolve_sqlite_database_under_root(
                supplied,
                boundary,
                purpose="state database",
            )
        )
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
                    accepted_at REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'committed' CHECK(status IN ('pending', 'committed'))
                );
                CREATE TABLE IF NOT EXISTS pipeline_runs (
                    input_hash TEXT PRIMARY KEY,
                    ledger_record_hash TEXT NOT NULL,
                    remediation_path TEXT NOT NULL,
                    tickets_path TEXT NOT NULL,
                    report_path TEXT NOT NULL,
                    processed_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS external_findings (
                    finding_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    risk_owner TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    reassessment_count INTEGER NOT NULL DEFAULT 0,
                    last_evidence_hash TEXT
                );
                CREATE TABLE IF NOT EXISTS external_finding_audit_outbox (
                    event_id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    delivered_at REAL,
                    UNIQUE(finding_id, evidence_hash)
                );
                """
            )
            payload_columns = {row[1] for row in connection.execute("PRAGMA table_info(accepted_payloads)").fetchall()}
            if "status" not in payload_columns:
                # SQLite cannot add the fresh-schema CHECK constraint through
                # ALTER TABLE. Upgraded stores enforce the domain in code.
                connection.execute("ALTER TABLE accepted_payloads ADD COLUMN status TEXT NOT NULL DEFAULT 'committed'")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_accepted_payloads_evidence_status "
                "ON accepted_payloads(evidence_id, status)"
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(pipeline_runs)").fetchall()}
            if "status" not in columns:
                connection.execute("ALTER TABLE pipeline_runs ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'")
            if "last_error" not in columns:
                connection.execute("ALTER TABLE pipeline_runs ADD COLUMN last_error TEXT")
            if "run_lease_until" not in columns:
                connection.execute("ALTER TABLE pipeline_runs ADD COLUMN run_lease_until REAL NOT NULL DEFAULT 0")
            finding_columns = {
                row[1] for row in connection.execute(
                    "PRAGMA table_info(external_findings)"
                ).fetchall()
            }
            if "last_evidence_hash" not in finding_columns:
                connection.execute(
                    "ALTER TABLE external_findings ADD COLUMN last_evidence_hash TEXT"
                )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(database=self.path, timeout=5, uri=False)
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
                "SELECT evidence_id FROM accepted_payloads WHERE payload_hash = ? AND status = 'committed'",
                (payload_hash,),
            ).fetchone()
        return None if row is None else str(row["evidence_id"])

    def begin_payload(self, payload_hash: str, evidence_id: str, now: float | None = None) -> bool:
        """Reserve a deterministic payload identity without making it processable."""
        current = time.time() if now is None else now
        with self._lock, closing(self._connect()) as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO accepted_payloads(payload_hash, evidence_id, accepted_at, status) VALUES (?, ?, ?, 'pending')",
                (payload_hash, evidence_id, current),
            )
            row = connection.execute(
                "SELECT evidence_id FROM accepted_payloads WHERE payload_hash = ?", (payload_hash,)
            ).fetchone()
            connection.commit()
        if row is None or str(row["evidence_id"]) != evidence_id:
            raise sqlite3.IntegrityError("payload identity mismatch")
        return cursor.rowcount == 1

    def commit_payload(self, payload_hash: str, evidence_id: str) -> bool:
        """Make a previously reserved payload eligible for worker processing."""
        with self._lock, closing(self._connect()) as connection:
            cursor = connection.execute(
                "UPDATE accepted_payloads SET status = 'committed' WHERE payload_hash = ? AND evidence_id = ?",
                (payload_hash, evidence_id),
            )
            connection.commit()
        return cursor.rowcount == 1

    def is_evidence_committed(self, evidence_id: str) -> bool:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT 1 FROM accepted_payloads WHERE evidence_id = ? AND status = 'committed'", (evidence_id,)
            ).fetchone()
        return row is not None

    def find_payload_by_evidence_id(self, evidence_id: str) -> dict[str, Any] | None:
        """Look up a payload record by its public evidence_id (not payload_hash).

        Returns the record regardless of status - 'pending' or 'committed' -
        the caller decides what to do with each; this method just reports
        what accepted_payloads currently has for that evidence_id, or None
        if there is no row at all.

        Used by publication reconciliation: given a file already on disk
        (named by its evidence_id), find whether accepted_payloads has a
        matching row and what its status is, so a crash between the file
        becoming durable and commit_payload() being called can be detected
        and self-healed instead of leaving the record stuck as 'pending'
        forever.
        """
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload_hash, evidence_id, accepted_at, status "
                "FROM accepted_payloads WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        return None if row is None else dict(row)

    def remember_payload(self, payload_hash: str, evidence_id: str, now: float | None = None) -> bool:
        """Persist an accepted payload and report whether this call created it."""
        current = time.time() if now is None else now
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO accepted_payloads(payload_hash, evidence_id, accepted_at) VALUES (?, ?, ?)",
                (payload_hash, evidence_id, current),
            )
            connection.commit()
        return cursor.rowcount == 1

    def claim_pipeline_run(self, input_hash: str, now: float | None = None, lease_seconds: int = 900) -> bool:
        current = time.time() if now is None else now
        with closing(self._connect()) as connection:
            connection.execute(BEGIN_IMMEDIATE_SQL)
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

    def get_external_finding(self, finding_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM external_findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = json.loads(result.pop("details_json"))
        return result

    def upsert_external_finding(self, finding: dict[str, Any], now: float | None = None) -> bool:
        """Store an external governed finding and return True only on creation.

        A stable connector-derived finding ID makes a repeated evidence bundle
        reassess the existing record rather than create a duplicate.
        """
        required = {
            "finding_id", "source", "control_id", "asset_id", "title",
            "risk_owner", "severity", "details",
        }
        missing = required.difference(finding)
        if missing:
            raise ValueError(f"External finding is missing fields: {sorted(missing)}")
        if finding["severity"] not in {"low", "medium", "high", "critical"}:
            raise ValueError("External finding severity is invalid.")

        current = time.time() if now is None else now
        details_json = json.dumps(finding["details"], sort_keys=True, separators=(",", ":"))
        values = (
            finding["finding_id"], finding["source"], finding["control_id"],
            finding["asset_id"], finding["title"], finding["risk_owner"],
            finding["severity"], details_json,
        )
        with self._lock, closing(self._connect()) as connection:
            connection.execute(BEGIN_IMMEDIATE_SQL)
            exists = connection.execute(
                "SELECT 1 FROM external_findings WHERE finding_id = ?", (finding["finding_id"],)
            ).fetchone() is not None
            if exists:
                connection.execute(
                    """
                    UPDATE external_findings
                    SET source = ?, control_id = ?, asset_id = ?, title = ?, risk_owner = ?,
                        severity = ?, details_json = ?, updated_at = ?,
                        reassessment_count = reassessment_count + 1
                    WHERE finding_id = ?
                    """,
                    (
                        finding["source"], finding["control_id"], finding["asset_id"],
                        finding["title"], finding["risk_owner"], finding["severity"],
                        details_json, current, finding["finding_id"],
                    ),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO external_findings(
                        finding_id, source, control_id, asset_id, title, risk_owner,
                        severity, details_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values + (current, current),
                )
            connection.commit()
        return not exists

    def record_external_finding_import(
        self,
        finding: dict[str, Any],
        evidence_hash: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Atomically persist a bridge import and its deterministic audit outbox event."""
        required = {
            "finding_id", "source", "control_id", "asset_id", "title",
            "risk_owner", "severity", "details",
        }
        missing = required.difference(finding)
        if missing:
            raise ValueError(f"External finding is missing fields: {sorted(missing)}")
        if finding["severity"] not in {"low", "medium", "high", "critical"}:
            raise ValueError("External finding severity is invalid.")
        if (
            not isinstance(evidence_hash, str)
            or len(evidence_hash) != 64
            or any(character not in "0123456789abcdef" for character in evidence_hash)
        ):
            raise ValueError("evidence_hash must be a lowercase SHA-256 digest")

        current = time.time() if now is None else now
        details_json = json.dumps(
            finding["details"], sort_keys=True, separators=(",", ":")
        )
        finding_id = finding["finding_id"]
        with self._lock, closing(self._connect()) as connection:
            connection.execute(BEGIN_IMMEDIATE_SQL)
            prior_import = connection.execute(
                """
                SELECT 1 FROM external_finding_audit_outbox
                WHERE finding_id = ? AND evidence_hash = ?
                """,
                (finding_id, evidence_hash),
            ).fetchone()
            existing = connection.execute(
                "SELECT last_evidence_hash FROM external_findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if prior_import is not None:
                action = "replayed"
            elif existing is None:
                action = "created"
                connection.execute(
                    """
                    INSERT INTO external_findings(
                        finding_id, source, control_id, asset_id, title, risk_owner,
                        severity, details_json, created_at, updated_at, last_evidence_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id, finding["source"], finding["control_id"],
                        finding["asset_id"], finding["title"], finding["risk_owner"],
                        finding["severity"], details_json, current, current, evidence_hash,
                    ),
                )
            else:
                action = "reassessed"
                connection.execute(
                    """
                    UPDATE external_findings
                    SET source = ?, control_id = ?, asset_id = ?, title = ?, risk_owner = ?,
                        severity = ?, details_json = ?, updated_at = ?,
                        reassessment_count = reassessment_count + 1,
                        last_evidence_hash = ?
                    WHERE finding_id = ?
                    """,
                    (
                        finding["source"], finding["control_id"], finding["asset_id"],
                        finding["title"], finding["risk_owner"], finding["severity"],
                        details_json, current, evidence_hash, finding_id,
                    ),
                )

            if action != "replayed":
                event_type = f"bridge.minisoar.finding.{action}"
                event_id = hashlib.sha256(
                    f"minisoar-audit|{finding_id}|{evidence_hash}|{event_type}".encode()
                ).hexdigest()[:24]
                audit_details = json.dumps(
                    {"control_id": finding["control_id"], "source": finding["source"]},
                    sort_keys=True,
                    separators=(",", ":"),
                )
                connection.execute(
                    """
                    INSERT INTO external_finding_audit_outbox(
                        event_id, finding_id, evidence_hash, event_type,
                        details_json, created_at, delivered_at
                    ) VALUES (?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        event_id, finding_id, evidence_hash, event_type,
                        audit_details, current,
                    ),
                )

            outbox = connection.execute(
                """
                SELECT event_id, finding_id, evidence_hash, event_type,
                       details_json, delivered_at
                FROM external_finding_audit_outbox
                WHERE finding_id = ? AND evidence_hash = ?
                """,
                (finding_id, evidence_hash),
            ).fetchone()
            connection.commit()

        audit_event = None
        if outbox is not None and outbox["delivered_at"] is None:
            audit_event = dict(outbox)
            audit_event["details"] = json.loads(audit_event.pop("details_json"))
        return {"action": action, "audit_event": audit_event}

    def mark_external_finding_audit_delivered(
        self,
        event_id: str,
        now: float | None = None,
    ) -> None:
        current = time.time() if now is None else now
        with self._lock, closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                UPDATE external_finding_audit_outbox
                SET delivered_at = COALESCE(delivered_at, ?)
                WHERE event_id = ?
                """,
                (current, event_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("unknown external finding audit event")
            connection.commit()

    def get_external_finding_audit_event(self, event_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM external_finding_audit_outbox WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = json.loads(result.pop("details_json"))
        return result

    def export_metadata(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            nonce_count = connection.execute("SELECT COUNT(*) FROM replay_nonces").fetchone()[0]
            payload_count = connection.execute("SELECT COUNT(*) FROM accepted_payloads").fetchone()[0]
        return {"replay_nonce_count": nonce_count, "accepted_payload_count": payload_count}

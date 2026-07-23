"""Bridge closed JML-Automation requests into SentinelGRC findings.

The source database is always opened with SQLite ``mode=ro``. This bridge
therefore cannot mutate JML lifecycle state, even when called by mistake with
an operator account that can access the database file.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from audit_log import AuditLog
from jml_connector import normalize_jml_request
from state_store import SQLiteStateStore

CONNECTOR_ACTOR = "jml-bridge-connector"


def _read_only_connection(db_path: str) -> sqlite3.Connection:
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _latest_verification(connection: sqlite3.Connection, request_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT * FROM verifications WHERE request_id = ? ORDER BY verification_id DESC LIMIT 1",
        (request_id,),
    ).fetchone()
    return None if row is None else dict(row)


def run_jml_bridge(
    jml_db: str,
    governance_db: str,
    request_id: str | None = None,
    *,
    audit_log_path: str | None = None,
) -> dict[str, Any]:
    """Read JML request rows read-only and upsert eligible governance findings."""
    result: dict[str, Any] = {
        "requests_read": 0,
        "findings_created": 0,
        "findings_reassessed": 0,
        "skipped": 0,
        "errors": 0,
        "finding_ids": [],
    }
    try:
        connection = _read_only_connection(jml_db)
    except (OSError, ValueError, sqlite3.Error):
        result["errors"] = 1
        result["skip_reason"] = "could not open JML database read-only"
        return result

    try:
        query = "SELECT * FROM jml_requests"
        params: tuple[str, ...] = ()
        if request_id is not None:
            query += " WHERE request_id = ?"
            params = (request_id,)
        rows = connection.execute(query, params).fetchall()
        store = SQLiteStateStore(governance_db)
        audit_path = audit_log_path or str(Path(governance_db).with_suffix(".audit.jsonl"))
        audit = AuditLog(audit_path)

        for row in rows:
            result["requests_read"] += 1
            request = dict(row)
            try:
                normalized = normalize_jml_request(
                    request, _latest_verification(connection, request["request_id"]),
                )
            except (TypeError, ValueError):
                result["errors"] += 1
                continue
            if normalized is None:
                result["skipped"] += 1
                continue

            created = store.upsert_external_finding(normalized)
            result["finding_ids"].append(normalized["finding_id"])
            result["findings_created" if created else "findings_reassessed"] += 1
            audit.append(
                "bridge.jml.finding.created" if created else "bridge.jml.finding.reassessed",
                CONNECTOR_ACTOR,
                normalized["finding_id"],
                {"control_id": normalized["control_id"], "source": normalized["source"]},
            )
    except sqlite3.Error:
        result["errors"] += 1
        result["skip_reason"] = "could not read JML request records"
    finally:
        connection.close()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bridge closed, verified JML-Automation requests into SentinelGRC findings.",
    )
    parser.add_argument("--jml-db", required=True)
    parser.add_argument("--governance-db", required=True)
    parser.add_argument("--request", help="Bridge exactly one request ID.")
    parser.add_argument("--audit-log", help="Optional SentinelGRC audit-log location.")
    args = parser.parse_args()
    result = run_jml_bridge(args.jml_db, args.governance_db, args.request, audit_log_path=args.audit_log)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

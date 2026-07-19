"""Evidence metadata and retention boundary.

Raw evidence is intentionally outside this module. Production should back the
metadata index with encrypted object storage and enforce download authorization
at the API gateway.
"""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any


class EvidenceMetadataStore:
    def __init__(self, path: str = "runtime/evidence-index.db") -> None:
        self.path = str(Path(path))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS evidence_index (
                    evidence_id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    collected_by TEXT NOT NULL,
                    retention_until TEXT,
                    review_status TEXT NOT NULL DEFAULT 'pending'
                )
            """)
            db.commit()

    def register(self, finding_id: str, source: str, content: bytes | str,
                 classification: str, collected_by: str,
                 retention_until: str | None = None) -> dict[str, Any]:
        if not finding_id.strip() or not source.strip() or not classification.strip():
            raise ValueError("finding_id, source and classification are required")
        if not collected_by.strip():
            raise ValueError("collected_by is required")
        raw = content.encode("utf-8") if isinstance(content, str) else content
        evidence_id = "EV-" + uuid.uuid4().hex[:12].upper()
        record = {
            "evidence_id": evidence_id,
            "finding_id": finding_id,
            "source": source,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "classification": classification,
            "collected_by": collected_by,
            "retention_until": retention_until,
            "review_status": "pending",
        }
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("INSERT INTO evidence_index VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       tuple(record.values()))
            db.commit()
        return record

    def authorize_download(self, evidence_id: str, actor_id: str, role: str) -> dict[str, Any]:
        if not actor_id.strip() or role not in {"analyst", "approver", "ciso", "risk_committee"}:
            raise PermissionError("role cannot download evidence")
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT * FROM evidence_index WHERE evidence_id = ?",
                             (evidence_id,)).fetchone()
        if row is None:
            raise KeyError(f"evidence {evidence_id} was not found")
        return dict(zip(("evidence_id", "finding_id", "source", "sha256",
                         "classification", "collected_by", "retention_until", "review_status"), row))

    def mark_reviewed(self, evidence_id: str, status: str) -> None:
        if status not in {"accepted", "rejected", "expired"}:
            raise ValueError("invalid evidence review status")
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE evidence_index SET review_status = ? WHERE evidence_id = ?",
                       (status, evidence_id))
            db.commit()

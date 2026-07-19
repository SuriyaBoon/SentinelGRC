"""Authenticated connector event boundary for enterprise integrations."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any


class ConnectorEventStore:
    def __init__(self, path: str = "runtime/connector-events.db") -> None:
        self.path = str(Path(path))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS connector_events (
                    event_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    accepted_at REAL NOT NULL
                )
            """)
            db.commit()

    def reserve(self, event_id: str, source: str, payload_hash: str) -> bool:
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            try:
                db.execute(
                    "INSERT INTO connector_events VALUES (?, ?, ?, ?)",
                    (event_id, source, payload_hash, time.time()),
                )
            except sqlite3.IntegrityError:
                db.rollback()
                return False
            db.commit()
            return True


def sign_event(payload: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_event_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = sign_event(payload, secret)
    provided = signature.removeprefix("sha256=")
    return hmac.compare_digest(expected, provided)


def ingest_event(
    raw: bytes,
    *,
    source: str,
    event_id: str,
    signature: str,
    secret: str,
    store: ConnectorEventStore,
    max_bytes: int = 1_048_576,
) -> dict[str, Any]:
    if not source.strip() or not event_id.strip():
        raise ValueError("source and event_id are required")
    if len(raw) > max_bytes:
        raise ValueError("connector payload exceeds size limit")
    if not verify_event_signature(raw, signature, secret):
        raise PermissionError("invalid connector signature")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("connector payload must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("connector payload must be an object")
    payload_hash = hashlib.sha256(raw).hexdigest()
    accepted = store.reserve(event_id, source, payload_hash)
    return {
        "status": "accepted" if accepted else "duplicate",
        "event_id": event_id,
        "source": source,
        "payload_hash": payload_hash,
        "payload": payload if accepted else None,
    }

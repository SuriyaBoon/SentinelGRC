"""Append-only, hash-chained audit events for enterprise governance operations."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class AuditLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists() or not self.path.read_text(encoding="utf-8").strip():
            return GENESIS_HASH
        valid, message = self.verify()
        if not valid:
            raise ValueError(f"Refusing to append to invalid audit log: {message}")
        record = json.loads(self.path.read_text(encoding="utf-8").splitlines()[-1])
        return record["event_hash"]

    def append(self, event_type: str, actor: str, target: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        record = {
            "schema_version": "1.0",
            "event_id": hashlib.sha256(f"{datetime.now(timezone.utc).timestamp()}:{event_type}:{target}".encode()).hexdigest()[:24],
            "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "actor": actor,
            "target": target,
            "details": details or {},
            "previous_hash": self._last_hash(),
        }
        record["event_hash"] = hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as file:
            file.write(canonical_json(record) + "\n")
        return record

    def verify(self) -> tuple[bool, str]:
        if not self.path.exists():
            return True, "Audit log is empty."
        previous = GENESIS_HASH
        try:
            for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
                record = json.loads(line)
                if not isinstance(record, dict):
                    return False, f"Audit record {number} is not an object."
                supplied = record.pop("event_hash", None)
                calculated = hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
                if record.get("previous_hash") != previous or supplied != calculated:
                    return False, f"Audit integrity failed at record {number}."
                previous = supplied
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
            return False, "Audit log could not be parsed safely."
        return True, "Audit log integrity verified."

"""Append-only, hash-chained audit events for enterprise governance operations."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass
from typing import Any

from file_lock import locked_file

GENESIS_HASH = "0" * 64

@dataclass(frozen=True)
class AuthenticatedActor:
    actor_id: str
    actor_type: str
    role: str | None = None
    auth_method: str = "unknown"

    def __post_init__(self) -> None:
        if not self.actor_id.strip() or self.actor_type not in {"human", "agent", "system"}:
            raise ValueError("actor_id and valid actor_type are required")
        if not self.auth_method.strip():
            raise ValueError("auth_method is required")

    def snapshot(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "actor_type": self.actor_type,
            "role": self.role,
            "auth_method": self.auth_method,
        }


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): normalize(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    if isinstance(value, float):
        if not __import__("math").isfinite(value):
            raise ValueError("non-finite numbers are not permitted in audit records")
        return value
    raise TypeError(f"unsupported audit value: {type(value).__name__}")

def canonical_json(value: Any) -> str:
    return json.dumps(normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class AuditLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _verify_unlocked(self) -> tuple[bool, str]:
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

    def _last_hash_unlocked(self) -> str:
        if not self.path.exists() or not self.path.read_text(encoding="utf-8").strip():
            return GENESIS_HASH
        valid, message = self._verify_unlocked()
        if not valid:
            raise ValueError(f"Refusing to append to invalid audit log: {message}")
        return json.loads(self.path.read_text(encoding="utf-8").splitlines()[-1])["event_hash"]

    def append(self, event_type: str, actor: str | AuthenticatedActor,
               target: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        with locked_file(str(self.path) + ".lock"):
            record = {
                "schema_version": "1.0",
                "event_id": hashlib.sha256(f"{datetime.now(timezone.utc).timestamp()}:{event_type}:{target}".encode()).hexdigest()[:24],
                "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "event_type": event_type,
                "actor": actor.snapshot() if isinstance(actor, AuthenticatedActor) else actor,
                "target": target,
                "details": details or {},
                "previous_hash": self._last_hash_unlocked(),
            }
            record["event_hash"] = hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
            with self.path.open("a", encoding="utf-8") as file:
                file.write(canonical_json(record) + "\n")
                file.flush()
                os.fsync(file.fileno())
            return record

    def append_human_event(self, event_type: str, actor: AuthenticatedActor,
                           target: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        if actor.actor_type != "human" or not actor.role:
            raise ValueError("human audit events require a role")
        return self.append(event_type, actor, target, details)

    def append_agent_event(self, event_type: str, actor: AuthenticatedActor,
                           target: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        if actor.actor_type != "agent":
            raise ValueError("agent audit events require an agent actor")
        return self.append(event_type, actor, target, details)

    def append_system_event(self, event_type: str, actor: AuthenticatedActor,
                            target: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        if actor.actor_type != "system":
            raise ValueError("system audit events require a system actor")
        return self.append(event_type, actor, target, details)

    def verify(self) -> tuple[bool, str]:
        with locked_file(str(self.path) + ".lock"):
            return self._verify_unlocked()

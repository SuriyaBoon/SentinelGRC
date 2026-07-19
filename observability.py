"""Small dependency-free observability contract with redaction."""

from __future__ import annotations

import json
import time
from collections import Counter
from typing import Any

SENSITIVE_KEYS = {"secret", "token", "authorization", "api_key", "content", "payload"}


def structured_event(event_type: str, *, correlation_id: str, **fields: Any) -> str:
    event = {
        "event_type": event_type,
        "correlation_id": correlation_id,
        "occurred_at": time.time(),
    }
    for key, value in fields.items():
        event[key] = "[REDACTED]" if key.lower() in SENSITIVE_KEYS else value
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


class Metrics:
    def __init__(self) -> None:
        self._counters: Counter[str] = Counter()

    def increment(self, name: str, amount: int = 1) -> None:
        if not name.strip():
            raise ValueError("metric name is required")
        self._counters[name] += amount

    def snapshot(self) -> dict[str, int]:
        return dict(self._counters)

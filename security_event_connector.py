"""Example LogWatcher/SOC security-event adapter."""

from __future__ import annotations

import hashlib
from typing import Any


def normalize_security_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "EventID" in event:
        event = {
            "event_code": event.get("EventID"),
            "event_id": event.get("EventRecordID") or "|".join([
                str(event.get("TimeCreated", "")),
                str(event.get("Computer", "")),
                str(event.get("TargetUserName", "")),
                str(event.get("IpAddress", "")),
            ]),
            "asset_id": event.get("Computer"),
            "timestamp": event.get("TimeCreated"),
            "account": event.get("TargetUserName"),
            "source_ip": event.get("IpAddress"),
            "privileged": str(event.get("TargetUserName", "")).lower() in {"administrator", "admin"},
            "status": event.get("status", "open"),
        }
    if event.get("event_code") != 4625 or event.get("status", "open") in {"closed", "resolved"}:
        return None
    required = ("event_id", "asset_id", "timestamp", "account")
    missing = [field for field in required if not str(event.get(field, "")).strip()]
    if missing:
        raise ValueError(f"security event missing: {', '.join(missing)}")
    privileged = bool(event.get("privileged"))
    identity = "|".join([
        "logwatcher", str(event["event_id"]), str(event["asset_id"]),
        str(event["account"]),
    ])
    return {
        "finding_id": "SEC-AUTH-" + hashlib.sha256(identity.encode()).hexdigest()[:16].upper(),
        "domain": "security",
        "source": "logwatcher",
        "control_id": "SEC-AUTH-001",
        "asset_id": str(event["asset_id"]),
        "title": f"Failed logon detected for {event['account']}",
        "risk_owner": str(event.get("owner") or "Security Operations"),
        "severity": "critical" if privileged else "high",
        "details": {
            "event_code": 4625,
            "event_id": str(event["event_id"]),
            "timestamp": str(event["timestamp"]),
            "source_ip": event.get("source_ip"),
            "account": str(event["account"]),
            "privileged": privileged,
        },
    }

"""Example LogWatcher/SOC security-event adapter."""

from __future__ import annotations

import hashlib
from typing import Any


def normalize_logwatcher_alert(alert: dict[str, Any]) -> dict[str, Any] | None:
    kind = str(alert.get("kind", "")).strip()
    if not kind:
        raise ValueError("LogWatcher alert kind is required")
    control_by_kind = {
        "brute_force": "SEC-AUTH-001",
        "account_lockout": "SEC-IAM-002",
        "privilege_escalation": "SEC-IAM-003",
    }
    if kind not in control_by_kind:
        raise ValueError(f"unsupported LogWatcher alert kind: {kind}")
    identity = "|".join([
        "logwatcher-alert", kind, str(alert.get("timestamp", "")),
        str(alert.get("computer", "")), str(alert.get("source_ip", "")),
        str(alert.get("target_user", "")), str(alert.get("message", "")),
    ])
    if identity.endswith("||||"):
        raise ValueError("LogWatcher alert has no stable identity fields")
    return {
        "finding_id": "SEC-ALERT-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16].upper(),
        "domain": "security",
        "source": "logwatcher_alert",
        "control_id": control_by_kind[kind],
        "asset_id": str(alert.get("computer") or "unknown"),
        "title": str(alert.get("message") or kind.replace("_", " ").title()),
        "risk_owner": "Security Operations",
        "severity": str(alert.get("severity") or "high").lower(),
        "details": {
            "kind": kind,
            "timestamp": alert.get("timestamp"),
            "source_ip": alert.get("source_ip"),
            "target_user": alert.get("target_user"),
            "event_id": alert.get("event_id"),
        },
    }


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

"""Strict, versioned security-alert contract for external detection sources."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import timezone
from typing import Any

from contract_validation import (
    IDENTIFIER,
    SOURCE_IDENTIFIER,
    is_canonical_text,
    is_evidence_reference,
    parse_rfc3339,
)


SCHEMA_VERSION = "security_alert.v1"
ALLOWED_FIELDS = {
    "schema_version",
    "source",
    "source_event_id",
    "observed_at",
    "asset_id",
    "kind",
    "severity",
    "title",
    "risk_owner",
    "event_code",
    "source_ip",
    "target_user",
    "evidence_refs",
}
REQUIRED_FIELDS = {
    "schema_version",
    "source",
    "source_event_id",
    "observed_at",
    "asset_id",
    "kind",
    "severity",
    "title",
    "risk_owner",
    "event_code",
    "evidence_refs",
}
CONTROL_BY_KIND = {
    "brute_force": "SEC-AUTH-001",
    "account_lockout": "SEC-IAM-002",
    "privilege_escalation": "SEC-IAM-003",
}
EVENT_CODE_BY_KIND = {
    "brute_force": 4625,
    "account_lockout": 4740,
    "privilege_escalation": 4672,
}
SEVERITIES = {"low", "medium", "high", "critical"}


def _required_text(payload: dict[str, Any], name: str, maximum: int) -> str:
    value = payload.get(name)
    if not is_canonical_text(value, maximum):
        raise ValueError(f"security alert {name} is invalid")
    return value


def _timestamp(value: Any) -> str:
    parsed = parse_rfc3339(value, "security alert", "observed_at")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _evidence_refs(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 20:
        raise ValueError("security alert evidence_refs must contain 1-20 references")
    references: list[str] = []
    for item in value:
        if not is_evidence_reference(item):
            raise ValueError("security alert evidence reference is not approved")
        references.append(item)
    if len(set(references)) != len(references):
        raise ValueError("security alert evidence references must be unique")
    return references


def _validate_alert_shape(alert: dict[str, Any]) -> None:
    for key in alert:
        if not isinstance(key, str):
            raise ValueError("security alert field names must be strings")
    unknown = sorted(set(alert) - ALLOWED_FIELDS)
    missing = sorted(REQUIRED_FIELDS - set(alert))
    if unknown:
        raise ValueError("security alert contains unknown fields: " + ", ".join(unknown))
    if missing:
        raise ValueError("security alert missing fields: " + ", ".join(missing))
    if alert.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"security alert schema_version must be {SCHEMA_VERSION}")


def _required_alert_fields(
    alert: dict[str, Any],
) -> tuple[str, str, str, str, str]:
    source = _required_text(alert, "source", 64)
    source_event_id = _required_text(alert, "source_event_id", 128)
    asset_id = _required_text(alert, "asset_id", 128)
    title = _required_text(alert, "title", 512)
    risk_owner = _required_text(alert, "risk_owner", 128)
    for name, value in (
        ("source", source),
        ("source_event_id", source_event_id),
        ("asset_id", asset_id),
        ("risk_owner", risk_owner),
    ):
        if IDENTIFIER.fullmatch(value) is None:
            raise ValueError(f"security alert {name} is invalid")
    if SOURCE_IDENTIFIER.fullmatch(source) is None:
        raise ValueError("security alert source must use canonical lowercase")
    return source, source_event_id, asset_id, title, risk_owner


def _event_fields(
    alert: dict[str, Any],
) -> tuple[str, str, Any, str, list[str]]:
    kind = _required_text(alert, "kind", 64)
    severity = _required_text(alert, "severity", 16)
    if kind not in CONTROL_BY_KIND:
        raise ValueError(f"unsupported security alert kind: {kind}")
    if severity not in SEVERITIES:
        raise ValueError("security alert severity is invalid")
    event_code = alert.get("event_code")
    if isinstance(event_code, bool) or event_code != EVENT_CODE_BY_KIND[kind]:
        raise ValueError("security alert event_code does not match kind")
    observed_at = _timestamp(alert.get("observed_at"))
    references = _evidence_refs(alert.get("evidence_refs"))
    return kind, severity, event_code, observed_at, references


def _optional_context(alert: dict[str, Any]) -> tuple[str | None, str | None]:
    source_ip = alert.get("source_ip")
    if source_ip is not None:
        if not is_canonical_text(source_ip, 64):
            raise ValueError("security alert source_ip is invalid")
        try:
            ipaddress.ip_address(source_ip)
        except ValueError as error:
            raise ValueError("security alert source_ip is invalid") from error
    target_user = alert.get("target_user")
    if target_user is not None and not is_canonical_text(target_user, 256):
        raise ValueError("security alert target_user is invalid")
    return source_ip, target_user


def normalize_security_alert_v1(alert: dict[str, Any]) -> dict[str, Any]:
    """Validate one canonical alert and convert it to a governance finding."""

    if not isinstance(alert, dict):
        raise ValueError("security alert must be an object")
    _validate_alert_shape(alert)
    source, source_event_id, asset_id, title, risk_owner = _required_alert_fields(
        alert
    )
    kind, severity, event_code, observed_at, references = _event_fields(alert)
    source_ip, target_user = _optional_context(alert)

    identity = "|".join((SCHEMA_VERSION, source, source_event_id, asset_id, kind))
    return {
        "finding_id": "SEC-ALERT-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16].upper(),
        "domain": "security",
        "source": source,
        "control_id": CONTROL_BY_KIND[kind],
        "asset_id": asset_id,
        "title": title,
        "risk_owner": risk_owner,
        "severity": severity,
        "details": {
            "schema_version": SCHEMA_VERSION,
            "source_event_id": source_event_id,
            "observed_at": observed_at,
            "kind": kind,
            "event_code": event_code,
            "source_ip": source_ip,
            "target_user": target_user,
            "evidence_refs": references,
        },
    }

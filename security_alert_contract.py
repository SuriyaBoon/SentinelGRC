"""Strict, versioned security-alert contract for external detection sources."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit


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
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
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
EVIDENCE_SCHEMES = {"https", "urn", "azblob", "sample"}


def _required_text(payload: dict[str, Any], name: str, maximum: int) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise ValueError(f"security alert {name} is invalid")
    return value.strip()


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("security alert observed_at is invalid")
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError("security alert observed_at is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("security alert observed_at must include a timezone")
    return value.strip()


def _evidence_refs(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 20:
        raise ValueError("security alert evidence_refs must contain 1-20 references")
    references: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item.strip()) > 512:
            raise ValueError("security alert evidence reference is invalid")
        reference = item.strip()
        parsed = urlsplit(reference)
        if parsed.scheme not in EVIDENCE_SCHEMES or parsed.username or parsed.password:
            raise ValueError("security alert evidence reference is not approved")
        if parsed.scheme in {"https", "azblob", "sample"} and not parsed.netloc:
            raise ValueError("security alert evidence reference is incomplete")
        references.append(reference)
    if len(set(references)) != len(references):
        raise ValueError("security alert evidence references must be unique")
    return references


def _validate_alert_shape(alert: dict[str, Any]) -> None:
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
    source = _required_text(alert, "source", 64).lower()
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
    return source, source_event_id, asset_id, title, risk_owner


def _event_fields(
    alert: dict[str, Any],
) -> tuple[str, str, Any, str, list[str]]:
    kind = _required_text(alert, "kind", 64).lower()
    severity = _required_text(alert, "severity", 16).lower()
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
        if not isinstance(source_ip, str):
            raise ValueError("security alert source_ip is invalid")
        try:
            ipaddress.ip_address(source_ip)
        except ValueError as error:
            raise ValueError("security alert source_ip is invalid") from error
    target_user = alert.get("target_user")
    if target_user is not None and (
        not isinstance(target_user, str)
        or not target_user.strip()
        or len(target_user.strip()) > 256
    ):
        raise ValueError("security alert target_user is invalid")
    normalized_user = (
        target_user.strip() if isinstance(target_user, str) else None
    )
    return source_ip, normalized_user


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

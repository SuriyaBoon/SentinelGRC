"""Normalize closed Mini-SOAR evidence into governed SentinelGRC findings.

The connector is intentionally read-only with respect to Mini-SOAR. It reads
the exported evidence bundle, derives a stable finding identity, and leaves
actor identity to the trusted local bridge process.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

from contract_validation import (
    is_canonical_text,
    is_evidence_reference,
    is_source_identifier,
)

_CONTROL_BY_KIND = {
    "brute_force": "SEC-AUTH-001",
    "privilege_escalation": "SEC-IAM-003",
    "malware": "SEC-END-001",
}
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_UPSTREAM_ALERT_ID = re.compile(r"ALT-[0-9A-F]{16}", re.ASCII)
_UPSTREAM_FINDING_ID = re.compile(r"FND-[0-9A-F]{16}", re.ASCII)


def _text(record: dict[str, Any], name: str, maximum: int, label: str) -> str:
    value = record.get(name)
    if not is_canonical_text(value, maximum):
        raise ValueError(f"Mini-SOAR {label} {name} is invalid")
    return value


def _optional_text(
    record: dict[str, Any], name: str, maximum: int, label: str
) -> str | None:
    value = record.get(name)
    if value is None:
        return None
    if not is_canonical_text(value, maximum):
        raise ValueError(f"Mini-SOAR {label} {name} is invalid")
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _normalize_upstream_timestamp(value: str) -> str:
    """Accept Mini-SOAR's timezone-aware ISO profile and emit UTC RFC3339."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Mini-SOAR alert detected_at is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("Mini-SOAR alert detected_at is invalid")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _source_payload(
    *,
    source: str,
    source_event_id: str,
    kind: str,
    severity: str,
    detected_at: str,
    asset_id: str,
    account: str | None,
    source_ip: str | None,
    message: str,
    evidence_ref: str | None,
    environment: str,
    risk_owner: str,
) -> dict[str, Any]:
    """Reconstruct the canonical producer input represented by an export."""
    payload: dict[str, Any] = {
        "source": source,
        "source_event_id": source_event_id,
        "kind": kind,
        "severity": severity,
        "detected_at": detected_at,
        "asset_id": asset_id,
        "message": message,
        "environment": environment,
        "risk_owner": risk_owner,
    }
    for name, value in (
        ("account", account),
        ("source_ip", source_ip),
        ("evidence_ref", evidence_ref),
    ):
        if value is not None:
            payload[name] = value
    return payload


def _verification_succeeded(verification: dict[str, Any] | None) -> bool:
    if not isinstance(verification, dict):
        return False
    passed = verification.get("passed")
    return passed is True or (type(passed) is int and passed == 1)


def _validated_alert(alert: dict[str, Any]) -> dict[str, Any]:
    source = _text(alert, "source", 128, "alert")
    source_event_id = _text(alert, "source_event_id", 128, "alert")
    asset_id = _text(alert, "asset_id", 128, "alert")
    kind = _text(alert, "kind", 64, "alert")
    severity = _text(alert, "severity", 16, "alert")
    if not is_source_identifier(source):
        raise ValueError("Mini-SOAR alert source is invalid")
    if kind not in _CONTROL_BY_KIND:
        raise ValueError(f"unsupported Mini-SOAR alert kind: {kind}")
    if severity not in {"low", "medium", "high", "critical"}:
        raise ValueError("Mini-SOAR alert severity is invalid")

    source_detected_at = _text(alert, "detected_at", 64, "alert")
    detected_at = _normalize_upstream_timestamp(source_detected_at)
    account = _optional_text(alert, "account", 256, "alert")
    source_ip = _optional_text(alert, "source_ip", 64, "alert")
    if source_ip is not None:
        try:
            ipaddress.ip_address(source_ip)
        except ValueError as error:
            raise ValueError("Mini-SOAR alert source_ip is invalid") from error
    evidence_ref = _optional_text(alert, "evidence_ref", 512, "alert")
    if evidence_ref is not None and not is_evidence_reference(evidence_ref):
        raise ValueError("Mini-SOAR alert evidence_ref is not approved")
    message = _text(alert, "message", 512, "alert")
    environment = _text(alert, "environment", 64, "alert")
    risk_owner = _text(alert, "risk_owner", 128, "alert")
    if environment != "synthetic-lab":
        raise ValueError("Mini-SOAR alert environment is invalid")
    if alert.get("supported") is not True:
        raise ValueError("Mini-SOAR alert supported flag is invalid")

    identity_material = {
        "source": source,
        "source_event_id": source_event_id,
        "kind": kind,
        "asset_id": asset_id,
        "account": account,
        "source_ip": source_ip,
    }
    expected_identity = hashlib.sha256(
        _canonical_json(identity_material).encode("utf-8")
    ).hexdigest()
    identity_hash = _text(alert, "identity_hash", 64, "alert")
    if identity_hash != expected_identity:
        raise ValueError("Mini-SOAR alert identity_hash is invalid")
    alert_id = _text(alert, "alert_id", 20, "alert")
    if (
        _UPSTREAM_ALERT_ID.fullmatch(alert_id) is None
        or alert_id != "ALT-" + identity_hash[:16].upper()
    ):
        raise ValueError("Mini-SOAR alert alert_id is invalid")
    payload_hash = _text(alert, "payload_hash", 64, "alert")
    expected_payload_hash = hashlib.sha256(
        _canonical_json(
            _source_payload(
                source=source,
                source_event_id=source_event_id,
                kind=kind,
                severity=severity,
                detected_at=source_detected_at,
                asset_id=asset_id,
                account=account,
                source_ip=source_ip,
                message=message,
                evidence_ref=evidence_ref,
                environment=environment,
                risk_owner=risk_owner,
            )
        ).encode("utf-8")
    ).hexdigest()
    if (
        _LOWER_SHA256.fullmatch(payload_hash) is None
        or not hmac.compare_digest(payload_hash, expected_payload_hash)
    ):
        raise ValueError("Mini-SOAR alert payload_hash is invalid")
    return {
        "source": source,
        "source_event_id": source_event_id,
        "asset_id": asset_id,
        "kind": kind,
        "severity": severity,
        "identity_hash": identity_hash,
        "alert_id": alert_id,
        "account": account,
        "source_ip": source_ip,
        "detected_at": detected_at,
        "source_detected_at": source_detected_at,
        "evidence_ref": evidence_ref,
        "message": message,
        "environment": environment,
        "risk_owner": risk_owner,
        "payload_hash": payload_hash,
    }


def _validated_finding_fields(
    finding: dict[str, Any], normalized_alert: dict[str, Any]
) -> tuple[str, str, str, str, str]:
    mini_soar_finding_id = _text(finding, "finding_id", 20, "finding")
    if (
        _UPSTREAM_FINDING_ID.fullmatch(mini_soar_finding_id) is None
        or mini_soar_finding_id
        != "FND-" + normalized_alert["identity_hash"][:16].upper()
    ):
        raise ValueError("Mini-SOAR finding finding_id is invalid")
    if finding.get("alert_id") != normalized_alert["alert_id"]:
        raise ValueError("Mini-SOAR finding does not belong to the alert")

    executor_id = _text(finding, "executor_id", 128, "finding")
    risk_owner = _text(finding, "risk_owner", 128, "finding")
    if risk_owner != normalized_alert["risk_owner"]:
        raise ValueError("Mini-SOAR finding risk_owner does not match the alert")
    severity = _text(finding, "severity", 16, "finding")
    if severity != normalized_alert["severity"]:
        raise ValueError("Mini-SOAR finding severity does not match the alert")
    title = _text(finding, "title", 512, "finding")
    if title != normalized_alert["message"]:
        raise ValueError("Mini-SOAR finding title does not match the alert")
    return mini_soar_finding_id, executor_id, risk_owner, severity, title


def _validated_verifier(
    verification: dict[str, Any] | None,
    mini_soar_finding_id: str,
    verification_passed: bool,
) -> str | None:
    if not verification_passed:
        return None
    assert isinstance(verification, dict)
    if verification.get("finding_id") != mini_soar_finding_id:
        raise ValueError("Mini-SOAR verification does not belong to the finding")
    return _text(verification, "verifier_id", 128, "verification")


def normalize_minisoar_incident(
    finding: dict[str, Any],
    alert: dict[str, Any],
    verification: dict[str, Any] | None,
    *,
    require_verification_pass: bool = True,
) -> dict[str, Any] | None:
    """Return a governed finding, or ``None`` when safety gates do not pass."""
    if not isinstance(finding, dict) or not isinstance(alert, dict):
        raise ValueError("Mini-SOAR finding and alert must be objects")
    if finding.get("status") != "closed":
        return None
    if alert.get("environment") != "synthetic-lab":
        return None

    verification_passed = _verification_succeeded(verification)
    if require_verification_pass and not verification_passed:
        return None

    normalized_alert = _validated_alert(alert)
    kind = normalized_alert["kind"]
    asset_id = normalized_alert["asset_id"]
    (
        mini_soar_finding_id,
        executor_id,
        risk_owner,
        severity,
        title,
    ) = _validated_finding_fields(finding, normalized_alert)
    verifier_id = _validated_verifier(
        verification, mini_soar_finding_id, verification_passed
    )
    if verifier_id == executor_id:
        return None

    control_id = _CONTROL_BY_KIND[kind]

    identity = f"minisoar-incident|{mini_soar_finding_id}|{control_id}|{asset_id}"
    finding_id = "SEC-IR-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16].upper()

    return {
        "finding_id": finding_id,
        "source": "minisoar_incident_response",
        "control_id": control_id,
        "asset_id": asset_id,
        "title": f"Incident response closed: {title}",
        "risk_owner": risk_owner,
        "severity": severity,
        "details": {
            "kind": kind,
            "source": normalized_alert["source"],
            "source_event_id": normalized_alert["source_event_id"],
            "source_alert_id": normalized_alert["alert_id"],
            "source_payload_hash": normalized_alert["payload_hash"],
            "source_detected_at": normalized_alert["source_detected_at"],
            "detected_at": normalized_alert["detected_at"],
            "account": normalized_alert["account"],
            "source_ip": normalized_alert["source_ip"],
            "evidence_ref": normalized_alert["evidence_ref"],
            "mini_soar_finding_id": mini_soar_finding_id,
            "playbook_id": finding.get("playbook_id"),
            "playbook_version": finding.get("playbook_version"),
            "verification_passed": verification_passed,
            "verifier_id": verifier_id,
            "execution_actor_id": executor_id,
            "simulated": True,
        },
    }

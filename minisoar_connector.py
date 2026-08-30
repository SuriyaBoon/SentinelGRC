"""Normalize closed Mini-SOAR evidence into governed SentinelGRC findings.

The connector is intentionally read-only with respect to Mini-SOAR. It reads
the exported evidence bundle, derives a stable finding identity, and leaves
actor identity to the trusted local bridge process.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any

from contract_validation import (
    is_canonical_text,
    is_evidence_reference,
    is_identifier,
    is_source_identifier,
    parse_rfc3339,
)

_CONTROL_BY_KIND = {
    "brute_force": "SEC-AUTH-001",
    "account_lockout": "SEC-IAM-002",
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


def _validated_alert(alert: dict[str, Any]) -> dict[str, Any]:
    source = _text(alert, "source", 128, "alert")
    source_event_id = _text(alert, "source_event_id", 128, "alert")
    asset_id = _text(alert, "asset_id", 128, "alert")
    kind = _text(alert, "kind", 64, "alert")
    severity = _text(alert, "severity", 16, "alert")
    if not is_source_identifier(source):
        raise ValueError("Mini-SOAR alert source is invalid")
    if not is_identifier(source_event_id) or not is_identifier(asset_id):
        raise ValueError("Mini-SOAR alert identity is invalid")
    if kind not in _CONTROL_BY_KIND:
        raise ValueError(f"unsupported Mini-SOAR alert kind: {kind}")
    if severity not in {"low", "medium", "high", "critical"}:
        raise ValueError("Mini-SOAR alert severity is invalid")

    detected_at = _text(alert, "detected_at", 64, "alert")
    parse_rfc3339(detected_at, "Mini-SOAR alert", "detected_at")
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
    if _LOWER_SHA256.fullmatch(payload_hash) is None:
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
        "evidence_ref": evidence_ref,
    }


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

    verification_passed = bool(
        isinstance(verification, dict)
        and isinstance(verification.get("passed"), (bool, int))
        and verification.get("passed") in {True, 1}
    )
    if require_verification_pass and not verification_passed:
        return None

    normalized_alert = _validated_alert(alert)
    kind = normalized_alert["kind"]
    asset_id = normalized_alert["asset_id"]
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
    verifier_id: str | None = None
    if verification_passed:
        assert isinstance(verification, dict)
        if verification.get("finding_id") != mini_soar_finding_id:
            raise ValueError("Mini-SOAR verification does not belong to the finding")
        verifier_id = _text(verification, "verifier_id", 128, "verification")
        if verifier_id == executor_id:
            return None

    control_id = _CONTROL_BY_KIND[kind]
    risk_owner = _text(finding, "risk_owner", 128, "finding")
    severity = _text(finding, "severity", 16, "finding")
    if severity != normalized_alert["severity"]:
        raise ValueError("Mini-SOAR finding severity does not match the alert")
    title = _text(finding, "title", 512, "finding")

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
            "mini_soar_finding_id": mini_soar_finding_id,
            "playbook_id": finding.get("playbook_id"),
            "playbook_version": finding.get("playbook_version"),
            "verification_passed": verification_passed,
            "verifier_id": verifier_id,
            "execution_actor_id": executor_id,
            "simulated": True,
        },
    }

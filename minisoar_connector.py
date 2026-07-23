"""Normalize closed Mini-SOAR evidence into governed SentinelGRC findings.

The connector is intentionally read-only with respect to Mini-SOAR. It reads
the exported evidence bundle, derives a stable finding identity, and leaves
actor identity to the trusted local bridge process.
"""

from __future__ import annotations

import hashlib
from typing import Any

_CONTROL_BY_KIND = {
    "brute_force": "SEC-AUTH-001",
    "account_lockout": "SEC-IAM-002",
    "privilege_escalation": "SEC-IAM-003",
    "malware": "SEC-END-001",
}


def normalize_minisoar_incident(
    finding: dict[str, Any],
    alert: dict[str, Any],
    verification: dict[str, Any] | None,
    *,
    require_verification_pass: bool = True,
) -> dict[str, Any] | None:
    """Return a governed finding, or ``None`` when safety gates do not pass."""
    if finding.get("status") != "closed":
        return None
    if alert.get("environment") != "synthetic-lab":
        return None

    verification_passed = bool(verification and verification.get("passed"))
    if require_verification_pass and not verification_passed:
        return None

    kind = str(alert.get("kind", "")).strip()
    if not kind:
        raise ValueError("Mini-SOAR alert is missing 'kind'.")
    mini_soar_finding_id = str(finding.get("finding_id", "")).strip()
    if not mini_soar_finding_id:
        raise ValueError("Mini-SOAR finding is missing 'finding_id'.")

    control_id = _CONTROL_BY_KIND.get(kind, "SEC-IR-000")
    asset_id = str(alert.get("asset_id") or "unknown")
    risk_owner = str(finding.get("risk_owner") or alert.get("risk_owner") or "Security Operations")
    severity = str(finding.get("severity") or alert.get("severity") or "high").lower()
    if severity not in {"low", "medium", "high", "critical"}:
        raise ValueError("Mini-SOAR finding severity is invalid.")
    title = str(finding.get("title") or kind.replace("_", " ").title())

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
            "simulated": True,
        },
    }

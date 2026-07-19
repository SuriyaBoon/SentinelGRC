"""Security governance domain pack.

Normalizes security observations from existing SentinelGRC collectors into the
shared finding contract consumed by GovernanceCore. It never performs changes
on endpoints or directory services.
"""

from __future__ import annotations

import hashlib
from typing import Any


def _finding_id(source: str) -> str:
    return "SEC-" + hashlib.sha256(source.encode("utf-8")).hexdigest()[:16].upper()


def build_security_findings(
    posture: dict[str, Any],
    access_review: dict[str, Any] | None = None,
    vulnerabilities: list[dict[str, Any]] | None = None,
    exposures: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    asset_id = str(posture.get("asset_id", "unknown"))
    owner = str(posture.get("owner") or "Security Operations")
    severity = str(posture.get("criticality") or "medium")
    for check in posture.get("checks", []):
        if check.get("passed") is False:
            source = f"posture:{asset_id}:{check.get('name')}"
            findings.append({
                "finding_id": _finding_id(source),
                "domain": "security",
                "source": "endpoint_posture",
                "control_id": str(check.get("name")),
                "asset_id": asset_id,
                "title": f"Endpoint control failed: {check.get('name')}",
                "risk_owner": owner,
                "severity": severity,
                "details": {"value": check.get("value"), "error": check.get("error")},
            })

    for user in (access_review or {}).get("users", []):
        if user.get("stale") and (user.get("enabled") or user.get("privileged")):
            account = str(user.get("sam_account_name", "unknown"))
            source = f"ad-access:{account}:{(access_review or {}).get('reviewed_at')}"
            findings.append({
                "finding_id": _finding_id(source),
                "domain": "security",
                "source": "ad_access_review",
                "control_id": "IAM-STALE-ACCOUNT",
                "asset_id": asset_id,
                "title": f"Stale account requires review: {account}",
                "risk_owner": "Identity Governance",
                "severity": "critical" if user.get("privileged") else "high",
                "details": {"enabled": bool(user.get("enabled")), "privileged": bool(user.get("privileged"))},
            })

    for item in vulnerabilities or []:
        if item.get("status", "open") == "open":
            source = f"vulnerability:{asset_id}:{item.get('id')}"
            findings.append({
                "finding_id": _finding_id(source),
                "domain": "security",
                "source": "vulnerability_scanner",
                "control_id": "VULN-OPEN",
                "asset_id": asset_id,
                "title": str(item.get("title") or "Open vulnerability"),
                "risk_owner": str(item.get("owner") or owner),
                "severity": str(item.get("severity") or "high"),
                "details": {"cve": item.get("cve"), "cvss": item.get("cvss")},
            })

    for item in exposures or []:
        if item.get("exposed") is True:
            source = f"exposure:{asset_id}:{item.get('id')}"
            findings.append({
                "finding_id": _finding_id(source),
                "domain": "security",
                "source": "network_exposure",
                "control_id": "NET-EXPOSURE",
                "asset_id": asset_id,
                "title": str(item.get("title") or "Unapproved network exposure"),
                "risk_owner": str(item.get("owner") or owner),
                "severity": str(item.get("severity") or "high"),
                "details": {"endpoint": item.get("endpoint"), "port": item.get("port")},
            })
    return findings

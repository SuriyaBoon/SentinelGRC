"""Executive KPI/KRI reporting over normalized governance findings."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


def build_executive_report(
    findings: list[dict[str, Any]],
    *,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    now = generated_at or datetime.now(timezone.utc)
    statuses = Counter(str(item.get("status", "open")) for item in findings)
    severities = Counter(str(item.get("severity", "unknown")).lower() for item in findings)
    domains = Counter(str(item.get("domain", "security")) for item in findings)
    overdue = [
        item for item in findings
        if item.get("due_date") and str(item["due_date"]) < now.date().isoformat()
        and item.get("status") not in {"closed", "verified", "accepted"}
    ]
    verification_failed = sum(
        1 for item in findings if item.get("verification_result") == "failed"
    )
    total = len(findings)
    closed = sum(statuses.get(status, 0) for status in {"closed", "verified", "accepted"})
    return {
        "schema_version": "1.0",
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "scope": "enterprise_governance",
        "kpi": {
            "total_findings": total,
            "closure_rate": round(closed / total, 4) if total else 1.0,
            "overdue_findings": len(overdue),
            "verification_failure_count": verification_failed,
        },
        "kri": {
            "critical_open_findings": sum(
                1 for item in findings
                if item.get("severity") == "critical"
                and item.get("status") not in {"closed", "verified", "accepted"}
            ),
            "high_risk_open_findings": sum(
                1 for item in findings
                if item.get("severity") in {"critical", "high"}
                and item.get("status") not in {"closed", "verified", "accepted"}
            ),
        },
        "by_status": dict(statuses),
        "by_severity": dict(severities),
        "by_domain": dict(domains),
        "overdue_finding_ids": [str(item["finding_id"]) for item in overdue],
    }

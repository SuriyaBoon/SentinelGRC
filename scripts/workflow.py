"""Generate reviewable remediation tickets from governance findings."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SLA = {
    "critical": {"response_minutes": 15, "resolution_hours": 4},
    "high": {"response_minutes": 30, "resolution_hours": 8},
    "medium": {"response_minutes": 240, "resolution_hours": 24},
    "low": {"response_minutes": 480, "resolution_hours": 72},
}


def ticket_id(source: str) -> str:
    return "SG-" + hashlib.sha256(source.encode("utf-8")).hexdigest()[:12].upper()


def make_ticket(
    source: str,
    title: str,
    priority: str,
    owner: str,
    evidence_ref: str,
    asset: dict[str, Any],
    created_at: datetime,
) -> dict[str, Any]:
    sla = SLA[priority]
    return {
        "ticket_id": ticket_id(source),
        "source": source,
        "title": title,
        "priority": priority,
        "owner": owner,
        "status": "open",
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "response_due_at": (
            created_at + timedelta(minutes=sla["response_minutes"])
        ).isoformat().replace("+00:00", "Z"),
        "resolution_due_at": (
            created_at + timedelta(hours=sla["resolution_hours"])
        ).isoformat().replace("+00:00", "Z"),
        "asset": {
            "asset_id": asset.get("asset_id"),
            "hostname": asset.get("hostname"),
            "business_service": asset.get("business_service"),
            "criticality": asset.get("criticality"),
        },
        "evidence_ref": evidence_ref,
        "auto_remediation": False,
    }


def generate_tickets(
    remediation: dict[str, Any],
    access_review: dict[str, Any],
    created_at: datetime | None = None,
) -> dict[str, Any]:
    created = created_at or datetime.now(timezone.utc)
    tickets = []

    for finding in remediation.get("findings", []):
        if finding.get("status") != "open":
            continue
        control = finding["control"]
        tickets.append(
            make_ticket(
                finding["finding_id"],
                f"Remediate control: {control['control_name']}",
                control["severity"],
                control["owner"],
                finding["finding_id"],
                finding["asset"],
                created,
            )
        )

    for user in access_review.get("users", []):
        if not user.get("stale"):
            continue
        if user.get("privileged"):
            priority = "critical"
            title = f"Review stale privileged account: {user['sam_account_name']}"
        elif user.get("enabled"):
            priority = "high"
            title = f"Review stale enabled account: {user['sam_account_name']}"
        else:
            continue
        source = f"AD:{user['sam_account_name']}:{access_review.get('reviewed_at')}"
        tickets.append(
            make_ticket(
                source,
                title,
                priority,
                "Identity Governance",
                source,
                {"asset_id": None, "hostname": None, "business_service": "Identity", "criticality": priority},
                created,
            )
        )

    return {
        "schema_version": "1.0",
        "generated_at": created.isoformat().replace("+00:00", "Z"),
        "tickets": tickets,
        "auto_remediation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SentinelGRC remediation tickets.")
    parser.add_argument("--remediation", required=True)
    parser.add_argument("--access-review", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = generate_tickets(
        json.loads(Path(args.remediation).read_text(encoding="utf-8")),
        json.loads(Path(args.access_review).read_text(encoding="utf-8")),
    )
    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""One-way migration helper from legacy JSON remediation queues to GovernanceCore."""

from __future__ import annotations

from typing import Any

from governance_core import ActorContext, GovernanceCore


def migrate_queue(queue: dict[str, Any], core: GovernanceCore, actor: ActorContext) -> int:
    if actor.role not in {"admin", "analyst"}:
        raise PermissionError("migration requires admin or analyst actor")
    migrated = 0
    for item in queue.get("findings", []):
        asset = item.get("asset") or {}
        control = item.get("control") or {}
        finding_id = str(item.get("finding_id", "")).strip()
        if not finding_id:
            raise ValueError("legacy finding is missing finding_id")
        core.upsert_finding(
            finding_id=finding_id,
            control_id=str(control.get("control_id") or control.get("id") or "legacy"),
            asset_id=str(asset.get("asset_id") or queue.get("asset_id") or "legacy"),
            title=str(control.get("control_name") or finding_id),
            risk_owner=str(control.get("owner") or "Security Operations"),
            severity=str(control.get("severity") or "medium"),
            actor=actor,
        )
        migrated += 1
    return migrated

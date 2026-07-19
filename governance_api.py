"""Authenticated governance API dispatcher.

This is the transport-neutral application layer. HTTP/gRPC adapters can call
dispatch() while keeping authentication and lifecycle policy centralized.
"""

from __future__ import annotations

from typing import Any

from governance_core import GovernanceCore
from human_identity import HumanIdentityStore


class GovernanceApi:
    FORBIDDEN_ACTOR_FIELDS = {"actor_id", "approved_by", "reviewed_by", "closed_by", "audit_actor"}

    def __init__(self, core: GovernanceCore, identities: HumanIdentityStore) -> None:
        self.core = core
        self.identities = identities

    def dispatch(self, action: str, key_id: str, secret: str, body: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise ValueError("request body must be an object")
        if self.FORBIDDEN_ACTOR_FIELDS.intersection(body):
            raise ValueError("actor identity must come from authentication context")
        actor = self.identities.authenticate(key_id, secret)
        finding_id = str(body.get("finding_id", ""))
        if action == "list":
            return {"findings": self.core.list_findings(body.get("status"))}
        if action == "get":
            return self.core.get_finding(finding_id)
        if action == "create":
            return self.core.create_finding(
                finding_id, str(body["control_id"]), str(body["asset_id"]),
                str(body["title"]), str(body["risk_owner"]),
                str(body["severity"]), actor,
            )
        if action == "assess":
            return self.core.assess_risk(finding_id, actor, str(body["likelihood"]), str(body["impact"]))
        if action == "propose":
            return self.core.propose_treatment(
                finding_id, actor, str(body["treatment_type"]), str(body["reason"]),
                str(body["action_owner"]), body.get("due_date"),
            )
        if action == "approve":
            return self.core.approve_treatment(finding_id, actor, str(body["decision"]), str(body.get("reason", "")))
        if action == "start":
            return self.core.start_action(finding_id, actor, str(body["implementer"]))
        if action == "evidence":
            return self.core.submit_evidence(finding_id, actor, str(body["source"]), str(body["content"]))
        if action == "verify":
            return self.core.verify(finding_id, actor, bool(body["passed"]), str(body.get("notes", "")))
        if action == "close":
            return self.core.close(finding_id, actor, str(body.get("reason", "")))
        if action == "report":
            return self.core.export_summary()
        raise ValueError(f"unsupported governance action: {action}")

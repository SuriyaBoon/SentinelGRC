"""Phase 1 governance core for the Sentinel Enterprise Trust Platform.

This module adds a transactional, auditable finding lifecycle on top of the
existing evidence and remediation pipeline. Human actors are supplied by the
trusted application layer; they are never accepted from finding payloads.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROLES = {"admin", "analyst", "risk_owner", "approver", "ciso", "risk_committee"}
TREATMENTS = {"mitigate", "accept", "transfer", "avoid"}
ACTIVE_STATUSES = {
    "open",
    "risk_assessed",
    "treatment_proposed",
    "pending_approval",
    "approved",
    "in_progress",
    "evidence_submitted",
    "pending_verification",
    "rejected",
}
TERMINAL_STATUSES = {"verified", "accepted", "closed"}

@dataclass(frozen=True)
class ActorContext:
    actor_id: str
    role: str
    auth_method: str = "oidc"

    def __post_init__(self) -> None:
        if not self.actor_id.strip():
            raise ValueError("actor_id is required")
        if self.role not in ROLES:
            raise ValueError(f"unsupported role: {self.role}")
        if not self.auth_method.strip():
            raise ValueError("auth_method is required")

class GovernanceCore:
    def __init__(self, path: str = "runtime/governance.db") -> None:
        self.path = str(Path(path))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            db.executescript(
                """
                PRAGMA foreign_keys = ON;
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    control_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    risk_owner TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    treatment_type TEXT,
                    treatment_reason TEXT,
                    due_date TEXT,
                    action_owner TEXT,
                    implementer TEXT,
                    evidence_submitter TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governance_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
                    source TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    submitted_by TEXT NOT NULL,
                    submitted_at REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'submitted'
                );
                CREATE TABLE IF NOT EXISTS governance_events (
                    event_id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
                    event_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    auth_method TEXT NOT NULL,
                    occurred_at REAL NOT NULL,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS idx_events_finding ON governance_events(finding_id, occurred_at);
                """
            )
            db.commit()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _now() -> float:
        return time.time()

    @staticmethod
    def _require(actor: ActorContext, *roles: str) -> None:
        if actor.role not in roles:
            raise PermissionError(f"role {actor.role} cannot perform this action")

    def _event(
        self, db: sqlite3.Connection, finding_id: str, event_type: str,
        actor: ActorContext, details: dict[str, Any], now: float,
    ) -> None:
        previous = db.execute(
            "SELECT event_hash FROM governance_events WHERE finding_id = ? ORDER BY occurred_at DESC LIMIT 1",
            (finding_id,),
        ).fetchone()
        previous_hash = "" if previous is None else str(previous["event_hash"])
        body = {
            "finding_id": finding_id, "event_type": event_type,
            "actor_id": actor.actor_id, "actor_role": actor.role,
            "auth_method": actor.auth_method, "occurred_at": now,
            "details": details, "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(
            (previous_hash + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode("utf-8")
        ).hexdigest()
        db.execute(
            "INSERT INTO governance_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (uuid.uuid4().hex, finding_id, event_type, actor.actor_id, actor.role,
             actor.auth_method, now, json.dumps(details, sort_keys=True),
             previous_hash, event_hash),
        )

    def _mutate(self, finding_id: str, actor: ActorContext, event_type: str,
                new_status: str, details: dict[str, Any] | None = None,
                updates: dict[str, Any] | None = None,
                allowed_statuses: set[str] | None = None) -> dict[str, Any]:
        now = self._now()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
            if row is None:
                db.rollback()
                raise KeyError(f"finding {finding_id} was not found")
            if allowed_statuses is not None and row["status"] not in allowed_statuses:
                db.rollback()
                raise ValueError(f"finding cannot transition from {row['status']}")
            fields = {"status": new_status, "updated_at": now, **(updates or {})}
            assignments = ", ".join(f"{key} = ?" for key in fields)
            db.execute(f"UPDATE findings SET {assignments} WHERE finding_id = ?",
                       (*fields.values(), finding_id))
            self._event(db, finding_id, event_type, actor, details or {}, now)
            db.commit()
            return self.get_finding(finding_id)

    def create_finding(self, finding_id: str, control_id: str, asset_id: str,
                       title: str, risk_owner: str, severity: str,
                       actor: ActorContext) -> dict[str, Any]:
        self._require(actor, "admin", "analyst")
        values = (finding_id, control_id, asset_id, title, risk_owner, severity, "open",
                  None, None, None, None, None, None, self._now(), self._now())
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)
                self._event(db, finding_id, "finding_created", actor, {
                    "control_id": control_id, "asset_id": asset_id, "severity": severity
                }, values[-2])
            except sqlite3.IntegrityError as error:
                db.rollback()
                raise ValueError(f"finding {finding_id} already exists") from error
            db.commit()
        return self.get_finding(finding_id)

    def assess_risk(self, finding_id: str, actor: ActorContext,
                    likelihood: str, impact: str) -> dict[str, Any]:
        self._require(actor, "risk_owner", "analyst", "admin")
        return self._mutate(finding_id, actor, "risk_assessed", "risk_assessed",
                            {"likelihood": likelihood, "impact": impact},
                            allowed_statuses={"open", "rejected"})

    def propose_treatment(self, finding_id: str, actor: ActorContext,
                          treatment_type: str, reason: str, action_owner: str,
                          due_date: str | None = None) -> dict[str, Any]:
        self._require(actor, "risk_owner", "analyst", "admin")
        if treatment_type not in TREATMENTS:
            raise ValueError(f"unsupported treatment: {treatment_type}")
        if not reason.strip() or not action_owner.strip():
            raise ValueError("treatment reason and action owner are required")
        return self._mutate(finding_id, actor, "treatment_proposed", "pending_approval", {
            "treatment_type": treatment_type, "reason": reason, "action_owner": action_owner
        }, {"treatment_type": treatment_type, "treatment_reason": reason, "action_owner": action_owner, "due_date": due_date},
                            allowed_statuses={"risk_assessed"})

    def approve_treatment(self, finding_id: str, actor: ActorContext,
                          decision: str, reason: str = "") -> dict[str, Any]:
        self._require(actor, "approver", "ciso", "risk_committee")
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be approved or rejected")
        finding = self.get_finding(finding_id)
        if actor.actor_id == finding["risk_owner"]:
            raise PermissionError("risk owner cannot approve the same finding")
        status = "accepted" if decision == "approved" and finding["treatment_type"] == "accept" else ("approved" if decision == "approved" else "risk_assessed")
        return self._mutate(finding_id, actor, "treatment_approved" if decision == "approved" else "treatment_rejected",
                            status, {"decision": decision, "reason": reason},
                            allowed_statuses={"pending_approval"})

    def start_action(self, finding_id: str, actor: ActorContext,
                     implementer: str) -> dict[str, Any]:
        self._require(actor, "risk_owner", "analyst", "admin")
        if not implementer.strip():
            raise ValueError("implementer is required")
        return self._mutate(finding_id, actor, "action_started", "in_progress",
                            {"implementer": implementer}, {"implementer": implementer},
                            allowed_statuses={"approved"})

    def submit_evidence(self, finding_id: str, actor: ActorContext,
                        source: str, content: bytes | str) -> dict[str, Any]:
        self._require(actor, "risk_owner", "analyst", "admin")
        if not source.strip():
            raise ValueError("evidence source is required")
        raw = content.encode("utf-8") if isinstance(content, str) else content
        evidence_id = "EV-" + uuid.uuid4().hex[:12].upper()
        now = self._now()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
            if row is None:
                db.rollback()
                raise KeyError(f"finding {finding_id} was not found")
            db.execute("INSERT INTO governance_evidence VALUES (?,?,?,?,?,?,?)",
                       (evidence_id, finding_id, source, hashlib.sha256(raw).hexdigest(),
                        actor.actor_id, now, "submitted"))
            db.execute("UPDATE findings SET status = 'pending_verification', evidence_submitter = ?, updated_at = ? WHERE finding_id = ?",
                       (actor.actor_id, now, finding_id))
            self._event(db, finding_id, "evidence_submitted", actor, {
                "evidence_id": evidence_id, "source": source, "sha256": hashlib.sha256(raw).hexdigest()
            }, now)
            db.commit()
        return self.get_finding(finding_id)

    def verify(self, finding_id: str, actor: ActorContext,
               passed: bool, notes: str = "") -> dict[str, Any]:
        self._require(actor, "analyst", "approver", "ciso", "risk_committee")
        finding = self.get_finding(finding_id)
        if actor.actor_id in {finding.get("implementer"), finding.get("evidence_submitter")}:
            raise PermissionError("verification must be independent from implementation and evidence submission")
        return self._mutate(finding_id, actor, "verification_passed" if passed else "verification_failed",
                            "verified" if passed else "in_progress", {"passed": passed, "notes": notes},
                            allowed_statuses={"pending_verification"})

    def close(self, finding_id: str, actor: ActorContext,
              reason: str = "") -> dict[str, Any]:
        self._require(actor, "approver", "ciso", "risk_committee")
        finding = self.get_finding(finding_id)
        if finding["status"] not in {"verified", "accepted"}:
            raise ValueError("finding cannot close before verification or accepted-risk treatment")
        return self._mutate(finding_id, actor, "finding_closed", "closed", {"reason": reason},
                            allowed_statuses={"verified", "accepted"})

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
        if row is None:
            raise KeyError(f"finding {finding_id} was not found")
        return dict(row)

    def list_events(self, finding_id: str) -> list[dict[str, Any]]:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM governance_events WHERE finding_id = ? ORDER BY occurred_at, event_id",
                              (finding_id,)).fetchall()
        return [dict(row) for row in rows]

    def verify_event_chain(self, finding_id: str) -> bool:
        events = self.list_events(finding_id)
        previous = ""
        for event in events:
            details = json.loads(event["details_json"])
            body = {
                "finding_id": finding_id, "event_type": event["event_type"],
                "actor_id": event["actor_id"], "actor_role": event["actor_role"],
                "auth_method": event["auth_method"], "occurred_at": event["occurred_at"],
                "details": details, "previous_hash": previous,
            }
            expected = hashlib.sha256((previous + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode("utf-8")).hexdigest()
            if event["previous_hash"] != previous or event["event_hash"] != expected:
                return False
            previous = event["event_hash"]
        return True

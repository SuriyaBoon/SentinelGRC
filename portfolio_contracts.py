"""Strict canonical contracts for asset context and remediation tickets."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from contract_validation import (
    is_canonical_text,
    parse_rfc3339,
)


IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
SOURCE_IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9._:-]{0,127}$"
SOURCE_IDENTIFIER = re.compile(SOURCE_IDENTIFIER_PATTERN, re.ASCII)
ASSET_SCHEMA_VERSION = "asset_context.v1"
TICKET_SCHEMA_VERSION = "remediation_ticket.v1"
# Custom ports are intentionally excluded: no connector contract requires them.
EVIDENCE_HOST_PATTERN = (
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
)
EVIDENCE_REFERENCE_PATTERN = (
    r"^(?:urn:[^\s]+|(?:https|azblob|sample)://"
    + EVIDENCE_HOST_PATTERN
    + r"(?:[/?#][^\s]*)?)$"
)
EVIDENCE_REFERENCE = re.compile(EVIDENCE_REFERENCE_PATTERN)
CRITICALITIES = {"low", "medium", "high", "critical"}
ASSET_STATUSES = {"active", "inactive", "retired", "unknown"}
TICKET_STATUSES = {"new", "assigned", "in_progress", "on_hold", "resolved", "closed"}
TICKET_PRIORITIES = {"P1", "P2", "P3", "P4"}


def _shape(payload: Any, *, label: str, allowed: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be an object")
    unknown = sorted(set(payload) - allowed)
    missing = sorted(required - set(payload))
    if unknown:
        raise ValueError(f"{label} contains unknown fields: " + ", ".join(unknown))
    if missing:
        raise ValueError(f"{label} missing fields: " + ", ".join(missing))
    return payload


def _text(payload: dict[str, Any], name: str, maximum: int, label: str) -> str:
    value = payload.get(name)
    if not is_canonical_text(value, maximum):
        raise ValueError(f"{label} {name} is invalid")
    return value


def _identifier(payload: dict[str, Any], name: str, label: str) -> str:
    value = _text(payload, name, 128, label)
    if IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} {name} is invalid")
    return value


def _source_identifier(payload: dict[str, Any], label: str) -> str:
    value = _identifier(payload, "source", label)
    if SOURCE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} source must use canonical lowercase")
    return value


def _timestamp(payload: dict[str, Any], name: str, label: str) -> str:
    value = _text(payload, name, 64, label)
    parse_rfc3339(value, label, name)
    return value


def _evidence_refs(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 20:
        raise ValueError(f"{label} evidence_refs must contain 1-20 references")
    references: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > 512
            or EVIDENCE_REFERENCE.fullmatch(item) is None
        ):
            raise ValueError(f"{label} evidence reference is not approved")
        references.append(item)
    if len(set(references)) != len(references):
        raise ValueError(f"{label} evidence references must be unique")
    return references


ASSET_ALLOWED = {
    "schema_version", "source", "source_asset_id", "observed_at", "asset_id",
    "hostname", "owner", "criticality", "status", "evidence_refs",
}
ASSET_REQUIRED = ASSET_ALLOWED - {"hostname"}


def normalize_asset_context_v1(payload: Any) -> dict[str, Any]:
    """Validate one source-owned asset record without mutating its source."""
    label = "asset context"
    value = _shape(payload, label=label, allowed=ASSET_ALLOWED, required=ASSET_REQUIRED)
    if value.get("schema_version") != ASSET_SCHEMA_VERSION:
        raise ValueError("asset context schema_version must be asset_context.v1")
    source = _source_identifier(value, label)
    source_asset_id = _identifier(value, "source_asset_id", label)
    asset_id = _identifier(value, "asset_id", label)
    owner = _identifier(value, "owner", label)
    observed_at = _timestamp(value, "observed_at", label)
    criticality = _text(value, "criticality", 16, label)
    status = _text(value, "status", 16, label)
    if criticality not in CRITICALITIES:
        raise ValueError("asset context criticality is invalid")
    if status not in ASSET_STATUSES:
        raise ValueError("asset context status is invalid")
    hostname = value.get("hostname")
    if hostname is not None and not is_canonical_text(hostname, 255):
        raise ValueError("asset context hostname is invalid")
    references = _evidence_refs(value.get("evidence_refs"), label)
    identity = "|".join((ASSET_SCHEMA_VERSION, source, source_asset_id, asset_id))
    return {
        "context_id": "ASSET-CTX-" + hashlib.sha256(identity.encode()).hexdigest()[:16].upper(),
        "schema_version": ASSET_SCHEMA_VERSION, "source": source,
        "source_asset_id": source_asset_id, "asset_id": asset_id,
        "hostname": hostname,
        "owner": owner, "criticality": criticality, "status": status,
        "observed_at": observed_at, "evidence_refs": references,
    }


TICKET_ALLOWED = {
    "schema_version", "source", "source_ticket_id", "finding_id", "asset_id",
    "owner", "status", "priority", "created_at", "updated_at", "due_at",
    "evidence_refs",
}
TICKET_REQUIRED = TICKET_ALLOWED


def normalize_remediation_ticket_v1(payload: Any) -> dict[str, Any]:
    """Validate a ticket/SLA status record linked to one governed finding."""
    label = "remediation ticket"
    value = _shape(payload, label=label, allowed=TICKET_ALLOWED, required=TICKET_REQUIRED)
    if value.get("schema_version") != TICKET_SCHEMA_VERSION:
        raise ValueError("remediation ticket schema_version must be remediation_ticket.v1")
    source = _source_identifier(value, label)
    source_ticket_id = _identifier(value, "source_ticket_id", label)
    finding_id = _identifier(value, "finding_id", label)
    asset_id = _identifier(value, "asset_id", label)
    owner = _identifier(value, "owner", label)
    status = _text(value, "status", 32, label)
    priority = _text(value, "priority", 2, label)
    if status not in TICKET_STATUSES:
        raise ValueError("remediation ticket status is invalid")
    if priority not in TICKET_PRIORITIES:
        raise ValueError("remediation ticket priority is invalid")
    created_at = _timestamp(value, "created_at", label)
    updated_at = _timestamp(value, "updated_at", label)
    due_at = _timestamp(value, "due_at", label)
    if parse_rfc3339(updated_at, label, "updated_at") < parse_rfc3339(
        created_at, label, "created_at"
    ):
        raise ValueError("remediation ticket updated_at cannot precede created_at")
    references = _evidence_refs(value.get("evidence_refs"), label)
    identity = "|".join((TICKET_SCHEMA_VERSION, source, source_ticket_id, finding_id))
    return {
        "ticket_context_id": "TICKET-CTX-" + hashlib.sha256(identity.encode()).hexdigest()[:16].upper(),
        "schema_version": TICKET_SCHEMA_VERSION, "source": source,
        "source_ticket_id": source_ticket_id, "finding_id": finding_id,
        "asset_id": asset_id, "owner": owner, "status": status,
        "priority": priority, "created_at": created_at, "updated_at": updated_at,
        "due_at": due_at, "evidence_refs": references,
    }

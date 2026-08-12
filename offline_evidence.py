"""Deterministic, sanitized evidence envelope for offline assurance results."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from staging_assurance import run_offline_assurance


EVIDENCE_SCHEMA = "sentinel.offline_assurance_evidence.v1"
ENVELOPE_SCHEMA = "sentinel.offline_assurance_evidence_envelope.v1"
PRODUCTION_DECISION = "NO_GO_PENDING_LIVE_EVIDENCE"
MAX_EVIDENCE_BYTES = 512 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_GUID = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}"
    r"-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"
)
_EMAIL = re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b")
_URL = re.compile(r"(?:https?|sample)://", re.IGNORECASE)
_PROHIBITED_FIELDS = {
    "access_key",
    "client_id",
    "client_secret",
    "connection_string",
    "email",
    "endpoint",
    "fqdn",
    "object_id",
    "password",
    "principal_id",
    "resource_id",
    "secret",
    "subscription_id",
    "tenant_id",
    "token",
    "url",
}
_REPORT_KEYS = {
    "schema_version",
    "mode",
    "azure_mutation_performed",
    "alert_count",
    "first_ingestion",
    "replay",
    "offline_gates",
    "offline_decision",
    "live_validation",
    "production_decision",
}
_INGESTION_KEYS = {
    "events_read",
    "findings_created",
    "findings_reassessed",
    "ignored",
    "errors",
    "finding_ids",
}


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"offline evidence contains duplicate key: {key}")
        result[key] = value
    return result


def _expect_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} fields are invalid")
    return value


def _reject_sensitive_material(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in _PROHIBITED_FIELDS:
                raise ValueError(f"{path} contains prohibited sensitive field: {key}")
            _reject_sensitive_material(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive_material(item, f"{path}[{index}]")
        return
    if isinstance(value, str) and (
        "/subscriptions/" in value.lower()
        or _GUID.search(value)
        or _EMAIL.search(value)
        or _URL.search(value)
    ):
        raise ValueError(f"{path} contains prohibited sensitive value")


def _canonical_text_bytes(path: str | Path, label: str) -> bytes:
    try:
        raw = Path(path).read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError(f"{label} cannot be read as UTF-8") from error
    if "\x00" in text:
        raise ValueError(f"{label} contains a prohibited null byte")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.encode("utf-8")


def _canonical_input_sha256(path: str | Path, label: str) -> str:
    return hashlib.sha256(_canonical_text_bytes(path, label)).hexdigest()


def _validate_ingestion_summary(value: Any, label: str) -> dict[str, int]:
    summary = _expect_exact_keys(value, _INGESTION_KEYS, label)
    for name in _INGESTION_KEYS - {"finding_ids"}:
        item = summary[name]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ValueError(f"{label} count is invalid: {name}")
    finding_ids = summary["finding_ids"]
    if not isinstance(finding_ids, list) or any(not isinstance(item, str) for item in finding_ids):
        raise ValueError(f"{label} finding identities are invalid")
    return {
        "events_read": summary["events_read"],
        "findings_created": summary["findings_created"],
        "findings_reassessed": summary["findings_reassessed"],
        "ignored": summary["ignored"],
        "errors": summary["errors"],
    }


def _validate_offline_report(report: Any) -> dict[str, Any]:
    document = _expect_exact_keys(report, _REPORT_KEYS, "offline assurance report")
    if (
        document["mode"] != "offline_no_azure"
        or document["azure_mutation_performed"] is not False
        or document["production_decision"] != "NO_GO"
    ):
        raise ValueError("offline assurance report claim boundary is invalid")
    live = _expect_exact_keys(
        document["live_validation"],
        {"gates", "decision", "all_required_live_gates_passed"},
        "offline assurance live validation",
    )
    if (
        live["decision"] != "NO_GO"
        or live["all_required_live_gates_passed"] is not False
        or not isinstance(live["gates"], dict)
        or not live["gates"]
        or any(value != "not_run" for value in live["gates"].values())
    ):
        raise ValueError("offline assurance report grants live-gate credit")
    gates = document["offline_gates"]
    if (
        not isinstance(gates, dict)
        or not gates
        or any(not isinstance(name, str) or not isinstance(value, bool) for name, value in gates.items())
    ):
        raise ValueError("offline assurance gate results are invalid")
    if document["offline_decision"] not in {"READY_FOR_MANUAL_AZURE_STAGING", "NO_GO"}:
        raise ValueError("offline assurance decision is invalid")
    alert_count = document["alert_count"]
    if isinstance(alert_count, bool) or not isinstance(alert_count, int) or alert_count < 1:
        raise ValueError("offline assurance alert count is invalid")
    return {
        "alert_count": alert_count,
        "first_ingestion": _validate_ingestion_summary(
            document["first_ingestion"], "first ingestion"
        ),
        "replay": _validate_ingestion_summary(document["replay"], "replay"),
        "offline_gates": dict(sorted(gates.items())),
        "offline_decision": document["offline_decision"],
    }


def _validate_evidence_identity(document: dict[str, Any]) -> None:
    _reject_sensitive_material(document)
    if (
        document["schema_version"] != EVIDENCE_SCHEMA
        or document["mode"] != "offline_no_azure"
    ):
        raise ValueError("offline evidence identity is invalid")
    if _COMMIT_SHA.fullmatch(str(document["source_commit_sha"])) is None:
        raise ValueError("offline evidence source commit SHA is invalid")


def _validate_evidence_inputs(value: Any) -> None:
    inputs = _expect_exact_keys(
        value,
        {"policy_sha256", "alerts_sha256", "source_contract"},
        "offline evidence inputs",
    )
    if inputs["source_contract"] != "security_alert.v1":
        raise ValueError("offline evidence source contract is invalid")
    for name in ("policy_sha256", "alerts_sha256"):
        if _SHA256.fullmatch(str(inputs[name])) is None:
            raise ValueError(f"offline evidence input hash is invalid: {name}")


def _validate_evidence_results(value: Any) -> None:
    results = _expect_exact_keys(
        value,
        {
            "alert_count",
            "first_ingestion",
            "replay",
            "offline_gates",
            "offline_decision",
        },
        "offline evidence results",
    )
    if (
        isinstance(results["alert_count"], bool)
        or not isinstance(results["alert_count"], int)
        or results["alert_count"] < 1
    ):
        raise ValueError("offline evidence alert count is invalid")
    for label in ("first_ingestion", "replay"):
        summary = _expect_exact_keys(
            results[label],
            {
                "events_read",
                "findings_created",
                "findings_reassessed",
                "ignored",
                "errors",
            },
            f"offline evidence {label}",
        )
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in summary.values()
        ):
            raise ValueError(f"offline evidence {label} counts are invalid")
    gates = results["offline_gates"]
    if (
        not isinstance(gates, dict)
        or not gates
        or any(
            not isinstance(name, str) or not isinstance(result, bool)
            for name, result in gates.items()
        )
    ):
        raise ValueError("offline evidence gates are invalid")
    if results["offline_decision"] not in {
        "READY_FOR_MANUAL_AZURE_STAGING",
        "NO_GO",
    }:
        raise ValueError("offline evidence decision is invalid")


def _validate_claim_boundary(value: Any) -> None:
    boundary = _expect_exact_keys(
        value,
        {
            "azure_mutation_performed",
            "current_live_gate_credit",
            "production_decision",
            "statement",
        },
        "offline evidence claim boundary",
    )
    if (
        boundary["azure_mutation_performed"] is not False
        or boundary["current_live_gate_credit"] is not False
        or boundary["production_decision"] != PRODUCTION_DECISION
        or boundary["statement"]
        != "Repository-only evidence does not satisfy live Azure or production gates."
    ):
        raise ValueError("offline evidence claim boundary is invalid")


def validate_evidence_document(value: Any) -> dict[str, Any]:
    document = _expect_exact_keys(
        value,
        {
            "schema_version",
            "mode",
            "source_commit_sha",
            "inputs",
            "results",
            "claim_boundary",
        },
        "offline evidence document",
    )
    _validate_evidence_identity(document)
    _validate_evidence_inputs(document["inputs"])
    _validate_evidence_results(document["results"])
    _validate_claim_boundary(document["claim_boundary"])
    return document


def canonical_evidence_document_bytes(value: Any) -> bytes:
    validated = validate_evidence_document(value)
    rendered = json.dumps(validated, sort_keys=True, separators=(",", ":")) + "\n"
    return rendered.encode("ascii")


def create_evidence_envelope(document: Any) -> dict[str, Any]:
    validated = validate_evidence_document(document)
    digest = hashlib.sha256(canonical_evidence_document_bytes(validated)).hexdigest()
    return {
        "schema_version": ENVELOPE_SCHEMA,
        "document": validated,
        "document_sha256": digest,
    }


def validate_evidence_envelope(value: Any) -> dict[str, Any]:
    envelope = _expect_exact_keys(
        value,
        {"schema_version", "document", "document_sha256"},
        "offline evidence envelope",
    )
    if envelope["schema_version"] != ENVELOPE_SCHEMA:
        raise ValueError("offline evidence envelope identity is invalid")
    document = validate_evidence_document(envelope["document"])
    expected = hashlib.sha256(canonical_evidence_document_bytes(document)).hexdigest()
    if not isinstance(envelope["document_sha256"], str) or envelope["document_sha256"] != expected:
        raise ValueError("offline evidence envelope checksum mismatch")
    return envelope


def load_evidence_envelope(path: str | Path) -> dict[str, Any]:
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise ValueError("offline evidence envelope cannot be read") from error
    if not raw or len(raw) > MAX_EVIDENCE_BYTES:
        raise ValueError("offline evidence envelope size is invalid")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("offline evidence envelope JSON is invalid") from error
    return validate_evidence_envelope(parsed)


def collect_offline_evidence(
    policy_path: str | Path,
    alerts_path: str | Path,
    source_commit_sha: str,
) -> dict[str, Any]:
    if _COMMIT_SHA.fullmatch(source_commit_sha) is None:
        raise ValueError("offline evidence source commit SHA is invalid")
    report = run_offline_assurance(str(policy_path), str(alerts_path), live_evidence=None)
    results = _validate_offline_report(report)
    document = {
        "schema_version": EVIDENCE_SCHEMA,
        "mode": "offline_no_azure",
        "source_commit_sha": source_commit_sha,
        "inputs": {
            "policy_sha256": _canonical_input_sha256(policy_path, "assurance policy"),
            "alerts_sha256": _canonical_input_sha256(alerts_path, "alert contract"),
            "source_contract": "security_alert.v1",
        },
        "results": results,
        "claim_boundary": {
            "azure_mutation_performed": False,
            "current_live_gate_credit": False,
            "production_decision": PRODUCTION_DECISION,
            "statement": "Repository-only evidence does not satisfy live Azure or production gates.",
        },
    }
    return create_evidence_envelope(document)

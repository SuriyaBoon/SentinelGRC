"""Deterministic pre-live security assessment for repository-controlled controls."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "sentinel.security_assessment.v1"
PRODUCTION_DECISION = "NO_GO_PENDING_LIVE_EVIDENCE"
PIP_AUDIT_ACTION = "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266"
SOURCE_SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
LIVE_CONTROLS = (
    "entra_role_separation",
    "managed_identity_resource_access",
    "private_network_exposure",
    "mtls_certificate_lifecycle",
    "azure_resource_configuration",
    "penetration_validation",
)
TEXT_SUFFIXES = {".py", ".ps1", ".json", ".yml", ".yaml", ".md", ".bicep", ".txt"}
SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[opsu]_[A-Za-z0-9]{30,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"AccountKey=[A-Za-z0-9+/=]{20,}"),
)


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    area: str
    status: str
    evidence: str
    owner: str
    severity_on_failure: str


def _canonical(value: dict[str, Any]) -> str:
    """Serialize an evidence document deterministically for hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def decode_tool_report(value: str) -> bytes:
    """Decode a bounded nonempty base64 scanner report."""
    if not isinstance(value, str) or len(value) > 1_400_000:
        raise ValueError("dependency scan report is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("dependency scan report is not valid base64") from error
    if not decoded or len(decoded) > 1_048_576:
        raise ValueError("dependency scan report must contain 1-1048576 bytes")
    return decoded


def _workflow_files(root: Path) -> list[Path]:
    """Return workflow files in deterministic order."""
    return sorted((root / ".github" / "workflows").glob("*.y*ml"))


def _actions_are_pinned(root: Path) -> tuple[bool, str]:
    """Require every external workflow action to use a full commit SHA."""
    references = []
    try:
        for path in _workflow_files(root):
            for line in path.read_text(encoding="utf-8").splitlines():
                match = re.fullmatch(r"(?:-\s*)?uses:\s*(\S+)", line.strip())
                if match:
                    references.append(match.group(1))
    except (OSError, UnicodeError):
        return False, "workflow action references unreadable"
    invalid = [reference for reference in references if not PINNED_ACTION.fullmatch(reference)]
    return not invalid and bool(references), f"{len(references)} action references; {len(invalid)} mutable"


def _requirement_blocks(text: str) -> list[str] | None:
    """Join continued requirement lines and reject incomplete continuations."""
    blocks: list[str] = []
    current: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        current.append(line[:-1].strip() if continued else line)
        if not continued:
            blocks.append(" ".join(current))
            current = []
    return None if current else blocks


def _dependency_lock_is_hashed(root: Path) -> tuple[bool, str]:
    """Require an exact version and at least one SHA-256 hash per requirement."""
    path = root / "requirements-hashed.txt"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False, "requirements-hashed.txt missing"
    blocks = _requirement_blocks(text)
    if not blocks:
        return False, "requirements-hashed.txt has no complete requirements"
    exact = re.compile(r"^[A-Za-z0-9_.-]+==[^\s]+(?:\s+--hash=sha256:[0-9a-f]{64})+$")
    invalid = [index for index, block in enumerate(blocks, 1) if not exact.fullmatch(block)]
    hash_count = sum(block.count("--hash=sha256:") for block in blocks)
    return not invalid, (
        f"{len(blocks)} exact packages; {hash_count} artifact hashes; "
        f"{len(invalid)} requirements without complete hash coverage"
    )


def _containers_are_pinned_non_root(root: Path) -> tuple[bool, str]:
    """Check immutable runtime base, non-root users, and narrow copy rules."""
    try:
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        assurance = (root / "Dockerfile.assurance").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False, "container build definitions missing or unreadable"
    base_images = re.findall(r"(?m)^FROM\s+([^\s]+)", dockerfile)
    pinned = bool(base_images) and all("@sha256:" in image for image in base_images)
    non_root = "USER 10001:10001" in dockerfile and "USER 10001:10001" in assurance
    narrow_copy = "COPY . ." not in dockerfile and "COPY . ." not in assurance
    return pinned and non_root and narrow_copy, "digest base, non-root runtime, explicit COPY allowlist"


def _security_decisions_are_bounded(root: Path, assessed_on: str) -> tuple[bool, str]:
    """Require current, explicitly bounded security decisions."""
    path = root / "config" / "sonar-security-decisions.json"
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
        today = date.fromisoformat(assessed_on)
        registry_expiry = registry["expires_on"]
        expiries = [
            date.fromisoformat(item.get("expires_on", registry_expiry))
            for item in registry["decisions"]
        ]
    except (OSError, KeyError, TypeError, ValueError):
        return False, "security decision registry invalid"
    if not expiries:
        return False, "0 reviewed decisions; earliest expiry absent"
    passed = (
        registry.get("production_verdict") == PRODUCTION_DECISION
        and bool(expiries)
        and all(expiry >= today for expiry in expiries)
    )
    return passed, f"{len(expiries)} reviewed decisions; earliest expiry {min(expiries).isoformat()}"


def _boundary_tests_exist(root: Path) -> tuple[bool, str]:
    """Check that required security regression suites remain present."""
    required = (
        "test_enterprise_safety.py",
        "test_path_security.py",
        "test_sonar_security_decisions.py",
        "test_supply_chain_policy.py",
        "test_crypto_agility.py",
        "test_azure_iac_policy.py",
    )
    missing = [name for name in required if not (root / name).is_file()]
    return not missing, f"{len(required) - len(missing)}/{len(required)} required boundary suites present"


def _secret_scan(root: Path) -> tuple[bool, str]:
    """Report high-confidence secret locations without retaining values."""
    matches: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(root)
        if any(part in {".git", "runtime", "evidence-inbox", "__pycache__"} for part in relative.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if any(pattern.search(line) for pattern in SECRET_PATTERNS):
                matches.append(f"{relative.as_posix()}:{number}")
    evidence = "no high-confidence secret patterns" if not matches else f"potential secret locations: {', '.join(matches[:20])}"
    return not matches, evidence


def _control(control_id: str, area: str, outcome: tuple[bool, str], owner: str, severity: str) -> ControlResult:
    """Convert one boolean repository check to a typed control result."""
    passed, evidence = outcome
    return ControlResult(control_id, area, "PASS" if passed else "FAIL", evidence, owner, severity)


def evaluate_repository_controls(root: str | Path, assessed_on: str) -> list[ControlResult]:
    """Evaluate deterministic security controls that need no live platform."""
    boundary = Path(root).resolve(strict=True)
    date.fromisoformat(assessed_on)
    return [
        _control("SEC-SUPPLY-001", "ci_supply_chain", _actions_are_pinned(boundary), "platform-owner", "high"),
        _control("SEC-DEP-001", "dependency_integrity", _dependency_lock_is_hashed(boundary), "dependency-owner", "high"),
        _control("SEC-CONTAINER-001", "container_boundary", _containers_are_pinned_non_root(boundary), "platform-owner", "high"),
        _control("SEC-GOV-001", "risk_acceptance", _security_decisions_are_bounded(boundary, assessed_on), "security-owner", "high"),
        _control("SEC-TEST-001", "security_regression", _boundary_tests_exist(boundary), "repository-owner", "high"),
        _control("SEC-SECRET-001", "secret_hygiene", _secret_scan(boundary), "security-owner", "critical"),
    ]


def _dependency_control(outcome: str, report: bytes | None) -> ControlResult:
    """Map the trusted CI scanner outcome to one fail-closed control."""
    if outcome not in {"success", "failure", "skipped", "cancelled"}:
        raise ValueError("dependency scan outcome is invalid")
    if outcome == "success":
        status = "PASS"
    elif outcome == "failure":
        status = "FAIL"
    else:
        status = "UNAVAILABLE"
    if status == "PASS" and not report:
        raise ValueError("successful dependency scan requires a report")
    digest = hashlib.sha256(report).hexdigest() if report is not None else "none"
    return ControlResult(
        "SEC-VULN-001",
        "dependency_vulnerability_scan",
        status,
        f"{PIP_AUDIT_ACTION}; report_sha256={digest}",
        "dependency-owner",
        "critical",
    )


def _findings(controls: list[ControlResult]) -> list[dict[str, str]]:
    """Create one owned open finding for every non-passing control."""
    return [
        {
            "finding_id": f"F-{control.control_id}",
            "control_id": control.control_id,
            "area": control.area,
            "severity": control.severity_on_failure,
            "status": "OPEN",
            "disposition": "REMEDIATE_OR_FORMALLY_ACCEPT",
            "owner": control.owner,
            "evidence": control.evidence,
        }
        for control in controls
        if control.status != "PASS"
    ]


def collect_security_assessment(
    root: str | Path,
    source_commit: str,
    assessed_on: str,
    dependency_scan_outcome: str,
    dependency_report: bytes | None,
) -> dict[str, Any]:
    """Collect a source-bound assessment while preserving live boundaries."""
    if SOURCE_SHA.fullmatch(source_commit) is None:
        raise ValueError("security assessment source commit SHA is invalid")
    controls = evaluate_repository_controls(root, assessed_on)
    controls.append(_dependency_control(dependency_scan_outcome, dependency_report))
    findings = _findings(controls)
    document = {
        "schema_version": SCHEMA_VERSION,
        "mode": "pre_live_repository_assessment",
        "source_commit_sha": source_commit,
        "assessed_on": assessed_on,
        "scope": [
            "repository_policy", "dependency_integrity", "dependency_vulnerabilities",
            "container_boundary", "risk_acceptance", "security_regression", "secret_hygiene",
        ],
        "controls": [control.__dict__ for control in controls],
        "findings": findings,
        "live_controls": [
            {"control": name, "status": "NOT_TESTED_LIVE"} for name in LIVE_CONTROLS
        ],
        "assessment_decision": "PASS_OFFLINE" if not findings else "NO_GO",
        "claim_boundary": {
            "azure_mutation_performed": False,
            "current_live_gate_credit": False,
            "independent_penetration_test_completed": False,
            "production_decision": PRODUCTION_DECISION,
            "tool_result_authenticity": "CI_ORCHESTRATION_METADATA_NOT_CRYPTOGRAPHIC_ATTESTATION",
        },
    }
    return {
        "document": document,
        "document_sha256": hashlib.sha256(_canonical(document).encode("ascii")).hexdigest(),
    }


def _validate_document_identity(envelope: dict[str, Any]) -> dict[str, Any]:
    """Validate envelope shape, schema identity, source SHA, and date."""
    if set(envelope) != {"document", "document_sha256"} or not isinstance(envelope["document"], dict):
        raise ValueError("security assessment envelope is invalid")
    document = envelope["document"]
    expected = {
        "schema_version", "mode", "source_commit_sha", "assessed_on", "scope", "controls",
        "findings", "live_controls", "assessment_decision", "claim_boundary",
    }
    if set(document) != expected or document["schema_version"] != SCHEMA_VERSION:
        raise ValueError("security assessment fields are invalid")
    if document["mode"] != "pre_live_repository_assessment" or SOURCE_SHA.fullmatch(document["source_commit_sha"]) is None:
        raise ValueError("security assessment identity is invalid")
    date.fromisoformat(document["assessed_on"])
    return document


def _validate_controls(
    document: dict[str, Any],
    root: str | Path,
    dependency_scan_outcome: str,
    dependency_report: bytes | None,
) -> list[dict[str, Any]]:
    """Recompute controls from repository state and trusted CI inputs."""
    controls = document["controls"]
    if not isinstance(controls, list) or len(controls) != 7:
        raise ValueError("security assessment controls are invalid")
    static = evaluate_repository_controls(root, document["assessed_on"])
    expected_controls = [control.__dict__ for control in static]
    expected_controls.append(
        _dependency_control(dependency_scan_outcome, dependency_report).__dict__
    )
    if controls != expected_controls:
        raise ValueError("security assessment controls are inconsistent with trusted inputs")
    return controls


def _validate_dependency_evidence(dependency: dict[str, Any]) -> None:
    """Validate dependency status and its sanitized report digest."""
    status = dependency.get("status")
    if status not in {"PASS", "FAIL", "UNAVAILABLE"}:
        raise ValueError("dependency scan status is invalid")
    evidence = dependency.get("evidence")
    if not isinstance(evidence, str) or not evidence.startswith(f"{PIP_AUDIT_ACTION}; report_sha256="):
        raise ValueError("dependency scan evidence is invalid")
    report_hash = evidence.rsplit("=", 1)[-1]
    if report_hash != "none" and DIGEST.fullmatch(report_hash) is None:
        raise ValueError("dependency scan report digest is invalid")
    if status == "PASS" and report_hash == "none":
        raise ValueError("successful dependency scan requires report evidence")
    if status == "UNAVAILABLE" and report_hash != "none":
        raise ValueError("dependency scan result is inconsistent")


def _validate_document_invariants(
    document: dict[str, Any], controls: list[dict[str, Any]]
) -> None:
    """Validate findings, live boundaries, decision, and immutable claims."""
    result_objects = [ControlResult(**item) for item in controls]
    if document["findings"] != _findings(result_objects):
        raise ValueError("security assessment findings are inconsistent")
    expected_live = [{"control": name, "status": "NOT_TESTED_LIVE"} for name in LIVE_CONTROLS]
    if document["live_controls"] != expected_live:
        raise ValueError("live security controls must remain not tested")
    expected_decision = "PASS_OFFLINE" if not document["findings"] else "NO_GO"
    if document["assessment_decision"] != expected_decision:
        raise ValueError("security assessment decision is inconsistent")
    if document["claim_boundary"] != {
        "azure_mutation_performed": False,
        "current_live_gate_credit": False,
        "independent_penetration_test_completed": False,
        "production_decision": PRODUCTION_DECISION,
        "tool_result_authenticity": "CI_ORCHESTRATION_METADATA_NOT_CRYPTOGRAPHIC_ATTESTATION",
    }:
        raise ValueError("security assessment claim boundary is invalid")


def validate_security_assessment(
    envelope: dict[str, Any],
    root: str | Path,
    dependency_scan_outcome: str,
    dependency_report: bytes | None,
) -> dict[str, Any]:
    """Validate a complete assessment against repository and trusted CI state."""
    document = _validate_document_identity(envelope)
    controls = _validate_controls(
        document, root, dependency_scan_outcome, dependency_report
    )
    _validate_dependency_evidence(controls[-1])
    _validate_document_invariants(document, controls)
    digest = hashlib.sha256(_canonical(document).encode("ascii")).hexdigest()
    if envelope["document_sha256"] != digest:
        raise ValueError("security assessment checksum mismatch")
    return envelope

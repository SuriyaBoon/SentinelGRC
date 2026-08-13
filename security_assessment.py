"""Deterministic pre-live security assessment for repository-controlled controls."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "sentinel.security_assessment.v1"
PRODUCTION_DECISION = "NO_GO_PENDING_LIVE_EVIDENCE"
PIP_AUDIT_ACTION = "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266"
SOURCE_SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
CI_RUN_ID = re.compile(r"[1-9][0-9]{0,19}")
PINNED_ACTION = re.compile(
    r"^(?!\./)(?!docker://)(?:[\w.-]+/)+[\w.-]+@[0-9a-f]{40}$",
    re.ASCII,
)
QUOTED_MAPPING_KEY = re.compile(
    r'(?:^[ \t]*(?:-\s*)?|[,{\[]\s*)'
    r'("(?:\\[^\r\n]|[^"\\\r\n])*")\s*:',
    re.MULTILINE,
)
ASSESSMENT_SCOPE = (
    "repository_policy",
    "dependency_integrity",
    "dependency_vulnerabilities",
    "container_boundary",
    "risk_acceptance",
    "security_regression",
    "secret_hygiene",
)
LIVE_CONTROLS = (
    "entra_role_separation",
    "managed_identity_resource_access",
    "private_network_exposure",
    "mtls_certificate_lifecycle",
    "azure_resource_configuration",
    "penetration_validation",
)
TEXT_SUFFIXES = {".py", ".ps1", ".json", ".yml", ".yaml", ".md", ".bicep", ".txt"}
SCAN_EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "evidence-inbox",
    "node_modules",
    "runtime",
    "venv",
}
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


def build_ci_scan_receipt(source_commit: str, outcome: str, ci_run_id: str) -> bytes:
    """Build a bounded source/run receipt when pip-audit exposes no report body."""
    if SOURCE_SHA.fullmatch(source_commit) is None or outcome != "success":
        raise ValueError("dependency scan receipt identity is invalid")
    if CI_RUN_ID.fullmatch(ci_run_id) is None:
        raise ValueError("dependency scan CI run ID is invalid")
    return _canonical({
        "action": PIP_AUDIT_ACTION,
        "ci_run_id": ci_run_id,
        "outcome": outcome,
        "source_commit_sha": source_commit,
    }).encode("ascii")


def _workflow_files(root: Path) -> list[Path]:
    """Return workflow files in deterministic order."""
    return sorted((root / ".github" / "workflows").glob("*.y*ml"))


def _strip_yaml_comment(line: str) -> str:
    """Remove YAML comments without treating quoted hashes as comments."""
    quote: str | None = None
    for index, character in enumerate(line):
        if character in {"'", '"'}:
            quote = None if quote == character else character if quote is None else quote
        elif character == "#" and quote is None:
            return line[:index]
    return line


def _decode_quoted_key(value: str) -> str | None:
    """Decode ASCII-relevant YAML hexadecimal escapes using JSON semantics."""
    normalized = re.sub(
        r"\\x([0-9a-fA-F]{2})",
        lambda match: "\\u00" + match.group(1),
        value,
    )
    normalized = re.sub(
        r"\\U0000([0-9a-fA-F]{4})",
        lambda match: "\\u" + match.group(1),
        normalized,
    )
    try:
        decoded = json.loads(normalized)
    except (json.JSONDecodeError, TypeError):
        return None
    return decoded if isinstance(decoded, str) else None


def _escaped_quoted_mapping_key_count(text: str) -> int:
    """Count escaped mapping keys that YAML resolves exactly to uses."""
    return sum(
        chr(92) in match.group(1)
        and _decode_quoted_key(match.group(1)) == "uses"
        for match in QUOTED_MAPPING_KEY.finditer(text)
    )


def _inline_uses_value(fragment: str) -> str | None:
    """Read one quoted or plain inline uses scalar, excluding flow delimiters."""
    value = fragment.lstrip()
    if not value:
        return None
    if value[0] in {"'", '"'}:
        quote = value[0]
        end = value.find(quote, 1)
        return None if end < 0 else value[1:end]
    end = len(value)
    for delimiter in (",", "}", "]"):
        position = value.find(delimiter)
        if position >= 0:
            end = min(end, position)
    return value[:end].strip() or None


def _block_uses_value(
    lines: list[str], start: int, parent_indent: int, marker: str
) -> tuple[str | None, int]:
    """Read a YAML block scalar and return its folded value and final index."""
    parts: list[str] = []
    index = start
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if stripped and indent <= parent_indent:
            break
        if stripped and not stripped.startswith("#"):
            parts.append(stripped)
        index += 1
    separator = " " if marker.startswith(">") else "\n"
    return (separator.join(parts) or None), index


def workflow_action_references(text: str) -> tuple[list[str], int]:
    """Extract block and flow-style workflow action references fail closed."""
    references: list[str] = []
    unparsed = _escaped_quoted_mapping_key_count(text)
    lines = text.splitlines()
    key_pattern = re.compile(r"(?:^|[,{])\s*(?:-\s*)?[\"']?uses[\"']?\s*:")
    index = 0
    while index < len(lines):
        code = _strip_yaml_comment(lines[index])
        matches = list(key_pattern.finditer(code))
        for match in matches:
            fragment = code[match.end():]
            marker = fragment.strip()
            if marker in {">", ">-", ">+", "|", "|-", "|+"}:
                value, next_index = _block_uses_value(
                    lines,
                    index + 1,
                    len(lines[index]) - len(lines[index].lstrip()),
                    marker,
                )
                index = max(index, next_index - 1)
            else:
                value = _inline_uses_value(fragment)
            if value is None:
                unparsed += 1
            else:
                references.append(value)
        index += 1
    return references, unparsed


def _actions_are_pinned(root: Path) -> tuple[bool, str]:
    """Require every external workflow action to use a full commit SHA."""
    references: list[str] = []
    unparsed = 0
    try:
        for path in _workflow_files(root):
            parsed, missing = workflow_action_references(
                path.read_text(encoding="utf-8")
            )
            references.extend(parsed)
            unparsed += missing
    except (OSError, UnicodeError):
        return False, "workflow action references unreadable"
    invalid = [reference for reference in references if not PINNED_ACTION.fullmatch(reference)]
    passed = not invalid and not unparsed and bool(references)
    return passed, (
        f"{len(references)} action references; {len(invalid)} mutable; "
        f"{unparsed} unparsed uses declarations"
    )


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


def _docker_instructions(text: str) -> list[tuple[str, str]] | None:
    """Parse logical Dockerfile directives while ignoring comments and blanks."""
    instructions: list[tuple[str, str]] = []
    current = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith(chr(92))
        current += (line[:-1] if continued else line) + (" " if continued else "")
        if continued:
            continue
        directive, separator, argument = current.strip().partition(" ")
        if not separator or not directive.isalpha() or not argument.strip():
            return None
        instructions.append((directive.upper(), argument.strip()))
        current = ""
    return None if current else instructions


@dataclass(frozen=True)
class CopySpec:
    sources: tuple[str, ...]
    from_reference: str | None


def _copy_spec(argument: str) -> CopySpec | None:
    """Parse reviewed Docker COPY flags, sources, and optional source image."""
    remaining = argument.strip()
    from_reference: str | None = None
    value_flags = {"chown", "chmod", "exclude", "from"}
    boolean_flags = {"link", "parents"}
    while remaining.startswith("--"):
        flag, separator, remaining = remaining.partition(" ")
        if not separator:
            return None
        name, equals, value = flag[2:].partition("=")
        if name in value_flags and (not equals or not value):
            return None
        if name in boolean_flags and equals and value not in {"true", "false"}:
            return None
        if name not in value_flags | boolean_flags:
            return None
        if name == "from":
            if from_reference is not None:
                return None
            from_reference = value
        remaining = remaining.lstrip()
    try:
        if remaining.startswith("["):
            values = json.loads(remaining)
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                return None
            sources = values[:-1] if len(values) >= 2 else None
            return None if sources is None else CopySpec(tuple(sources), from_reference)
        values = shlex.split(remaining, posix=True)
    except ValueError:
        return None
    sources = values[:-1] if len(values) >= 2 else None
    return None if sources is None else CopySpec(tuple(sources), from_reference)


def _from_spec(argument: str) -> tuple[str, str | None] | None:
    """Parse one FROM image and optional build-stage alias."""
    try:
        tokens = shlex.split(argument, posix=True)
    except ValueError:
        return None
    while tokens and tokens[0].startswith("--"):
        name, equals, value = tokens.pop(0)[2:].partition("=")
        if name != "platform" or not equals or not value:
            return None
    if len(tokens) == 1:
        return tokens[0], None
    if len(tokens) == 3 and tokens[1].upper() == "AS":
        return tokens[0], tokens[2]
    return None


def _container_metadata(
    instructions: list[tuple[str, str]],
) -> tuple[list[str], str | None] | None:
    """Return parsed base images and the effective final-stage user."""
    final_user: str | None = None
    base_images: list[str] = []
    for directive, argument in instructions:
        if directive == "FROM":
            final_user = None
            parsed = _from_spec(argument)
            if parsed is None:
                return None
            image, _alias = parsed
            base_images.append(image)
        elif directive == "USER":
            final_user = argument
    return base_images, final_user


def _copy_sources_are_narrow(instructions: list[tuple[str, str]]) -> bool:
    """Reject malformed COPY directives and repository-root copies."""
    for directive, argument in instructions:
        if directive != "COPY":
            continue
        spec = _copy_spec(argument)
        if spec is None:
            return False
        normalized = {
            source.replace(chr(92), "/").rstrip("/")
            for source in spec.sources
        }
        if "." in normalized:
            return False
    return True


def _is_prior_stage(reference: str, aliases: set[str], stage_count: int) -> bool:
    """Return whether a FROM/COPY reference names an already declared stage."""
    return reference in aliases or (
        reference.isdecimal() and int(reference) < stage_count
    )


def _container_references_are_immutable(
    instructions: list[tuple[str, str]], require_pinned_base: bool
) -> bool:
    """Require digests for external FROM and COPY --from references."""
    aliases: set[str] = set()
    stage_count = 0
    for directive, argument in instructions:
        if directive == "FROM":
            parsed = _from_spec(argument)
            if parsed is None:
                return False
            image, alias = parsed
            internal = _is_prior_stage(image, aliases, stage_count)
            if require_pinned_base and not internal and "@sha256:" not in image:
                return False
            if alias:
                aliases.add(alias)
            stage_count += 1
        elif directive == "COPY":
            spec = _copy_spec(argument)
            if spec is None:
                return False
            reference = spec.from_reference
            if (
                reference
                and not _is_prior_stage(reference, aliases, stage_count)
                and "@sha256:" not in reference
            ):
                return False
    return stage_count > 0


def _container_file_passes(text: str, require_pinned_base: bool) -> bool:
    """Evaluate final-stage user and broad-copy behavior from parsed directives."""
    instructions = _docker_instructions(text)
    if not instructions or not _copy_sources_are_narrow(instructions):
        return False
    metadata = _container_metadata(instructions)
    if metadata is None:
        return False
    _base_images, final_user = metadata
    immutable = _container_references_are_immutable(
        instructions, require_pinned_base
    )
    return final_user == "10001:10001" and immutable


def _containers_are_pinned_non_root(root: Path) -> tuple[bool, str]:
    """Check immutable runtime base, effective non-root user, and narrow copies."""
    try:
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        assurance = (root / "Dockerfile.assurance").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False, "container build definitions missing or unreadable"
    runtime_passed = _container_file_passes(dockerfile, require_pinned_base=True)
    assurance_passed = _container_file_passes(assurance, require_pinned_base=False)
    return runtime_passed and assurance_passed, (
        "parsed final-stage user, digest base, and COPY source policy"
    )


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
    except (AttributeError, OSError, KeyError, TypeError, ValueError):
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
        "test_security_assessment.py",
        "test_crypto_agility.py",
        "test_azure_iac_policy.py",
    )
    missing = [name for name in required if not (root / name).is_file()]
    return not missing, f"{len(required) - len(missing)}/{len(required)} required boundary suites present"


def _scan_candidates(root: Path) -> list[Path]:
    """Return deterministic repository text candidates outside runtime state."""
    candidates: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(root)
        if any(part in SCAN_EXCLUDED_PARTS for part in relative.parts):
            continue
        candidates.append(path)
    return candidates


def _secret_hits(text: str, relative: Path) -> list[str]:
    """Return only locations of high-confidence matches, never matched values."""
    return [
        f"{relative.as_posix()}:{number}"
        for number, line in enumerate(text.splitlines(), 1)
        if any(pattern.search(line) for pattern in SECRET_PATTERNS)
    ]


def _secret_scan(root: Path) -> tuple[bool, str]:
    """Report high-confidence secret locations without retaining values."""
    matches: list[str] = []
    unreadable: list[str] = []
    for path in _scan_candidates(root):
        relative = path.relative_to(root)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            unreadable.append(relative.as_posix())
            continue
        matches.extend(_secret_hits(text, relative))
    locations = f"potential secret locations: {', '.join(matches[:20])}" if matches else ""
    unreadable_evidence = (
        f"unreadable secret-scan candidates: {', '.join(unreadable[:20])}"
        if unreadable else ""
    )
    evidence = "; ".join(part for part in (locations, unreadable_evidence) if part)
    return not matches and not unreadable, evidence or "no high-confidence secret patterns"


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
    if status == "UNAVAILABLE" and report:
        raise ValueError("unavailable dependency scan must not carry a report")
    digest = hashlib.sha256(report).hexdigest() if report else "none"
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
        "scope": list(ASSESSMENT_SCOPE),
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


def _validate_document_identity(
    envelope: dict[str, Any], trusted_source_commit: str, trusted_assessed_on: str
) -> dict[str, Any]:
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
    if document["source_commit_sha"] != trusted_source_commit:
        raise ValueError("security assessment source commit is not the trusted commit")
    if document["assessed_on"] != trusted_assessed_on:
        raise ValueError("security assessment date is not the trusted date")
    if document["scope"] != list(ASSESSMENT_SCOPE):
        raise ValueError("security assessment scope is invalid")
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
    static = evaluate_repository_controls(root, document["assessed_on"])
    expected_controls = [control.__dict__ for control in static]
    expected_controls.append(
        _dependency_control(dependency_scan_outcome, dependency_report).__dict__
    )
    if not isinstance(controls, list) or len(controls) != len(expected_controls):
        raise ValueError("security assessment controls are invalid")
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
    *,
    trusted_source_commit: str,
    trusted_assessed_on: str,
) -> dict[str, Any]:
    """Validate a complete assessment against repository and trusted CI state."""
    if SOURCE_SHA.fullmatch(trusted_source_commit) is None:
        raise ValueError("trusted security assessment source commit is invalid")
    date.fromisoformat(trusted_assessed_on)
    document = _validate_document_identity(
        envelope, trusted_source_commit, trusted_assessed_on
    )
    controls = _validate_controls(
        document, root, dependency_scan_outcome, dependency_report
    )
    _validate_dependency_evidence(controls[-1])
    _validate_document_invariants(document, controls)
    digest = hashlib.sha256(_canonical(document).encode("ascii")).hexdigest()
    if envelope["document_sha256"] != digest:
        raise ValueError("security assessment checksum mismatch")
    return envelope

"""Deterministic pre-live security assessment for repository-controlled controls."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import posixpath
import re
import shlex
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

try:
    import yaml
    from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
except ImportError:  # The evidence collector must survive dependency setup failure.
    yaml = None


SCHEMA_VERSION = "sentinel.security_assessment.v1"
PRODUCTION_DECISION = "NO_GO_PENDING_LIVE_EVIDENCE"
PIP_AUDIT_ACTION = "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266"
SOURCE_SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
CI_RUN_ID = re.compile(r"[1-9]\d{0,19}", re.ASCII)
PINNED_ACTION = re.compile(
    r"^(?!\./)(?!docker://)(?:[\w.-]+/)+[\w.-]+@[0-9a-f]{40}$",
    re.ASCII,
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
COPY_VALUE_FLAGS = frozenset({"chown", "chmod", "exclude", "from"})
COPY_BOOLEAN_FLAGS = frozenset({"link", "parents"})
DOCKER_ESCAPE_DIRECTIVE = re.compile(r"^#\s*escape\s*=\s*([\\`])\s*$", re.IGNORECASE)
DOCKER_PARSER_DIRECTIVE = re.compile(
    r"^#\s*(?P<key>[A-Za-z][\w.-]*)\s*=.*$", re.ASCII
)
UNSUPPORTED_DOCKER_PARSER_DIRECTIVES = frozenset({"check", "syntax"})


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    area: str
    status: str
    evidence: str
    owner: str
    severity_on_failure: str


@dataclass(frozen=True)
class DockerfileSpec:
    instructions: tuple[tuple[str, str], ...]
    escape_character: str


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


STANDARD_YAML_TAGS = {
    "tag:yaml.org,2002:bool",
    "tag:yaml.org,2002:float",
    "tag:yaml.org,2002:int",
    "tag:yaml.org,2002:map",
    "tag:yaml.org,2002:null",
    "tag:yaml.org,2002:seq",
    "tag:yaml.org,2002:str",
    "tag:yaml.org,2002:timestamp",
}
STRING_TAG = "tag:yaml.org,2002:str"


def _collect_action_references(
    node: Node,
    references: list[str],
    active_nodes: set[int],
    budget: list[int],
) -> None:
    """Traverse one composed YAML document and collect scalar uses values."""
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("workflow YAML exceeds the structural node limit")
    if node.tag not in STANDARD_YAML_TAGS:
        raise ValueError("workflow contains an unsupported YAML tag")
    identity = id(node)
    if identity in active_nodes:
        raise ValueError("workflow contains a recursive YAML alias")
    active_nodes.add(identity)
    try:
        if isinstance(node, MappingNode):
            _collect_mapping_action_references(
                node, references, active_nodes, budget
            )
        elif isinstance(node, SequenceNode):
            for item in node.value:
                _collect_action_references(item, references, active_nodes, budget)
        elif not isinstance(node, ScalarNode):
            raise ValueError("workflow contains an unsupported YAML node")
    finally:
        active_nodes.remove(identity)


def _collect_mapping_action_references(
    node: MappingNode,
    references: list[str],
    active_nodes: set[int],
    budget: list[int],
) -> None:
    """Reject ambiguous mapping keys and collect every structural uses entry."""
    keys: set[tuple[str, str]] = set()
    for key_node, value_node in node.value:
        if not isinstance(key_node, ScalarNode) or key_node.tag not in STANDARD_YAML_TAGS:
            raise ValueError("workflow mapping key must be scalar")
        identity = (key_node.tag, key_node.value)
        if identity in keys:
            raise ValueError("workflow contains a duplicate mapping key")
        keys.add(identity)
        if key_node.value == "uses":
            if not isinstance(value_node, ScalarNode) or value_node.tag != STRING_TAG:
                raise ValueError("workflow uses value must be a string scalar")
            reference = value_node.value.strip()
            if not reference:
                raise ValueError("workflow uses value must not be empty")
            references.append(reference)
        _collect_action_references(value_node, references, active_nodes, budget)


def workflow_action_references(text: str) -> tuple[list[str], int]:
    """Parse one workflow structurally and fail closed on unsupported YAML."""
    if yaml is None:
        return [], 1
    try:
        if len(text.encode("utf-8")) > 1_048_576:
            raise ValueError("workflow YAML exceeds the byte limit")
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
        if len(documents) != 1 or not isinstance(documents[0], MappingNode):
            raise ValueError("workflow must contain one mapping document")
        references: list[str] = []
        _collect_action_references(documents[0], references, set(), [100_000])
        return references, 0
    except (ValueError, yaml.YAMLError, RecursionError):
        return [], 1


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
    """Require exact versions and SHA-256 hashes in both dependency locks."""
    lock_names = ("requirements-hashed.txt", "requirements-assessment-hashed.txt")
    blocks: list[str] = []
    for name in lock_names:
        try:
            parsed = _requirement_blocks((root / name).read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            return False, f"{name} missing"
        if not parsed:
            return False, f"{name} has no complete requirements"
        blocks.extend(parsed)
    exact = re.compile(r"^[A-Za-z0-9_.-]+==[^\s]+(?:\s+--hash=sha256:[0-9a-f]{64})+$")
    invalid = [index for index, block in enumerate(blocks, 1) if not exact.fullmatch(block)]
    hash_count = sum(block.count("--hash=sha256:") for block in blocks)
    return not invalid, (
        f"{len(blocks)} exact packages; {hash_count} artifact hashes; "
        f"{len(invalid)} requirements without complete hash coverage"
    )


def _docker_comment_state(
    line: str,
    escape_character: str,
    directive_seen: bool,
    parser_window_open: bool,
) -> tuple[str, bool, bool] | None:
    """Apply the supported escape directive inside Docker's parser window."""
    if not parser_window_open:
        return escape_character, directive_seen, False
    matched = DOCKER_ESCAPE_DIRECTIVE.fullmatch(line)
    if matched is not None:
        if directive_seen:
            return None
        return matched.group(1), True, True
    if re.match(r"^#\s*escape\b", line, re.IGNORECASE):
        return None
    directive = DOCKER_PARSER_DIRECTIVE.fullmatch(line)
    if (
        directive is not None
        and directive.group("key").lower()
        in UNSUPPORTED_DOCKER_PARSER_DIRECTIVES
    ):
        return None
    return escape_character, directive_seen, False


def _docker_instruction_fragment(
    current: str, line: str, escape_character: str
) -> tuple[str, tuple[str, str] | None] | None:
    """Join one physical line and emit a complete Docker instruction."""
    trailing_escapes = len(line) - len(line.rstrip(escape_character))
    continued = trailing_escapes % 2 == 1
    combined = current + (line[:-1] if continued else line)
    if continued:
        return combined + " ", None
    directive, separator, argument = combined.strip().partition(" ")
    if not separator or not directive.isalpha() or not argument.strip():
        return None
    return "", (directive.upper(), argument.strip())


def _docker_instructions(text: str) -> DockerfileSpec | None:
    """Parse Dockerfile instructions using Docker's directive-window rules."""
    instructions: list[tuple[str, str]] = []
    current = ""
    escape_character = chr(92)
    escape_directive_seen = False
    parser_window_open = True
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            parser_window_open = False
            continue
        if line.startswith("#"):
            state = _docker_comment_state(
                line,
                escape_character,
                escape_directive_seen,
                parser_window_open,
            )
            if state is None:
                return None
            escape_character, escape_directive_seen, parser_window_open = state
            continue
        parser_window_open = False
        parsed = _docker_instruction_fragment(current, line, escape_character)
        if parsed is None:
            return None
        current, instruction = parsed
        if instruction is not None:
            instructions.append(instruction)
    if current or not instructions:
        return None
    return DockerfileSpec(tuple(instructions), escape_character)


@dataclass(frozen=True)
class CopySpec:
    sources: tuple[str, ...]
    from_reference: str | None


def _copy_flag_value(flag: str) -> tuple[str, str] | None:
    """Validate one reviewed COPY flag and return its name and value."""
    name, equals, value = flag[2:].partition("=")
    if name in COPY_VALUE_FLAGS:
        return None if not equals or not value else (name, value)
    if name in COPY_BOOLEAN_FLAGS:
        return None if equals and value not in {"true", "false"} else (name, value)
    return None


def _copy_flags(argument: str) -> tuple[str | None, str] | None:
    """Consume reviewed COPY flags and return source image plus remainder."""
    remaining = argument.strip()
    from_reference: str | None = None
    while remaining.startswith("--"):
        flag, separator, remaining = remaining.partition(" ")
        if not separator:
            return None
        parsed = _copy_flag_value(flag)
        if parsed is None:
            return None
        name, value = parsed
        if name == "from":
            if from_reference is not None:
                return None
            from_reference = value
        remaining = remaining.lstrip()
    return from_reference, remaining


def _copy_sources(
    remaining: str, escape_character: str = chr(92)
) -> tuple[str, ...] | None:
    """Parse JSON or shell-form COPY sources without interpreting paths."""
    try:
        if remaining.startswith("["):
            values = json.loads(remaining)
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                return None
            sources = values[:-1] if len(values) >= 2 else None
            return None if sources is None else tuple(sources)
        lexer = shlex.shlex(remaining, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        lexer.escape = escape_character
        values = list(lexer)
    except ValueError:
        return None
    sources = values[:-1] if len(values) >= 2 else None
    return None if sources is None else tuple(sources)


def _copy_spec(argument: str, escape_character: str = chr(92)) -> CopySpec | None:
    """Parse reviewed Docker COPY flags, sources, and optional source image."""
    parsed_flags = _copy_flags(argument)
    if parsed_flags is None:
        return None
    from_reference, remaining = parsed_flags
    sources = _copy_sources(remaining, escape_character)
    return None if sources is None else CopySpec(sources, from_reference)


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
    instructions: tuple[tuple[str, str], ...],
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


def _copy_sources_are_narrow(
    instructions: tuple[tuple[str, str], ...], escape_character: str
) -> bool:
    """Reject ADD and malformed, broad, or escaping COPY sources."""
    for directive, argument in instructions:
        if directive == "ADD":
            return False
        if directive != "COPY":
            continue
        spec = _copy_spec(argument, escape_character)
        if spec is None:
            return False
        if spec.from_reference is None and any(
            not _narrow_copy_source(source) for source in spec.sources
        ):
            return False
    return True


def _narrow_copy_source(source: str) -> bool:
    """Validate one COPY source after portable lexical canonicalization."""
    portable = source.replace(chr(92), "/")
    if (
        not portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable) or "$" in portable
        or any(character in portable for character in "*?[]")
    ):
        return False
    if ".." in portable.split("/"):
        return False
    normalized = posixpath.normpath(portable)
    return normalized not in {"", ".", "/"} and not normalized.startswith("../")


# re.ASCII is required so Unicode decimal digits cannot act as stage indexes.
STAGE_INDEX = re.compile(r"\d+", re.ASCII)
OVERLAY_RUNTIME_IMAGE_REFERENCE = "${RUNTIME_IMAGE}"
OVERLAY_ALLOWED_UNPINNED_BASES = frozenset({OVERLAY_RUNTIME_IMAGE_REFERENCE})


def _is_prior_stage(reference: str, aliases: set[str], stage_count: int) -> bool:
    """Return whether a FROM/COPY reference names an already declared stage."""
    return reference.lower() in aliases or (
        STAGE_INDEX.fullmatch(reference) is not None
        and int(reference) < stage_count
    )


def _is_digest_pinned_reference(reference: str) -> bool:
    """Accept only a complete lowercase SHA-256 image digest."""
    _, separator, digest = reference.rpartition("@sha256:")
    return bool(separator) and DIGEST.fullmatch(digest) is not None


def _from_reference(
    argument: str,
    aliases: set[str],
    stage_count: int,
    allowed_unpinned_bases: frozenset[str],
) -> tuple[bool, str | None]:
    """Validate one FROM reference and return its optional stage alias."""
    parsed = _from_spec(argument)
    if parsed is None:
        return False, None
    image, alias = parsed
    immutable = (
        _is_prior_stage(image, aliases, stage_count)
        or image in allowed_unpinned_bases
        or _is_digest_pinned_reference(image)
    )
    return immutable, alias


def _copy_reference_is_immutable(
    argument: str,
    aliases: set[str],
    stage_count: int,
    escape_character: str,
) -> bool:
    """Require an external COPY source image to use an immutable digest."""
    spec = _copy_spec(argument, escape_character)
    if spec is None:
        return False
    reference = spec.from_reference
    return (
        reference is None
        or _is_prior_stage(reference, aliases, stage_count)
        or _is_digest_pinned_reference(reference)
    )


def _container_references_are_immutable(
    instructions: tuple[tuple[str, str], ...],
    allowed_unpinned_bases: frozenset[str],
    escape_character: str,
) -> bool:
    """Require digests for external FROM and COPY --from references."""
    aliases: set[str] = set()
    stage_count = 0
    for directive, argument in instructions:
        if directive == "FROM":
            immutable, alias = _from_reference(
                argument, aliases, stage_count, allowed_unpinned_bases
            )
            if not immutable:
                return False
            if alias:
                aliases.add(alias.lower())
            stage_count += 1
        elif directive == "COPY" and not _copy_reference_is_immutable(
            argument, aliases, stage_count, escape_character
        ):
            return False
    return stage_count > 0


def _container_file_passes(
    text: str,
    allowed_unpinned_bases: frozenset[str] = frozenset(),
) -> bool:
    """Evaluate final-stage user and broad-copy behavior from parsed directives."""
    dockerfile = _docker_instructions(text)
    if dockerfile is None or not _copy_sources_are_narrow(
        dockerfile.instructions, dockerfile.escape_character
    ):
        return False
    instructions = dockerfile.instructions
    metadata = _container_metadata(instructions)
    if metadata is None:
        return False
    _base_images, final_user = metadata
    immutable = _container_references_are_immutable(
        instructions, allowed_unpinned_bases, dockerfile.escape_character
    )
    return final_user == "10001:10001" and immutable


def _containers_are_pinned_non_root(root: Path) -> tuple[bool, str]:
    """Check immutable runtime base, effective non-root user, and narrow copies."""
    try:
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        assurance = (root / "Dockerfile.assurance").read_text(encoding="utf-8")
        qualification = (root / "Dockerfile.qualification").read_text(
            encoding="utf-8"
        )
    except (OSError, UnicodeError):
        return False, "container build definitions missing or unreadable"
    checks = (
        ("Dockerfile", dockerfile, frozenset()),
        ("Dockerfile.assurance", assurance, OVERLAY_ALLOWED_UNPINNED_BASES),
        (
            "Dockerfile.qualification",
            qualification,
            OVERLAY_ALLOWED_UNPINNED_BASES,
        ),
    )
    failing = [
        name
        for name, content, allowed_unpinned_bases in checks
        if not _container_file_passes(content, allowed_unpinned_bases)
    ]
    evidence = (
        "parsed final-stage user, digest base, and COPY source policy; "
        f"{len(failing)} failing definitions"
    )
    if failing:
        evidence += f": {', '.join(failing)}"
    return not failing, evidence


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
    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = sorted(
            name for name in subdirectories if name not in SCAN_EXCLUDED_PARTS
        )
        for name in sorted(filenames):
            path = Path(directory) / name
            if path.suffix.lower() in TEXT_SUFFIXES and path.is_file():
                candidates.append(path)
    return sorted(candidates)


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

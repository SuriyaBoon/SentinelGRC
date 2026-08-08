"""Role-isolated staging lifecycle validation for private Azure deployments.

Each invocation uses exactly one role-bearing managed identity and executes one
bounded lifecycle phase. The canonical governance state is the handoff between
phases; no process can request both analyst and approver tokens.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from urllib.parse import urlparse
from uuid import UUID


MAX_RESPONSE_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 16384
ROLE_PHASES = {
    "analyst": {"analyst_prepare", "analyst_remediate"},
    "approver": {"approver_approve", "approver_close"},
}
NEXT_PHASE = {
    "analyst_prepare": "approver_approve",
    "approver_approve": "analyst_remediate",
    "analyst_remediate": "approver_close",
    "approver_close": None,
}
LEGACY_DUAL_IDENTITY_SETTINGS = {
    "SENTINEL_VALIDATION_ANALYST_CLIENT_ID",
    "SENTINEL_VALIDATION_APPROVER_CLIENT_ID",
}


class ValidationFailure(RuntimeError):
    """Fail-closed validation error without sensitive runtime details."""


class TokenProvider(Protocol):
    def get_token(self, client_id: str, audience: str) -> str: ...


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        token: str | None = None,
        body: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, Any]]: ...


@dataclass(frozen=True)
class ValidatorConfig:
    api_base_url: str
    audience: str
    client_id: str
    role: str
    phase: str
    run_id: str
    expected_subject: str
    peer_subject: str

    def validate(self) -> None:
        parsed = urlparse(self.api_base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or not parsed.hostname
            or not parsed.hostname.endswith(".azurecontainerapps.io")
        ):
            raise ValueError(
                "api_base_url must be a root HTTPS Azure Container Apps URL"
            )
        if (
            not isinstance(self.audience, str)
            or not self.audience.startswith("api://")
            or len(self.audience) > 256
        ):
            raise ValueError("audience must be a bounded api:// URI")
        try:
            UUID(self.client_id)
        except (ValueError, AttributeError) as error:
            raise ValueError("client_id must be a GUID") from error
        if self.role not in ROLE_PHASES:
            raise ValueError("validation role is unsupported")
        if self.phase not in ROLE_PHASES[self.role]:
            raise ValueError("validation phase is not allowed for this role")
        for name, value in (
            ("expected_subject", self.expected_subject),
            ("peer_subject", self.peer_subject),
        ):
            try:
                UUID(value)
            except (ValueError, AttributeError) as error:
                raise ValueError(f"{name} must be a GUID") from error
        if self.expected_subject == self.peer_subject:
            raise ValueError("validation actor subjects must be distinct")
        if (
            not isinstance(self.run_id, str)
            or not 1 <= len(self.run_id) <= 24
            or not self.run_id.replace("-", "").isalnum()
        ):
            raise ValueError("run_id must be bounded alphanumeric text")


class ManagedIdentityTokenProvider:
    def get_token(self, client_id: str, audience: str) -> str:
        try:
            from azure.identity import ManagedIdentityCredential
        except ModuleNotFoundError as error:
            raise ValidationFailure(
                "managed identity dependency is unavailable"
            ) from error
        credential = ManagedIdentityCredential(client_id=client_id)
        token = credential.get_token(f"{audience}/.default").token
        if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN_BYTES:
            raise ValidationFailure("managed identity returned an invalid token")
        return token


class UrllibTransport:
    def __init__(self, timeout_seconds: float = 15.0) -> None:
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("HTTP timeout must be between 1 and 30 seconds")
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _payload(raw: bytes) -> dict[str, Any]:
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValidationFailure("validation response exceeded the size limit")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValidationFailure("validation response was not JSON") from error
        if not isinstance(payload, dict):
            raise ValidationFailure("validation response was not an object")
        return payload

    def request(
        self,
        method: str,
        url: str,
        *,
        token: str | None = None,
        body: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "SentinelGRC-Azure-Staging-Validator/2.0",
        }
        data = None
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(
                body, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        request = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout_seconds
            ) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                return int(response.status), self._payload(raw)
        except urllib.error.HTTPError as error:
            raw = error.read(MAX_RESPONSE_BYTES + 1)
            return int(error.code), self._payload(raw)
        except Exception as error:
            raise ValidationFailure("validation HTTP request failed") from error


def _token_subject(token: str) -> str:
    if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN_BYTES:
        raise ValidationFailure("identity token was invalid")
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("invalid JWT")
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(raw.decode("utf-8"))
        subject = claims.get("sub") if isinstance(claims, dict) else None
        if not isinstance(subject, str) or not subject or len(subject) > 256:
            raise ValueError("missing subject")
        return subject
    except Exception as error:
        raise ValidationFailure("identity token had no usable subject") from error


class AzureStagingLifecycleValidator:
    def __init__(
        self,
        config: ValidatorConfig,
        token_provider: TokenProvider,
        transport: HttpTransport,
    ) -> None:
        config.validate()
        self.config = config
        self.token_provider = token_provider
        self.transport = transport
        self.gates: list[dict[str, Any]] = []

    def _expect(
        self,
        name: str,
        method: str,
        path: str,
        expected_status: int,
        *,
        token: str | None = None,
        body: dict[str, Any] | None = None,
        predicate: Callable[[dict[str, Any]], bool] | None = None,
    ) -> dict[str, Any]:
        status, payload = self.transport.request(
            method,
            self.config.api_base_url.rstrip("/") + path,
            token=token,
            body=body,
        )
        passed = status == expected_status and (
            predicate(payload) if predicate is not None else True
        )
        self.gates.append(
            {
                "name": name,
                "expected_http_status": expected_status,
                "actual_http_status": status,
                "passed": bool(passed),
            }
        )
        if not passed:
            raise ValidationFailure(f"validation gate failed: {name}")
        return payload

    def _post(
        self,
        name: str,
        action: str,
        finding_id: str,
        expected_status: int,
        token: str,
        body: dict[str, Any],
        *,
        expected_finding_status: str | None = None,
        expected_error: str | None = None,
    ) -> dict[str, Any]:
        if expected_finding_status is not None and expected_error is not None:
            raise ValueError("only one response predicate may be configured")
        predicate = None
        if expected_finding_status is not None:
            predicate = (
                lambda payload: payload.get("status")
                == expected_finding_status
            )
        elif expected_error is not None:
            predicate = lambda payload: payload.get("error") == expected_error
        return self._expect(
            name,
            "POST",
            f"/v1/governance/{action}",
            expected_status,
            token=token,
            body={"finding_id": finding_id, **body},
            predicate=predicate,
        )

    def _read_state(
        self, name: str, finding_id: str, token: str, expected: str
    ) -> None:
        self._expect(
            name,
            "GET",
            f"/findings/{finding_id}",
            200,
            token=token,
            predicate=lambda payload: payload.get("status") == expected,
        )

    def _finding_state(
        self,
        name: str,
        finding_id: str,
        token: str,
        *,
        allowed: set[str],
        expected_fields: dict[str, str],
        allow_absent: bool = False,
        state_fields: dict[str, dict[str, str]] | None = None,
    ) -> str:
        status, payload = self.transport.request(
            "GET",
            self.config.api_base_url.rstrip("/") + f"/findings/{finding_id}",
            token=token,
        )
        error = payload.get("error")
        if (
            allow_absent
            and status == 400
            and isinstance(error, str)
            and "was not found" in error
        ):
            state = "absent"
        elif status == 200 and payload.get("status") in allowed:
            state = str(payload["status"])
            if any(payload.get(key) != value for key, value in expected_fields.items()):
                raise ValidationFailure(
                    f"validation finding identity mismatch: {name}"
                )
            expected_for_state = (state_fields or {}).get(state, {})
            if any(
                payload.get(key) != value
                for key, value in expected_for_state.items()
            ):
                raise ValidationFailure(
                    f"validation finding state data mismatch: {name}"
                )
        else:
            raise ValidationFailure(f"validation state was not resumable: {name}")
        self.gates.append(
            {
                "name": name,
                "expected_outcomes": sorted(
                    ({"absent"} if allow_absent else set()) | allowed
                ),
                "actual_http_status": status,
                "actual_finding_status": state,
                "passed": True,
            }
        )
        return state

    def _health(self) -> None:
        self._expect(
            "healthz",
            "GET",
            "/healthz",
            200,
            predicate=lambda payload: payload.get("status") == "ok",
        )
        self._expect(
            "ready",
            "GET",
            "/ready",
            200,
            predicate=lambda payload: payload.get("status") == "ready"
            and isinstance(payload.get("checks"), dict)
            and bool(payload["checks"])
            and all(value is True for value in payload["checks"].values()),
        )

    def _analyst_prepare(
        self, finding_id: str, token: str, subject: str
    ) -> str:
        self._expect(
            "missing_auth_rejected",
            "GET",
            "/findings",
            401,
            predicate=lambda payload: payload.get("error")
            == "missing_bearer_token",
        )
        self._post(
            "actor_spoof_rejected",
            "create",
            finding_id,
            400,
            token,
            {
                "control_id": "AZ-STAGING-AUTH",
                "asset_id": "azure-staging",
                "title": "Actor spoof validation",
                "risk_owner": subject,
                "severity": "high",
                "actor_id": "caller-controlled",
            },
            expected_error="actor identity must come from authentication context",
        )
        create_body = {
            "control_id": "AZ-STAGING-E2E",
            "asset_id": "azure-staging",
            "title": "Role-isolated Azure staging lifecycle validation",
            "risk_owner": subject,
            "severity": "critical",
        }
        state = self._finding_state(
            "main_finding_resume_state",
            finding_id,
            token,
            allowed={"open", "risk_assessed", "pending_approval"},
            expected_fields={
                "control_id": create_body["control_id"],
                "asset_id": create_body["asset_id"],
                "risk_owner": subject,
            },
            allow_absent=True,
        )
        if state == "absent":
            self._post(
                "finding_created",
                "create",
                finding_id,
                200,
                token,
                create_body,
                expected_finding_status="open",
            )
            state = "open"
        self._post(
            "duplicate_finding_rejected",
            "create",
            finding_id,
            400,
            token,
            create_body,
            expected_error=f"finding {finding_id} already exists",
        )
        if state == "open":
            self._post(
                "risk_assessed",
                "assess",
                finding_id,
                200,
                token,
                {"likelihood": "high", "impact": "critical"},
                expected_finding_status="risk_assessed",
            )
            state = "risk_assessed"
        if state == "risk_assessed":
            self._post(
                "treatment_proposed",
                "propose",
                finding_id,
                200,
                token,
                {
                    "treatment_type": "mitigate",
                    "reason": "Validate the private staging lifecycle",
                    "action_owner": subject,
                },
                expected_finding_status="pending_approval",
            )

        sod_id = f"AZ-{self.config.run_id}-SOD"
        sod_body = {
            "control_id": "AZ-STAGING-SOD",
            "asset_id": "azure-staging",
            "title": "Risk-owner self-approval rejection validation",
            "risk_owner": self.config.peer_subject,
            "severity": "high",
        }
        sod_state = self._finding_state(
            "self_approval_finding_resume_state",
            sod_id,
            token,
            allowed={"open", "risk_assessed", "pending_approval"},
            expected_fields={
                "control_id": sod_body["control_id"],
                "asset_id": sod_body["asset_id"],
                "risk_owner": self.config.peer_subject,
            },
            allow_absent=True,
        )
        if sod_state == "absent":
            self._post(
                "self_approval_finding_created", "create", sod_id, 200,
                token, sod_body, expected_finding_status="open",
            )
            sod_state = "open"
        if sod_state == "open":
            self._post(
                "self_approval_risk_assessed", "assess", sod_id, 200,
                token, {"likelihood": "high", "impact": "high"},
                expected_finding_status="risk_assessed",
            )
            sod_state = "risk_assessed"
        if sod_state == "risk_assessed":
            self._post(
                "self_approval_treatment_proposed", "propose", sod_id, 200,
                token,
                {
                    "treatment_type": "mitigate",
                    "reason": "Prove server-side self-approval rejection",
                    "action_owner": subject,
                },
                expected_finding_status="pending_approval",
            )
        return "pending_approval"

    def _approver_approve(
        self, finding_id: str, token: str, subject: str
    ) -> str:
        sod_id = f"AZ-{self.config.run_id}-SOD"
        sod_state = self._finding_state(
            "self_approval_handoff_verified",
            sod_id,
            token,
            allowed={"pending_approval"},
            expected_fields={
                "control_id": "AZ-STAGING-SOD",
                "asset_id": "azure-staging",
                "risk_owner": subject,
                "treatment_type": "mitigate",
                "action_owner": self.config.peer_subject,
            },
        )
        if sod_state != "pending_approval":
            raise ValidationFailure("self-approval finding was not prepared")
        self._post(
            "risk_owner_self_approval_rejected",
            "approve",
            sod_id,
            403,
            token,
            {"decision": "approved", "reason": "must be rejected"},
            expected_error="risk owner cannot approve the same finding",
        )
        state = self._finding_state(
            "pending_approval_handoff_verified",
            finding_id,
            token,
            allowed={"pending_approval", "approved"},
            expected_fields={
                "control_id": "AZ-STAGING-E2E",
                "asset_id": "azure-staging",
                "risk_owner": self.config.peer_subject,
                "treatment_type": "mitigate",
                "action_owner": self.config.peer_subject,
            },
        )
        if state == "pending_approval":
            self._post(
                "premature_close_rejected",
                "close",
                finding_id,
                400,
                token,
                {"reason": "must not close before verification"},
                expected_error="finding cannot close before verification or accepted-risk treatment",
            )
            self._post(
                "treatment_approved",
                "approve",
                finding_id,
                200,
                token,
                {"decision": "approved", "reason": "staging validation"},
                expected_finding_status="approved",
            )
        return "approved"

    def _analyst_remediate(
        self, finding_id: str, token: str, subject: str
    ) -> str:
        state = self._finding_state(
            "approved_handoff_verified",
            finding_id,
            token,
            allowed={"approved", "in_progress", "pending_verification"},
            expected_fields={
                "control_id": "AZ-STAGING-E2E",
                "asset_id": "azure-staging",
                "risk_owner": subject,
                "treatment_type": "mitigate",
                "action_owner": subject,
            },
            state_fields={
                "in_progress": {"implementer": subject},
                "pending_verification": {
                    "implementer": subject,
                    "evidence_submitter": subject,
                },
            },
        )
        if state == "approved":
            self._post(
                "action_started",
                "start",
                finding_id,
                200,
                token,
                {"implementer": subject},
                expected_finding_status="in_progress",
            )
            state = "in_progress"
        evidence_content = (
            f"sentinelgrc-azure-staging-validation:{self.config.run_id}"
        )
        if state == "in_progress":
            self._post(
                "evidence_submitted",
                "evidence",
                finding_id,
                200,
                token,
                {
                    "source": "azure-staging-validator",
                    "content": evidence_content,
                },
                expected_finding_status="pending_verification",
            )
        self._post(
            "implementer_self_verification_rejected",
            "verify",
            finding_id,
            403,
            token,
            {"passed": True, "notes": "must be independently verified"},
            expected_error=(
                "verification must be independent from implementation and "
                "evidence submission"
            ),
        )
        return "pending_verification"

    def _approver_close(
        self, finding_id: str, token: str, subject: str
    ) -> str:
        state = self._finding_state(
            "pending_verification_handoff_verified",
            finding_id,
            token,
            allowed={"pending_verification", "verified", "closed"},
            expected_fields={
                "control_id": "AZ-STAGING-E2E",
                "asset_id": "azure-staging",
                "risk_owner": self.config.peer_subject,
                "treatment_type": "mitigate",
                "action_owner": self.config.peer_subject,
            },
            state_fields={
                "pending_verification": {
                    "implementer": self.config.peer_subject,
                    "evidence_submitter": self.config.peer_subject,
                },
                "verified": {
                    "implementer": self.config.peer_subject,
                    "evidence_submitter": self.config.peer_subject,
                },
                "closed": {
                    "implementer": self.config.peer_subject,
                    "evidence_submitter": self.config.peer_subject,
                },
            },
        )
        if state == "pending_verification":
            self._post(
                "independent_verification_passed",
                "verify",
                finding_id,
                200,
                token,
                {"passed": True, "notes": "validated in private Azure staging"},
                expected_finding_status="verified",
            )
            state = "verified"
        if state == "verified":
            self._post(
                "finding_closed",
                "close",
                finding_id,
                200,
                token,
                {"reason": "role-isolated staging lifecycle completed"},
                expected_finding_status="closed",
            )
        self._read_state(
            "closed_finding_readback", finding_id, token, "closed"
        )
        return "closed"

    def run(self) -> dict[str, Any]:
        self._health()
        token = self.token_provider.get_token(
            self.config.client_id, self.config.audience
        )
        subject = _token_subject(token)
        if subject != self.config.expected_subject:
            raise ValidationFailure(
                "token subject did not match the configured managed identity"
            )
        if subject == self.config.peer_subject:
            raise ValidationFailure("validation actors were not distinct")
        finding_id = f"AZ-{self.config.run_id}-E2E"
        handlers = {
            "analyst_prepare": self._analyst_prepare,
            "approver_approve": self._approver_approve,
            "analyst_remediate": self._analyst_remediate,
            "approver_close": self._approver_close,
        }
        final_status = handlers[self.config.phase](
            finding_id, token, subject
        )
        next_phase = NEXT_PHASE[self.config.phase]
        state_material = "|".join(
            (
                self.config.run_id,
                finding_id,
                final_status,
                next_phase or "complete",
            )
        )
        report = {
            "schema_version": "2.0.0",
            "scope": "azure_staging_validation",
            "status": "passed",
            "run_id": self.config.run_id,
            "phase": self.config.phase,
            "role": self.config.role,
            "finding_id": finding_id,
            "actor_fingerprint": hashlib.sha256(
                subject.encode("utf-8")
            ).hexdigest(),
            "peer_actor_fingerprint": hashlib.sha256(
                self.config.peer_subject.encode("utf-8")
            ).hexdigest(),
            "cross_role_actors_distinct": True,
            "state_sha256": hashlib.sha256(
                state_material.encode("utf-8")
            ).hexdigest(),
            "final_finding_status": final_status,
            "next_phase": next_phase,
            "gates": self.gates,
            "production_ready": False,
        }
        serialized = json.dumps(report, sort_keys=True)
        if token in serialized or subject in serialized:
            raise ValidationFailure("sanitized report contained identity material")
        return report


def _config_from_environment() -> ValidatorConfig:
    if any(os.environ.get(name, "").strip() for name in LEGACY_DUAL_IDENTITY_SETTINGS):
        raise ValueError("legacy dual-identity validation settings are forbidden")
    names = {
        "api_base_url": "SENTINEL_VALIDATION_API_URL",
        "audience": "SENTINEL_VALIDATION_AUDIENCE",
        "client_id": "SENTINEL_VALIDATION_CLIENT_ID",
        "role": "SENTINEL_VALIDATION_ROLE",
        "phase": "SENTINEL_VALIDATION_PHASE",
        "run_id": "SENTINEL_VALIDATION_RUN_ID",
        "expected_subject": "SENTINEL_VALIDATION_EXPECTED_SUBJECT",
        "peer_subject": "SENTINEL_VALIDATION_PEER_SUBJECT",
    }
    values: dict[str, str] = {}
    for field, environment_name in names.items():
        value = os.environ.get(environment_name, "").strip()
        if not value:
            raise ValueError(f"missing required setting: {environment_name}")
        values[field] = value
    config = ValidatorConfig(**values)
    config.validate()
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one role-isolated SentinelGRC staging validation phase."
    )
    parser.add_argument(
        "--pretty", action="store_true", help="Indent the sanitized JSON report."
    )
    args = parser.parse_args(argv)
    try:
        report = AzureStagingLifecycleValidator(
            _config_from_environment(),
            ManagedIdentityTokenProvider(),
            UrllibTransport(),
        ).run()
        print(
            json.dumps(
                report,
                indent=2 if args.pretty else None,
                sort_keys=True,
            )
        )
        return 0
    except Exception:
        print(
            json.dumps(
                {
                    "schema_version": "2.0.0",
                    "scope": "azure_staging_validation",
                    "status": "failed",
                    "error": "validation_failed",
                    "production_ready": False,
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())

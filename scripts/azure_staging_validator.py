"""Staging-only authenticated lifecycle validator for private Azure deployments.

The validator obtains short-lived tokens from separate managed identities and
prints a sanitized proof report. It is not part of the SentinelGRC server
runtime and is not a production-readiness claim.
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
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from urllib.parse import urlparse
from uuid import UUID


MAX_RESPONSE_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 16384


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
    analyst_client_id: str
    approver_client_id: str

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
        for name, value in (
            ("analyst_client_id", self.analyst_client_id),
            ("approver_client_id", self.approver_client_id),
        ):
            try:
                UUID(value)
            except (ValueError, AttributeError) as error:
                raise ValueError(f"{name} must be a GUID") from error
        if self.analyst_client_id == self.approver_client_id:
            raise ValueError("analyst and approver identities must be separate")


class ManagedIdentityTokenProvider:
    def __init__(self) -> None:
        self._credentials: dict[str, Any] = {}

    def get_token(self, client_id: str, audience: str) -> str:
        try:
            from azure.identity import ManagedIdentityCredential
        except ModuleNotFoundError as error:
            raise ValidationFailure("managed identity dependency is unavailable") from error
        credential = self._credentials.get(client_id)
        if credential is None:
            credential = ManagedIdentityCredential(client_id=client_id)
            self._credentials[client_id] = credential
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
            "User-Agent": "SentinelGRC-Azure-Staging-Validator/1.0",
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
        *,
        run_id_factory: Callable[[], str] | None = None,
    ) -> None:
        config.validate()
        self.config = config
        self.token_provider = token_provider
        self.transport = transport
        self.run_id_factory = run_id_factory or (lambda: uuid.uuid4().hex[:12])
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
    ) -> dict[str, Any]:
        predicate = None
        if expected_finding_status is not None:
            predicate = lambda payload: payload.get("status") == expected_finding_status
        return self._expect(
            name,
            "POST",
            f"/v1/governance/{action}",
            expected_status,
            token=token,
            body={"finding_id": finding_id, **body},
            predicate=predicate,
        )

    def run(self) -> dict[str, Any]:
        run_id = self.run_id_factory()
        if (
            not isinstance(run_id, str)
            or not run_id
            or len(run_id) > 32
            or not run_id.replace("-", "").isalnum()
        ):
            raise ValidationFailure("run identifier was invalid")

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

        analyst_token = self.token_provider.get_token(
            self.config.analyst_client_id, self.config.audience
        )
        approver_token = self.token_provider.get_token(
            self.config.approver_client_id, self.config.audience
        )
        analyst_subject = _token_subject(analyst_token)
        approver_subject = _token_subject(approver_token)
        if analyst_subject == approver_subject:
            raise ValidationFailure("managed identities did not produce separate actors")

        self._expect(
            "missing_auth_rejected",
            "GET",
            "/findings",
            401,
            predicate=lambda payload: payload.get("error") == "missing_bearer_token",
        )

        spoof_id = f"AZ-{run_id}-SPOOF"
        self._post(
            "actor_spoof_rejected",
            "create",
            spoof_id,
            400,
            analyst_token,
            {
                "control_id": "AZ-STAGING-AUTH",
                "asset_id": "azure-staging",
                "title": "Actor spoof validation",
                "risk_owner": analyst_subject,
                "severity": "high",
                "actor_id": "caller-controlled",
            },
        )

        self_approval_id = f"AZ-{run_id}-SOD"
        self._post(
            "self_approval_finding_created",
            "create",
            self_approval_id,
            200,
            analyst_token,
            {
                "control_id": "AZ-STAGING-SOD",
                "asset_id": "azure-staging",
                "title": "Self approval rejection validation",
                "risk_owner": approver_subject,
                "severity": "high",
            },
            expected_finding_status="open",
        )
        self._post(
            "self_approval_risk_assessed",
            "assess",
            self_approval_id,
            200,
            analyst_token,
            {"likelihood": "high", "impact": "high"},
            expected_finding_status="risk_assessed",
        )
        self._post(
            "self_approval_treatment_proposed",
            "propose",
            self_approval_id,
            200,
            analyst_token,
            {
                "treatment_type": "mitigate",
                "reason": "Validate server-side self-approval rejection",
                "action_owner": analyst_subject,
            },
            expected_finding_status="pending_approval",
        )
        self._post(
            "risk_owner_self_approval_rejected",
            "approve",
            self_approval_id,
            403,
            approver_token,
            {"decision": "approved", "reason": "must be rejected"},
        )

        finding_id = f"AZ-{run_id}-E2E"
        create_body = {
            "control_id": "AZ-STAGING-E2E",
            "asset_id": "azure-staging",
            "title": "Authenticated Azure staging lifecycle validation",
            "risk_owner": analyst_subject,
            "severity": "critical",
        }
        self._post(
            "finding_created",
            "create",
            finding_id,
            200,
            analyst_token,
            create_body,
            expected_finding_status="open",
        )
        self._post(
            "duplicate_finding_rejected",
            "create",
            finding_id,
            400,
            analyst_token,
            create_body,
        )
        self._post(
            "risk_assessed",
            "assess",
            finding_id,
            200,
            analyst_token,
            {"likelihood": "high", "impact": "critical"},
            expected_finding_status="risk_assessed",
        )
        self._post(
            "treatment_proposed",
            "propose",
            finding_id,
            200,
            analyst_token,
            {
                "treatment_type": "mitigate",
                "reason": "Validate the private staging lifecycle",
                "action_owner": analyst_subject,
            },
            expected_finding_status="pending_approval",
        )
        self._post(
            "premature_close_rejected",
            "close",
            finding_id,
            400,
            approver_token,
            {"reason": "must not close before verification"},
        )
        self._post(
            "treatment_approved",
            "approve",
            finding_id,
            200,
            approver_token,
            {"decision": "approved", "reason": "staging validation"},
            expected_finding_status="approved",
        )
        self._post(
            "action_started",
            "start",
            finding_id,
            200,
            analyst_token,
            {"implementer": analyst_subject},
            expected_finding_status="in_progress",
        )
        evidence_content = f"sentinelgrc-azure-staging-validation:{run_id}"
        evidence_sha256 = hashlib.sha256(
            evidence_content.encode("utf-8")
        ).hexdigest()
        self._post(
            "evidence_submitted",
            "evidence",
            finding_id,
            200,
            analyst_token,
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
            analyst_token,
            {"passed": True, "notes": "must be independently verified"},
        )
        self._post(
            "independent_verification_passed",
            "verify",
            finding_id,
            200,
            approver_token,
            {"passed": True, "notes": "validated in private Azure staging"},
            expected_finding_status="verified",
        )
        self._post(
            "finding_closed",
            "close",
            finding_id,
            200,
            approver_token,
            {"reason": "authenticated staging lifecycle completed"},
            expected_finding_status="closed",
        )
        self._expect(
            "closed_finding_readback",
            "GET",
            f"/findings/{finding_id}",
            200,
            token=analyst_token,
            predicate=lambda payload: payload.get("status") == "closed",
        )

        report = {
            "schema_version": "1.0.0",
            "scope": "azure_staging_validation",
            "status": "passed",
            "run_id": run_id,
            "finding_ids": {
                "segregation_of_duties": self_approval_id,
                "complete_lifecycle": finding_id,
            },
            "actor_fingerprints": {
                "analyst": hashlib.sha256(
                    analyst_subject.encode("utf-8")
                ).hexdigest(),
                "approver": hashlib.sha256(
                    approver_subject.encode("utf-8")
                ).hexdigest(),
            },
            "evidence_sha256": evidence_sha256,
            "final_finding_status": "closed",
            "gates": self.gates,
            "production_ready": False,
        }
        serialized = json.dumps(report, sort_keys=True)
        if analyst_token in serialized or approver_token in serialized:
            raise ValidationFailure("sanitized report contained a bearer token")
        return report


def _config_from_environment() -> ValidatorConfig:
    names = {
        "api_base_url": "SENTINEL_VALIDATION_API_URL",
        "audience": "SENTINEL_VALIDATION_AUDIENCE",
        "analyst_client_id": "SENTINEL_VALIDATION_ANALYST_CLIENT_ID",
        "approver_client_id": "SENTINEL_VALIDATION_APPROVER_CLIENT_ID",
    }
    values: dict[str, str] = {}
    for field, environment_name in names.items():
        value = os.environ.get(environment_name, "").strip()
        if not value:
            raise ValueError(f"missing required setting: {environment_name}")
        values[field] = value
    return ValidatorConfig(**values)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the staging-only SentinelGRC Azure lifecycle validation."
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
                    "schema_version": "1.0.0",
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

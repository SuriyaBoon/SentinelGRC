import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from governance_api import GovernanceApi
from governance_core import ActorContext, GovernanceCore
from governance_http import GovernanceHttpApplication
from human_identity import AuthenticationError, HumanIdentityStore
from scripts.azure_staging_validator import (
    AzureStagingLifecycleValidator,
    ValidationFailure,
    ValidatorConfig,
    _config_from_environment,
    _token_subject,
)


ANALYST_ID = "11111111-1111-4111-8111-111111111111"
APPROVER_ID = "22222222-2222-4222-8222-222222222222"
ANALYST_SUBJECT = "33333333-3333-4333-8333-333333333333"
APPROVER_SUBJECT = "44444444-4444-4444-8444-444444444444"


def fake_token(subject):
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": subject}).encode("utf-8")
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


class SingleIdentityTokenProvider:
    def __init__(self, client_id, subject):
        self.client_id = client_id
        self.subject = subject
        self.token = fake_token(subject)
        self.calls = []

    def get_token(self, client_id, audience):
        self.calls.append((client_id, audience))
        if client_id != self.client_id or audience != "api://sentinel-test":
            raise AssertionError("cross-role token request attempted")
        return self.token


class ScriptedTransport:
    def __init__(self, responses):
        self.calls = []
        self.responses = list(responses)

    def request(self, method, url, *, token=None, body=None):
        self.calls.append(
            {"method": method, "url": url, "token": token, "body": body}
        )
        if not self.responses:
            raise AssertionError("unexpected request")
        return self.responses.pop(0)


class RoleTokenVerifier:
    def __init__(self, actors):
        self.actors = actors

    def verify(self, token):
        try:
            return self.actors[token]
        except KeyError as error:
            raise AuthenticationError("invalid bearer token") from error


class InProcessGovernanceTransport:
    """Exercise the real HTTP adapter while preserving runtime readiness shape."""

    def __init__(self, application):
        self.application = application

    def request(self, method, url, *, token=None, body=None):
        path = "/" + url.split("/", 3)[-1] if url.count("/") >= 3 else "/"
        if path == "/ready":
            return READY
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        encoded = b"" if body is None else json.dumps(body).encode("utf-8")
        return self.application.handle(method, path, headers, encoded)


class DisconnectAfterCommitTransport:
    """Lose one successful mutation response after the server has committed it."""

    def __init__(self, inner, path, occurrence=1):
        self.inner = inner
        self.path = path
        self.occurrence = occurrence
        self.commits = 0

    def request(self, method, url, *, token=None, body=None):
        result = self.inner.request(method, url, token=token, body=body)
        if method == "POST" and url.endswith(self.path) and result[0] == 200:
            self.commits += 1
            if self.commits == self.occurrence:
                raise ValidationFailure("simulated response loss after commit")
        return result


READY = (
    200,
    {
        "status": "ready",
        "checks": {
            "configuration": True,
            "governance_store": True,
            "identity_store": True,
        },
    },
)


class AzureStagingValidatorTests(unittest.TestCase):
    def config(self, role="analyst", phase="analyst_prepare"):
        return ValidatorConfig(
            api_base_url=(
                "https://sentinel.internal.example.azurecontainerapps.io"
            ),
            audience="api://sentinel-test",
            client_id=ANALYST_ID if role == "analyst" else APPROVER_ID,
            role=role,
            phase=phase,
            run_id="testrun123",
            expected_subject=(
                ANALYST_SUBJECT if role == "analyst" else APPROVER_SUBJECT
            ),
            peer_subject=(
                APPROVER_SUBJECT if role == "analyst" else ANALYST_SUBJECT
            ),
        )

    def run_phase(self, role, phase, responses):
        subject = ANALYST_SUBJECT if role == "analyst" else APPROVER_SUBJECT
        provider = SingleIdentityTokenProvider(
            ANALYST_ID if role == "analyst" else APPROVER_ID,
            subject,
        )
        transport = ScriptedTransport([(200, {"status": "ok"}), READY, *responses])
        report = AzureStagingLifecycleValidator(
            self.config(role, phase), provider, transport
        ).run()
        self.assertEqual(provider.calls, [(provider.client_id, "api://sentinel-test")])
        self.assertFalse(transport.responses)
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn(subject, serialized)
        self.assertNotIn(provider.token, serialized)
        self.assertTrue(all(gate["passed"] for gate in report["gates"]))
        return report, transport

    def test_analyst_prepare_uses_only_analyst_identity(self):
        report, transport = self.run_phase(
            "analyst",
            "analyst_prepare",
            [
                (401, {"error": "missing_bearer_token"}),
                (400, {"error": "actor identity must come from authentication context"}),
                (400, {"error": "finding AZ-testrun123-E2E was not found"}),
                (200, {"status": "open"}),
                (400, {"error": "finding AZ-testrun123-E2E already exists"}),
                (200, {"status": "risk_assessed"}),
                (200, {"status": "pending_approval"}),
                (400, {"error": "finding AZ-testrun123-SOD was not found"}),
                (200, {"status": "open"}),
                (200, {"status": "risk_assessed"}),
                (200, {"status": "pending_approval"}),
            ],
        )
        self.assertEqual(report["final_finding_status"], "pending_approval")
        self.assertEqual(report["next_phase"], "approver_approve")
        self.assertEqual(len(report["gates"]), 13)
        self.assertFalse(any("/approve" in call["url"] for call in transport.calls))
        self.assertIsNone(transport.calls[2]["token"])

    def test_approver_approve_uses_only_approver_identity(self):
        report, transport = self.run_phase(
            "approver",
            "approver_approve",
            [
                (200, {
                    "status": "pending_approval",
                    "control_id": "AZ-STAGING-SOD",
                    "asset_id": "azure-staging",
                    "risk_owner": APPROVER_SUBJECT,
                    "treatment_type": "mitigate",
                    "action_owner": ANALYST_SUBJECT,
                }),
                (403, {"error": "risk owner cannot approve the same finding"}),
                (200, {
                    "status": "pending_approval",
                    "control_id": "AZ-STAGING-E2E",
                    "asset_id": "azure-staging",
                    "risk_owner": ANALYST_SUBJECT,
                    "treatment_type": "mitigate",
                    "action_owner": ANALYST_SUBJECT,
                }),
                (400, {"error": "finding cannot close before verification or accepted-risk treatment"}),
                (200, {"status": "approved"}),
            ],
        )
        self.assertEqual(report["final_finding_status"], "approved")
        self.assertEqual(report["next_phase"], "analyst_remediate")
        self.assertEqual(len(report["gates"]), 7)
        forbidden = ("/create", "/assess", "/propose", "/start", "/evidence")
        self.assertFalse(any(any(part in call["url"] for part in forbidden) for call in transport.calls))

    def test_analyst_remediate_uses_only_analyst_identity(self):
        report, transport = self.run_phase(
            "analyst",
            "analyst_remediate",
            [
                (200, {
                    "status": "approved",
                    "control_id": "AZ-STAGING-E2E",
                    "asset_id": "azure-staging",
                    "risk_owner": ANALYST_SUBJECT,
                    "treatment_type": "mitigate",
                    "action_owner": ANALYST_SUBJECT,
                }),
                (200, {"status": "in_progress"}),
                (200, {"status": "pending_verification"}),
                (403, {"error": "verification must be independent from implementation and evidence submission"}),
            ],
        )
        self.assertEqual(report["final_finding_status"], "pending_verification")
        self.assertEqual(report["next_phase"], "approver_close")
        self.assertEqual(len(report["gates"]), 6)
        self.assertFalse(any("/approve" in call["url"] or "/close" in call["url"] for call in transport.calls))

    def test_approver_close_uses_only_approver_identity(self):
        report, transport = self.run_phase(
            "approver",
            "approver_close",
            [
                (200, {
                    "status": "pending_verification",
                    "control_id": "AZ-STAGING-E2E",
                    "asset_id": "azure-staging",
                    "risk_owner": ANALYST_SUBJECT,
                    "treatment_type": "mitigate",
                    "action_owner": ANALYST_SUBJECT,
                    "implementer": ANALYST_SUBJECT,
                    "evidence_submitter": ANALYST_SUBJECT,
                }),
                (200, {"status": "verified"}),
                (200, {"status": "closed"}),
                (200, {"status": "closed"}),
            ],
        )
        self.assertEqual(report["final_finding_status"], "closed")
        self.assertIsNone(report["next_phase"])
        self.assertEqual(len(report["gates"]), 6)
        forbidden = ("/create", "/assess", "/propose", "/start", "/evidence")
        self.assertFalse(any(any(part in call["url"] for part in forbidden) for call in transport.calls))

    def test_role_phase_mismatch_and_invalid_inputs_fail_closed(self):
        bad = [
            {"audience": ANALYST_ID},
            {"api_base_url": "http://sentinel.azurecontainerapps.io"},
            {"api_base_url": "https://example.com"},
            {"client_id": "not-a-guid"},
            {"role": "admin"},
            {"phase": "approver_approve"},
            {"run_id": "contains_underscore"},
            {"expected_subject": "not-a-guid"},
            {"peer_subject": ANALYST_SUBJECT},
        ]
        for update in bad:
            with self.subTest(update=update):
                values = self.config().__dict__.copy()
                values.update(update)
                with self.assertRaises(ValueError):
                    ValidatorConfig(**values).validate()

    def test_legacy_dual_identity_environment_is_rejected(self):
        environment = {
            "SENTINEL_VALIDATION_API_URL": self.config().api_base_url,
            "SENTINEL_VALIDATION_AUDIENCE": "api://sentinel-test",
            "SENTINEL_VALIDATION_CLIENT_ID": ANALYST_ID,
            "SENTINEL_VALIDATION_ROLE": "analyst",
            "SENTINEL_VALIDATION_PHASE": "analyst_prepare",
            "SENTINEL_VALIDATION_RUN_ID": "testrun123",
            "SENTINEL_VALIDATION_EXPECTED_SUBJECT": ANALYST_SUBJECT,
            "SENTINEL_VALIDATION_PEER_SUBJECT": APPROVER_SUBJECT,
            "SENTINEL_VALIDATION_APPROVER_CLIENT_ID": APPROVER_ID,
        }
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(ValueError, "dual-identity"):
                _config_from_environment()

    def test_unexpected_http_status_fails_closed_without_token_leak(self):
        provider = SingleIdentityTokenProvider(ANALYST_ID, ANALYST_SUBJECT)
        validator = AzureStagingLifecycleValidator(
            self.config(),
            provider,
            ScriptedTransport([(503, {"error": "backend unavailable"})]),
        )
        with self.assertRaisesRegex(
            ValidationFailure, "validation gate failed: healthz"
        ):
            validator.run()
        self.assertFalse(provider.calls)

    def test_token_subject_parser_is_bounded_and_strict(self):
        self.assertEqual(_token_subject(fake_token("actor-1")), "actor-1")
        for token in ("", "not-a-jwt", "a.e30.signature"):
            with self.subTest(token=token):
                with self.assertRaises(ValidationFailure):
                    _token_subject(token)

    def test_four_role_isolated_phases_complete_real_governance_lifecycle(self):
        analyst_token = fake_token(ANALYST_SUBJECT)
        approver_token = fake_token(APPROVER_SUBJECT)
        actors = {
            analyst_token: ActorContext(
                ANALYST_SUBJECT, "analyst", auth_method="oidc"
            ),
            approver_token: ActorContext(
                APPROVER_SUBJECT, "approver", auth_method="oidc"
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = GovernanceCore(str(root / "governance.db"))
            application = GovernanceHttpApplication(
                GovernanceApi(
                    core,
                    HumanIdentityStore(str(root / "identity.db")),
                ),
                authentication_mode="oidc",
                oidc_verifier=RoleTokenVerifier(actors),
            )
            transport = InProcessGovernanceTransport(application)
            phases = (
                ("analyst", "analyst_prepare", ANALYST_ID, ANALYST_SUBJECT),
                ("approver", "approver_approve", APPROVER_ID, APPROVER_SUBJECT),
                ("analyst", "analyst_remediate", ANALYST_ID, ANALYST_SUBJECT),
                ("approver", "approver_close", APPROVER_ID, APPROVER_SUBJECT),
            )
            observed = []
            for role, phase, client_id, subject in phases:
                report = AzureStagingLifecycleValidator(
                    self.config(role, phase),
                    SingleIdentityTokenProvider(client_id, subject),
                    transport,
                ).run()
                observed.append(report["final_finding_status"])

            self.assertEqual(
                observed,
                ["pending_approval", "approved", "pending_verification", "closed"],
            )
            finding = core.get_finding("AZ-testrun123-E2E")
            self.assertEqual(finding["status"], "closed")
            events = core.list_events(finding["finding_id"])
            self.assertTrue(core.verify_event_chain(finding["finding_id"]))
            self.assertEqual(
                {event["actor_id"] for event in events},
                {ANALYST_SUBJECT, APPROVER_SUBJECT},
            )
            sod = core.get_finding("AZ-testrun123-SOD")
            self.assertEqual(sod["status"], "pending_approval")
            self.assertEqual(sod["risk_owner"], APPROVER_SUBJECT)

    def test_token_subject_must_match_expected_managed_identity(self):
        provider = SingleIdentityTokenProvider(ANALYST_ID, APPROVER_SUBJECT)
        validator = AzureStagingLifecycleValidator(
            self.config(),
            provider,
            ScriptedTransport([(200, {"status": "ok"}), READY]),
        )
        with self.assertRaisesRegex(ValidationFailure, "did not match"):
            validator.run()

    def test_out_of_order_phase_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analyst_token = fake_token(ANALYST_SUBJECT)
            approver_token = fake_token(APPROVER_SUBJECT)
            application = GovernanceHttpApplication(
                GovernanceApi(
                    GovernanceCore(str(root / "governance.db")),
                    HumanIdentityStore(str(root / "identity.db")),
                ),
                authentication_mode="oidc",
                oidc_verifier=RoleTokenVerifier({
                    analyst_token: ActorContext(
                        ANALYST_SUBJECT, "analyst", auth_method="oidc"
                    ),
                    approver_token: ActorContext(
                        APPROVER_SUBJECT, "approver", auth_method="oidc"
                    ),
                }),
            )
            with self.assertRaisesRegex(ValidationFailure, "not resumable"):
                AzureStagingLifecycleValidator(
                    self.config("approver", "approver_approve"),
                    SingleIdentityTokenProvider(
                        APPROVER_ID, APPROVER_SUBJECT
                    ),
                    InProcessGovernanceTransport(application),
                ).run()

    def test_every_committed_intermediate_state_is_resumable(self):
        interruption_points = (
            ("analyst_prepare", "/v1/governance/create", 1),
            ("analyst_prepare", "/v1/governance/assess", 1),
            ("analyst_prepare", "/v1/governance/propose", 1),
            ("analyst_prepare", "/v1/governance/create", 2),
            ("analyst_prepare", "/v1/governance/assess", 2),
            ("analyst_prepare", "/v1/governance/propose", 2),
            ("approver_approve", "/v1/governance/approve", 1),
            ("analyst_remediate", "/v1/governance/start", 1),
            ("analyst_remediate", "/v1/governance/evidence", 1),
            ("approver_close", "/v1/governance/verify", 1),
            ("approver_close", "/v1/governance/close", 1),
        )
        phase_order = (
            ("analyst", "analyst_prepare", ANALYST_ID, ANALYST_SUBJECT),
            ("approver", "approver_approve", APPROVER_ID, APPROVER_SUBJECT),
            ("analyst", "analyst_remediate", ANALYST_ID, ANALYST_SUBJECT),
            ("approver", "approver_close", APPROVER_ID, APPROVER_SUBJECT),
        )
        for interrupted_phase, path, occurrence in interruption_points:
            with self.subTest(
                phase=interrupted_phase, path=path, occurrence=occurrence
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                analyst_token = fake_token(ANALYST_SUBJECT)
                approver_token = fake_token(APPROVER_SUBJECT)
                core = GovernanceCore(str(root / "governance.db"))
                application = GovernanceHttpApplication(
                    GovernanceApi(
                        core,
                        HumanIdentityStore(str(root / "identity.db")),
                    ),
                    authentication_mode="oidc",
                    oidc_verifier=RoleTokenVerifier({
                        analyst_token: ActorContext(
                            ANALYST_SUBJECT, "analyst", auth_method="oidc"
                        ),
                        approver_token: ActorContext(
                            APPROVER_SUBJECT, "approver", auth_method="oidc"
                        ),
                    }),
                )
                transport = InProcessGovernanceTransport(application)
                interrupted = False
                for role, phase, client_id, subject in phase_order:
                    provider = SingleIdentityTokenProvider(client_id, subject)
                    if phase == interrupted_phase and not interrupted:
                        lossy = DisconnectAfterCommitTransport(
                            transport, path, occurrence
                        )
                        with self.assertRaisesRegex(
                            ValidationFailure, "response loss"
                        ):
                            AzureStagingLifecycleValidator(
                                self.config(role, phase), provider, lossy
                            ).run()
                        self.assertEqual(lossy.commits, occurrence)
                        interrupted = True
                        provider = SingleIdentityTokenProvider(
                            client_id, subject
                        )
                    report = AzureStagingLifecycleValidator(
                        self.config(role, phase), provider, transport
                    ).run()
                    self.assertEqual(report["status"], "passed")

                self.assertTrue(interrupted)
                finding = core.get_finding("AZ-testrun123-E2E")
                self.assertEqual(finding["status"], "closed")
                self.assertTrue(core.verify_event_chain(finding["finding_id"]))


if __name__ == "__main__":
    unittest.main()

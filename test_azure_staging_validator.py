import base64
import json
import unittest

from scripts.azure_staging_validator import (
    AzureStagingLifecycleValidator,
    ValidationFailure,
    ValidatorConfig,
    _token_subject,
)


def fake_token(subject):
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": subject}).encode("utf-8")
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


class FakeTokenProvider:
    def __init__(self):
        self.tokens = {
            "11111111-1111-4111-8111-111111111111": fake_token("analyst-subject"),
            "22222222-2222-4222-8222-222222222222": fake_token("approver-subject"),
        }

    def get_token(self, client_id, audience):
        if audience != "api://sentinel-test":
            raise AssertionError("unexpected audience")
        return self.tokens[client_id]


class ScriptedTransport:
    def __init__(self):
        self.calls = []
        self.responses = [
            (200, {"status": "ok"}),
            (
                200,
                {
                    "status": "ready",
                    "checks": {
                        "configuration": True,
                        "governance_store": True,
                        "identity_store": True,
                    },
                },
            ),
            (401, {"error": "missing_bearer_token"}),
            (400, {"error": "actor identity must come from authentication context"}),
            (200, {"status": "open"}),
            (200, {"status": "risk_assessed"}),
            (200, {"status": "pending_approval"}),
            (403, {"error": "risk owner cannot approve the same finding"}),
            (200, {"status": "open"}),
            (400, {"error": "finding already exists"}),
            (200, {"status": "risk_assessed"}),
            (200, {"status": "pending_approval"}),
            (400, {"error": "finding cannot close before verification"}),
            (200, {"status": "approved"}),
            (200, {"status": "in_progress"}),
            (200, {"status": "pending_verification"}),
            (403, {"error": "verification must be independent"}),
            (200, {"status": "verified"}),
            (200, {"status": "closed"}),
            (200, {"status": "closed"}),
        ]

    def request(self, method, url, *, token=None, body=None):
        self.calls.append(
            {"method": method, "url": url, "token": token, "body": body}
        )
        if not self.responses:
            raise AssertionError("unexpected request")
        return self.responses.pop(0)


class AzureStagingValidatorTests(unittest.TestCase):
    def config(self):
        return ValidatorConfig(
            api_base_url=(
                "https://sentinel.internal.example."
                "azurecontainerapps.io"
            ),
            audience="api://sentinel-test",
            analyst_client_id="11111111-1111-4111-8111-111111111111",
            approver_client_id="22222222-2222-4222-8222-222222222222",
        )

    def test_complete_report_is_sanitized_and_all_gates_pass(self):
        transport = ScriptedTransport()
        validator = AzureStagingLifecycleValidator(
            self.config(),
            FakeTokenProvider(),
            transport,
            run_id_factory=lambda: "testrun123",
        )

        report = validator.run()

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["final_finding_status"], "closed")
        self.assertFalse(report["production_ready"])
        self.assertEqual(len(report["gates"]), 20)
        self.assertTrue(all(gate["passed"] for gate in report["gates"]))
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("analyst-subject", serialized)
        self.assertNotIn("approver-subject", serialized)
        self.assertNotIn(FakeTokenProvider().tokens[
            "11111111-1111-4111-8111-111111111111"
        ], serialized)
        self.assertFalse(transport.responses)
        spoof_call = transport.calls[3]
        self.assertEqual(spoof_call["body"]["actor_id"], "caller-controlled")
        self.assertIsNone(transport.calls[2]["token"])

    def test_configuration_fails_closed(self):
        bad = [
            {
                "audience": "11111111-1111-4111-8111-111111111111",
            },
            {
                "api_base_url": "http://sentinel.azurecontainerapps.io",
            },
            {
                "api_base_url": "https://example.com",
            },
            {
                "analyst_client_id": "not-a-guid",
            },
            {
                "approver_client_id": "11111111-1111-4111-8111-111111111111",
            },
        ]
        for update in bad:
            with self.subTest(update=update):
                values = self.config().__dict__.copy()
                values.update(update)
                with self.assertRaises(ValueError):
                    ValidatorConfig(**values).validate()

    def test_unexpected_http_status_fails_closed_without_token_leak(self):
        transport = ScriptedTransport()
        transport.responses[0] = (503, {"error": "backend unavailable"})
        validator = AzureStagingLifecycleValidator(
            self.config(),
            FakeTokenProvider(),
            transport,
            run_id_factory=lambda: "testrun123",
        )
        with self.assertRaisesRegex(
            ValidationFailure, "validation gate failed: healthz"
        ):
            validator.run()

    def test_token_subject_parser_is_bounded_and_strict(self):
        self.assertEqual(_token_subject(fake_token("actor-1")), "actor-1")
        for token in ("", "not-a-jwt", "a.e30.signature"):
            with self.subTest(token=token):
                with self.assertRaises(ValidationFailure):
                    _token_subject(token)


if __name__ == "__main__":
    unittest.main()

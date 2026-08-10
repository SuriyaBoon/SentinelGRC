from __future__ import annotations

import json
import unittest
from datetime import date, datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DECISIONS_PATH = ROOT / "config" / "sonar-security-decisions.json"
INGESTION_API = ROOT / "scripts" / "ingestion_api.py"
AZURE_TEMPLATE = ROOT / "infra" / "azure" / "main.bicep"


def validate_review_window(
    reviewed_on: str, expires_on: str, *, today_utc: date | None = None
) -> None:
    reviewed = date.fromisoformat(reviewed_on)
    expires = date.fromisoformat(expires_on)
    current = today_utc or datetime.now(timezone.utc).date()
    if reviewed > current:
        raise ValueError("security decision review date cannot be in the future")
    if expires < reviewed:
        raise ValueError("security decision expiry cannot predate review")
    if (expires - reviewed).days > 90:
        raise ValueError("security decision review window cannot exceed 90 days")
    if expires < current:
        raise ValueError("security decision expired and requires security-owner review")


class SonarSecurityDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads(DECISIONS_PATH.read_text(encoding="utf-8"))
        cls.decisions = {item["rule"]: item for item in cls.registry["decisions"]}

    def test_registry_is_bounded_to_the_two_reviewed_security_findings(self):
        self.assertEqual(
            {
                "python:S5332": "AZ_eYu98jmTxNrSpRwha",
                "azureresourcemanager:S6382": "AZ_eYu_yjmTxNrSpRwia",
            },
            {rule: item["issue_key"] for rule, item in self.decisions.items()},
        )
        self.assertEqual("UTC", self.registry["date_basis"])
        self.assertEqual("repository-security-owner", self.registry["review_owner"])
        self.assertEqual(
            "NO_GO_PENDING_LIVE_EVIDENCE", self.registry["production_verdict"]
        )

    def test_decisions_have_a_current_bounded_review_window(self):
        validate_review_window(
            self.registry["reviewed_on"], self.registry["expires_on"]
        )

    def test_future_review_date_is_rejected_using_utc_basis(self):
        with self.assertRaisesRegex(ValueError, "review date cannot be in the future"):
            validate_review_window(
                "2026-08-11",
                "2026-09-01",
                today_utc=date(2026, 8, 10),
            )

    def test_plain_http_finding_is_a_narrow_false_positive(self):
        decision = self.decisions["python:S5332"]
        source = INGESTION_API.read_text(encoding="utf-8")
        self.assertEqual("false_positive", decision["classification"])
        self.assertEqual("falsepositive", decision["sonar_transition"])
        self.assertIn("ssl.PROTOCOL_TLS_SERVER", source)
        self.assertIn("tls_context.wrap_socket", source)
        self.assertIn("environment != \"lab\"", source)
        self.assertIn("args.host not in {\"127.0.0.1\", \"localhost\", \"::1\"}", source)
        self.assertIn("--allow-loopback-http", source)

    def test_client_certificate_acceptance_preserves_real_identity_boundary(self):
        decision = self.decisions["azureresourcemanager:S6382"]
        source = AZURE_TEMPLATE.read_text(encoding="utf-8")
        self.assertEqual("accepted", decision["classification"])
        self.assertEqual("accept", decision["sonar_transition"])
        self.assertIn("external: false", source)
        self.assertIn("allowInsecure: false", source)
        self.assertNotIn("clientCertificateMode: 'require'", source)
        self.assertIn("validationAnalystIdentity", source)
        self.assertIn("validationApproverIdentity", source)
        self.assertGreaterEqual(len(decision["required_live_evidence"]), 3)

    def test_every_decision_has_operational_review_metadata(self):
        for decision in self.registry["decisions"]:
            with self.subTest(rule=decision["rule"]):
                self.assertTrue(decision["rationale"].strip())
                self.assertTrue(decision["implemented_controls"])
                self.assertTrue(decision["evidence_tests"])
                for evidence_test in decision["evidence_tests"]:
                    self.assertTrue(
                        (ROOT / evidence_test).is_file(),
                        f"missing evidence test: {evidence_test}",
                    )
                self.assertTrue(decision["revisit_when"])
                self.assertTrue(decision["sonar_comment"].strip())


if __name__ == "__main__":
    unittest.main()

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from offline_evidence import (
    PRODUCTION_DECISION,
    canonical_evidence_document_bytes,
    collect_offline_evidence,
    create_evidence_envelope,
    load_evidence_envelope,
    validate_evidence_envelope,
)
from scripts.collect_offline_evidence import OUTPUT_PATH, main


ROOT = Path(__file__).resolve().parent
POLICY = ROOT / "config" / "staging-assurance.example.json"
ALERTS = ROOT / "docs" / "evidence" / "staging-readiness" / "logwatcher-security-alert.v1.jsonl"
SOURCE_COMMIT = "a" * 40


class OfflineEvidenceTests(unittest.TestCase):
    def test_collector_is_deterministic_hash_verified_and_offline_only(self):
        first = collect_offline_evidence(POLICY, ALERTS, SOURCE_COMMIT)
        second = collect_offline_evidence(POLICY, ALERTS, SOURCE_COMMIT)
        self.assertEqual(first, second)
        self.assertEqual(validate_evidence_envelope(first), first)
        document = first["document"]
        self.assertEqual(document["mode"], "offline_no_azure")
        self.assertFalse(document["claim_boundary"]["azure_mutation_performed"])
        self.assertFalse(document["claim_boundary"]["current_live_gate_credit"])
        self.assertEqual(
            document["claim_boundary"]["production_decision"],
            PRODUCTION_DECISION,
        )
        self.assertNotIn("live_validation", document)
        self.assertNotIn("finding_ids", canonical_evidence_document_bytes(document).decode("ascii"))

    def test_input_hashes_are_stable_across_line_endings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy_lf = root / "policy-lf.json"
            policy_crlf = root / "policy-crlf.json"
            alerts_lf = root / "alerts-lf.jsonl"
            alerts_crlf = root / "alerts-crlf.jsonl"
            policy_text = POLICY.read_text(encoding="utf-8").replace("\r\n", "\n")
            alerts_text = ALERTS.read_text(encoding="utf-8").replace("\r\n", "\n")
            policy_lf.write_text(policy_text, encoding="utf-8", newline="\n")
            policy_crlf.write_text(policy_text, encoding="utf-8", newline="\r\n")
            alerts_lf.write_text(alerts_text, encoding="utf-8", newline="\n")
            alerts_crlf.write_text(alerts_text, encoding="utf-8", newline="\r\n")
            lf_result = collect_offline_evidence(policy_lf, alerts_lf, SOURCE_COMMIT)
            crlf_result = collect_offline_evidence(
                policy_crlf, alerts_crlf, SOURCE_COMMIT
            )
        self.assertEqual(lf_result, crlf_result)

    def test_tampering_unknown_fields_and_sensitive_material_are_rejected(self):
        baseline = collect_offline_evidence(POLICY, ALERTS, SOURCE_COMMIT)
        cases = []
        tampered = copy.deepcopy(baseline)
        tampered["document"]["results"]["alert_count"] += 1
        cases.append((tampered, "checksum mismatch"))
        unknown = copy.deepcopy(baseline)
        unknown["document"]["unexpected"] = True
        cases.append((unknown, "fields are invalid"))
        secret = copy.deepcopy(baseline)
        secret["document"]["claim_boundary"]["client_secret"] = "not-a-real-secret"
        cases.append((secret, "prohibited sensitive field"))
        url = copy.deepcopy(baseline)
        url["document"]["claim_boundary"]["statement"] = "See https://private.example"
        cases.append((url, "prohibited sensitive value"))
        guid = copy.deepcopy(baseline)
        guid["document"]["claim_boundary"]["statement"] = (
            "Identifier 12345678-1234-1234-1234-123456789abc"
        )
        cases.append((guid, "prohibited sensitive value"))
        for envelope, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    validate_evidence_envelope(envelope)

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.json"
            path.write_text(
                '{"schema_version":"a","schema_version":"b"}',
                encoding="ascii",
            )
            with self.assertRaisesRegex(ValueError, "duplicate key"):
                load_evidence_envelope(path)

    def test_cli_writes_only_fixed_output_and_returns_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "config").mkdir()
            fixture_root = root / "docs" / "evidence" / "staging-readiness"
            fixture_root.mkdir(parents=True)
            (root / "config" / POLICY.name).write_bytes(POLICY.read_bytes())
            (fixture_root / ALERTS.name).write_bytes(ALERTS.read_bytes())
            previous = Path.cwd()
            try:
                os.chdir(root)
                exit_code = main(["--source-commit", SOURCE_COMMIT])
            finally:
                os.chdir(previous)
            output = root / OUTPUT_PATH
            self.assertEqual(exit_code, 0)
            self.assertTrue(output.is_file())
            self.assertEqual(
                load_evidence_envelope(output)["document"]["source_commit_sha"],
                SOURCE_COMMIT,
            )

    def test_cli_returns_distinct_gate_failure_and_validation_error_codes(self):
        good = collect_offline_evidence(POLICY, ALERTS, SOURCE_COMMIT)
        failed_document = copy.deepcopy(good["document"])
        failed_document["results"]["offline_decision"] = "NO_GO"
        failed_document["results"]["offline_gates"]["event_chain_valid"] = False
        failed = create_evidence_envelope(failed_document)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with mock.patch(
                    "scripts.collect_offline_evidence.collect_offline_evidence",
                    return_value=failed,
                ):
                    gate_exit = main(
                        [
                            "--source-commit",
                            SOURCE_COMMIT,
                            "--policy",
                            ".",
                            "--alerts",
                            ".",
                        ]
                    )
                validation_exit = main(
                    [
                        "--source-commit",
                        "main",
                        "--policy",
                        ".",
                        "--alerts",
                        ".",
                    ]
                )
            finally:
                os.chdir(previous)
        self.assertEqual(gate_exit, 1)
        self.assertEqual(validation_exit, 2)

    def test_collector_source_has_no_azure_client_boundary(self):
        sources = [
            (ROOT / "offline_evidence.py").read_text(encoding="utf-8"),
            (ROOT / "scripts" / "collect_offline_evidence.py").read_text(
                encoding="utf-8"
            ),
        ]
        joined = "\n".join(sources)
        self.assertNotIn("azure.identity", joined)
        self.assertNotIn("DefaultAzureCredential", joined)
        self.assertNotIn("ManagedIdentityCredential", joined)


if __name__ == "__main__":
    unittest.main()

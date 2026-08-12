import copy
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from hermetic_recovery import (
    PRODUCTION_DECISION,
    READINESS_SCHEMA,
    collect_hermetic_recovery_evidence,
    create_envelope,
    load_envelope,
    run_pipeline_commit_ack_recovery,
    validate_envelope,
)
from scripts.collect_hermetic_recovery_evidence import OUTPUT_PATH, main


ROOT = Path(__file__).resolve().parent
SOURCE_COMMIT = "b" * 40


def readiness_document(**overrides):
    document = {
        "schema_version": READINESS_SCHEMA,
        "initial_http_status": 200,
        "loss_http_status": 503,
        "recovered_http_status": 200,
        "initial_status": "ready",
        "loss_status": "not_ready",
        "recovered_status": "ready",
        "sqlite_fallback_observed": False,
    }
    document.update(overrides)
    return document


class HermeticRecoveryTests(unittest.TestCase):
    def test_ci_recovery_steps_and_policy_entry_are_single_instance(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        for step_name in (
            "- name: Verify PostgreSQL dependency recovery",
            "- name: Collect hermetic failure and recovery evidence",
            "- name: Retain hermetic recovery evidence",
        ):
            with self.subTest(step_name=step_name):
                self.assertEqual(workflow.count(step_name), 1)
        self.assertEqual(
            workflow.count(
                "name: hermetic-recovery-${{ github.run_id }}-${{ github.run_attempt }}"
            ),
            1,
        )
        path_policy = (ROOT / "scripts" / "path_policy.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            path_policy.count(
                '"runtime/staging-assurance/hermetic-recovery-evidence.json": Path('
            ),
            1,
        )
        recovery_source = (ROOT / "hermetic_recovery.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'HERMETIC_EVIDENCE_FILENAME = "hermetic-evidence.json"',
            recovery_source,
        )
        self.assertEqual(recovery_source.count('"hermetic-evidence.json"'), 1)
        docs_bytes = (ROOT / "docs" / "staging-assurance.md").read_bytes()
        self.assertTrue(docs_bytes.isascii())
        self.assertIn(
            b"identity and hashes in an approved private evidence location - not this public",
            docs_bytes,
        )

    def test_real_failpoint_replay_preserves_exactly_once_state(self):
        result = run_pipeline_commit_ack_recovery(ROOT)
        self.assertTrue(all(result.values()), result)

    def test_envelope_is_strict_hash_verified_and_grants_no_live_credit(self):
        with tempfile.TemporaryDirectory() as temp:
            readiness = Path(temp) / "readiness.json"
            readiness.write_text(json.dumps(readiness_document()), encoding="ascii")
            envelope = collect_hermetic_recovery_evidence(ROOT, readiness, SOURCE_COMMIT)
        self.assertEqual(validate_envelope(envelope), envelope)
        self.assertEqual(envelope["document"]["decision"], "PASS")
        self.assertEqual(
            envelope["document"]["claim_boundary"]["production_decision"],
            PRODUCTION_DECISION,
        )
        self.assertFalse(
            envelope["document"]["claim_boundary"]["current_live_gate_credit"]
        )

    def test_tampering_unknown_fields_sensitive_values_and_duplicates_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            readiness = Path(temp) / "readiness.json"
            readiness.write_text(json.dumps(readiness_document()), encoding="ascii")
            baseline = collect_hermetic_recovery_evidence(ROOT, readiness, SOURCE_COMMIT)
            cases = []
            inconsistent = copy.deepcopy(baseline)
            inconsistent["document"]["pipeline_recovery"]["replay_succeeded"] = False
            cases.append((inconsistent, "decision is inconsistent"))
            tampered = copy.deepcopy(baseline)
            tampered["document"]["source_commit_sha"] = "c" * 40
            cases.append((tampered, "checksum mismatch"))
            unknown = copy.deepcopy(baseline)
            unknown["document"]["unexpected"] = True
            cases.append((unknown, "fields are invalid"))
            sensitive = copy.deepcopy(baseline)
            sensitive["document"]["claim_boundary"]["token"] = "not-a-token"
            cases.append((sensitive, "prohibited field"))
            for value, message in cases:
                with self.subTest(message=message):
                    with self.assertRaisesRegex(ValueError, message):
                        validate_envelope(value)
            duplicate = Path(temp) / "duplicate.json"
            duplicate.write_text('{"schema_version":"a","schema_version":"b"}', encoding="ascii")
            with self.assertRaisesRegex(ValueError, "duplicate key"):
                load_envelope(duplicate)

    def test_readiness_failure_is_a_valid_no_go_not_a_validation_error(self):
        with tempfile.TemporaryDirectory() as temp:
            readiness = Path(temp) / "readiness.json"
            readiness.write_text(
                json.dumps(readiness_document(recovered_http_status=503, recovered_status="not_ready")),
                encoding="ascii",
            )
            envelope = collect_hermetic_recovery_evidence(ROOT, readiness, SOURCE_COMMIT)
        self.assertEqual(envelope["document"]["decision"], "NO_GO")
        self.assertFalse(
            envelope["document"]["postgres_readiness"]["dependency_recovered"]
        )

    def test_cli_uses_fixed_output_and_distinct_exit_codes(self):
        passing = create_envelope(
            {
                "schema_version": "sentinel.hermetic_recovery_evidence.v1",
                "mode": "hermetic_ci",
                "source_commit_sha": SOURCE_COMMIT,
                "pipeline_recovery": {
                    "failpoint_exit_observed": True,
                    "durable_outputs_present": True,
                    "replay_succeeded": True,
                    "replay_reported_duplicate": True,
                    "output_hashes_unchanged": True,
                    "database_counts_unchanged": True,
                    "business_records_present": True,
                    "queue_completed_once": True,
                },
                "postgres_readiness": {
                    "initial_ready": True,
                    "dependency_loss_failed_closed": True,
                    "dependency_recovered": True,
                },
                "decision": "PASS",
                "claim_boundary": {
                    "azure_mutation_performed": False,
                    "current_live_gate_credit": False,
                    "production_decision": PRODUCTION_DECISION,
                },
            }
        )
        failing = copy.deepcopy(passing)
        failing["document"]["postgres_readiness"]["dependency_recovered"] = False
        failing["document"]["decision"] = "NO_GO"
        failing = create_envelope(failing["document"])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            readiness = root / "readiness.json"
            readiness.write_text(json.dumps(readiness_document()), encoding="ascii")
            previous = Path.cwd()
            try:
                import os

                os.chdir(root)
                with mock.patch(
                    "scripts.collect_hermetic_recovery_evidence.collect_hermetic_recovery_evidence",
                    return_value=passing,
                ):
                    stdout = StringIO()
                    with redirect_stdout(stdout):
                        success = main(["--source-commit", SOURCE_COMMIT, "--readiness", "readiness.json"])
                with mock.patch(
                    "scripts.collect_hermetic_recovery_evidence.collect_hermetic_recovery_evidence",
                    return_value=failing,
                ):
                    gate_failure = main(["--source-commit", SOURCE_COMMIT, "--readiness", "readiness.json"])
                validation_error = main(["--source-commit", "main", "--readiness", "readiness.json"])
            finally:
                os.chdir(previous)
        self.assertEqual(success, 0)
        self.assertEqual(json.loads(stdout.getvalue())["output"], OUTPUT_PATH)
        self.assertEqual(gate_failure, 1)
        self.assertEqual(validation_error, 2)


if __name__ == "__main__":
    unittest.main()
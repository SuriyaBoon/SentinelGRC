import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from scripts.collect_security_assessment import OUTPUT_PATH, main
from security_assessment import (
    LIVE_CONTROLS,
    _canonical,
    _actions_are_pinned,
    _boundary_tests_exist,
    _container_file_passes,
    _containers_are_pinned_non_root,
    _dependency_lock_is_hashed,
    _security_decisions_are_bounded,
    _secret_scan,
    build_ci_scan_receipt,
    collect_security_assessment,
    decode_tool_report,
    validate_security_assessment,
    workflow_action_references,
)


SOURCE_SHA = "d" * 40
ASSESSMENT_DATE = "2026-08-13"
REPORT = b"No known vulnerabilities found"


class SecurityAssessmentTests(unittest.TestCase):
    @staticmethod
    def _rehash(envelope):
        canonical = _canonical(envelope["document"])
        envelope["document_sha256"] = hashlib.sha256(canonical.encode("ascii")).hexdigest()

    def test_current_repository_passes_offline_without_live_credit(self):
        root = Path(__file__).resolve().parent
        envelope = collect_security_assessment(root, SOURCE_SHA, ASSESSMENT_DATE, "success", REPORT)
        document = validate_security_assessment(
            envelope, root, "success", REPORT,
            trusted_source_commit=SOURCE_SHA,
            trusted_assessed_on=ASSESSMENT_DATE,
        )["document"]
        self.assertEqual(document["assessment_decision"], "PASS_OFFLINE")
        self.assertEqual(document["findings"], [])
        self.assertEqual(
            document["live_controls"],
            [{"control": control, "status": "NOT_TESTED_LIVE"} for control in LIVE_CONTROLS],
        )
        self.assertFalse(document["claim_boundary"]["current_live_gate_credit"])
        self.assertEqual(
            document["claim_boundary"]["production_decision"],
            "NO_GO_PENDING_LIVE_EVIDENCE",
        )

    def test_missing_or_failed_dependency_scan_fails_closed(self):
        root = Path(__file__).resolve().parent
        for outcome, report in (("skipped", None), ("cancelled", None), ("failure", None)):
            with self.subTest(outcome=outcome):
                envelope = collect_security_assessment(root, SOURCE_SHA, ASSESSMENT_DATE, outcome, report)
                document = validate_security_assessment(
                    envelope, root, outcome, report,
                    trusted_source_commit=SOURCE_SHA,
                    trusted_assessed_on=ASSESSMENT_DATE,
                )["document"]
                self.assertEqual(document["assessment_decision"], "NO_GO")
                self.assertIn(
                    "SEC-VULN-001",
                    [finding["control_id"] for finding in document["findings"]],
                )

    def test_completed_dependency_scan_requires_nonempty_report(self):
        root = Path(__file__).resolve().parent
        for report in (None, b""):
            with self.subTest(report=report):
                with self.assertRaisesRegex(ValueError, "requires a report"):
                    collect_security_assessment(
                        root, SOURCE_SHA, ASSESSMENT_DATE, "success", report
                    )
        failure = collect_security_assessment(
            root, SOURCE_SHA, ASSESSMENT_DATE, "failure", b""
        )
        self.assertEqual(failure["document"]["controls"][-1]["status"], "FAIL")
        self.assertTrue(failure["document"]["controls"][-1]["evidence"].endswith("=none"))
        with self.assertRaises(ValueError):
            decode_tool_report("")
        with self.assertRaisesRegex(ValueError, "base64"):
            decode_tool_report("not base64!")

    def test_workflow_action_forms_are_complete_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            pinned = "a" * 40
            (workflows / "unsafe.yml").write_text(
                f"steps:\n  - uses: owner/action@{pinned}\n"
                f"  - {{ name: flow, uses: owner/other/subdir@{pinned} }}\n"
                f"  - uses: >-\n      owner/folded@{pinned}\n",
                encoding="utf-8",
            )
            passed, evidence = _actions_are_pinned(root)
            self.assertTrue(passed, evidence)
            (workflows / "unsafe.yml").write_text(
                "steps:\n  - { uses: owner/action@main }\n"
                "  - uses: ./.github/actions/local\n"
                "  - uses: docker://example/image:latest\n"
                "  - uses:\n",
                encoding="utf-8",
            )
            passed, evidence = _actions_are_pinned(root)
        self.assertFalse(passed)
        self.assertIn("3 mutable", evidence)
        self.assertIn("1 unparsed", evidence)

    def test_multiline_action_scalar_is_parsed_as_its_value(self):
        pinned = "a" * 40
        references, unparsed = workflow_action_references(
            f"steps:\n  - uses: >-\n      github/codeql-action/init@{pinned}\n"
        )
        self.assertEqual(references, [f"github/codeql-action/init@{pinned}"])
        self.assertEqual(unparsed, 0)

    def test_escaped_yaml_mapping_keys_fail_closed(self):
        pinned = "a" * 40
        escaped_forms = (
            '"\\u0075ses": attacker/action@main',
            '"u\\x73es": attacker/action@main',
            '"unrelated\\u002dkey": value',
        )
        for escaped_key in escaped_forms:
            with self.subTest(escaped_key=escaped_key):
                references, unparsed = workflow_action_references(
                    f"steps:\n  - uses: owner/action@{pinned}\n  - {{{escaped_key}}}\n"
                )
                self.assertEqual(references, [f"owner/action@{pinned}"])
                self.assertEqual(unparsed, 1)

    def test_each_requirement_must_have_its_own_hash(self):
        digest = "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements-hashed.txt").write_text(
                f"first==1.0 --hash=sha256:{digest}\nsecond==2.0\n",
                encoding="utf-8",
            )
            passed, evidence = _dependency_lock_is_hashed(root)
        self.assertFalse(passed)
        self.assertIn("1 requirements without complete hash coverage", evidence)

    def test_missing_container_files_and_empty_decisions_fail_as_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            container_passed, container_evidence = _containers_are_pinned_non_root(root)
            config = root / "config"
            config.mkdir()
            (config / "sonar-security-decisions.json").write_text(
                json.dumps({
                    "expires_on": "2026-11-08",
                    "production_verdict": "NO_GO_PENDING_LIVE_EVIDENCE",
                    "decisions": [],
                }),
                encoding="utf-8",
            )
            decision_passed, decision_evidence = _security_decisions_are_bounded(
                root, ASSESSMENT_DATE
            )
        self.assertFalse(container_passed)
        self.assertIn("missing or unreadable", container_evidence)
        self.assertFalse(decision_passed)
        self.assertIn("earliest expiry absent", decision_evidence)

    def test_current_repository_decisions_are_valid_on_current_utc_date(self):
        root = Path(__file__).resolve().parent
        current_date = datetime.now(timezone.utc).date().isoformat()
        passed, evidence = _security_decisions_are_bounded(root, current_date)
        self.assertTrue(passed, evidence)

    def test_non_mapping_security_decision_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.mkdir()
            (config / "sonar-security-decisions.json").write_text(
                json.dumps({
                    "expires_on": "2026-11-08",
                    "production_verdict": "NO_GO_PENDING_LIVE_EVIDENCE",
                    "decisions": ["not-a-mapping"],
                }),
                encoding="utf-8",
            )
            passed, evidence = _security_decisions_are_bounded(
                root, ASSESSMENT_DATE
            )
        self.assertFalse(passed)
        self.assertEqual(evidence, "security decision registry invalid")

    def test_container_policy_uses_effective_user_and_copy_directives(self):
        digest = "a" * 64
        base = f"FROM python@sha256:{digest}\n"
        valid = base + "COPY app.py /app/app.py\nUSER 10001:10001\n"
        misleading_user = (
            base
            + "# USER 10001:10001\n"
            + "RUN echo USER 10001:10001\nUSER root\n"
        )
        broad_copy = (
            base
            + "COPY --chown=0:0 ./ /app\nUSER 10001:10001\n"
        )
        self.assertTrue(_container_file_passes(valid, require_pinned_base=True))
        self.assertFalse(
            _container_file_passes(misleading_user, require_pinned_base=True)
        )
        self.assertFalse(
            _container_file_passes(broad_copy, require_pinned_base=True)
        )
        continued_with_comment = (
            base
            + "COPY app.py \\\n"
            + "  # Docker ignores this comment\n"
            + "  helper.py /app/\nUSER 10001:10001\n"
        )
        self.assertTrue(
            _container_file_passes(
                continued_with_comment, require_pinned_base=True
            )
        )
        malformed_base = (
            'FROM "python@sha256:' + digest + "\nUSER 10001:10001\n"
        )
        self.assertFalse(
            _container_file_passes(malformed_base, require_pinned_base=True)
        )

    def test_regression_control_requires_its_own_assessment_suite(self):
        required_without_self = (
            "test_enterprise_safety.py",
            "test_path_security.py",
            "test_sonar_security_decisions.py",
            "test_supply_chain_policy.py",
            "test_crypto_agility.py",
            "test_azure_iac_policy.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in required_without_self:
                (root / name).touch()
            passed, evidence = _boundary_tests_exist(root)
        self.assertFalse(passed)
        self.assertIn("6/7 required", evidence)

    def test_recomputed_checksum_cannot_hide_repository_control_tampering(self):
        root = Path(__file__).resolve().parent
        envelope = collect_security_assessment(root, SOURCE_SHA, ASSESSMENT_DATE, "success", REPORT)
        envelope["document"]["controls"][0]["status"] = "FAIL"
        envelope["document"]["controls"][0]["evidence"] = "forged"
        envelope["document"]["findings"] = []
        self._rehash(envelope)
        with self.assertRaisesRegex(ValueError, "inconsistent with trusted inputs"):
            validate_security_assessment(
                envelope, root, "success", REPORT,
                trusted_source_commit=SOURCE_SHA,
                trusted_assessed_on=ASSESSMENT_DATE,
            )

    def test_recomputed_checksum_cannot_forge_dependency_scan_result(self):
        root = Path(__file__).resolve().parent
        envelope = collect_security_assessment(root, SOURCE_SHA, ASSESSMENT_DATE, "failure", REPORT)
        dependency = envelope["document"]["controls"][-1]
        dependency["evidence"] = (
            f"{dependency['evidence'].rsplit('=', 1)[0]}={'0' * 64}"
        )
        self._rehash(envelope)
        with self.assertRaisesRegex(ValueError, "inconsistent with trusted inputs"):
            validate_security_assessment(
                envelope, root, "failure", REPORT,
                trusted_source_commit=SOURCE_SHA,
                trusted_assessed_on=ASSESSMENT_DATE,
            )

    def test_recomputed_checksum_cannot_grant_live_credit(self):
        root = Path(__file__).resolve().parent
        envelope = collect_security_assessment(root, SOURCE_SHA, ASSESSMENT_DATE, "success", REPORT)
        envelope["document"]["live_controls"][0]["status"] = "PASS"
        envelope["document"]["claim_boundary"]["current_live_gate_credit"] = True
        self._rehash(envelope)
        with self.assertRaisesRegex(ValueError, "live security controls"):
            validate_security_assessment(
                envelope, root, "success", REPORT,
                trusted_source_commit=SOURCE_SHA,
                trusted_assessed_on=ASSESSMENT_DATE,
            )

    def test_rehashed_identity_fields_cannot_override_trusted_context(self):
        root = Path(__file__).resolve().parent
        mutations = (
            ("source_commit_sha", "e" * 40, "trusted commit"),
            ("assessed_on", "2026-01-01", "trusted date"),
            ("scope", ["repository_policy"], "scope"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field):
                envelope = collect_security_assessment(
                    root, SOURCE_SHA, ASSESSMENT_DATE, "success", REPORT
                )
                envelope["document"][field] = value
                self._rehash(envelope)
                with self.assertRaisesRegex(ValueError, message):
                    validate_security_assessment(
                        envelope, root, "success", REPORT,
                        trusted_source_commit=SOURCE_SHA,
                        trusted_assessed_on=ASSESSMENT_DATE,
                    )

    def test_secret_scan_reports_location_without_secret_value(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "credential.txt"
            secret = "AKIA" + "A" * 16
            marker.write_text(f"token={secret}\n", encoding="utf-8")
            passed, evidence = _secret_scan(Path(directory))
            self.assertFalse(passed)
            self.assertNotIn(secret, evidence)
            self.assertIn("credential.txt:1", evidence)

    def test_secret_scan_fails_closed_on_invalid_utf8_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "unreadable.txt"
            marker.write_bytes(b"\xffAKIA" + b"A" * 16)
            passed, evidence = _secret_scan(Path(directory))
        self.assertFalse(passed)
        self.assertIn("unreadable secret-scan candidates", evidence)
        self.assertIn("unreadable.txt", evidence)
        self.assertNotIn("AKIA", evidence)

    def test_ci_scan_receipt_is_source_and_run_bound(self):
        first = build_ci_scan_receipt(SOURCE_SHA, "success", "12345")
        second = build_ci_scan_receipt(SOURCE_SHA, "success", "12345")
        self.assertEqual(first, second)
        self.assertIn(SOURCE_SHA.encode("ascii"), first)
        with self.assertRaisesRegex(ValueError, "CI run ID"):
            build_ci_scan_receipt(SOURCE_SHA, "success", "not-a-run")

    def test_cli_writes_only_fixed_sanitized_output(self):
        root = Path(__file__).resolve().parent
        stdout = StringIO()
        with (
            patch("scripts.collect_security_assessment.Path.cwd", return_value=root),
            patch("scripts.collect_security_assessment.write_text_under_root") as writer,
            redirect_stdout(stdout),
        ):
            result = main([
                "--source-commit", SOURCE_SHA,
                "--assessed-on", ASSESSMENT_DATE,
                "--dependency-scan-outcome", "success",
                "--ci-run-id", "12345",
            ])
        writer.assert_called_once()
        self.assertEqual(writer.call_args.args[0], OUTPUT_PATH)
        payload = json.loads(writer.call_args.args[2])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue())["output"], OUTPUT_PATH)
        serialized = json.dumps(payload)
        receipt = build_ci_scan_receipt(SOURCE_SHA, "success", "12345")
        self.assertNotIn(receipt.decode("ascii"), serialized)
        self.assertIn(
            hashlib.sha256(receipt).hexdigest(),
            payload["document"]["controls"][-1]["evidence"],
        )
        self.assertFalse(payload["document"]["claim_boundary"]["current_live_gate_credit"])


if __name__ == "__main__":
    unittest.main()

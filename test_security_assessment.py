import base64
import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from scripts.collect_security_assessment import OUTPUT_PATH, main
from security_assessment import (
    LIVE_CONTROLS,
    _secret_scan,
    collect_security_assessment,
    decode_tool_report,
    validate_security_assessment,
)


SOURCE_SHA = "d" * 40
ASSESSMENT_DATE = "2026-08-13"
REPORT = b"No known vulnerabilities found"


class SecurityAssessmentTests(unittest.TestCase):
    @staticmethod
    def _rehash(envelope):
        canonical = json.dumps(
            envelope["document"], sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
        envelope["document_sha256"] = hashlib.sha256(canonical.encode("ascii")).hexdigest()

    def test_current_repository_passes_offline_without_live_credit(self):
        root = Path(__file__).resolve().parent
        envelope = collect_security_assessment(root, SOURCE_SHA, ASSESSMENT_DATE, "success", REPORT)
        document = validate_security_assessment(envelope, root, "success", REPORT)["document"]
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
                document = validate_security_assessment(envelope, root, outcome, report)["document"]
                self.assertEqual(document["assessment_decision"], "NO_GO")
                self.assertIn(
                    "SEC-VULN-001",
                    [finding["control_id"] for finding in document["findings"]],
                )

    def test_completed_dependency_scan_requires_nonempty_report(self):
        root = Path(__file__).resolve().parent
        with self.assertRaisesRegex(ValueError, "requires a report"):
            collect_security_assessment(root, SOURCE_SHA, ASSESSMENT_DATE, "success", None)
        failure = collect_security_assessment(
            root, SOURCE_SHA, ASSESSMENT_DATE, "failure", None
        )
        self.assertEqual(failure["document"]["controls"][-1]["status"], "FAIL")
        with self.assertRaises(ValueError):
            decode_tool_report("")
        with self.assertRaisesRegex(ValueError, "base64"):
            decode_tool_report("not base64!")

    def test_recomputed_checksum_cannot_hide_repository_control_tampering(self):
        root = Path(__file__).resolve().parent
        envelope = collect_security_assessment(root, SOURCE_SHA, ASSESSMENT_DATE, "success", REPORT)
        envelope["document"]["controls"][0]["status"] = "FAIL"
        envelope["document"]["controls"][0]["evidence"] = "forged"
        envelope["document"]["findings"] = []
        self._rehash(envelope)
        with self.assertRaisesRegex(ValueError, "inconsistent with trusted inputs"):
            validate_security_assessment(envelope, root, "success", REPORT)

    def test_recomputed_checksum_cannot_forge_dependency_scan_result(self):
        root = Path(__file__).resolve().parent
        envelope = collect_security_assessment(root, SOURCE_SHA, ASSESSMENT_DATE, "failure", REPORT)
        dependency = envelope["document"]["controls"][-1]
        dependency["status"] = "PASS"
        dependency["evidence"] = (
            dependency["evidence"].replace("outcome=failure", "outcome=success")
        )
        envelope["document"]["findings"] = []
        envelope["document"]["assessment_decision"] = "PASS_OFFLINE"
        self._rehash(envelope)
        with self.assertRaisesRegex(ValueError, "inconsistent with trusted inputs"):
            validate_security_assessment(envelope, root, "failure", REPORT)

    def test_recomputed_checksum_cannot_grant_live_credit(self):
        root = Path(__file__).resolve().parent
        envelope = collect_security_assessment(root, SOURCE_SHA, ASSESSMENT_DATE, "success", REPORT)
        envelope["document"]["live_controls"][0]["status"] = "PASS"
        envelope["document"]["claim_boundary"]["current_live_gate_credit"] = True
        self._rehash(envelope)
        with self.assertRaisesRegex(ValueError, "live security controls"):
            validate_security_assessment(envelope, root, "success", REPORT)

    def test_secret_scan_reports_location_without_secret_value(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "credential.txt"
            secret = "AKIA" + "A" * 16
            marker.write_text(f"token={secret}\n", encoding="utf-8")
            passed, evidence = _secret_scan(Path(directory))
            self.assertFalse(passed)
            self.assertNotIn(secret, evidence)
            self.assertIn("credential.txt:1", evidence)

    def test_cli_writes_only_fixed_sanitized_output(self):
        root = Path(__file__).resolve().parent
        encoded = base64.b64encode(REPORT).decode("ascii")
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
                "--dependency-report-base64", encoded,
            ])
        writer.assert_called_once()
        self.assertEqual(writer.call_args.args[0], OUTPUT_PATH)
        payload = json.loads(writer.call_args.args[2])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue())["output"], OUTPUT_PATH)
        serialized = json.dumps(payload)
        self.assertNotIn(REPORT.decode("ascii"), serialized)
        self.assertFalse(payload["document"]["claim_boundary"]["current_live_gate_credit"])


if __name__ == "__main__":
    unittest.main()

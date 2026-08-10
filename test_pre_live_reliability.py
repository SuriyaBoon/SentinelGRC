import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class PreLiveReliabilityTests(unittest.TestCase):
    def test_posture_collector_handles_optional_cim_failures_explicitly(self):
        source = (ROOT / "agent" / "Export-SecurityPosture.ps1").read_text(
            encoding="utf-8"
        )
        self.assertNotRegex(source, r"catch\s*\{\s*\}")
        self.assertEqual(source.count("Write-Verbose"), 2)
        self.assertIn("Unable to query Win32_ComputerSystem", source)
        self.assertIn("Unable to query Win32_OperatingSystem", source)

    def test_posture_collector_uses_null_first_comparison(self):
        source = (ROOT / "agent" / "Export-SecurityPosture.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("$null -ne $_.InstalledOn", source)
        self.assertNotIn("$_.InstalledOn -ne $null", source)

    def test_live_gate_default_preserves_fail_closed_semantics(self):
        from staging_assurance import evaluate_live_gates

        policy = {"required_live_gates": ["identity", "delivery"]}
        result = evaluate_live_gates(policy, None)
        self.assertEqual(
            result["gates"], {"identity": "not_run", "delivery": "not_run"}
        )
        self.assertEqual(result["decision"], "NO_GO")
        self.assertFalse(result["all_required_live_gates_passed"])

    def test_ui_rejects_failed_requests_with_an_error_object(self):
        source = (ROOT / "ui" / "app.js").read_text(encoding="utf-8")
        self.assertIn("Promise.reject(new Error(", source)
        self.assertNotRegex(source, r"Promise\.reject\(response\.status\)")
        self.assertIn('/v1/governance/report', source)


if __name__ == "__main__":
    unittest.main()

import unittest
from datetime import datetime, timezone

from reporting import build_executive_report


class ReportingTests(unittest.TestCase):
    def test_report_calculates_kpi_kri_without_evidence_content(self):
        report = build_executive_report([
            {"finding_id": "F-1", "domain": "security", "severity": "critical",
             "status": "open", "due_date": "2026-07-01"},
            {"finding_id": "F-2", "domain": "privacy", "severity": "high",
             "status": "verified", "due_date": "2026-08-01"},
            {"finding_id": "F-3", "domain": "bcm", "severity": "medium",
             "status": "closed", "verification_result": "passed"},
        ], generated_at=datetime(2026, 7, 19, tzinfo=timezone.utc))
        self.assertEqual(report["kpi"]["total_findings"], 3)
        self.assertEqual(report["kpi"]["closure_rate"], 0.6667)
        self.assertEqual(report["kpi"]["overdue_findings"], 1)
        self.assertEqual(report["kri"]["critical_open_findings"], 1)
        self.assertEqual(report["by_domain"]["privacy"], 1)
        self.assertNotIn("evidence", report)

    def test_empty_report_is_safe(self):
        report = build_executive_report([])
        self.assertEqual(report["kpi"]["closure_rate"], 1.0)
        self.assertEqual(report["kri"]["critical_open_findings"], 0)

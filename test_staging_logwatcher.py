import json
import tempfile
import unittest
from pathlib import Path

from staging_logwatcher import run_logwatcher_staging


class LogWatcherStagingTests(unittest.TestCase):
    def test_native_logwatcher_jsonl_reaches_governance_core(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            event = {
                "TimeCreated": "2026-07-03T02:14:01",
                "EventID": 4625,
                "Computer": "WIN-DC01",
                "TargetUserName": "administrator",
                "IpAddress": "203.0.113.45",
                "LogonType": 3,
            }
            path = root / "events.jsonl"
            path.write_text(json.dumps(event) + "\n" + json.dumps(event) + "\n", encoding="utf-8")
            result = run_logwatcher_staging(str(path), str(root / "governance.db"))
            self.assertEqual(result["events_read"], 2)
            self.assertEqual(result["findings_created"], 1)
            self.assertEqual(result["findings_reassessed"], 1)

    def test_malformed_lines_are_reported_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "events.jsonl"
            path.write_text("{bad json}\n", encoding="utf-8")
            result = run_logwatcher_staging(str(path), str(root / "governance.db"))
            self.assertEqual(result["errors"], 1)

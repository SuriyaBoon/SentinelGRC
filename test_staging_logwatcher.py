import json
import tempfile
import unittest
from pathlib import Path

from scripts.staging_logwatcher import run_logwatcher_staging


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

    def test_logwatcher_alerts_create_business_findings_and_replay_idempotently(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            alerts = [
                {
                    "kind": "brute_force",
                    "message": "5 failed logons from 203.0.113.45 within 5 min",
                    "severity": "high",
                    "computer": "WIN-DC01",
                    "source_ip": "203.0.113.45",
                    "target_user": "administrator",
                    "timestamp": "2026-07-03T02:14:25",
                },
                {
                    "kind": "account_lockout",
                    "message": "Account 'jsmith' was locked out",
                    "severity": "medium",
                    "computer": "WIN-DC01",
                    "target_user": "jsmith",
                    "timestamp": "2026-07-03T08:03:02",
                },
                {
                    "kind": "privilege_escalation",
                    "message": "Unexpected elevated-privilege logon by 'guest'",
                    "severity": "critical",
                    "computer": "WIN-FILE02",
                    "target_user": "guest",
                    "timestamp": "2026-07-03T11:47:22",
                },
            ]
            path = root / "alerts.jsonl"
            path.write_text("\n".join(json.dumps(alert) for alert in alerts) + "\n", encoding="utf-8")
            db = str(root / "governance.db")

            first = run_logwatcher_staging(str(path), db, input_kind="alert")
            replay = run_logwatcher_staging(str(path), db, input_kind="alert")

            self.assertEqual(first["events_read"], 3)
            self.assertEqual(first["findings_created"], 3)
            self.assertEqual(first["findings_reassessed"], 0)
            self.assertEqual(first["errors"], 0)
            self.assertEqual(replay["findings_created"], 0)
            self.assertEqual(replay["findings_reassessed"], 3)
            self.assertEqual(replay["errors"], 0)
            self.assertEqual(len(set(first["finding_ids"])), 3)

    def test_malformed_lines_are_reported_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "events.jsonl"
            path.write_text("{bad json}\n", encoding="utf-8")
            result = run_logwatcher_staging(str(path), str(root / "governance.db"))
            self.assertEqual(result["errors"], 1)

    def test_missing_input_file_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run_logwatcher_staging(str(Path(temp) / "missing.jsonl"), str(Path(temp) / "governance.db"))
            self.assertEqual(result["errors"], 1)

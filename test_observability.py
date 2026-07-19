import json
import unittest

from observability import Metrics, structured_event


class ObservabilityTests(unittest.TestCase):
    def test_structured_events_redact_sensitive_fields(self):
        event = json.loads(structured_event(
            "governance_action", correlation_id="corr-1",
            actor_id="alice", token="do-not-log", content="evidence",
        ))
        self.assertEqual(event["actor_id"], "alice")
        self.assertEqual(event["token"], "[REDACTED]")
        self.assertEqual(event["content"], "[REDACTED]")

    def test_metrics_are_incremental_and_exportable(self):
        metrics = Metrics()
        metrics.increment("findings.created")
        metrics.increment("findings.created", 2)
        metrics.increment("findings.closed")
        self.assertEqual(metrics.snapshot(), {"findings.created": 3, "findings.closed": 1})

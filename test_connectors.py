import json
import tempfile
import unittest
from pathlib import Path

from connectors import ConnectorEventStore, ingest_event, sign_event


class ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = ConnectorEventStore(str(Path(self.temp.name) / "events.db"))
        self.raw = json.dumps({"asset_id": "APP-1", "status": "open"}).encode()
        self.signature = sign_event(self.raw, "connector-secret")

    def tearDown(self):
        self.temp.cleanup()

    def test_authenticated_event_is_idempotent(self):
        first = ingest_event(self.raw, source="siem", event_id="evt-1",
                              signature=self.signature, secret="connector-secret", store=self.store)
        second = ingest_event(self.raw, source="siem", event_id="evt-1",
                              signature=self.signature, secret="connector-secret", store=self.store)
        self.assertEqual(first["status"], "accepted")
        self.assertEqual(second["status"], "duplicate")
        self.assertIsNone(second["payload"])

    def test_invalid_signature_and_invalid_payload_are_rejected(self):
        with self.assertRaises(PermissionError):
            ingest_event(self.raw, source="siem", event_id="evt-2",
                         signature="sha256=bad", secret="connector-secret", store=self.store)
        with self.assertRaises(ValueError):
            ingest_event(b"[]", source="siem", event_id="evt-3",
                         signature=sign_event(b"[]", "connector-secret"),
                         secret="connector-secret", store=self.store)

    def test_event_id_is_not_accepted_before_authentication(self):
        with self.assertRaises(PermissionError):
            ingest_event(self.raw, source="cloud", event_id="evt-4",
                         signature="bad", secret="connector-secret", store=self.store)
        accepted = ingest_event(self.raw, source="cloud", event_id="evt-4",
                                signature=self.signature, secret="connector-secret", store=self.store)
        self.assertEqual(accepted["status"], "accepted")

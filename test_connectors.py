import json
import tempfile
import unittest
from pathlib import Path

from connectors import (
    ConnectorEventConflictError,
    ConnectorEventStore,
    ingest_event,
    sign_event,
)


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
        fixture_key = "connector-fixture-material"
        with self.assertRaises(PermissionError):
            ingest_event(self.raw, source="siem", event_id="evt-2",
                         signature="sha256=bad", secret=fixture_key, store=self.store)
        invalid_payload = b"[]"
        invalid_signature = sign_event(invalid_payload, fixture_key)
        with self.assertRaises(ValueError):
            ingest_event(invalid_payload, source="siem", event_id="evt-3",
                         signature=invalid_signature,
                         secret=fixture_key, store=self.store)

    def test_event_id_is_not_accepted_before_authentication(self):
        with self.assertRaises(PermissionError):
            ingest_event(self.raw, source="cloud", event_id="evt-4",
                         signature="bad", secret="connector-secret", store=self.store)
        accepted = ingest_event(self.raw, source="cloud", event_id="evt-4",
                                signature=self.signature, secret="connector-secret", store=self.store)
        self.assertEqual(accepted["status"], "accepted")

    def test_same_event_id_from_different_sources_is_not_a_duplicate(self):
        first = ingest_event(self.raw, source="siem", event_id="shared-event",
                             signature=self.signature, secret="connector-secret", store=self.store)
        second = ingest_event(self.raw, source="edr", event_id="shared-event",
                              signature=self.signature, secret="connector-secret", store=self.store)
        self.assertEqual(first["status"], "accepted")
        self.assertEqual(second["status"], "accepted")

    def test_same_source_event_identity_cannot_change_payload(self):
        ingest_event(
            self.raw,
            source="siem",
            event_id="evt-1",
            signature=self.signature,
            secret="connector-secret",
            store=self.store,
        )
        changed = json.dumps(
            {"asset_id": "APP-1", "status": "closed"}
        ).encode()

        with self.assertRaisesRegex(
            ConnectorEventConflictError, "belongs to a different payload"
        ):
            ingest_event(
                changed,
                source="siem",
                event_id="evt-1",
                signature=sign_event(changed, "connector-secret"),
                secret="connector-secret",
                store=self.store,
            )

        replay = ingest_event(
            self.raw,
            source="siem",
            event_id="evt-1",
            signature=self.signature,
            secret="connector-secret",
            store=self.store,
        )
        self.assertEqual(replay["status"], "duplicate")

    def test_event_identity_must_be_canonical_before_reservation(self):
        cases = (
            ("SIEM", "evt-1"),
            (" siem", "evt-1"),
            ("siem", " evt-1"),
            ("siem", "evt\n1"),
            ("siem", "x" * 129),
        )
        for source, event_id in cases:
            with self.subTest(source=source, event_id=event_id):
                with self.assertRaises(ValueError):
                    ingest_event(
                        self.raw,
                        source=source,
                        event_id=event_id,
                        signature=self.signature,
                        secret="connector-secret",
                        store=self.store,
                    )

import io
import json
import re
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.ingestion_api import (
    IngestionError,
    NonceStore,
    PostureHandler,
    authenticate_request,
    make_signature,
    parse_authorization,
    validate_posture,
)


class StaticKeyRegistry:
    def __init__(self, secret):
        self.secret = secret

    def resolve_secret(self, key_id, key_secrets):
        return self.secret


class MemoryPayloadState:
    def __init__(self):
        self.evidence_ids = {}

    def get_evidence_id(self, payload_hash):
        return self.evidence_ids.get(payload_hash)

    def remember_payload(self, payload_hash, evidence_id):
        if payload_hash in self.evidence_ids:
            return False
        self.evidence_ids[payload_hash] = evidence_id
        return True


class IngestionSecurityTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = b"test-fixture-material"
        self.body = json.dumps(
            {
                "schema_version": "1.0",
                "collected_at": "2026-07-16T10:00:00Z",
                "asset_id": "WS-001",
                "hostname": "finance-laptop-01",
                "bitlocker_system_drive": True,
                "firewall_all_profiles_enabled": True,
                "defender_realtime_enabled": True,
                "days_since_last_update": 2,
            },
            separators=(",", ":"),
        ).encode()
        self.timestamp = "1000"
        self.nonce = "nonce-1234567890"
        self.key_id = "ws-001-v1"

    def auth(self):
        return "HMAC " + self.key_id + ":" + make_signature(
            self.signing_key, self.timestamp, self.nonce, self.body
        )

    def test_valid_keyed_signature_is_accepted_once(self):
        store = NonceStore()
        authenticate_request(
            self.signing_key, self.auth(), self.timestamp, self.nonce, self.body, store, now=1000
        )
        authorization = self.auth()
        with self.assertRaises(IngestionError):
            authenticate_request(
                self.signing_key, authorization, self.timestamp, self.nonce, self.body, store, now=1000
            )

    def test_authorization_parser_requires_key_id(self):
        self.assertEqual(parse_authorization(self.auth())[0], self.key_id)
        with self.assertRaises(ValueError):
            parse_authorization("HMAC " + ("a" * 64))

    def test_modified_body_fails_signature(self):
        signature = make_signature(
            self.signing_key, self.timestamp, self.nonce, self.body
        )
        authorization = "HMAC " + self.key_id + ":" + signature
        store = NonceStore()
        with self.assertRaises(IngestionError):
            authenticate_request(
                self.signing_key,
                authorization,
                self.timestamp,
                "nonce-0987654321",
                self.body + b" ",
                store,
                now=1000,
            )

    def test_old_timestamp_fails(self):
        authorization = self.auth()
        store = NonceStore()
        with self.assertRaises(IngestionError):
            authenticate_request(
                self.signing_key, authorization, self.timestamp, self.nonce, self.body, store, now=2000
            )

    def test_required_fields_are_validated(self):
        validate_posture(json.loads(self.body))
        invalid = json.loads(self.body)
        del invalid["hostname"]
        with self.assertRaises(ValueError):
            validate_posture(invalid)

    def test_unknown_fields_and_naive_timestamp_are_rejected(self):
        invalid = json.loads(self.body)
        invalid["unexpected"] = "reject-me"
        with self.assertRaises(ValueError):
            validate_posture(invalid)

    def test_posture_validation_preserves_error_precedence_and_messages(self):
        valid = json.loads(self.body)
        cases = [
            ([], "Posture payload must be a JSON object."),
            ({key: value for key, value in valid.items() if key != "hostname"}, "Missing required fields: ['hostname']"),
            ({**valid, "unexpected": True}, "Unknown fields: ['unexpected']"),
            ({**valid, "schema_version": "2.0"}, "Unsupported posture schema version."),
            ({**valid, "asset_id": ""}, "asset_id length is invalid."),
            ({**valid, "collected_at": "not-a-timestamp"}, "collected_at must be an ISO-8601 timestamp."),
            ({**valid, "firewall_all_profiles_enabled": 1}, "firewall_all_profiles_enabled must be boolean."),
            ({**valid, "days_since_last_update": -1}, "days_since_last_update must be a non-negative integer or null."),
        ]
        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, re.escape(message)):
                    validate_posture(payload)

        invalid_at_multiple_layers = {
            **valid,
            "unexpected": True,
            "asset_id": "",
        }
        with self.assertRaisesRegex(ValueError, "Unknown fields"):
            validate_posture(invalid_at_multiple_layers)

    def test_http_handler_preserves_authenticated_acceptance_and_deduplication(self):
        state = MemoryPayloadState()
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            responses = []
            for nonce in ("nonce-http-000001", "nonce-http-000002"):
                timestamp = str(int(time.time()))
                authorization = "HMAC " + self.key_id + ":" + make_signature(
                    self.signing_key, timestamp, nonce, self.body
                )
                handler = PostureHandler.__new__(PostureHandler)
                handler.path = "/v1/posture"
                handler.headers = {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(self.body)),
                    "X-Sentinel-Timestamp": timestamp,
                    "X-Sentinel-Nonce": nonce,
                    "Authorization": authorization,
                }
                handler.rfile = io.BytesIO(self.body)
                handler.server = SimpleNamespace(
                    key_registry=StaticKeyRegistry(self.signing_key),
                    key_secrets={},
                    nonce_store=NonceStore(),
                    state_store=state,
                    output_dir=output_dir,
                )
                handler._send_json = lambda status, payload: responses.append(
                    (status, payload)
                )
                handler.do_POST()
        self.assertEqual(responses[0][1]["status"], "accepted")
        self.assertEqual(responses[1][1]["status"], "duplicate")
        self.assertEqual(responses[0][1]["evidence_id"], responses[1][1]["evidence_id"])
        invalid = json.loads(self.body)
        invalid["collected_at"] = "2026-07-16T10:00:00"
        with self.assertRaises(ValueError):
            validate_posture(invalid)


if __name__ == "__main__":
    unittest.main()

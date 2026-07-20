import json
import unittest

from scripts.ingestion_api import (
    IngestionError,
    NonceStore,
    authenticate_request,
    make_signature,
    parse_authorization,
    validate_posture,
)


class IngestionSecurityTests(unittest.TestCase):
    def setUp(self):
        self.secret = b"test-only-secret"
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
            self.secret, self.timestamp, self.nonce, self.body
        )

    def test_valid_keyed_signature_is_accepted_once(self):
        store = NonceStore()
        authenticate_request(
            self.secret, self.auth(), self.timestamp, self.nonce, self.body, store, now=1000
        )
        with self.assertRaises(IngestionError):
            authenticate_request(
                self.secret, self.auth(), self.timestamp, self.nonce, self.body, store, now=1000
            )

    def test_authorization_parser_requires_key_id(self):
        self.assertEqual(parse_authorization(self.auth())[0], self.key_id)
        with self.assertRaises(ValueError):
            parse_authorization("HMAC " + ("a" * 64))

    def test_modified_body_fails_signature(self):
        with self.assertRaises(IngestionError):
            authenticate_request(
                self.secret,
                "HMAC " + self.key_id + ":" + make_signature(
                    self.secret, self.timestamp, self.nonce, self.body
                ),
                self.timestamp,
                "nonce-0987654321",
                self.body + b" ",
                NonceStore(),
                now=1000,
            )

    def test_old_timestamp_fails(self):
        with self.assertRaises(IngestionError):
            authenticate_request(
                self.secret, self.auth(), self.timestamp, self.nonce, self.body, NonceStore(), now=2000
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
        invalid = json.loads(self.body)
        invalid["collected_at"] = "2026-07-16T10:00:00"
        with self.assertRaises(ValueError):
            validate_posture(invalid)


if __name__ == "__main__":
    unittest.main()

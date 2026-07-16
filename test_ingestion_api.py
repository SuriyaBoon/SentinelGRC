import json
import unittest

from ingestion_api import (
    IngestionError,
    NonceStore,
    authenticate_request,
    make_signature,
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

    def test_valid_signature_is_accepted_once(self):
        auth = "HMAC " + make_signature(
            self.secret, self.timestamp, self.nonce, self.body
        )
        store = NonceStore()
        authenticate_request(
            self.secret, auth, self.timestamp, self.nonce, self.body, store, now=1000
        )
        with self.assertRaises(IngestionError):
            authenticate_request(
                self.secret, auth, self.timestamp, self.nonce, self.body, store, now=1000
            )

    def test_modified_body_fails_signature(self):
        auth = "HMAC " + make_signature(
            self.secret, self.timestamp, self.nonce, self.body
        )
        with self.assertRaises(IngestionError):
            authenticate_request(
                self.secret,
                auth,
                self.timestamp,
                "nonce-0987654321",
                self.body + b" ",
                NonceStore(),
                now=1000,
            )

    def test_old_timestamp_fails(self):
        auth = "HMAC " + make_signature(
            self.secret, self.timestamp, self.nonce, self.body
        )
        with self.assertRaises(IngestionError):
            authenticate_request(
                self.secret, auth, self.timestamp, self.nonce, self.body, NonceStore(), now=2000
            )

    def test_required_fields_are_validated(self):
        validate_posture(json.loads(self.body))
        invalid = json.loads(self.body)
        del invalid["hostname"]
        with self.assertRaises(ValueError):
            validate_posture(invalid)


if __name__ == "__main__":
    unittest.main()

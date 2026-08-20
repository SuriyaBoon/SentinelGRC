import io
import json
import re
import tempfile
import threading
import time
import unittest
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

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
    def __init__(self, secret, allowed_scopes):
        self.secret = secret
        self.allowed_scopes = set(allowed_scopes)

    def resolve_secret(self, key_id, key_secrets):
        return self.secret

    def is_authorized(self, key_id, required_scope):
        return required_scope in self.allowed_scopes


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


    def _dispatch(
        self, path, payload, nonce, state, output_dir, *, sort_keys=False,
        allowed_scopes=("posture:write", "asset-context:write",
                        "remediation-ticket:write"),
    ):
        body = json.dumps(
            payload, separators=(",", ":"), sort_keys=sort_keys
        ).encode()
        timestamp = str(int(time.time()))
        authorization = "HMAC " + self.key_id + ":" + make_signature(
            self.signing_key, timestamp, nonce, body
        )
        responses = []
        handler = PostureHandler.__new__(PostureHandler)
        handler.path = path
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Sentinel-Timestamp": timestamp,
            "X-Sentinel-Nonce": nonce,
            "Authorization": authorization,
        }
        handler.rfile = io.BytesIO(body)
        posture_dir = output_dir / "posture"
        portfolio_dirs = {
            "asset_context": output_dir / "asset-context",
            "remediation_ticket": output_dir / "remediation-ticket",
        }
        for directory in (posture_dir, *portfolio_dirs.values()):
            directory.mkdir(parents=True, exist_ok=True)
        handler.server = SimpleNamespace(
            key_registry=StaticKeyRegistry(self.signing_key, allowed_scopes),
            key_secrets={},
            nonce_store=NonceStore(),
            state_store=state,
            output_dir=posture_dir,
            portfolio_output_dirs=portfolio_dirs,
        )
        handler._send_json = lambda status, response: responses.append(
            (status, response)
        )
        handler.do_POST()
        return responses[-1]

    @staticmethod
    def _asset_context():
        return {
            "schema_version": "asset_context.v1",
            "source": "home-lab-v5",
            "source_asset_id": "INV-1",
            "observed_at": "2026-08-19T00:00:00Z",
            "asset_id": "WIN-01",
            "hostname": "win-01",
            "owner": "owner-01",
            "criticality": "high",
            "status": "active",
            "evidence_refs": ["sample://inventory/INV-1"],
        }

    @staticmethod
    def _remediation_ticket():
        return {
            "schema_version": "remediation_ticket.v1",
            "source": "helpdesk",
            "source_ticket_id": "HD-1",
            "finding_id": "F-1",
            "asset_id": "WIN-01",
            "owner": "analyst-01",
            "status": "assigned",
            "priority": "P2",
            "created_at": "2026-08-19T00:00:00Z",
            "updated_at": "2026-08-19T00:01:00Z",
            "due_at": "2026-08-19T08:00:00Z",
            "evidence_refs": ["https://helpdesk.invalid/tickets/HD-1"],
        }

    def test_portfolio_routes_normalize_before_idempotent_persistence(self):
        definitions = (
            ("/v1/asset-context", self._asset_context(), "context_id"),
            (
                "/v1/remediation-ticket",
                self._remediation_ticket(),
                "ticket_context_id",
            ),
        )
        for index, (path, payload, identity_field) in enumerate(definitions):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                state = MemoryPayloadState()
                output_dir = Path(directory)
                first_status, first = self._dispatch(
                    path, payload, f"nonce-portfolio-{index}a", state, output_dir
                )
                second_status, second = self._dispatch(
                    path,
                    dict(reversed(tuple(payload.items()))),
                    f"nonce-portfolio-{index}b",
                    state,
                    output_dir,
                    sort_keys=True,
                )
                self.assertEqual(first_status, HTTPStatus.ACCEPTED)
                self.assertEqual(second_status, HTTPStatus.ACCEPTED)
                self.assertEqual(first["status"], "accepted")
                self.assertEqual(second["status"], "duplicate")
                self.assertEqual(first["evidence_id"], second["evidence_id"])
                self.assertEqual(first[identity_field], second[identity_field])
                record_directory = (
                    output_dir / ("asset-context" if path.endswith("asset-context")
                                  else "remediation-ticket")
                )
                files = list(record_directory.glob("*.json"))
                self.assertEqual(len(files), 1)
                self.assertEqual(list((output_dir / "posture").glob("*.json")), [])
                normalized = json.loads(files[0].read_text(encoding="utf-8"))
                self.assertEqual(normalized[identity_field], first[identity_field])

    def test_source_derived_identity_is_rejected_before_business_side_effects(self):
        definitions = (
            ("/v1/asset-context", self._asset_context(), "context_id"),
            (
                "/v1/remediation-ticket",
                self._remediation_ticket(),
                "ticket_context_id",
            ),
        )
        for index, (path, payload, identity_field) in enumerate(definitions):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                payload[identity_field] = "ATTACKER-CONTROLLED"
                state = MemoryPayloadState()
                output_dir = Path(directory)
                status, response = self._dispatch(
                    path, payload, f"nonce-rejected-{index}", state, output_dir
                )
                self.assertEqual(status, HTTPStatus.BAD_REQUEST)
                self.assertIn("unknown fields", response["error"])
                self.assertEqual(state.evidence_ids, {})
                self.assertEqual(list(output_dir.rglob("*.json")), [])

    def test_http_handler_preserves_authenticated_acceptance_and_deduplication(self):
        state = MemoryPayloadState()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self._dispatch(
                "/v1/posture", json.loads(self.body), "nonce-http-000001", state, root
            )
            second = self._dispatch(
                "/v1/posture", json.loads(self.body), "nonce-http-000002", state, root
            )
            self.assertEqual(first[1]["status"], "accepted")
            self.assertEqual(second[1]["status"], "duplicate")
            self.assertEqual(first[1]["evidence_id"], second[1]["evidence_id"])
            self.assertEqual(len(list((root / "posture").glob("*.json"))), 1)

    def test_posture_key_cannot_submit_portfolio_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status, response = self._dispatch(
                "/v1/asset-context",
                self._asset_context(),
                "nonce-scope-00001",
                MemoryPayloadState(),
                root,
                allowed_scopes=("posture:write",),
            )
            self.assertEqual(status, HTTPStatus.FORBIDDEN)
            self.assertIn("not authorized", response["error"])
            self.assertEqual(list(root.rglob("*.json")), [])

    def test_unknown_record_route_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            status, response = self._dispatch(
                "/v1/unknown-record",
                self._asset_context(),
                "nonce-unknown-001",
                MemoryPayloadState(),
                Path(directory),
            )
            self.assertEqual(status, HTTPStatus.NOT_FOUND)
            self.assertEqual(response, {"error": "not_found"})

    def test_equivalent_timestamps_deduplicate_after_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = MemoryPayloadState()
            first_payload = self._asset_context()
            second_payload = self._asset_context()
            second_payload["observed_at"] = "2026-08-19T07:00:00+07:00"
            first = self._dispatch(
                "/v1/asset-context", first_payload, "nonce-time-000001", state, root
            )
            second = self._dispatch(
                "/v1/asset-context", second_payload, "nonce-time-000002", state, root
            )
            self.assertEqual(first[1]["evidence_id"], second[1]["evidence_id"])
            self.assertEqual(second[1]["status"], "duplicate")

    def test_invisible_boundary_characters_are_rejected(self):
        valid = json.loads(self.body)
        for character in ("\ufeff", "\u200b"):
            with self.subTest(character=ord(character)):
                invalid = {**valid, "hostname": character + "win-01"}
                with self.assertRaises(ValueError):
                    validate_posture(invalid)

    def test_concurrent_publication_uses_independent_temporary_files(self):
        class BarrierState(MemoryPayloadState):
            def __init__(self):
                super().__init__()
                self.barrier = threading.Barrier(2)
                self.lock = threading.Lock()

            def get_evidence_id(self, payload_hash):
                with self.lock:
                    result = self.evidence_ids.get(payload_hash)
                if result is None:
                    self.barrier.wait(timeout=5)
                return result

            def remember_payload(self, payload_hash, evidence_id):
                with self.lock:
                    return super().remember_payload(payload_hash, evidence_id)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            state = BarrierState()
            failures = []

            def persist():
                handler = PostureHandler.__new__(PostureHandler)
                handler.server = SimpleNamespace(state_store=state)
                handler._send_json = lambda status, response: None
                try:
                    handler._persist_validated_body(
                        self.body, {"record_type": "posture"}, output
                    )
                except Exception as error:  # pragma: no cover - asserted below
                    failures.append(error)

            workers = [threading.Thread(target=persist) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=10)
            self.assertFalse(failures)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual(len(list(output.glob("*.json"))), 1)
            self.assertEqual(list(output.glob(".*.tmp")), [])

    def test_naive_collected_at_is_rejected(self):
        invalid = json.loads(self.body)
        invalid["collected_at"] = "2026-07-16T10:00:00"
        with self.assertRaises(ValueError):
            validate_posture(invalid)

    def test_publication_requests_directory_fsync_after_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            state = MemoryPayloadState()
            handler = PostureHandler.__new__(PostureHandler)
            handler.server = SimpleNamespace(state_store=state)
            handler._send_json = lambda status, response: None

            with mock.patch(
                "scripts.ingestion_api._fsync_directory"
            ) as fsync_directory:
                handler._persist_validated_body(
                    self.body, {"record_type": "posture"}, output
                )

            fsync_directory.assert_called_once_with(output)
            self.assertEqual(len(list(output.glob("*.json"))), 1)

    def test_posix_directory_fsync_uses_directory_descriptor(self):
        from scripts import ingestion_api

        directory = Path("/runtime/posture")
        with mock.patch.object(ingestion_api, "DIRECTORY_FSYNC_SUPPORTED", True), \
             mock.patch.object(ingestion_api.os, "open", return_value=919) as open_mock, \
             mock.patch.object(ingestion_api.os, "fsync") as fsync_mock, \
             mock.patch.object(ingestion_api.os, "close") as close_mock:
            ingestion_api._fsync_directory(directory)

        expected_flags = ingestion_api.os.O_RDONLY | getattr(
            ingestion_api.os, "O_DIRECTORY", 0
        )
        open_mock.assert_called_once_with(directory, expected_flags)
        fsync_mock.assert_called_once_with(919)
        close_mock.assert_called_once_with(919)

    def test_windows_directory_fsync_path_is_a_safe_noop(self):
        from scripts import ingestion_api

        with mock.patch.object(ingestion_api, "DIRECTORY_FSYNC_SUPPORTED", False), \
             mock.patch.object(ingestion_api.os, "open") as open_mock:
            ingestion_api._fsync_directory(Path("C:/runtime/posture"))

        open_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()

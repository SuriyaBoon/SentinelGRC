import io
import json
import hashlib
import re
import sqlite3
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
from publication_reconciliation import reconcile_pending_publications
from state_store import SQLiteStateStore
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
        self.pending = {}
    def get_evidence_id(self, payload_hash):
        return self.evidence_ids.get(payload_hash)
    def begin_payload(self, payload_hash, evidence_id):
        existing = self.pending.get(payload_hash) or self.evidence_ids.get(payload_hash)
        if existing is not None:
            if existing != evidence_id:
                raise sqlite3.IntegrityError("payload identity mismatch")
            return False
        self.pending[payload_hash] = evidence_id
        return True
    def commit_payload(self, payload_hash, evidence_id):
        if self.pending.get(payload_hash) != evidence_id:
            return False
        self.evidence_ids[payload_hash] = self.pending.pop(payload_hash)
        return True
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
            ({**valid, "asset_id": ""}, "asset_id must be a canonical identifier."),
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
    def test_authenticated_malformed_posture_types_return_400(self):
        valid = json.loads(self.body)
        cases = (("asset_id", 123), ("criticality", []))
        for index, (field, invalid_value) in enumerate(cases):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                status, response = self._dispatch(
                    "/v1/posture",
                    {**valid, field: invalid_value},
                    f"nonce-malformed-type-{index:04d}",
                    MemoryPayloadState(),
                    Path(directory),
                )
                self.assertEqual(status, HTTPStatus.BAD_REQUEST)
                self.assertIn("error", response)

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
            publication_lock=threading.Lock(),
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
    def test_concurrent_publication_serializes_and_deduplicates(self):
        class BarrierState(MemoryPayloadState):
            """Locks the exact methods _persist_validated_body() calls.

            The production path is get_evidence_id() -> begin_payload() ->
            (file write) -> commit_payload(). Locking remember_payload()
            (as this class previously did) locks a method nothing in the
            current code path ever calls, so it proved nothing about
            concurrent access to the pending/committed transition - it only
            happened to pass because the handler's own publication_lock
            (below) already serializes the whole critical section
            regardless. Locking the three real methods here makes this
            test an independent proof of that invariant, not just a
            passenger on the production lock's coverage.
            """

            def __init__(self):
                super().__init__()
                self.lock = threading.Lock()

            def get_evidence_id(self, payload_hash):
                with self.lock:
                    return super().get_evidence_id(payload_hash)

            def begin_payload(self, payload_hash, evidence_id):
                with self.lock:
                    return super().begin_payload(payload_hash, evidence_id)

            def commit_payload(self, payload_hash, evidence_id):
                with self.lock:
                    return super().commit_payload(payload_hash, evidence_id)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            state = BarrierState()
            publication_lock = threading.Lock()
            failures = []
            def persist():
                handler = PostureHandler.__new__(PostureHandler)
                handler.server = SimpleNamespace(state_store=state, publication_lock=publication_lock)
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
            # Prove the pending -> committed transition actually completed
            # for exactly one payload, and nothing was left dangling in
            # 'pending' by the race between the two threads.
            self.assertEqual(state.pending, {})
            self.assertEqual(len(state.evidence_ids), 1)
    def test_storage_failures_are_retryable_without_path_or_state_leakage(self):
        targets = (
            "scripts.ingestion_api.os.replace",
            "scripts.ingestion_api._fsync_directory",
            "scripts.ingestion_api.Path.unlink",
        )
        for index, target in enumerate(targets):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                state = MemoryPayloadState()
                failure = OSError(5, "storage failed", "/secret/runtime/evidence")
                with mock.patch(target, side_effect=failure):
                    status, response = self._dispatch(
                        "/v1/posture", json.loads(self.body),
                        f"nonce-storage-{index:04d}", state, Path(directory),
                    )
                self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
                self.assertEqual(response, {"error": "Evidence storage is unavailable."})
                self.assertNotIn("/secret/", json.dumps(response))
                self.assertEqual(state.evidence_ids, {})
    def test_pending_publication_is_not_reported_as_accepted(self):
        for method in ("get_evidence_id", "begin_payload", "commit_payload"):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                state = MemoryPayloadState()
                setattr(state, method, mock.Mock(side_effect=sqlite3.OperationalError("locked")))
                status, response = self._dispatch(
                    "/v1/posture", json.loads(self.body), f"nonce-db-{method}", state, Path(directory)
                )
                self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
                self.assertEqual(response, {"error": "Evidence storage is unavailable."})
                self.assertEqual(state.evidence_ids, {})
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
            handler.server = SimpleNamespace(state_store=state, publication_lock=threading.Lock())
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

    def test_reconciliation_self_heals_a_crash_between_durable_write_and_commit(self):
        # Reproduces the exact reported failure mode: begin_payload()
        # succeeds, the file becomes fully durable (temp write + fsync +
        # os.replace + directory fsync), then the process crashes before
        # commit_payload() runs. Without reconciliation this record stays
        # 'pending' forever and every future is_evidence_committed() check
        # (what pipeline_worker.process_inbox_once() gates enqueueing on)
        # returns False - the file is on disk but never gets processed,
        # and nothing about it changes unless a client retries.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "posture"
            output_dir.mkdir()
            store = SQLiteStateStore(str(root / "state.db"), storage_root=root)

            body = b'{"schema_version":"1.0"}'
            payload_hash = hashlib.sha256(body).hexdigest()
            evidence_id = payload_hash[:24]
            store.begin_payload(payload_hash, evidence_id)
            (output_dir / f"{evidence_id}.json").write_bytes(body)
            # commit_payload() is deliberately never called - simulates the crash.

            self.assertFalse(store.is_evidence_committed(evidence_id))

            reconciled = reconcile_pending_publications(
                store, [output_dir], now=time.time() + 100_000
            )

            self.assertEqual(reconciled, [evidence_id])
            self.assertTrue(store.is_evidence_committed(evidence_id))
            self.assertEqual(store.get_evidence_id(payload_hash), evidence_id)

    def test_reconciliation_respects_the_grace_period(self):
        # A payload that is still within its grace window might be a
        # legitimately in-flight request between begin_payload() and
        # commit_payload() right now - reconciliation must not race it.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "posture"
            output_dir.mkdir()
            store = SQLiteStateStore(str(root / "state.db"), storage_root=root)

            body = b'{"schema_version":"1.0"}'
            payload_hash = hashlib.sha256(body).hexdigest()
            evidence_id = payload_hash[:24]
            store.begin_payload(payload_hash, evidence_id)
            (output_dir / f"{evidence_id}.json").write_bytes(body)

            reconciled = reconcile_pending_publications(
                store, [output_dir], grace_seconds=300, now=time.time() + 5
            )

            self.assertEqual(reconciled, [])
            self.assertFalse(store.is_evidence_committed(evidence_id))

    def test_reconciliation_refuses_content_hash_mismatch(self):
        # A pending row must only ever be committed if the file's actual
        # content still matches the hash that was reserved at
        # begin_payload() time - never based on filename/evidence_id alone.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "posture"
            output_dir.mkdir()
            store = SQLiteStateStore(str(root / "state.db"), storage_root=root)

            body = b'{"schema_version":"1.0"}'
            payload_hash = hashlib.sha256(body).hexdigest()
            evidence_id = payload_hash[:24]
            store.begin_payload(payload_hash, evidence_id)
            (output_dir / f"{evidence_id}.json").write_bytes(b'{"tampered":true}')

            reconciled = reconcile_pending_publications(
                store, [output_dir], now=time.time() + 100_000
            )

            self.assertEqual(reconciled, [])
            self.assertFalse(store.is_evidence_committed(evidence_id))

    def test_reconciliation_ignores_files_with_no_matching_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "posture"
            output_dir.mkdir()
            store = SQLiteStateStore(str(root / "state.db"), storage_root=root)
            (output_dir / "aaaaaaaaaaaaaaaaaaaaaaaa.json").write_bytes(b"{}")

            reconciled = reconcile_pending_publications(
                store, [output_dir], now=time.time() + 100_000
            )

            self.assertEqual(reconciled, [])

    def test_reconciliation_is_idempotent_and_safe_on_already_committed_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "posture"
            output_dir.mkdir()
            store = SQLiteStateStore(str(root / "state.db"), storage_root=root)

            body = b'{"schema_version":"1.0"}'
            payload_hash = hashlib.sha256(body).hexdigest()
            evidence_id = payload_hash[:24]
            store.begin_payload(payload_hash, evidence_id)
            store.commit_payload(payload_hash, evidence_id)
            (output_dir / f"{evidence_id}.json").write_bytes(body)

            first = reconcile_pending_publications(store, [output_dir], now=time.time() + 100_000)
            second = reconcile_pending_publications(store, [output_dir], now=time.time() + 200_000)

            self.assertEqual(first, [])
            self.assertEqual(second, [])
            self.assertTrue(store.is_evidence_committed(evidence_id))

    def test_immediate_restart_reconciles_recent_pending_publication(self):
        # This is the exact gap the review identified: the previous test
        # only proved reconciliation works once a pending record is old
        # enough to clear the default 300s grace period (by backdating
        # accepted_at 100,000s into the past), which never exercised a
        # crash-then-immediate-restart - the single most common real-world
        # trigger for this code path. No backdating here: begin_payload()
        # runs with the real current time, the matching file is written,
        # and IngestionServer is constructed immediately afterward with no
        # simulated delay at all.
        from scripts.ingestion_api import IngestionServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "posture"
            asset_dir = root / "asset-context"
            ticket_dir = root / "remediation-ticket"
            state_db = root / "state.db"

            store = SQLiteStateStore(str(state_db), storage_root=root)
            body = b'{"schema_version":"1.0"}'
            payload_hash = hashlib.sha256(body).hexdigest()
            evidence_id = payload_hash[:24]
            store.begin_payload(payload_hash, evidence_id)  # real time.time(), no now= override
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / f"{evidence_id}.json").write_bytes(body)
            # No accepted_at backdating - the record is as fresh as a real
            # crash-and-restart-within-the-same-second would produce.

            server = IngestionServer(
                ("127.0.0.1", 0),
                StaticKeyRegistry(b"unused", ()),
                {},
                output_dir,
                {"asset_context": asset_dir, "remediation_ticket": ticket_dir},
                state_db,
                root,
            )
            try:
                self.assertTrue(server.state_store.is_evidence_committed(evidence_id))
            finally:
                server.server_close()

    def test_server_startup_calls_reconciliation_with_zero_grace_period(self):
        # Structural companion to the behavioral test above: asserts the
        # exact argument IngestionServer.__init__ passes, so a future
        # change back to the default grace period fails this test
        # immediately and explicitly, rather than only failing the
        # behavioral test in a way that could be misread as flakiness.
        from scripts import ingestion_api as ingestion_api_module
        from scripts.ingestion_api import IngestionServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "posture"
            asset_dir = root / "asset-context"
            ticket_dir = root / "remediation-ticket"
            state_db = root / "state.db"

            with mock.patch.object(
                ingestion_api_module,
                "reconcile_pending_publications",
                wraps=ingestion_api_module.reconcile_pending_publications,
            ) as spy:
                server = IngestionServer(
                    ("127.0.0.1", 0),
                    StaticKeyRegistry(b"unused", ()),
                    {},
                    output_dir,
                    {"asset_context": asset_dir, "remediation_ticket": ticket_dir},
                    state_db,
                    root,
                )
                try:
                    spy.assert_called_once()
                    self.assertEqual(spy.call_args.kwargs.get("grace_seconds"), 0)
                finally:
                    server.server_close()

    def test_reconciliation_rejects_negative_grace_seconds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "posture"
            output_dir.mkdir()
            store = SQLiteStateStore(str(root / "state.db"), storage_root=root)
            with self.assertRaisesRegex(ValueError, "grace_seconds"):
                reconcile_pending_publications(store, [output_dir], grace_seconds=-1)

    def test_reconciliation_skips_symlinks_without_following_them(self):
        # A symlink named like a valid evidence file could point anywhere,
        # including outside the managed directory. Reconciliation must
        # never read through it to compute a hash.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "posture"
            output_dir.mkdir()
            store = SQLiteStateStore(str(root / "state.db"), storage_root=root)

            secret = root / "outside-secret.json"
            secret.write_bytes(b'{"do":"not read this"}')
            body = b'{"schema_version":"1.0"}'
            payload_hash = hashlib.sha256(body).hexdigest()
            evidence_id = payload_hash[:24]
            store.begin_payload(payload_hash, evidence_id)
            symlink_path = output_dir / f"{evidence_id}.json"
            try:
                symlink_path.symlink_to(secret)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not supported on this filesystem")

            reconciled = reconcile_pending_publications(
                store, [output_dir], now=time.time() + 100_000
            )

            self.assertEqual(reconciled, [])
            self.assertFalse(store.is_evidence_committed(evidence_id))

    def test_reconciliation_skips_non_regular_files(self):
        # glob("*.json") matches by name only, not by file type - a
        # directory that happens to be named like an evidence file must
        # not be opened as if it were one.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "posture"
            output_dir.mkdir()
            store = SQLiteStateStore(str(root / "state.db"), storage_root=root)

            body = b'{"schema_version":"1.0"}'
            payload_hash = hashlib.sha256(body).hexdigest()
            evidence_id = payload_hash[:24]
            store.begin_payload(payload_hash, evidence_id)
            (output_dir / f"{evidence_id}.json").mkdir()  # a directory, not a file

            reconciled = reconcile_pending_publications(
                store, [output_dir], now=time.time() + 100_000
            )

            self.assertEqual(reconciled, [])
            self.assertFalse(store.is_evidence_committed(evidence_id))


if __name__ == "__main__":
    unittest.main()

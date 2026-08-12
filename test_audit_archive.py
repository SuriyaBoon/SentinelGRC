import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from audit_archive import (
    ARCHIVE_INTEGRITY_ERROR,
    AuditArchiveError,
    AuditArchiveIntegrityError,
    AzureBlobAuditArchive,
    LocalAuditArchive,
    MAX_AUDIT_EVENT_BYTES,
    MemoryAuditArchive,
    serialize_event,
)
from audit_log import canonical_json


class ProviderError(Exception):
    def __init__(self, status_code, error_code=""):
        super().__init__("provider detail that must not escape")
        self.status_code = status_code
        self.error_code = error_code


class Download:
    def __init__(self, content):
        self.content = content

    def readall(self):
        return self.content


class FakeBlob:
    def __init__(self, failures=None):
        self.failures = list(failures or [])
        self.content = None
        self.metadata = {}
        self.upload_calls = 0

    def upload_blob(self, content, **options):
        self.upload_calls += 1
        if self.failures:
            raise self.failures.pop(0)
        if self.content is not None:
            raise ProviderError(409, "BlobAlreadyExists")
        self.content = bytes(content)
        self.metadata = dict(options["metadata"])

    def get_blob_properties(self, **options):
        return SimpleNamespace(
            metadata=dict(self.metadata),
            size=len(self.content or b""),
            etag='"audit-etag"',
        )

    def download_blob(self, **options):
        return Download(self.content)


class FakeContainer:
    def __init__(self, blob=None, ready=True):
        self.blob = blob or FakeBlob()
        self.is_ready = ready
        self.requested_keys = []

    def get_blob_client(self, object_key):
        self.requested_keys.append(object_key)
        return self.blob

    def get_container_properties(self, **options):
        if not self.is_ready:
            raise ProviderError(503)
        return {}


def event(sequence=1, previous_hash="", **changes):
    body = {
        "finding_id": "F-1",
        "event_type": "finding_created",
        "actor_id": "analyst",
        "actor_role": "analyst",
        "auth_method": "oidc",
        "occurred_at": 100.0 + sequence,
        "details": {"severity": "high"},
        "previous_hash": previous_hash,
    }
    event_hash = hashlib.sha256(
        (
            previous_hash
            + json.dumps(body, sort_keys=True, separators=(",", ":"))
        ).encode("utf-8")
    ).hexdigest()
    value = {
        **body,
        "event_id": f"{sequence:032x}",
        "event_sequence": sequence,
        "event_hash": event_hash,
    }
    value.update(changes)
    return value


def rehash(value):
    chain_body = {
        key: value[key]
        for key in (
            "finding_id",
            "event_type",
            "actor_id",
            "actor_role",
            "auth_method",
            "occurred_at",
            "details",
            "previous_hash",
        )
    }
    value["event_hash"] = hashlib.sha256(
        (
            value["previous_hash"]
            + json.dumps(chain_body, sort_keys=True, separators=(",", ":"))
        ).encode("utf-8")
    ).hexdigest()
    return value


class AuditArchiveTests(unittest.TestCase):
    def test_memory_archive_preserves_content_integrity_error_contract(self):
        archive = MemoryAuditArchive()
        value = event()
        stored = archive.persist_event(value)
        archive.objects[stored.object_key] = b"tampered"

        with self.assertRaises(AuditArchiveIntegrityError) as raised:
            archive.persist_event(value)

        self.assertEqual(str(raised.exception), ARCHIVE_INTEGRITY_ERROR)

    def test_local_archive_preserves_content_integrity_error_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = LocalAuditArchive(temp)
            value = event()
            stored = archive.persist_event(value)
            (Path(temp) / stored.object_key).write_bytes(b"tampered")

            with self.assertRaises(AuditArchiveIntegrityError) as raised:
                archive.persist_event(value)

        self.assertEqual(str(raised.exception), ARCHIVE_INTEGRITY_ERROR)

    def test_azure_archive_preserves_content_integrity_error_contract(self):
        value = event()
        content, digest, _ = serialize_event(value)
        blob = FakeBlob()
        blob.content = b"x" * len(content)
        blob.metadata = {"sha256": digest, "size": str(len(content))}
        archive = AzureBlobAuditArchive(
            "https://account.blob.core.windows.net/audit-archive",
            container_client=FakeContainer(blob),
        )

        with self.assertRaises(AuditArchiveIntegrityError) as raised:
            archive.persist_event(value)

        self.assertEqual(str(raised.exception), ARCHIVE_INTEGRITY_ERROR)

    def test_serialize_rejects_non_object_before_schema_validation(self):
        invalid_event = []
        with self.assertRaisesRegex(ValueError, "^audit event must be an object$"):
            serialize_event(invalid_event)

    def test_serialize_rejects_missing_and_extra_schema_keys(self):
        missing = event()
        missing.pop("details")
        extra = event(extra_field="unexpected")
        for invalid_event in (missing, extra):
            with self.subTest(keys=sorted(invalid_event)):
                with self.assertRaisesRegex(
                    ValueError, "^audit event has an invalid schema$"
                ):
                    serialize_event(invalid_event)

    def test_serialize_validates_event_id_before_event_hash(self):
        invalid_event = event(event_id="invalid", event_hash="invalid")
        with self.assertRaisesRegex(ValueError, "^audit event_id is invalid$"):
            serialize_event(invalid_event)

    def test_serialize_validates_event_hash_before_finding_id(self):
        invalid_event = event(event_hash="invalid", finding_id="")
        with self.assertRaisesRegex(ValueError, "^audit event_hash is invalid$"):
            serialize_event(invalid_event)

    def test_serialize_validates_finding_id_before_sequence(self):
        invalid_event = event(finding_id="", event_sequence=0)
        with self.assertRaisesRegex(ValueError, "^audit finding_id is invalid$"):
            serialize_event(invalid_event)

    def test_serialize_validates_sequence_before_scalar_fields(self):
        invalid_event = event(event_sequence=True, event_type="")
        with self.assertRaisesRegex(ValueError, "^audit event_sequence is invalid$"):
            serialize_event(invalid_event)

    def test_serialize_rejects_each_invalid_scalar_field(self):
        for name in ("event_type", "actor_id", "actor_role", "auth_method"):
            invalid_event = event(**{name: " "})
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    ValueError, f"^audit {name} is invalid$"
                ):
                    serialize_event(invalid_event)

    def test_serialize_validates_details_before_timestamp(self):
        invalid_event = event(details="invalid", occurred_at=True)
        with self.assertRaisesRegex(ValueError, "^audit details must be an object$"):
            serialize_event(invalid_event)

    def test_serialize_validates_timestamp_before_previous_hash(self):
        invalid_event = event(occurred_at=True, previous_hash="invalid")
        with self.assertRaisesRegex(ValueError, "^audit occurred_at is invalid$"):
            serialize_event(invalid_event)

    def test_serialize_validates_previous_hash_before_chain_hash(self):
        invalid_event = event(previous_hash="invalid", event_hash="0" * 64)
        with self.assertRaisesRegex(ValueError, "^audit previous_hash is invalid$"):
            serialize_event(invalid_event)

    def test_serialize_reports_chain_hash_mismatch_as_integrity_error(self):
        invalid_event = event(event_hash="0" * 64)
        with self.assertRaisesRegex(
            AuditArchiveIntegrityError, "^audit event chain hash is invalid$"
        ):
            serialize_event(invalid_event)

    def test_serialize_checks_size_after_chain_integrity(self):
        oversized = event(details={"content": "x" * MAX_AUDIT_EVENT_BYTES})
        rehash(oversized)
        with self.assertRaisesRegex(
            ValueError, "^audit event exceeds the size limit$"
        ):
            serialize_event(oversized)

    def test_serialize_output_is_deterministic_and_matches_identity(self):
        value = event(sequence=7)
        first = serialize_event(value)
        second = serialize_event(value)
        expected_content = canonical_json(value).encode("utf-8")
        expected_digest = hashlib.sha256(expected_content).hexdigest()
        finding_digest = hashlib.sha256(value["finding_id"].encode("utf-8")).hexdigest()
        expected_key = (
            f"events/{finding_digest[:2]}/{finding_digest}/"
            f"{value['event_sequence']:020d}-{value['event_id']}-"
            f"{value['event_hash']}.json"
        )
        self.assertEqual(first, second)
        self.assertEqual(first, (expected_content, expected_digest, expected_key))

    def test_serialize_unicode_preserves_legacy_chain_hash_compatibility(self):
        value = event(details={"reason": "\u0e22\u0e37\u0e19\u0e22\u0e31\u0e19\u0e01\u0e32\u0e23\u0e04\u0e27\u0e1a\u0e04\u0e38\u0e21"})
        rehash(value)
        content, digest, object_key = serialize_event(value)
        expected_content = canonical_json(value).encode("utf-8")
        self.assertEqual(content, expected_content)
        self.assertEqual(digest, hashlib.sha256(expected_content).hexdigest())
        self.assertTrue(object_key.endswith(f"-{value['event_hash']}.json"))

    def test_local_archive_is_ordered_create_only_and_replay_safe(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = LocalAuditArchive(temp)
            first = archive.persist_event(event())
            replay = archive.persist_event(event())
            self.assertEqual(first, replay)
            self.assertRegex(
                first.object_key,
                r"^events/[a-f0-9]{2}/[a-f0-9]{64}/"
                r"00000000000000000001-[a-f0-9]{32}-[a-f0-9]{64}\.json$",
            )
            self.assertEqual(
                len([path for path in Path(temp).rglob("*.json")]),
                1,
            )
            self.assertTrue(archive.ready())

    def test_tamper_oversize_and_existing_corruption_fail_closed(self):
        tampered_event = event(details={"severity": "tampered"})
        with self.assertRaises(AuditArchiveIntegrityError):
            serialize_event(tampered_event)
        oversized = event()
        oversized["details"] = {"content": "x" * MAX_AUDIT_EVENT_BYTES}
        body = {
            key: oversized[key]
            for key in (
                "finding_id",
                "event_type",
                "actor_id",
                "actor_role",
                "auth_method",
                "occurred_at",
                "details",
                "previous_hash",
            )
        }
        oversized["event_hash"] = hashlib.sha256(
            canonical_json(body).encode("utf-8")
        ).hexdigest()
        with self.assertRaises(ValueError):
            serialize_event(oversized)
        with tempfile.TemporaryDirectory() as temp:
            archive = LocalAuditArchive(temp)
            stored = archive.persist_event(event())
            (Path(temp) / stored.object_key).write_bytes(b"tampered")
            replayed_event = event()
            with self.assertRaises(AuditArchiveIntegrityError):
                archive.persist_event(replayed_event)

    def test_unicode_chain_hash_is_compatible_with_existing_events(self):
        value = event()
        value["details"] = {"reason": "ยืนยันการควบคุม"}
        body = {
            key: value[key]
            for key in (
                "finding_id",
                "event_type",
                "actor_id",
                "actor_role",
                "auth_method",
                "occurred_at",
                "details",
                "previous_hash",
            )
        }
        value["event_hash"] = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            self.assertGreater(
                LocalAuditArchive(temp).persist_event(value).size_bytes,
                0,
            )

    def test_azure_archive_replays_and_verifies_persisted_content(self):
        container = FakeContainer()
        archive = AzureBlobAuditArchive(
            "https://account.blob.core.windows.net/audit-archive",
            container_client=container,
            sleep=lambda _: None,
        )
        first = archive.persist_event(event())
        second = archive.persist_event(event())
        self.assertEqual(first, second)
        self.assertEqual(container.requested_keys, [first.object_key, first.object_key])
        self.assertEqual(container.blob.upload_calls, 2)
        self.assertTrue(archive.ready())

    def test_azure_archive_retries_only_transient_failures(self):
        delays = []
        transient = FakeBlob([ProviderError(503), ProviderError(429)])
        archive = AzureBlobAuditArchive(
            "https://account.blob.core.windows.net/audit-archive",
            container_client=FakeContainer(transient),
            retry_attempts=2,
            sleep=delays.append,
        )
        self.assertGreater(archive.persist_event(event()).size_bytes, 0)
        self.assertEqual(transient.upload_calls, 3)
        self.assertEqual(len(delays), 2)
        permanent = FakeBlob([ProviderError(403)])
        archive = AzureBlobAuditArchive(
            "https://account.blob.core.windows.net/audit-archive",
            container_client=FakeContainer(permanent),
            retry_attempts=5,
            sleep=lambda _: None,
        )
        with self.assertRaisesRegex(
            AuditArchiveError, "^audit archive is unavailable$"
        ):
            archive.persist_event(event())
        self.assertEqual(permanent.upload_calls, 1)

    def test_azure_archive_rejects_credentials_and_detects_mismatch(self):
        for url in (
            "http://account.blob.core.windows.net/audit-archive",
            "https://account.blob.core.windows.net/audit-archive?sig=secret",
        ):
            with self.subTest(url=url):
                container = FakeContainer()
                with self.assertRaises(ValueError):
                    AzureBlobAuditArchive(url, container_client=container)
        with self.assertRaisesRegex(ValueError, "managed identity client ID"):
            AzureBlobAuditArchive(
                "https://account.blob.core.windows.net/audit-archive"
            )
        blob = FakeBlob()
        blob.content = b"wrong"
        blob.metadata = {"sha256": "0" * 64, "size": "5"}
        archive = AzureBlobAuditArchive(
            "https://account.blob.core.windows.net/audit-archive",
            container_client=FakeContainer(blob),
        )
        replayed_event = event()
        with self.assertRaises(AuditArchiveIntegrityError):
            archive.persist_event(replayed_event)
        self.assertFalse(
            AzureBlobAuditArchive(
                "https://account.blob.core.windows.net/audit-archive",
                container_client=FakeContainer(ready=False),
            ).ready()
        )

    def test_azure_adapter_has_no_developer_or_shared_key_fallback(self):
        source = Path("audit_archive.py").read_text(encoding="utf-8")
        self.assertIn("ManagedIdentityCredential", source)
        self.assertNotIn("DefaultAzureCredential", source)
        self.assertNotIn("from_connection_string", source)


if __name__ == "__main__":
    unittest.main()

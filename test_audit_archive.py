import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from audit_archive import (
    AuditArchiveError,
    AuditArchiveIntegrityError,
    AzureBlobAuditArchive,
    LocalAuditArchive,
    MAX_AUDIT_EVENT_BYTES,
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


class AuditArchiveTests(unittest.TestCase):
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
        with self.assertRaises(AuditArchiveIntegrityError):
            serialize_event(event(details={"severity": "tampered"}))
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
            with self.assertRaises(AuditArchiveIntegrityError):
                archive.persist_event(event())

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
                with self.assertRaises(ValueError):
                    AzureBlobAuditArchive(url, container_client=FakeContainer())
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
        with self.assertRaises(AuditArchiveIntegrityError):
            archive.persist_event(event())
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

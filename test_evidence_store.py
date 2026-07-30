import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from evidence_store import (
    AzureBlobEvidenceStore,
    EvidenceIntegrityError,
    EvidenceStoreError,
    LocalEvidenceStore,
    MAX_EVIDENCE_BYTES,
)
from governance_core import ActorContext, GovernanceCore


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
            etag='"etag-1"',
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


class EvidenceStoreTests(unittest.TestCase):
    def test_local_store_is_content_addressed_create_only_and_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            store = LocalEvidenceStore(temp)
            first = store.persist(b"verified evidence")
            second = store.persist(b"verified evidence")
            self.assertEqual(first, second)
            self.assertRegex(first.object_key, r"^sha256/[a-f0-9]{2}/[a-f0-9]{64}$")
            files = [path for path in Path(temp).rglob("*") if path.is_file()]
            self.assertEqual(len(files), 1)
            self.assertTrue(store.ready())
            with self.assertRaises(ValueError):
                store.persist(b"x" * (MAX_EVIDENCE_BYTES + 1))

    def test_local_store_detects_existing_object_corruption(self):
        with tempfile.TemporaryDirectory() as temp:
            store = LocalEvidenceStore(temp)
            stored = store.persist(b"original")
            (Path(temp) / stored.object_key).write_bytes(b"tampered")
            with self.assertRaises(EvidenceIntegrityError):
                store.persist(b"original")

    def test_azure_store_uses_server_key_and_verifies_replay(self):
        container = FakeContainer()
        store = AzureBlobEvidenceStore(
            "https://account.blob.core.windows.net/evidence",
            container_client=container,
            sleep=lambda _: None,
        )
        first = store.persist(b"evidence")
        second = store.persist(b"evidence")
        self.assertEqual(first, second)
        self.assertEqual(container.requested_keys, [first.object_key, first.object_key])
        self.assertEqual(container.blob.upload_calls, 2)
        self.assertTrue(store.ready())

    def test_azure_store_retries_only_transient_failures(self):
        delays = []
        transient = FakeBlob([ProviderError(503), ProviderError(429)])
        store = AzureBlobEvidenceStore(
            "https://account.blob.core.windows.net/evidence",
            container_client=FakeContainer(transient),
            retry_attempts=2,
            sleep=delays.append,
        )
        self.assertEqual(store.persist(b"retry").size_bytes, 5)
        self.assertEqual(transient.upload_calls, 3)
        self.assertEqual(len(delays), 2)

        permanent = FakeBlob([ProviderError(403)])
        store = AzureBlobEvidenceStore(
            "https://account.blob.core.windows.net/evidence",
            container_client=FakeContainer(permanent),
            retry_attempts=5,
            sleep=lambda _: None,
        )
        with self.assertRaisesRegex(EvidenceStoreError, "^evidence storage is unavailable$"):
            store.persist(b"denied")
        self.assertEqual(permanent.upload_calls, 1)

    def test_azure_store_rejects_unsafe_url_and_integrity_mismatch(self):
        with self.assertRaises(ValueError):
            AzureBlobEvidenceStore(
                "http://account.blob.core.windows.net/evidence",
                container_client=FakeContainer(),
            )
        with self.assertRaises(ValueError):
            AzureBlobEvidenceStore(
                "https://account.blob.core.windows.net/evidence?sig=secret",
                container_client=FakeContainer(),
            )
        with self.assertRaisesRegex(ValueError, "managed identity client ID"):
            AzureBlobEvidenceStore(
                "https://account.blob.core.windows.net/evidence"
            )
        blob = FakeBlob()
        blob.content = b"wrong"
        blob.metadata = {
            "sha256": hashlib.sha256(b"expected").hexdigest(),
            "size": str(len(b"expected")),
        }
        store = AzureBlobEvidenceStore(
            "https://account.blob.core.windows.net/evidence",
            container_client=FakeContainer(blob),
            sleep=lambda _: None,
        )
        with self.assertRaises(EvidenceIntegrityError):
            store.persist(b"expected")
        self.assertFalse(
            AzureBlobEvidenceStore(
                "https://account.blob.core.windows.net/evidence",
                container_client=FakeContainer(ready=False),
            ).ready()
        )

    def test_azure_adapter_has_no_shared_key_or_developer_credential_fallback(self):
        source = Path("evidence_store.py").read_text(encoding="utf-8")
        self.assertIn("ManagedIdentityCredential", source)
        self.assertNotIn("DefaultAzureCredential", source)
        self.assertNotIn("from_connection_string", source)

    def test_storage_failure_does_not_commit_evidence_or_transition(self):
        class FailingStore:
            def persist(self, content):
                raise EvidenceStoreError("evidence storage is unavailable")

            def ready(self):
                return False

        with tempfile.TemporaryDirectory() as temp:
            core = GovernanceCore(
                str(Path(temp) / "governance.db"),
                evidence_store=FailingStore(),
            )
            analyst = ActorContext("analyst", "analyst")
            owner = ActorContext("owner", "risk_owner")
            approver = ActorContext("approver", "approver")
            core.create_finding(
                "F-FAIL", "AC-1", "APP-1", "Storage failure", "owner", "high", analyst
            )
            core.assess_risk("F-FAIL", owner, "high", "high")
            core.propose_treatment("F-FAIL", owner, "mitigate", "fix", "team")
            core.approve_treatment("F-FAIL", approver, "approved")
            core.start_action("F-FAIL", owner, "engineer")
            with self.assertRaisesRegex(
                EvidenceStoreError, "^evidence storage is unavailable$"
            ):
                core.submit_evidence("F-FAIL", owner, "ticket", b"proof")
            self.assertEqual(core.get_finding("F-FAIL")["status"], "in_progress")
            self.assertEqual(core.list_evidence("F-FAIL"), [])

    def test_governance_commits_only_verified_object_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            store = LocalEvidenceStore(str(Path(temp) / "objects"))
            core = GovernanceCore(
                str(Path(temp) / "governance.db"),
                evidence_store=store,
            )
            analyst = ActorContext("analyst", "analyst")
            owner = ActorContext("owner", "risk_owner")
            approver = ActorContext("approver", "approver")
            core.create_finding(
                "F-STORE", "AC-1", "APP-1", "Evidence store", "owner", "high", analyst
            )
            core.assess_risk("F-STORE", owner, "high", "high")
            core.propose_treatment(
                "F-STORE", owner, "mitigate", "fix", "team"
            )
            core.approve_treatment("F-STORE", approver, "approved")
            core.start_action("F-STORE", owner, "engineer")
            core.submit_evidence("F-STORE", owner, "ticket", b"proof")
            replay = core.submit_evidence("F-STORE", owner, "ticket", b"proof")
            record = core.list_evidence("F-STORE")[0]
            self.assertEqual(replay["status"], "pending_verification")
            self.assertEqual(len(core.list_evidence("F-STORE")), 1)
            self.assertEqual(record["sha256"], hashlib.sha256(b"proof").hexdigest())
            self.assertEqual(record["size_bytes"], 5)
            self.assertTrue((Path(temp) / "objects" / record["object_key"]).is_file())
            with self.assertRaisesRegex(ValueError, "cannot transition"):
                core.submit_evidence("F-STORE", owner, "ticket", b"different")


if __name__ == "__main__":
    unittest.main()

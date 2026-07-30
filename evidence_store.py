"""Content-addressed evidence storage adapters.

Object names are derived only from the SHA-256 digest. Caller-controlled
filenames and paths never cross this boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlparse


MAX_EVIDENCE_BYTES = 256 * 1024
TRANSIENT_STATUS_CODES = {408, 429, 500, 502, 503, 504}


class EvidenceStoreError(RuntimeError):
    """Base error returned without leaking provider credentials or responses."""


class EvidenceIntegrityError(EvidenceStoreError):
    pass


@dataclass(frozen=True)
class EvidenceObject:
    object_key: str
    sha256: str
    size_bytes: int
    etag: str


class EvidenceStore(Protocol):
    def persist(self, content: bytes) -> EvidenceObject: ...

    def ready(self) -> bool: ...


def _validate_content(content: bytes) -> tuple[str, str]:
    if not isinstance(content, bytes):
        raise ValueError("evidence content must be bytes")
    if not content or len(content) > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence content must be non-empty and within the size limit")
    digest = hashlib.sha256(content).hexdigest()
    return digest, f"sha256/{digest[:2]}/{digest}"


class MemoryEvidenceStore:
    """Process-local adapter for isolated domain tests, never runtime staging."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def persist(self, content: bytes) -> EvidenceObject:
        digest, object_key = _validate_content(content)
        existing = self.objects.setdefault(object_key, bytes(content))
        if not hmac.compare_digest(hashlib.sha256(existing).hexdigest(), digest):
            raise EvidenceIntegrityError("stored evidence failed integrity verification")
        return EvidenceObject(object_key, digest, len(content), digest)

    def ready(self) -> bool:
        return True


class LocalEvidenceStore:
    """Create-only content-addressed storage for the explicit local lab mode."""

    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def persist(self, content: bytes) -> EvidenceObject:
        digest, object_key = _validate_content(content)
        target = (self.root / object_key).resolve()
        if self.root not in target.parents:
            raise EvidenceIntegrityError("unsafe evidence object path")
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            try:
                with target.open("xb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError:
                pass
            stored = target.read_bytes()
        if (
            len(stored) != len(content)
            or not hmac.compare_digest(hashlib.sha256(stored).hexdigest(), digest)
        ):
            raise EvidenceIntegrityError("stored evidence failed integrity verification")
        return EvidenceObject(object_key, digest, len(content), digest)

    def ready(self) -> bool:
        return self.root.is_dir() and os.access(self.root, os.R_OK | os.W_OK)


class AzureBlobEvidenceStore:
    """Azure Blob adapter using create-only writes and managed identity."""

    def __init__(
        self,
        container_url: str,
        *,
        managed_identity_client_id: str = "",
        timeout_seconds: int = 10,
        retry_attempts: int = 3,
        container_client: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        parsed = urlparse(container_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Azure evidence container must be an absolute HTTPS URL")
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("evidence-store timeout must be between 1 and 30 seconds")
        if not 0 <= retry_attempts <= 5:
            raise ValueError("evidence-store retries must be between 0 and 5")
        self.container_url = container_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.retry_attempts = retry_attempts
        self.sleep = sleep
        if container_client is None:
            if not managed_identity_client_id:
                raise ValueError(
                    "Azure evidence storage requires a managed identity client ID"
                )
            try:
                from azure.identity import ManagedIdentityCredential
                from azure.storage.blob import ContainerClient
            except ModuleNotFoundError as error:
                raise RuntimeError(
                    "Azure evidence dependencies are not installed"
                ) from error
            credential = ManagedIdentityCredential(
                client_id=managed_identity_client_id
            )
            container_client = ContainerClient.from_container_url(
                self.container_url,
                credential=credential,
                retry_total=retry_attempts,
                retry_connect=retry_attempts,
                retry_read=retry_attempts,
                retry_status=retry_attempts,
            )
        self.container_client = container_client

    @staticmethod
    def _status(error: Exception) -> int | None:
        value = getattr(error, "status_code", None)
        return value if isinstance(value, int) else None

    @classmethod
    def _already_exists(cls, error: Exception) -> bool:
        return cls._status(error) == 409 and getattr(
            error, "error_code", ""
        ) in {"BlobAlreadyExists", "ResourceAlreadyExists"}

    @classmethod
    def _transient(cls, error: Exception) -> bool:
        return (
            cls._status(error) in TRANSIENT_STATUS_CODES
            or type(error).__name__ in {"ServiceRequestError", "ServiceResponseError"}
        )

    def _persist_once(
        self, content: bytes, digest: str, object_key: str
    ) -> EvidenceObject:
        blob = self.container_client.get_blob_client(object_key)
        metadata = {"sha256": digest, "size": str(len(content))}
        try:
            blob.upload_blob(
                content,
                overwrite=False,
                metadata=metadata,
                validate_content=True,
                timeout=self.timeout_seconds,
            )
        except Exception as error:
            if not self._already_exists(error):
                raise
        properties = blob.get_blob_properties(timeout=self.timeout_seconds)
        stored_metadata = getattr(properties, "metadata", {}) or {}
        stored_size = getattr(properties, "size", None)
        if (
            stored_metadata.get("sha256") != digest
            or stored_metadata.get("size") != str(len(content))
            or stored_size != len(content)
        ):
            raise EvidenceIntegrityError("stored evidence metadata is inconsistent")
        stored = blob.download_blob(timeout=self.timeout_seconds).readall()
        if (
            not isinstance(stored, bytes)
            or len(stored) != len(content)
            or not hmac.compare_digest(hashlib.sha256(stored).hexdigest(), digest)
        ):
            raise EvidenceIntegrityError("stored evidence failed integrity verification")
        etag = str(getattr(properties, "etag", "")).strip('"')
        if not etag:
            raise EvidenceIntegrityError("stored evidence has no immutable version tag")
        return EvidenceObject(
            object_key,
            digest,
            len(content),
            etag,
        )

    def persist(self, content: bytes) -> EvidenceObject:
        digest, object_key = _validate_content(content)
        for attempt in range(self.retry_attempts + 1):
            try:
                return self._persist_once(content, digest, object_key)
            except (EvidenceIntegrityError, ValueError):
                raise
            except Exception as error:
                if not self._transient(error) or attempt >= self.retry_attempts:
                    raise EvidenceStoreError("evidence storage is unavailable") from None
                self.sleep(min(0.25 * (2**attempt), 2.0))
        raise EvidenceStoreError("evidence storage is unavailable")

    def ready(self) -> bool:
        try:
            self.container_client.get_container_properties(
                timeout=self.timeout_seconds
            )
            return True
        except Exception:
            return False

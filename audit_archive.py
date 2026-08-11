"""Append-only audit archive adapters for lab and Azure staging.

Archive object identities are generated only from trusted governance event
fields. Callers cannot supply filenames or object paths.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlparse

from audit_log import canonical_json


MAX_AUDIT_EVENT_BYTES = 256 * 1024
TRANSIENT_STATUS_CODES = {408, 429, 500, 502, 503, 504}
HEX_64 = re.compile(r"^[a-f0-9]{64}$")
EVENT_ID = re.compile(r"^[a-f0-9]{32}$")
REQUIRED_AUDIT_EVENT_FIELDS = {
    "event_id",
    "finding_id",
    "event_sequence",
    "event_type",
    "actor_id",
    "actor_role",
    "auth_method",
    "occurred_at",
    "details",
    "previous_hash",
    "event_hash",
}
AUDIT_SCALAR_FIELDS = ("event_type", "actor_id", "actor_role", "auth_method")
AUDIT_CHAIN_FIELDS = (
    "finding_id",
    "event_type",
    "actor_id",
    "actor_role",
    "auth_method",
    "occurred_at",
    "details",
    "previous_hash",
)


class AuditArchiveError(RuntimeError):
    """Provider-neutral archive failure."""


class AuditArchiveIntegrityError(AuditArchiveError):
    pass


@dataclass(frozen=True)
class ArchivedAuditObject:
    object_key: str
    sha256: str
    size_bytes: int
    etag: str


class AuditArchive(Protocol):
    def persist_event(self, event: dict[str, Any]) -> ArchivedAuditObject: ...

    def ready(self) -> bool: ...


def _validate_event_schema(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("audit event must be an object")
    if set(event) != REQUIRED_AUDIT_EVENT_FIELDS:
        raise ValueError("audit event has an invalid schema")
    return event


def _validate_event_identity(
    event: dict[str, Any],
) -> tuple[str, str, str, int]:
    event_id = event["event_id"]
    event_hash = event["event_hash"]
    finding_id = event["finding_id"]
    sequence = event["event_sequence"]
    if not isinstance(event_id, str) or not EVENT_ID.fullmatch(event_id):
        raise ValueError("audit event_id is invalid")
    if not isinstance(event_hash, str) or not HEX_64.fullmatch(event_hash):
        raise ValueError("audit event_hash is invalid")
    if not isinstance(finding_id, str) or not finding_id or len(finding_id) > 128:
        raise ValueError("audit finding_id is invalid")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ValueError("audit event_sequence is invalid")
    return event_id, event_hash, finding_id, sequence


def _validate_scalar_fields(event: dict[str, Any]) -> None:
    for name in AUDIT_SCALAR_FIELDS:
        value = event[name]
        if not isinstance(value, str) or not value.strip() or len(value) > 128:
            raise ValueError(f"audit {name} is invalid")


def _validate_payload_fields(event: dict[str, Any]) -> str:
    if not isinstance(event["details"], dict):
        raise ValueError("audit details must be an object")
    if not isinstance(event["occurred_at"], (int, float)) or isinstance(
        event["occurred_at"], bool
    ):
        raise ValueError("audit occurred_at is invalid")
    previous_hash = event["previous_hash"]
    if previous_hash != "" and (
        not isinstance(previous_hash, str) or not HEX_64.fullmatch(previous_hash)
    ):
        raise ValueError("audit previous_hash is invalid")
    return previous_hash


def _verify_chain_hash(
    event: dict[str, Any], previous_hash: str, event_hash: str
) -> None:
    chain_body = {key: event[key] for key in AUDIT_CHAIN_FIELDS}
    expected_event_hash = hashlib.sha256(
        (
            previous_hash
            + json.dumps(chain_body, sort_keys=True, separators=(",", ":"))
        ).encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(expected_event_hash, event_hash):
        raise AuditArchiveIntegrityError("audit event chain hash is invalid")


def _serialize_content(event: dict[str, Any]) -> tuple[bytes, str]:
    content = canonical_json(event).encode("utf-8")
    if not content or len(content) > MAX_AUDIT_EVENT_BYTES:
        raise ValueError("audit event exceeds the size limit")
    digest = hashlib.sha256(content).hexdigest()
    return content, digest


def _build_object_key(
    finding_id: str, sequence: int, event_id: str, event_hash: str
) -> str:
    finding_digest = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()
    return (
        f"events/{finding_digest[:2]}/{finding_digest}/"
        f"{sequence:020d}-{event_id}-{event_hash}.json"
    )


def serialize_event(event: dict[str, Any]) -> tuple[bytes, str, str]:
    validated_event = _validate_event_schema(event)
    event_id, event_hash, finding_id, sequence = _validate_event_identity(
        validated_event
    )
    _validate_scalar_fields(validated_event)
    previous_hash = _validate_payload_fields(validated_event)
    _verify_chain_hash(validated_event, previous_hash, event_hash)
    content, digest = _serialize_content(validated_event)
    object_key = _build_object_key(finding_id, sequence, event_id, event_hash)
    return content, digest, object_key


class MemoryAuditArchive:
    """Process-local archive used only by isolated tests."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def persist_event(self, event: dict[str, Any]) -> ArchivedAuditObject:
        content, digest, object_key = serialize_event(event)
        existing = self.objects.setdefault(object_key, content)
        if not hmac.compare_digest(hashlib.sha256(existing).hexdigest(), digest):
            raise AuditArchiveIntegrityError("archived audit event failed integrity verification")
        return ArchivedAuditObject(object_key, digest, len(content), digest)

    def ready(self) -> bool:
        return True


class LocalAuditArchive:
    """Create-only filesystem archive for explicit lab mode."""

    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def persist_event(self, event: dict[str, Any]) -> ArchivedAuditObject:
        content, digest, object_key = serialize_event(event)
        target = (self.root / object_key).resolve()
        if self.root not in target.parents:
            raise AuditArchiveIntegrityError("unsafe audit archive path")
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
            raise AuditArchiveIntegrityError(
                "archived audit event failed integrity verification"
            )
        return ArchivedAuditObject(object_key, digest, len(content), digest)

    def ready(self) -> bool:
        return self.root.is_dir() and os.access(self.root, os.R_OK | os.W_OK)


class AzureBlobAuditArchive:
    """Managed-identity Azure Blob archive with create-only writes."""

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
            raise ValueError("Azure audit container must be an absolute HTTPS URL")
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("audit-archive timeout must be between 1 and 30 seconds")
        if not 0 <= retry_attempts <= 5:
            raise ValueError("audit-archive retries must be between 0 and 5")
        self.container_url = container_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.retry_attempts = retry_attempts
        self.sleep = sleep
        if container_client is None:
            if not managed_identity_client_id:
                raise ValueError(
                    "Azure audit archive requires a managed identity client ID"
                )
            try:
                from azure.identity import ManagedIdentityCredential
                from azure.storage.blob import ContainerClient
            except ModuleNotFoundError as error:
                raise RuntimeError(
                    "Azure audit archive dependencies are not installed"
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
    ) -> ArchivedAuditObject:
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
            raise AuditArchiveIntegrityError(
                "archived audit metadata is inconsistent"
            )
        stored = blob.download_blob(timeout=self.timeout_seconds).readall()
        if (
            not isinstance(stored, bytes)
            or len(stored) != len(content)
            or not hmac.compare_digest(hashlib.sha256(stored).hexdigest(), digest)
        ):
            raise AuditArchiveIntegrityError(
                "archived audit event failed integrity verification"
            )
        etag = str(getattr(properties, "etag", "")).strip('"')
        if not etag:
            raise AuditArchiveIntegrityError(
                "archived audit event has no immutable version tag"
            )
        return ArchivedAuditObject(object_key, digest, len(content), etag)

    def persist_event(self, event: dict[str, Any]) -> ArchivedAuditObject:
        content, digest, object_key = serialize_event(event)
        for attempt in range(self.retry_attempts + 1):
            try:
                return self._persist_once(content, digest, object_key)
            except (AuditArchiveIntegrityError, ValueError):
                raise
            except Exception as error:
                if not self._transient(error) or attempt >= self.retry_attempts:
                    raise AuditArchiveError("audit archive is unavailable") from None
                self.sleep(min(0.25 * (2**attempt), 2.0))
        raise AuditArchiveError("audit archive is unavailable")

    def ready(self) -> bool:
        try:
            self.container_client.get_container_properties(
                timeout=self.timeout_seconds
            )
            return True
        except Exception:
            return False

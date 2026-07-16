"""Authenticated per-agent posture ingestion API for SentinelGRC."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agent_keys import AgentKeyRegistry
from state_store import SQLiteStateStore

MAX_BODY_BYTES = 64 * 1024
MAX_CLOCK_SKEW_SECONDS = 300
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
REQUIRED_FIELDS = {
    "schema_version", "collected_at", "asset_id", "hostname",
    "bitlocker_system_drive", "firewall_all_profiles_enabled",
    "defender_realtime_enabled", "days_since_last_update",
}
ALLOWED_FIELDS = REQUIRED_FIELDS | {"os", "os_version", "domain", "checks", "owner", "criticality"}


def make_signature(secret: bytes, timestamp: str, nonce: str, body: bytes) -> str:
    message = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def parse_authorization(value: str) -> tuple[str, str]:
    if not value.startswith("HMAC "):
        raise ValueError("Missing HMAC authorization.")
    credential = value[5:].strip()
    if ":" not in credential:
        raise ValueError("Key ID is required.")
    key_id, signature = credential.split(":", 1)
    if not KEY_ID_PATTERN.fullmatch(key_id) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise ValueError("Invalid HMAC credential.")
    return key_id, signature


def validate_posture(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError("Posture payload must be a JSON object.")
    missing = REQUIRED_FIELDS.difference(payload)
    if missing:
        raise ValueError(f"Missing required fields: {sorted(missing)}")
    unknown = set(payload).difference(ALLOWED_FIELDS)
    if unknown:
        raise ValueError(f"Unknown fields: {sorted(unknown)}")
    if payload["schema_version"] != "1.0":
        raise ValueError("Unsupported posture schema version.")
    if not isinstance(payload["asset_id"], str) or not 1 <= len(payload["asset_id"]) <= 128:
        raise ValueError("asset_id length is invalid.")
    if not isinstance(payload["hostname"], str) or not 1 <= len(payload["hostname"]) <= 255:
        raise ValueError("hostname length is invalid.")
    if any(ord(char) < 32 for char in payload["asset_id"] + payload["hostname"]):
        raise ValueError("asset_id and hostname cannot contain control characters.")
    try:
        collected_at = datetime.fromisoformat(payload["collected_at"].replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("collected_at must be an ISO-8601 timestamp.") from error
    if collected_at.tzinfo is None:
        raise ValueError("collected_at must include a timezone.")
    for field in ("bitlocker_system_drive", "firewall_all_profiles_enabled", "defender_realtime_enabled"):
        if not isinstance(payload[field], bool):
            raise ValueError(f"{field} must be boolean.")
    age = payload["days_since_last_update"]
    if age is not None and (not isinstance(age, int) or isinstance(age, bool) or age < 0):
        raise ValueError("days_since_last_update must be a non-negative integer or null.")


class NonceStore:
    def __init__(self, ttl_seconds: int = MAX_CLOCK_SKEW_SECONDS, db_path: str | None = None):
        self.ttl_seconds = ttl_seconds
        self._persistent = SQLiteStateStore(db_path) if db_path else None
        self._values: dict[str, float] = {}

    def reserve(self, nonce: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        if self._persistent is not None:
            return self._persistent.reserve_nonce(nonce, self.ttl_seconds, current)
        if nonce in self._values and self._values[nonce] > current:
            return False
        self._values[nonce] = current + self.ttl_seconds
        return True


class IngestionError(Exception):
    def __init__(self, message: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


def authenticate_request(
    secret: bytes,
    authorization: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    nonce_store: NonceStore,
    now: int | None = None,
) -> None:
    current = int(time.time() if now is None else now)
    try:
        request_time = int(timestamp)
    except ValueError as error:
        raise IngestionError("Invalid timestamp.", HTTPStatus.UNAUTHORIZED) from error
    if abs(current - request_time) > MAX_CLOCK_SKEW_SECONDS:
        raise IngestionError("Timestamp outside replay window.", HTTPStatus.UNAUTHORIZED)
    if not NONCE_PATTERN.fullmatch(nonce):
        raise IngestionError("Invalid nonce.", HTTPStatus.UNAUTHORIZED)
    try:
        _, supplied = parse_authorization(authorization)
    except ValueError as error:
        raise IngestionError(str(error), HTTPStatus.UNAUTHORIZED) from error
    expected = make_signature(secret, timestamp, nonce, body)
    if not hmac.compare_digest(supplied, expected):
        raise IngestionError("Invalid signature.", HTTPStatus.UNAUTHORIZED)
    if not nonce_store.reserve(nonce, now=float(current)):
        raise IngestionError("Replay detected.", HTTPStatus.UNAUTHORIZED)


class PostureHandler(BaseHTTPRequestHandler):
    server_version = "SentinelGRC/0.7"

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/posture":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        try:
            if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
                raise IngestionError("Content-Type must be application/json.")
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > MAX_BODY_BYTES:
                raise IngestionError("Payload size is not allowed.", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            body = self.rfile.read(length)
            if len(body) != length:
                raise IngestionError("Incomplete request body.")
            timestamp = self.headers.get("X-Sentinel-Timestamp", "")
            nonce = self.headers.get("X-Sentinel-Nonce", "")
            key_id, signature = parse_authorization(self.headers.get("Authorization", ""))
            secret = self.server.key_registry.resolve_secret(key_id, self.server.key_secrets)
            if secret is None:
                raise IngestionError("Unknown or revoked key.", HTTPStatus.UNAUTHORIZED)
            authenticate_request(
                secret, f"HMAC {key_id}:{signature}", timestamp, nonce, body, self.server.nonce_store
            )
            payload = json.loads(body.decode("utf-8"))
            validate_posture(payload)
            payload_hash = hashlib.sha256(body).hexdigest()
            existing_id = self.server.state_store.get_evidence_id(payload_hash)
            if existing_id:
                self._send_json(HTTPStatus.ACCEPTED, {"status": "duplicate", "evidence_id": existing_id})
                return
            evidence_id = payload_hash[:24]
            self.server.state_store.remember_payload(payload_hash, evidence_id)
            (self.server.output_dir / f"{evidence_id}.json").write_bytes(body)
            self._send_json(HTTPStatus.ACCEPTED, {"status": "accepted", "evidence_id": evidence_id})
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
        except IngestionError as error:
            self._send_json(error.status, {"error": str(error)})
        except (OSError, ValueError) as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: HTTPStatus, payload: dict[str, str]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class IngestionServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], key_registry: AgentKeyRegistry, key_secrets: dict[str, str], output_dir: Path, state_db: str):
        super().__init__(address, PostureHandler)
        self.key_registry = key_registry
        self.key_secrets = key_secrets
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.state_store = SQLiteStateStore(state_db)
        self.nonce_store = NonceStore(db_path=state_db)


def run_server(args: argparse.Namespace) -> int:
    raw_keys = os.environ.get(args.keys_env)
    if not raw_keys:
        raise SystemExit(f"Environment variable {args.keys_env} is required.")
    try:
        key_secrets = json.loads(raw_keys)
    except json.JSONDecodeError as error:
        raise SystemExit(f"Environment variable {args.keys_env} must be a JSON object.") from error
    if not isinstance(key_secrets, dict):
        raise SystemExit(f"Environment variable {args.keys_env} must be a JSON object.")
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.allow_insecure_network:
        raise SystemExit("Refusing non-loopback bind without --allow-insecure-network.")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    registry = AgentKeyRegistry(args.state_db)
    server = IngestionServer(
        (args.host, args.port), registry, key_secrets, output_dir, args.state_db
    )
    print(f"SentinelGRC ingestion listening on {args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelGRC authenticated per-agent ingestion.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--output-dir", default="evidence-inbox")
    serve.add_argument("--state-db", default="sentinelgrc-state.db")
    serve.add_argument("--keys-env", default="SENTINELGRC_AGENT_KEYS_JSON")
    serve.add_argument("--allow-insecure-network", action="store_true")
    args = parser.parse_args()
    return run_server(args)


if __name__ == "__main__":
    raise SystemExit(main())

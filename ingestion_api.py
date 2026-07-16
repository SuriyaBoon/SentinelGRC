"""Authenticated posture ingestion API for SentinelGRC."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import threading
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

MAX_BODY_BYTES = 64 * 1024
MAX_CLOCK_SKEW_SECONDS = 300
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
REQUIRED_FIELDS = {
    "schema_version",
    "collected_at",
    "asset_id",
    "hostname",
    "bitlocker_system_drive",
    "firewall_all_profiles_enabled",
    "defender_realtime_enabled",
    "days_since_last_update",
}
ALLOWED_FIELDS = REQUIRED_FIELDS | {
    "os",
    "os_version",
    "domain",
    "checks",
}


def canonical_body(body: bytes) -> bytes:
    return body


def make_signature(secret: bytes, timestamp: str, nonce: str, body: bytes) -> str:
    message = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + canonical_body(body)
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


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
    for field in (
        "bitlocker_system_drive",
        "firewall_all_profiles_enabled",
        "defender_realtime_enabled",
    ):
        if not isinstance(payload[field], bool):
            raise ValueError(f"{field} must be boolean.")
    age = payload["days_since_last_update"]
    if age is not None and (not isinstance(age, int) or isinstance(age, bool) or age < 0):
        raise ValueError("days_since_last_update must be a non-negative integer or null.")
    if "domain" in payload and payload["domain"] is not None and not isinstance(payload["domain"], bool):
        raise ValueError("domain must be boolean or null.")
    if "checks" in payload and not isinstance(payload["checks"], list):
        raise ValueError("checks must be an array.")


class NonceStore:
    def __init__(self, ttl_seconds: int = MAX_CLOCK_SKEW_SECONDS):
        self.ttl_seconds = ttl_seconds
        self._values: dict[str, float] = {}
        self._lock = threading.Lock()

    def reserve(self, nonce: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        with self._lock:
            self._values = {
                value: expires
                for value, expires in self._values.items()
                if expires > current
            }
            if nonce in self._values:
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
    if not authorization.startswith("HMAC "):
        raise IngestionError("Missing HMAC authorization.", HTTPStatus.UNAUTHORIZED)
    supplied = authorization[5:].strip()
    expected = make_signature(secret, timestamp, nonce, body)
    if not hmac.compare_digest(supplied, expected):
        raise IngestionError("Invalid signature.", HTTPStatus.UNAUTHORIZED)
    if not nonce_store.reserve(nonce, now=float(current)):
        raise IngestionError("Replay detected.", HTTPStatus.UNAUTHORIZED)


class PostureHandler(BaseHTTPRequestHandler):
    server_version = "SentinelGRC/0.4"

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/posture":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        try:
            content_type = self.headers.get("Content-Type", "")
            if not content_type.lower().startswith("application/json"):
                raise IngestionError("Content-Type must be application/json.")
            length_header = self.headers.get("Content-Length")
            if length_header is None:
                raise IngestionError("Content-Length is required.")
            length = int(length_header)
            if length < 1 or length > MAX_BODY_BYTES:
                raise IngestionError(
                    "Payload size is not allowed.",
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )
            body = self.rfile.read(length)
            if len(body) != length:
                raise IngestionError("Incomplete request body.")
            timestamp = self.headers.get("X-Sentinel-Timestamp", "")
            nonce = self.headers.get("X-Sentinel-Nonce", "")
            authenticate_request(
                self.server.secret,
                self.headers.get("Authorization", ""),
                timestamp,
                nonce,
                body,
                self.server.nonce_store,
            )
            payload = json.loads(body.decode("utf-8"))
            validate_posture(payload)
            evidence_id = hashlib.sha256(
                f"{timestamp}:{nonce}".encode() + body
            ).hexdigest()[:24]
            output = self.server.output_dir / f"{evidence_id}.json"
            output.write_bytes(body)
            self._send_json(
                HTTPStatus.ACCEPTED,
                {"status": "accepted", "evidence_id": evidence_id},
            )
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

    def __init__(self, address: tuple[str, int], secret: bytes, output_dir: Path):
        super().__init__(address, PostureHandler)
        self.secret = secret
        self.output_dir = output_dir
        self.nonce_store = NonceStore()


def run_server(args: argparse.Namespace) -> int:
    secret_value = os.environ.get(args.secret_env)
    if not secret_value:
        raise SystemExit(f"Environment variable {args.secret_env} is required.")
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.allow_insecure_network:
        raise SystemExit("Refusing non-loopback bind without --allow-insecure-network.")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    server = IngestionServer((args.host, args.port), secret_value.encode("utf-8"), output_dir)
    print(f"SentinelGRC ingestion listening on {args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelGRC authenticated posture ingestion.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--output-dir", default="evidence-inbox")
    serve.add_argument("--secret-env", default="SENTINELGRC_INGESTION_SECRET")
    serve.add_argument("--allow-insecure-network", action="store_true")
    args = parser.parse_args()
    return run_server(args)


if __name__ == "__main__":
    raise SystemExit(main())

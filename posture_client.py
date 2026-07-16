"""Submit a posture JSON file to SentinelGRC using HMAC authentication."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.request


def make_signature(secret: bytes, timestamp: str, nonce: str, body: bytes) -> str:
    message = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Send signed posture evidence.")
    parser.add_argument("posture_file")
    parser.add_argument("--url", default="http://127.0.0.1:8080/v1/posture")
    parser.add_argument("--secret-env", default="SENTINELGRC_INGESTION_SECRET")
    args = parser.parse_args()

    secret_value = os.environ.get(args.secret_env)
    if not secret_value:
        raise SystemExit(f"Environment variable {args.secret_env} is required.")
    with open(args.posture_file, "rb") as file:
        body = file.read()
    if len(body) > 64 * 1024:
        raise SystemExit("Posture payload exceeds the 64 KiB limit.")

    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    request = urllib.request.Request(
        args.url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "HMAC "
            + make_signature(secret_value.encode("utf-8"), timestamp, nonce, body),
            "X-Sentinel-Timestamp": timestamp,
            "X-Sentinel-Nonce": nonce,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            print(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise SystemExit(f"Server rejected posture: HTTP {error.code}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Submit a posture JSON file using per-agent HMAC authentication."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import secrets
import urllib.error
import urllib.request
import time


def make_signature(secret: bytes, timestamp: str, nonce: str, body: bytes) -> str:
    message = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Send signed posture evidence.")
    parser.add_argument("posture_file")
    parser.add_argument("--url", default="http://127.0.0.1:8080/v1/posture")
    parser.add_argument("--key-id-env", default="SENTINELGRC_AGENT_KEY_ID")
    parser.add_argument("--secret-env", default="SENTINELGRC_AGENT_SECRET")
    args = parser.parse_args()

    key_id = os.environ.get(args.key_id_env)
    secret_value = os.environ.get(args.secret_env)
    if not key_id or not secret_value:
        raise SystemExit(f"Both {args.key_id_env} and {args.secret_env} are required.")
    with open(args.posture_file, "rb") as file:
        body = file.read()
    if len(body) > 64 * 1024:
        raise SystemExit("Posture payload exceeds the 64 KiB limit.")

    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    signature = make_signature(secret_value.encode("utf-8"), timestamp, nonce, body)
    request = urllib.request.Request(
        args.url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"HMAC {key_id}:{signature}",
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

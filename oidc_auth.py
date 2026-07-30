"""Cryptographic OIDC access-token verification for trusted HTTP boundaries."""

from __future__ import annotations

import base64
import json
import re
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol
from urllib.parse import urlparse
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from governance_core import ActorContext, ROLES
from human_identity import AuthenticationError
from oidc_contract import ROLE_MAP, actor_from_claims


MAX_TOKEN_BYTES = 16384
MAX_JWKS_BYTES = 1024 * 1024
BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def _b64url(value: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or not BASE64URL_PATTERN.fullmatch(value)
    ):
        raise ValueError("invalid base64url value")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_object(raw: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("JSON value must be an object")
    return value


def _numeric_date(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"invalid {name} claim")
    return int(value)


class SigningKeyClient(Protocol):
    def get_signing_key(self, key_id: str) -> rsa.RSAPublicKey: ...
    def ready(self) -> bool: ...


class JwksClient:
    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float,
        cache_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = url
        self.timeout_seconds = timeout_seconds
        self.cache_seconds = cache_seconds
        self.clock = clock
        self._keys: dict[str, rsa.RSAPublicKey] = {}
        self._expires_at = 0.0
        self._last_forced_refresh = float("-inf")
        self._lock = threading.Lock()

    def _fetch(self) -> dict[str, rsa.RSAPublicKey]:
        request = urllib.request.Request(
            self.url,
            headers={"Accept": "application/json", "User-Agent": "SentinelGRC/oidc"},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            final_url = urlparse(response.geturl())
            if final_url.scheme != "https" or not final_url.netloc:
                raise ValueError("JWKS redirect must remain HTTPS")
            content_length = int(response.headers.get("Content-Length", "0") or 0)
            if content_length > MAX_JWKS_BYTES:
                raise ValueError("JWKS response is too large")
            raw = response.read(MAX_JWKS_BYTES + 1)
        if len(raw) > MAX_JWKS_BYTES:
            raise ValueError("JWKS response is too large")
        document = _json_object(raw)
        if not isinstance(document.get("keys"), list):
            raise ValueError("invalid JWKS document")
        parsed: dict[str, rsa.RSAPublicKey] = {}
        for item in document["keys"]:
            if (
                isinstance(item, dict)
                and item.get("kty") == "RSA"
                and item.get("use", "sig") == "sig"
                and item.get("alg", "RS256") == "RS256"
                and isinstance(item.get("kid"), str)
            ):
                modulus = int.from_bytes(_b64url(item["n"]), "big")
                exponent = int.from_bytes(_b64url(item["e"]), "big")
                if modulus.bit_length() >= 2048 and exponent >= 3:
                    parsed[item["kid"]] = rsa.RSAPublicNumbers(
                        exponent, modulus
                    ).public_key()
        if not parsed:
            raise ValueError("JWKS contains no acceptable signing keys")
        return parsed

    def _refresh(self) -> None:
        keys = self._fetch()
        self._keys = keys
        self._expires_at = self.clock() + self.cache_seconds

    def get_signing_key(self, key_id: str) -> rsa.RSAPublicKey:
        with self._lock:
            refreshed = False
            if self.clock() >= self._expires_at:
                self._refresh()
                refreshed = True
            key = self._keys.get(key_id)
            forced_refresh_interval = min(60.0, self.cache_seconds)
            if (
                key is None
                and not refreshed
                and self.clock() - self._last_forced_refresh
                >= forced_refresh_interval
            ):
                self._refresh()
                self._last_forced_refresh = self.clock()
                key = self._keys.get(key_id)
            if key is None:
                raise KeyError("unknown signing key")
            return key

    def ready(self) -> bool:
        try:
            with self._lock:
                if self.clock() >= self._expires_at:
                    self._refresh()
            return bool(self._keys)
        except Exception:
            return False


@dataclass(frozen=True)
class OidcVerifierConfig:
    issuer: str
    audience: str
    tenant_id: str
    jwks_url: str
    role_map: dict[str, str] = field(default_factory=lambda: dict(ROLE_MAP))
    group_role_map: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 5.0
    cache_seconds: float = 3600.0
    clock_skew_seconds: int = 60

    def validate(self) -> None:
        for name, value in (("issuer", self.issuer), ("jwks_url", self.jwks_url)):
            parsed = urlparse(value)
            if parsed.scheme != "https" or not parsed.netloc or parsed.username:
                raise ValueError(f"OIDC {name} must be an absolute HTTPS URL")
        if not self.audience:
            raise ValueError("OIDC audience is required")
        try:
            UUID(self.tenant_id)
        except (ValueError, AttributeError) as error:
            raise ValueError("OIDC tenant ID must be a GUID") from error
        if not 0 < self.timeout_seconds <= 30:
            raise ValueError("OIDC timeout must be between 0 and 30 seconds")
        if not 60 <= self.cache_seconds <= 86400:
            raise ValueError("OIDC cache lifetime must be between 60 and 86400 seconds")
        if not 0 <= self.clock_skew_seconds <= 300:
            raise ValueError("OIDC clock skew must be between 0 and 300 seconds")
        for name, mapping in (
            ("role map", self.role_map),
            ("group role map", self.group_role_map),
        ):
            if (
                len(mapping) > 100
                or any(
                    not isinstance(key, str)
                    or not key.strip()
                    or role not in ROLES
                    for key, role in mapping.items()
                )
            ):
                raise ValueError(f"OIDC {name} is invalid")


class EntraTokenVerifier:
    def __init__(
        self,
        config: OidcVerifierConfig,
        key_client: SigningKeyClient | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        config.validate()
        self.config = config
        self.clock = clock
        self.key_client = key_client or JwksClient(
            config.jwks_url,
            timeout_seconds=config.timeout_seconds,
            cache_seconds=config.cache_seconds,
        )

    def verify(self, token: str) -> ActorContext:
        if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN_BYTES:
            raise AuthenticationError("invalid bearer token")
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("invalid token structure")
            header = _json_object(_b64url(parts[0]))
            if (
                not isinstance(header, dict)
                or header.get("alg") != "RS256"
                or not isinstance(header.get("kid"), str)
            ):
                raise ValueError("invalid token header")
            key = self.key_client.get_signing_key(header["kid"])
            key.verify(
                _b64url(parts[2]),
                f"{parts[0]}.{parts[1]}".encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            claims = _json_object(_b64url(parts[1]))
            required = {"aud", "exp", "iat", "iss", "nbf", "sub", "tid"}
            if not required.issubset(claims):
                raise ValueError("incomplete token claims")
            now = int(self.clock())
            if _numeric_date(claims, "iat") > now + self.config.clock_skew_seconds:
                raise ValueError("future token")
            if _numeric_date(claims, "nbf") > now + self.config.clock_skew_seconds:
                raise ValueError("inactive token")
            if _numeric_date(claims, "exp") <= now - self.config.clock_skew_seconds:
                raise ValueError("expired token")
            return actor_from_claims(
                claims,
                issuer=self.config.issuer,
                audience=self.config.audience,
                tenant_id=self.config.tenant_id,
                role_map=self.config.role_map,
                group_role_map=self.config.group_role_map,
                now=now,
                clock_skew_seconds=self.config.clock_skew_seconds,
            )
        except Exception:
            raise AuthenticationError("invalid bearer token") from None

    def ready(self) -> bool:
        return self.key_client.ready()

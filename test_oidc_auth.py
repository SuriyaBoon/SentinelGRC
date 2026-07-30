import base64
import json
import unittest

from human_identity import AuthenticationError

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from oidc_auth import EntraTokenVerifier, JwksClient, OidcVerifierConfig
    CRYPTOGRAPHY_AVAILABLE = True
except ModuleNotFoundError:
    CRYPTOGRAPHY_AVAILABLE = False


ISSUER = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
TENANT = "11111111-1111-1111-1111-111111111111"
AUDIENCE = "api://sentinel"


def encoded(value):
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class FakeKeys:
    def __init__(self, key, key_id="key-1", ready=True):
        self.key = key
        self.key_id = key_id
        self.is_ready = ready

    def get_signing_key(self, key_id):
        if key_id != self.key_id:
            raise KeyError("unknown")
        return self.key

    def ready(self):
        return self.is_ready


@unittest.skipUnless(
    CRYPTOGRAPHY_AVAILABLE,
    "cryptography is installed from requirements.txt in CI/runtime images",
)
class OidcAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        cls.other_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )

    def claims(self, **changes):
        value = {
            "aud": AUDIENCE,
            "exp": 2000,
            "iat": 900,
            "iss": ISSUER,
            "nbf": 900,
            "roles": ["sentinel-analyst"],
            "sub": "user-1",
            "tid": TENANT,
        }
        value.update(changes)
        return value

    def token(self, claims=None, *, algorithm="RS256", key_id="key-1", key=None):
        header = encoded({"alg": algorithm, "kid": key_id, "typ": "JWT"})
        payload = encoded(claims or self.claims())
        message = f"{header}.{payload}".encode()
        signature = (key or self.private_key).sign(
            message, padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{header}.{payload}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"

    def verifier(self, **config):
        values = {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "tenant_id": TENANT,
            "jwks_url": "https://login.microsoftonline.com/tenant/keys",
        }
        values.update(config)
        return EntraTokenVerifier(
            OidcVerifierConfig(**values),
            FakeKeys(self.private_key.public_key()),
            clock=lambda: 1000,
        )

    def test_valid_signed_token_creates_server_actor(self):
        actor = self.verifier().verify(self.token())
        self.assertEqual((actor.actor_id, actor.role, actor.auth_method), (
            "user-1", "analyst", "oidc"
        ))

    def test_tampering_wrong_key_algorithm_and_kid_fail_closed(self):
        verifier = self.verifier()
        cases = [
            self.token({**self.claims(), "sub": "tampered"})[:-2] + "aa",
            self.token(key=self.other_key),
            self.token(algorithm="HS256"),
            self.token(key_id="unknown"),
        ]
        for token in cases:
            with self.subTest(token=token[:20]):
                with self.assertRaisesRegex(AuthenticationError, "^invalid bearer token$"):
                    verifier.verify(token)

    def test_wrong_trust_and_time_claims_fail_closed(self):
        cases = [
            {"issuer": "https://issuer.invalid"},
            {"audience": "other"},
            {"tenant_id": "22222222-2222-2222-2222-222222222222"},
        ]
        for config in cases:
            with self.subTest(config=config):
                with self.assertRaises(AuthenticationError):
                    self.verifier(**config).verify(self.token())
        for claims in (
            self.claims(exp=800),
            self.claims(nbf=1200),
            self.claims(iat=1200),
        ):
            with self.assertRaises(AuthenticationError):
                self.verifier().verify(self.token(claims))

    def test_group_mapping_and_ambiguous_roles(self):
        verifier = self.verifier(
            role_map={},
            group_role_map={"group-risk": "risk_owner"},
        )
        actor = verifier.verify(self.token(self.claims(
            roles=[], groups=["group-risk"]
        )))
        self.assertEqual(actor.role, "risk_owner")
        with self.assertRaises(AuthenticationError):
            verifier.verify(self.token(self.claims(
                roles=["sentinel-analyst", "sentinel-approver"]
            )))

    def test_clock_skew_is_bounded_and_numeric_dates_are_strict(self):
        actor = self.verifier().verify(self.token(self.claims(
            iat=1059, nbf=1059, exp=941
        )))
        self.assertEqual(actor.actor_id, "user-1")
        for claims in (
            self.claims(exp=True),
            self.claims(nbf="900"),
            self.claims(iat=None),
        ):
            with self.subTest(claims=claims):
                with self.assertRaises(AuthenticationError):
                    self.verifier().verify(self.token(claims))

    def test_configuration_and_readiness_are_fail_closed(self):
        with self.assertRaises(ValueError):
            self.verifier(jwks_url="http://metadata.invalid/keys")
        with self.assertRaises(ValueError):
            self.verifier(role_map={"role": "not-a-sentinel-role"})
        with self.assertRaises(ValueError):
            self.verifier(clock_skew_seconds=301)
        unavailable = EntraTokenVerifier(
            OidcVerifierConfig(
                issuer=ISSUER,
                audience=AUDIENCE,
                tenant_id=TENANT,
                jwks_url="https://login.microsoftonline.com/tenant/keys",
            ),
            FakeKeys(self.private_key.public_key(), ready=False),
        )
        self.assertFalse(unavailable.ready())

    def test_unknown_key_refresh_is_rate_limited(self):
        current = [1000.0]
        client = JwksClient(
            "https://login.microsoftonline.com/tenant/keys",
            timeout_seconds=1,
            cache_seconds=3600,
            clock=lambda: current[0],
        )
        client._keys = {"known": self.private_key.public_key()}
        client._expires_at = 2000
        refreshes = []

        def refresh():
            refreshes.append(current[0])
            client._expires_at = current[0] + 3600

        client._refresh = refresh
        for _ in range(2):
            with self.assertRaises(KeyError):
                client.get_signing_key("attacker-controlled-kid")
        self.assertEqual(refreshes, [1000.0])
        current[0] = 1060.0
        with self.assertRaises(KeyError):
            client.get_signing_key("another-unknown-kid")
        self.assertEqual(refreshes, [1000.0, 1060.0])


if __name__ == "__main__":
    unittest.main()

import unittest

from oidc_contract import actor_from_claims


class OIDCContractTests(unittest.TestCase):
    def test_verified_claims_map_to_server_actor(self):
        actor = actor_from_claims({
            "iss": "https://idp.example",
            "aud": "sentinel",
            "sub": "user-1",
            "exp": 2000,
            "roles": ["sentinel-approver"],
        }, issuer="https://idp.example", audience="sentinel", now=1000)
        self.assertEqual(actor.actor_id, "user-1")
        self.assertEqual(actor.role, "approver")
        self.assertEqual(actor.auth_method, "oidc")

    def test_invalid_audience_expiry_and_role_fail_closed(self):
        base = {"iss": "https://idp.example", "aud": "sentinel", "sub": "user-1", "exp": 1000}
        with self.assertRaises(PermissionError):
            actor_from_claims(base, issuer="https://idp.example", audience="other", now=1)
        with self.assertRaises(PermissionError):
            actor_from_claims({**base, "roles": ["sentinel-analyst"]}, issuer="https://idp.example", audience="sentinel", now=1000)
        with self.assertRaises(PermissionError):
            actor_from_claims({**base, "roles": ["unknown"]}, issuer="https://idp.example", audience="sentinel", now=1)

    def test_trust_lifetime_and_authorization_error_precedence_is_stable(self):
        claims = {
            "iss": "wrong",
            "aud": "wrong",
            "sub": "",
            "exp": 0,
            "roles": "not-a-list",
        }
        with self.assertRaisesRegex(PermissionError, "^invalid OIDC issuer$"):
            actor_from_claims(
                claims,
                issuer="https://idp.example",
                audience="sentinel",
                now=1000,
            )

        claims["iss"] = "https://idp.example"
        with self.assertRaisesRegex(PermissionError, "^invalid OIDC audience$"):
            actor_from_claims(
                claims,
                issuer="https://idp.example",
                audience="sentinel",
                now=1000,
            )

        claims["aud"] = "sentinel"
        with self.assertRaisesRegex(
            PermissionError,
            "^expired or incomplete OIDC claims$",
        ):
            actor_from_claims(
                claims,
                issuer="https://idp.example",
                audience="sentinel",
                now=1000,
            )

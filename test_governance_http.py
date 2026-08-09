import json
import tempfile
import unittest
from pathlib import Path

from governance_api import GovernanceApi
from governance_core import ActorContext, GovernanceCore
from governance_http import GovernanceHttpApplication
from human_identity import AuthenticationError, HumanIdentityStore


class GovernanceHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        identities = HumanIdentityStore(str(root / "identity.db"))
        identities.create_user("alice", "analyst")
        self.secret = identities.issue_api_key("alice", "alice-v1")
        self.app = GovernanceHttpApplication(
            GovernanceApi(GovernanceCore(str(root / "governance.db")), identities)
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_health_and_authenticated_governance_route(self):
        self.assertEqual(self.app.handle("GET", "/healthz", {}, b"")[0], 200)
        status, result = self.app.handle(
            "POST", "/v1/governance/create",
            {"X-API-Key-ID": "alice-v1", "Authorization": f"Bearer {self.secret}"},
            json.dumps({
                "finding_id": "F-HTTP", "control_id": "AC-HTTP", "asset_id": "APP-HTTP",
                "title": "Missing control", "risk_owner": "owner", "severity": "high",
            }).encode(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["finding_id"], "F-HTTP")

    def test_readiness_and_finding_read_routes_require_authentication(self):
        self.assertEqual(self.app.handle("GET", "/ready", {}, b"")[0], 200)
        headers = {"X-API-Key-ID": "alice-v1", "Authorization": f"Bearer {self.secret}"}
        status, result = self.app.handle("GET", "/findings", headers, b"")
        self.assertEqual(status, 200)
        self.assertEqual(result["findings"], [])
        self.app.handle("POST", "/findings/F-READ/create", headers, json.dumps({
            "control_id": "AC", "asset_id": "APP", "title": "Read route",
            "risk_owner": "owner", "severity": "low",
        }).encode())
        status, result = self.app.handle("GET", "/findings/F-READ", headers, b"")
        self.assertEqual(status, 200)
        self.assertEqual(result["finding_id"], "F-READ")

    def test_invalid_auth_and_route_are_rejected(self):
        self.assertEqual(self.app.handle("GET", "/wrong", {}, b"")[0], 404)
        status, _ = self.app.handle("POST", "/v1/governance/report", {}, b"{}")
        self.assertEqual(status, 401)

    def test_invalid_json_and_oversized_requests_are_rejected(self):
        headers = {"X-API-Key-ID": "alice-v1", "Authorization": f"Bearer {self.secret}"}
        status, result = self.app.handle(
            "POST", "/v1/governance/create", headers, b"\xff"
        )
        self.assertEqual((status, result), (400, {"error": "invalid_json"}))
        status, result = self.app.handle(
            "POST", "/v1/governance/create", headers, b"{"
        )
        self.assertEqual((status, result), (400, {"error": "invalid_json"}))
        self.assertEqual(
            self.app.handle("POST", "/v1/governance/create", headers, b"x" * (256 * 1024 + 1))[0], 413
        )

    def test_authorization_failure_is_not_reported_as_authentication_failure(self):
        identities = HumanIdentityStore(str(Path(self.temp.name) / "restricted-identity.db"))
        identities.create_user("reviewer", "risk_owner")
        secret = identities.issue_api_key("reviewer", "reviewer-v1")
        app = GovernanceHttpApplication(
            GovernanceApi(GovernanceCore(str(Path(self.temp.name) / "restricted.db")), identities)
        )
        status, _ = app.handle(
            "POST", "/v1/governance/create",
            {"X-API-Key-ID": "reviewer-v1", "Authorization": f"Bearer {secret}"},
            json.dumps({
                "finding_id": "F-FORBIDDEN", "control_id": "AC", "asset_id": "APP",
                "title": "Forbidden", "risk_owner": "owner", "severity": "low",
            }).encode(),
        )
        self.assertEqual(status, 403)

    def test_oidc_actor_is_server_derived_and_body_cannot_override_it(self):
        class VerifiedActor:
            def verify(self, token):
                if token != "signed-token":
                    raise AuthenticationError("invalid bearer token")
                return ActorContext("entra-user", "analyst", auth_method="oidc")

        app = GovernanceHttpApplication(
            self.app.api,
            authentication_mode="oidc",
            oidc_verifier=VerifiedActor(),
        )
        headers = {"Authorization": "Bearer signed-token"}
        body = {
            "finding_id": "F-OIDC",
            "control_id": "AC-OIDC",
            "asset_id": "APP-OIDC",
            "title": "OIDC boundary",
            "risk_owner": "owner",
            "severity": "high",
        }
        status, result = app.handle(
            "POST", "/v1/governance/create", headers, json.dumps(body).encode()
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["finding_id"], "F-OIDC")
        event = self.app.api.core.list_events("F-OIDC")[0]
        self.assertEqual((event["actor_id"], event["auth_method"]), (
            "entra-user", "oidc"
        ))
        body["actor_id"] = "forged-user"
        status, _ = app.handle(
            "POST", "/v1/governance/create", headers, json.dumps(body).encode()
        )
        self.assertEqual(status, 400)

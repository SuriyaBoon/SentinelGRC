import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from production_contract import Settings
from runtime_app import create_application, sqlite_path


class RuntimeApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.settings = Settings(
            environment="staging",
            database_url=f"sqlite:///{root / 'governance.db'}",
            identity_database_url=f"sqlite:///{root / 'identity.db'}",
            evidence_dir=str(root / "evidence"),
        )
        self.application = create_application(self.settings)

    def tearDown(self):
        self.temp.cleanup()

    def request(self, path, method="GET", body=b"", headers=None):
        captured = {}

        def start_response(status, response_headers):
            captured["status"] = status
            captured["headers"] = dict(response_headers)

        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
        }
        for name, value in (headers or {}).items():
            environ["HTTP_" + name.upper().replace("-", "_")] = value
        encoded = b"".join(self.application(environ, start_response))
        return captured, json.loads(encoded)

    def test_liveness_and_readiness_are_distinct_and_include_request_id(self):
        live, live_body = self.request("/healthz")
        ready, ready_body = self.request("/ready")
        self.assertTrue(live["status"].startswith("200"))
        self.assertTrue(ready["status"].startswith("200"))
        self.assertEqual(ready_body["status"], "ready")
        self.assertIn("governance_store", ready_body["checks"])
        self.assertIn("identity_store", ready_body["checks"])
        self.assertEqual(
            live["headers"]["X-Request-ID"], live_body["request_id"]
        )

    def test_invalid_content_length_is_rejected_without_traceback(self):
        captured = {}

        def start_response(status, response_headers):
            captured["status"] = status

        body = b"".join(
            self.application(
                {
                    "REQUEST_METHOD": "POST",
                    "PATH_INFO": "/v1/governance/create",
                    "CONTENT_LENGTH": "invalid",
                    "wsgi.input": io.BytesIO(b"{}"),
                },
                start_response,
            )
        )
        self.assertTrue(captured["status"].startswith("400"))
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_wsgi_header_normalization_preserves_api_key_authentication(self):
        identities = self.application.runtime.http.api.identities
        identities.create_user("runtime-user", "analyst")
        secret = identities.issue_api_key("runtime-user", "runtime-key")
        captured, body = self.request(
            "/findings",
            headers={
                "Authorization": f"Bearer {secret}",
                "X-API-Key-ID": "runtime-key",
            },
        )
        self.assertTrue(captured["status"].startswith("200"))
        self.assertEqual(body["findings"], [])

    def test_oversized_body_is_rejected_before_wsgi_input_is_read(self):
        class Unreadable:
            def read(self, size):
                raise AssertionError("oversized body must not be read")

        captured = {}

        def start_response(status, response_headers):
            captured["status"] = status

        encoded = b"".join(
            self.application(
                {
                    "REQUEST_METHOD": "POST",
                    "PATH_INFO": "/v1/governance/create",
                    "CONTENT_LENGTH": str(256 * 1024 + 1),
                    "wsgi.input": Unreadable(),
                },
                start_response,
            )
        )
        self.assertTrue(captured["status"].startswith("413"))
        self.assertEqual(json.loads(encoded)["error"], "request_too_large")

    def test_production_startup_is_fail_closed_until_adapters_exist(self):
        settings = Settings(
            environment="production",
            database_url="postgresql://db/sentinel",
            identity_database_url="postgresql://db/sentinel",
            evidence_dir=self.settings.evidence_dir,
            evidence_store_url="azblob://evidence",
            audit_archive_url="azblob://audit",
            oidc_issuer="https://login.microsoftonline.com/tenant/v2.0",
            oidc_audience="api://sentinel",
            require_tls=True,
        )
        with self.assertRaisesRegex(RuntimeError, "production startup is blocked"):
            create_application(settings)

    def test_environment_boolean_is_strict(self):
        with patch.dict(os.environ, {"SENTINEL_REQUIRE_TLS": "sometimes"}):
            with self.assertRaisesRegex(ValueError, "must be a boolean"):
                Settings.from_env()

    def test_non_sqlite_and_remote_sqlite_urls_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "only SQLite"):
            sqlite_path("postgresql://db/sentinel")
        with self.assertRaisesRegex(ValueError, "remote host"):
            sqlite_path("sqlite://server/share/sentinel.db")

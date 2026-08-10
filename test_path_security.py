import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit
from unittest import mock

from path_security import (
    resolve_existing_file_under_root,
    resolve_sqlite_database_under_root,
    resolve_under_root,
    validate_outbound_url,
)
from scripts import ingestion_api, posture_client
from scripts.agent_keys import AgentKeyRegistry
from state_store import SQLiteStateStore


class PathSecurityTests(unittest.TestCase):
    def test_secure_posture_client_default_matches_ingestion_server_port(self):
        endpoint = urlsplit(posture_client.DEFAULT_POSTURE_URL)
        self.assertEqual(endpoint.scheme, "https")
        self.assertEqual(endpoint.hostname, "127.0.0.1")
        self.assertEqual(endpoint.port, ingestion_api.DEFAULT_INGESTION_PORT)
        self.assertEqual(endpoint.path, "/v1/posture")

    def test_file_and_database_paths_are_confined_to_runtime_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            root.mkdir()
            source = root / "input.json"
            source.write_text("{}", encoding="utf-8")
            self.assertEqual(resolve_existing_file_under_root(source, root), source.resolve())
            self.assertEqual(
                resolve_sqlite_database_under_root("state.db", root),
                (root / "state.db").resolve(),
            )
            for unsafe in ("../outside.db", "file:state.db?mode=ro", "state.txt"):
                with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                    resolve_sqlite_database_under_root(unsafe, root)
            with self.assertRaises(ValueError):
                resolve_existing_file_under_root("../input.json", root)

    def test_symlink_input_escape_is_rejected_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "secret.json").write_text("{}", encoding="utf-8")
            link = root / "escape"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks are unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "must remain under"):
                resolve_existing_file_under_root(link / "secret.json", root)

    def test_outbound_url_requires_https_and_exact_host_allowlist(self):
        self.assertEqual(
            validate_outbound_url(
                "https://collector.example/v1/posture",
                allowed_hosts={"collector.example"},
            ),
            "https://collector.example/v1/posture",
        )
        unsafe = (
            "https://attacker.example/v1/posture",
            "https://collector.example@attacker.example/v1/posture",
            "http://collector.example/v1/posture",
            "https://user:secret@collector.example/v1/posture",
        )
        for value in unsafe:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_outbound_url(value, allowed_hosts={"collector.example"})

    def test_plain_http_requires_explicit_loopback_lab_opt_in(self):
        value = "http://127.0.0.1:8080/v1/posture"
        with self.assertRaises(ValueError):
            validate_outbound_url(value, allowed_hosts={"127.0.0.1"})
        self.assertEqual(
            validate_outbound_url(
                value,
                allowed_hosts={"127.0.0.1"},
                allow_loopback_http=True,
            ),
            value,
        )
        with self.assertRaises(ValueError):
            validate_outbound_url(
                "http://10.0.0.4/v1/posture",
                allowed_hosts={"10.0.0.4"},
                allow_loopback_http=True,
            )

    def test_sqlite_stores_reject_connection_uris(self):
        with self.assertRaisesRegex(ValueError, "not a URI"):
            SQLiteStateStore("file:state.db?mode=memory")
        with self.assertRaisesRegex(ValueError, "not a URI"):
            AgentKeyRegistry("file:keys.db?mode=memory")

    def test_ingestion_server_is_tls_by_default_and_loopback_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = dict(
                host="127.0.0.1",
                port=0,
                runtime_root=str(root),
                output_dir="evidence-inbox",
                state_db="state.db",
                keys_env="TEST_SENTINEL_KEYS",
                tls_cert=None,
                tls_key=None,
                allow_loopback_http=False,
            )
            environment = {
                "TEST_SENTINEL_KEYS": json.dumps({"k": "s"}),
                "SENTINEL_RUNTIME_ROOT": str(root),
            }
            missing_tls = argparse.Namespace(**base)
            with mock.patch.dict(os.environ, environment):
                with self.assertRaisesRegex(SystemExit, "TLS certificate and key are required"):
                    ingestion_api.run_server(missing_tls)
                remote = argparse.Namespace(**{**base, "host": "0.0.0.0"})
                with self.assertRaisesRegex(SystemExit, "loopback-only"):
                    ingestion_api.run_server(remote)
                partial_tls = argparse.Namespace(**{**base, "tls_cert": "cert.pem"})
                with self.assertRaisesRegex(SystemExit, "configured together"):
                    ingestion_api.run_server(partial_tls)

    def test_null_and_empty_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for value in ("", "bad\x00name"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    resolve_under_root(value, directory)


if __name__ == "__main__":
    unittest.main()

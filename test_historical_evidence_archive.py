import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from historical_evidence_archive import (
    HISTORICAL_DECISION,
    load_manifest,
    manifest_sha256,
    validate_manifest,
    verify_archive,
    verify_private_sources,
)


PACKAGE_ROOT = (
    Path(__file__).resolve().parent
    / "docs"
    / "evidence"
    / "historical-azure-staging-202608"
)


class HistoricalEvidenceArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (PACKAGE_ROOT / "manifest.json").read_text(encoding="utf-8")
        )

    def _copy_archive(self, destination: Path) -> None:
        destination.mkdir()
        for name in ("README.md", "manifest.json", "SHA256SUMS.txt"):
            (destination / name).write_bytes((PACKAGE_ROOT / name).read_bytes())

    def test_tracked_archive_verifies_and_grants_no_current_gate_credit(self) -> None:
        result = verify_archive(PACKAGE_ROOT)
        self.assertEqual(result["archive_id"], "AZURE-STAGING-20260804-05")
        self.assertEqual(result["control_count"], 10)
        self.assertEqual(result["decision"], HISTORICAL_DECISION)
        self.assertFalse(result["current_live_gate_credit"])

    def test_canonical_manifest_hash_is_deterministic(self) -> None:
        reordered = dict(reversed(list(self.manifest.items())))
        self.assertEqual(manifest_sha256(self.manifest), manifest_sha256(reordered))
        self.assertEqual(
            manifest_sha256(self.manifest),
            "2766940fa1807785b278856fca9cf1fdd53af8d9c97730e1f67b2133fba799cf",
        )

    def test_manifest_tampering_is_rejected_by_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "archive"
            self._copy_archive(root)
            changed = copy.deepcopy(self.manifest)
            changed["controls"][0]["summary"] = "A safe but unauthorized change."
            (root / "manifest.json").write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "archive checksum mismatch"):
                verify_archive(root)

    def test_readme_tampering_is_rejected_by_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "archive"
            self._copy_archive(root)
            (root / "README.md").write_text("Inflated production claim.\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "archive checksum mismatch"):
                verify_archive(root)

    def test_readme_checksum_is_stable_across_lf_and_crlf(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "archive"
            self._copy_archive(root)
            checked_out = (root / "README.md").read_bytes()
            lf_readme = checked_out.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

            (root / "README.md").write_bytes(lf_readme)
            self.assertEqual(verify_archive(root)["decision"], HISTORICAL_DECISION)

            crlf_readme = lf_readme.replace(b"\n", b"\r\n")
            (root / "README.md").write_bytes(crlf_readme)
            self.assertEqual(verify_archive(root)["decision"], HISTORICAL_DECISION)

    def test_readme_invalid_utf8_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "archive"
            self._copy_archive(root)
            (root / "README.md").write_bytes(b"\xff\xfe")
            with self.assertRaisesRegex(ValueError, "valid UTF-8"):
                verify_archive(root)

    def test_readme_filesystem_failure_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "archive"
            self._copy_archive(root)
            original_read_bytes = Path.read_bytes

            def fail_readme(target: Path) -> bytes:
                if target.name == "README.md":
                    raise PermissionError("simulated README race")
                return original_read_bytes(target)

            with patch.object(Path, "read_bytes", fail_readme):
                with self.assertRaisesRegex(ValueError, "README.md cannot be read"):
                    verify_archive(root)

    def test_extra_archive_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "archive"
            self._copy_archive(root)
            (root / "raw-export.json").write_text("{}", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "archive files are invalid"):
                verify_archive(root)

    def test_nested_archive_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "archive"
            self._copy_archive(root)
            (root / "private-originals").mkdir()
            with self.assertRaisesRegex(ValueError, "archive files are invalid"):
                verify_archive(root)

    def test_archive_root_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "archive"
            self._copy_archive(root)
            alias = base / "archive-link"
            try:
                alias.symlink_to(root, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("directory symlinks are unavailable on this host")
            with self.assertRaisesRegex(ValueError, "archive root is invalid"):
                verify_archive(alias)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            path.write_text('{"schema_version":"a","schema_version":"b"}', encoding="ascii")
            with self.assertRaisesRegex(ValueError, "duplicate key"):
                load_manifest(path)

    def test_missing_provenance_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed.pop("provenance")
        with self.assertRaisesRegex(ValueError, "manifest fields are invalid"):
            validate_manifest(changed)

    def test_malformed_provenance_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["provenance"]["source_commit_sha"] = "main"
        with self.assertRaisesRegex(ValueError, "source commit SHA is invalid"):
            validate_manifest(changed)
        changed = copy.deepcopy(self.manifest)
        changed["provenance"]["runtime_image_digest"] = "runtime:latest"
        with self.assertRaisesRegex(ValueError, "runtime_image_digest is invalid"):
            validate_manifest(changed)

    def test_production_ready_claim_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["claim_boundary"]["production_ready"] = True
        with self.assertRaisesRegex(ValueError, "cannot claim production readiness"):
            validate_manifest(changed)

    def test_current_live_gate_credit_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["claim_boundary"]["current_live_gate_credit"] = True
        with self.assertRaisesRegex(ValueError, "cannot satisfy current live gates"):
            validate_manifest(changed)

    def test_unknown_control_status_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["controls"][0]["status"] = "accepted"
        with self.assertRaisesRegex(ValueError, "control status is invalid"):
            validate_manifest(changed)

    def test_generic_schema_accepts_a_truthful_status_subset(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["controls"] = [changed["controls"][1]]
        self.assertEqual(validate_manifest(changed)["controls"][0]["status"], "passed")

    def test_tracked_archive_retains_every_observed_status_class(self) -> None:
        statuses = {item["status"] for item in self.manifest["controls"]}
        self.assertEqual(statuses, {"passed", "partial", "failed", "not_tested"})

    def test_duplicate_control_identity_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["controls"][1]["control_id"] = changed["controls"][0]["control_id"]
        with self.assertRaisesRegex(ValueError, "control identity is invalid"):
            validate_manifest(changed)

    def test_source_path_traversal_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["controls"][0]["source_file"] = "../private.json"
        with self.assertRaisesRegex(ValueError, "source filename is invalid"):
            validate_manifest(changed)

    def test_sensitive_resource_identifier_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["controls"][0]["summary"] = "/subscriptions/example/private-resource"
        with self.assertRaisesRegex(ValueError, "prohibited sensitive value"):
            validate_manifest(changed)

    def test_sensitive_email_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["controls"][0]["summary"] = "Operator person@example.com performed the test."
        with self.assertRaisesRegex(ValueError, "prohibited sensitive value"):
            validate_manifest(changed)

    def test_bare_guid_shaped_identifier_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["controls"][0]["summary"] = (
            "Sanitized identifier 12345678-1234-1234-1234-123456789abc leaked."
        )
        with self.assertRaisesRegex(ValueError, "prohibited sensitive value"):
            validate_manifest(changed)

    def test_private_sources_verify_without_being_added_to_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            private_root = Path(temp)
            changed = copy.deepcopy(self.manifest)
            contents: dict[str, bytes] = {}
            for control in changed["controls"]:
                name = control["source_file"]
                contents.setdefault(name, f"private evidence for {name}\n".encode("ascii"))
                control["source_sha256"] = hashlib.sha256(contents[name]).hexdigest()
            for name, content in contents.items():
                (private_root / name).write_bytes(content)
            verified = verify_private_sources(changed, private_root)
            self.assertEqual(set(verified), set(contents))

    def test_private_source_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            private_root = Path(temp)
            for control in self.manifest["controls"]:
                (private_root / control["source_file"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verify_private_sources(self.manifest, private_root)

    def test_private_root_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            private_root = base / "private"
            private_root.mkdir()
            alias = base / "private-link"
            try:
                alias.symlink_to(private_root, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("directory symlinks are unavailable on this host")
            with self.assertRaisesRegex(ValueError, "private historical evidence root is invalid"):
                verify_private_sources(self.manifest, alias)


if __name__ == "__main__":
    unittest.main()

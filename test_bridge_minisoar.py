import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.bridge_minisoar import run_minisoar_bridge
from state_store import SQLiteStateStore


def write_bundle(
    root: Path,
    *,
    status="closed",
    passed=True,
    kind="brute_force",
    environment="synthetic-lab",
    severity="high",
    executor_id="worker-01",
    verifier_id="verifier-01",
):
    identity_fields = {
        "source": "logwatcher",
        "source_event_id": "EVT-4625-DEMO-001",
        "kind": kind,
        "asset_id": "WIN-DC01",
        "account": "alice",
        "source_ip": "203.0.113.45",
    }
    identity_hash = hashlib.sha256(
        json.dumps(
            identity_fields,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    alert_id = "ALT-" + identity_hash[:16].upper()
    finding_id = "FND-" + identity_hash[:16].upper()
    (root / "finding.json").write_text(json.dumps({
        "finding_id": finding_id,
        "alert_id": alert_id,
        "title": "Five failed logons within five minutes",
        "risk_owner": "asset-owner-01",
        "severity": severity,
        "status": status,
        "playbook_id": "PB-BF-001",
        "playbook_version": 1,
        "executor_id": executor_id,
        "created_at": "2026-07-22T10:57:44Z",
        "updated_at": "2026-07-22T10:58:00Z",
    }), encoding="utf-8")
    alert = {
        **identity_fields,
        "alert_id": alert_id,
        "identity_hash": identity_hash,
        "severity": severity,
        "risk_owner": "asset-owner-01",
        "environment": environment,
        "detected_at": "2026-07-22T10:00:00Z",
        "message": "Five failed logons within five minutes",
        "evidence_ref": "sample://logwatcher/alerts/001",
    }
    alert["payload_hash"] = hashlib.sha256(
        json.dumps(alert, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    (root / "alert.json").write_text(json.dumps(alert), encoding="utf-8")
    (root / "verification.json").write_text(json.dumps({
        "finding_id": finding_id,
        "passed": passed,
        "notes": "simulated post-conditions",
        "verifier_id": verifier_id,
        "verification_id": "VER-0000000000000001",
        "verified_at": "2026-07-22T10:59:00Z",
    }), encoding="utf-8")


class MiniSoarBridgeTests(unittest.TestCase):
    def test_evidence_path_failure_returns_structured_error_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            runtime = parent / "runtime"
            outside = parent / "outside"
            runtime.mkdir()
            outside.mkdir()
            result = run_minisoar_bridge(
                str(outside),
                str(runtime / "governance.db"),
                runtime_root=runtime,
            )

        self.assertEqual(result["errors"], 1)
        self.assertFalse(result["bundle_read"])
        self.assertFalse(result["finding_created"])
        self.assertIsNone(result["sentinel_finding_id"])

    def test_invalid_governance_database_returns_structured_error(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            evidence = runtime / "evidence"
            evidence.mkdir()
            write_bundle(evidence)
            result = run_minisoar_bridge(
                str(evidence),
                str(runtime / "governance.notadb"),
                runtime_root=runtime,
            )

        self.assertEqual(result["errors"], 1)
        self.assertTrue(result["bundle_read"])
        self.assertFalse(result["finding_created"])
        self.assertIsNone(result["sentinel_finding_id"])

    def test_invalid_audit_path_is_rejected_before_finding_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            runtime = parent / "runtime"
            evidence = runtime / "evidence"
            evidence.mkdir(parents=True)
            write_bundle(evidence)
            database = runtime / "governance.db"
            result = run_minisoar_bridge(
                str(evidence),
                str(database),
                audit_log_path=str(parent / "outside-audit.jsonl"),
                runtime_root=runtime,
            )

            self.assertFalse(database.exists())
        self.assertEqual(result["errors"], 1)
        self.assertTrue(result["bundle_read"])
        self.assertFalse(result["finding_created"])
        self.assertIsNone(result["sentinel_finding_id"])

    def test_storage_construction_failure_returns_structured_error(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            evidence = runtime / "evidence"
            evidence.mkdir()
            write_bundle(evidence)
            with mock.patch(
                "scripts.bridge_minisoar.SQLiteStateStore",
                side_effect=OSError("storage unavailable"),
            ):
                result = run_minisoar_bridge(
                    str(evidence),
                    str(runtime / "governance.db"),
                    runtime_root=runtime,
                )

        self.assertEqual(result["errors"], 1)
        self.assertFalse(result["finding_created"])
        self.assertIsNone(result["sentinel_finding_id"])
        self.assertIn("governance storage failed", result["skipped_reason"])

    def test_storage_upsert_failure_returns_structured_error(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            evidence = runtime / "evidence"
            evidence.mkdir()
            write_bundle(evidence)
            store = mock.Mock()
            store.record_external_finding_import.side_effect = sqlite3.OperationalError(
                "database is locked"
            )
            with mock.patch(
                "scripts.bridge_minisoar.SQLiteStateStore",
                return_value=store,
            ):
                result = run_minisoar_bridge(
                    str(evidence),
                    str(runtime / "governance.db"),
                    runtime_root=runtime,
                )

        self.assertEqual(result["errors"], 1)
        self.assertFalse(result["finding_created"])
        self.assertIsNone(result["sentinel_finding_id"])
        self.assertIn("governance storage failed", result["skipped_reason"])

    def test_audit_write_failure_preserves_persisted_finding_visibility(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            evidence = runtime / "evidence"
            evidence.mkdir()
            write_bundle(evidence)
            database = runtime / "governance.db"
            with mock.patch(
                "scripts.bridge_minisoar.AuditLog.append_idempotent",
                side_effect=OSError("disk full"),
            ):
                result = run_minisoar_bridge(
                    str(evidence),
                    str(database),
                    runtime_root=runtime,
                )

            persisted = SQLiteStateStore(database).get_external_finding(
                result["sentinel_finding_id"]
            )
        self.assertEqual(result["errors"], 1)
        self.assertTrue(result["finding_created"])
        self.assertIsNotNone(result["sentinel_finding_id"])
        self.assertIsNotNone(persisted)
        self.assertIn("was persisted but audit delivery failed", result["skipped_reason"])

    def test_retry_after_audit_failure_repairs_creation_without_reassessment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root)
            database = root / "governance.db"
            with mock.patch(
                "scripts.bridge_minisoar.AuditLog.append_idempotent",
                side_effect=OSError("disk full"),
            ):
                failed = run_minisoar_bridge(str(root), str(database))

            retried = run_minisoar_bridge(str(root), str(database))
            stored = SQLiteStateStore(database).get_external_finding(
                failed["sentinel_finding_id"]
            )
            audit_records = [
                json.loads(line)
                for line in database.with_suffix(".audit.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]

        self.assertEqual(failed["errors"], 1)
        self.assertTrue(failed["finding_created"])
        self.assertEqual(retried["errors"], 0)
        self.assertTrue(retried["finding_replayed"])
        self.assertEqual(stored["reassessment_count"], 0)
        self.assertEqual(len(audit_records), 1)
        self.assertEqual(
            audit_records[0]["event_type"], "bridge.minisoar.finding.created"
        )

    def test_retry_after_audit_append_before_ack_does_not_duplicate_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root)
            database = root / "governance.db"
            with mock.patch.object(
                SQLiteStateStore,
                "mark_external_finding_audit_delivered",
                side_effect=OSError("acknowledgement unavailable"),
            ):
                failed = run_minisoar_bridge(str(root), str(database))

            retried = run_minisoar_bridge(str(root), str(database))
            stored = SQLiteStateStore(database).get_external_finding(
                failed["sentinel_finding_id"]
            )
            audit_records = [
                json.loads(line)
                for line in database.with_suffix(".audit.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]

        self.assertEqual(failed["errors"], 1)
        self.assertTrue(retried["finding_replayed"])
        self.assertEqual(stored["reassessment_count"], 0)
        self.assertEqual(len(audit_records), 1)

    def test_cross_drive_root_inference_returns_structured_error(self):
        with (
            mock.patch(
                "scripts.bridge_minisoar.os.path.commonpath",
                side_effect=ValueError("Paths don't have the same drive"),
            ),
            mock.patch(
                "scripts.bridge_minisoar.resolve_directory_under_root",
                side_effect=AssertionError("no side effect should begin"),
            ),
        ):
            result = run_minisoar_bridge(r"C:\evidence", r"D:\governance.db")

        self.assertEqual(result["errors"], 1)
        self.assertEqual(
            result["skipped_reason"],
            "bridge paths must share a common runtime root",
        )
        self.assertFalse(result["bundle_read"])
        self.assertFalse(result["finding_created"])
        self.assertFalse(result["finding_reassessed"])
        self.assertFalse(result["finding_replayed"])
        self.assertIsNone(result["sentinel_finding_id"])

    def test_closed_and_verified_incident_creates_governance_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root)
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))
            self.assertTrue(result["bundle_read"])
            self.assertTrue(result["finding_created"])
            self.assertEqual(result["errors"], 0)
            self.assertTrue(result["sentinel_finding_id"].startswith("SEC-IR-"))

    def test_exact_replay_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root)
            db = str(root / "governance.db")
            first = run_minisoar_bridge(str(root), db)
            replay = run_minisoar_bridge(str(root), db)
            self.assertTrue(first["finding_created"])
            self.assertTrue(replay["finding_replayed"])
            self.assertFalse(replay["finding_reassessed"])
            self.assertEqual(first["sentinel_finding_id"], replay["sentinel_finding_id"])
            stored = SQLiteStateStore(db).get_external_finding(first["sentinel_finding_id"])
            self.assertEqual(stored["reassessment_count"], 0)

    def test_changed_evidence_reassesses_once_then_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, severity="high")
            db = str(root / "governance.db")
            created = run_minisoar_bridge(str(root), db)

            write_bundle(root, severity="critical")
            reassessed = run_minisoar_bridge(str(root), db)
            replayed = run_minisoar_bridge(str(root), db)
            stored = SQLiteStateStore(db).get_external_finding(
                created["sentinel_finding_id"]
            )
            audit_records = [
                json.loads(line)
                for line in (root / "governance.audit.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]

        self.assertTrue(created["finding_created"])
        self.assertTrue(reassessed["finding_reassessed"])
        self.assertTrue(replayed["finding_replayed"])
        self.assertEqual(stored["severity"], "critical")
        self.assertEqual(stored["reassessment_count"], 1)
        self.assertEqual(
            [record["event_type"] for record in audit_records],
            [
                "bridge.minisoar.finding.created",
                "bridge.minisoar.finding.reassessed",
            ],
        )

    def test_unverified_incident_is_skipped_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, passed=False)
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))
            self.assertTrue(result["bundle_read"])
            self.assertFalse(result["finding_created"])
            self.assertIn("verified", result["skipped_reason"])

    def test_executor_cannot_supply_independent_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, executor_id="same-actor", verifier_id="same-actor")
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))

        self.assertFalse(result["finding_created"])
        self.assertEqual(result["errors"], 0)
        self.assertIn("verified", result["skipped_reason"])

    def test_cross_record_identity_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root)
            finding_path = root / "finding.json"
            finding = json.loads(finding_path.read_text(encoding="utf-8"))
            finding["alert_id"] = "ALT-0000000000000000"
            finding_path.write_text(json.dumps(finding), encoding="utf-8")
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))

        self.assertEqual(result["errors"], 1)
        self.assertFalse(result["finding_created"])
        self.assertIn("does not belong", result["skipped_reason"])

    def test_unsupported_alert_kind_is_rejected_instead_of_fallback_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, kind="unknown_kind")
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))

        self.assertEqual(result["errors"], 1)
        self.assertFalse(result["finding_created"])
        self.assertIn("unsupported", result["skipped_reason"])

    def test_unverified_incident_can_be_explicitly_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, passed=False)
            result = run_minisoar_bridge(
                str(root), str(root / "governance.db"), require_verification_pass=False,
            )
            self.assertTrue(result["finding_created"])

    def test_open_incident_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, status="pending_verification")
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))
            self.assertFalse(result["finding_created"])
            self.assertEqual(result["errors"], 0)

    def test_non_synthetic_incident_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(root, environment="production")
            result = run_minisoar_bridge(str(root), str(root / "governance.db"))
            self.assertFalse(result["finding_created"])
            self.assertEqual(result["errors"], 0)

    def test_missing_bundle_is_reported_without_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_minisoar_bridge(str(root / "missing"), str(root / "governance.db"))
            self.assertFalse(result["bundle_read"])
            self.assertEqual(result["errors"], 1)


if __name__ == "__main__":
    unittest.main()

import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from live_gate_harness import (
    AzureServiceBusGateReceiver,
    DLQ_DESCRIPTION,
    DLQ_REASON,
    ExpectedServiceBusMessage,
    LiveGateError,
    PostgresRestoreVerifier,
    REQUIRED_POSTGRES_TABLES,
    SYNTHETIC_TABLE_KEYS,
    verify_restore_snapshot,
    verify_service_bus_message,
)


MESSAGE_ID = "a" * 32
SESSION_ID = "LIVE-GATE-FINDING-001"


class FakeMessage:
    def __init__(self):
        payload = {
            "event_id": "event-001",
            "event_sequence": 1,
            "finding_id": SESSION_ID,
        }
        self.body_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.body = [self.body_bytes]
        self.message_id = MESSAGE_ID
        self.session_id = SESSION_ID
        self.subject = "governance.event.v1"
        self.content_type = "application/json"
        self.correlation_id = "event-001"
        self.delivery_count = 1
        self.enqueued_time_utc = datetime(2026, 9, 1, tzinfo=timezone.utc)
        self.dead_letter_reason = None
        self.dead_letter_error_description = None
        self.application_properties = {
            b"event_sequence": 1,
            b"payload_sha256": hashlib.sha256(self.body_bytes).hexdigest().encode(
                "ascii"
            ),
        }


class FakeReceiver:
    def __init__(self, message):
        self.message = message
        self.actions = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def receive_messages(self, **kwargs):
        self.receive_kwargs = kwargs
        return [self.message]

    def complete_message(self, message):
        self.actions.append(("complete", message))

    def abandon_message(self, message):
        self.actions.append(("abandon", message))

    def dead_letter_message(self, message, **kwargs):
        self.actions.append(("dead-letter", message, kwargs))


class FakeClient:
    def __init__(self, receiver, captured, **kwargs):
        self.receiver = receiver
        self.captured = captured
        self.captured["client"] = kwargs

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get_queue_receiver(self, **kwargs):
        self.captured["receiver"] = kwargs
        return self.receiver


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class FakePostgresConnection:
    def __init__(
        self,
        migration_id,
        migration_checksum,
        *,
        database_name="sentinel",
        database_oid=16384,
        server_address="10.0.2.4",
        server_port=5432,
        isolation_level="repeatable read",
        read_only="on",
    ):
        self.migration_id = migration_id
        self.migration_checksum = migration_checksum
        self.database_name = database_name
        self.database_oid = database_oid
        self.server_address = server_address
        self.server_port = server_port
        self.isolation_level = isolation_level
        self.read_only = read_only
        self.closed = False
        self.rolled_back = False
        self.executed_sql = []

    def execute(self, sql, parameters=()):
        self.executed_sql.append(sql)
        if sql == "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY":
            return FakeCursor([])
        if "current_setting('transaction_isolation')" in sql:
            return FakeCursor(
                [
                    {
                        "isolation_level": self.isolation_level,
                        "read_only": self.read_only,
                    }
                ]
            )
        if "current_database() AS database_name" in sql:
            return FakeCursor(
                [
                    {
                        "database_name": self.database_name,
                        "database_oid": self.database_oid,
                        "server_address": self.server_address,
                        "server_port": self.server_port,
                    }
                ]
            )
        if "FROM schema_migrations" in sql:
            return FakeCursor(
                [
                    {
                        "migration_id": self.migration_id,
                        "checksum": self.migration_checksum,
                    }
                ]
            )
        if "FROM information_schema.tables" in sql:
            return FakeCursor(
                [{"table_name": name} for name in sorted(REQUIRED_POSTGRES_TABLES)]
            )
        if "WHERE finding_id = ?" in sql:
            return FakeCursor(
                [
                    {
                        "finding_id": parameters[0],
                        "status": "closed",
                        "updated_at": 123.0,
                    }
                ]
            )
        if "WHERE left(" in sql:
            self.asserted_prefix_parameters = parameters
            return FakeCursor([])
        raise AssertionError(sql)

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class FakePostgresDatabase:
    dialect = "postgresql"

    def __init__(
        self,
        host,
        migration_id,
        migration_checksum,
        *,
        database_name="sentinel",
        **connection_kwargs,
    ):
        self.database_url = (
            f"postgresql://user:secret@{host}:5432/{database_name}"
        )
        self.connection = FakePostgresConnection(
            migration_id,
            migration_checksum,
            database_name=database_name,
            **connection_kwargs,
        )

    def connect(self):
        return self.connection


class LiveGateHarnessTests(unittest.TestCase):
    def expected(self, message):
        return ExpectedServiceBusMessage(
            MESSAGE_ID,
            SESSION_ID,
            hashlib.sha256(message.body_bytes).hexdigest(),
        )

    def verifier(self, database, migrations_dir, resource_suffix="source"):
        return PostgresRestoreVerifier(
            database,
            migrations_dir,
            expected_target_resource_id=(
                "/subscriptions/00000000-0000-4000-8000-000000000001/"
                "resourceGroups/staging/providers/"
                "Microsoft.DBforPostgreSQL/flexibleServers/"
                f"{resource_suffix}"
            ),
            expected_hostname=(
                database.database_url.split("@", 1)[1].split(":", 1)[0]
            ),
            evidence_hmac_key="harness-test-hmac-key-32-bytes!!",
        )

    def test_service_bus_message_is_bound_to_exact_canonical_contract(self):
        message = FakeMessage()
        observation = verify_service_bus_message(message, self.expected(message))
        self.assertEqual(observation["message_id"], MESSAGE_ID)
        self.assertEqual(observation["session_id"], SESSION_ID)
        self.assertEqual(observation["event_sequence"], 1)
        self.assertNotIn("body", observation)

        mutations = (
            ("message_id", "b" * 32),
            ("session_id", "OTHER-SESSION"),
            ("subject", "other.topic"),
            ("content_type", "text/plain"),
            ("correlation_id", "wrong-event"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                changed = FakeMessage()
                setattr(changed, field, value)
                expected = self.expected(changed)
                with self.assertRaises(LiveGateError):
                    verify_service_bus_message(changed, expected)

        extra_property = FakeMessage()
        extra_property.application_properties[b"unexpected"] = b"value"
        expected = self.expected(extra_property)
        with self.assertRaisesRegex(LiveGateError, "properties do not match"):
            verify_service_bus_message(extra_property, expected)

        boolean_sequence = FakeMessage()
        boolean_sequence.application_properties[b"event_sequence"] = True
        expected = self.expected(boolean_sequence)
        with self.assertRaisesRegex(LiveGateError, "sequence is invalid"):
            verify_service_bus_message(boolean_sequence, expected)

    def test_receiver_settles_only_verified_message_and_is_session_bound(self):
        message = FakeMessage()
        fake_receiver = FakeReceiver(message)
        captured = {}
        receiver = AzureServiceBusGateReceiver(
            "sentinel-live.servicebus.windows.net",
            "governance-outbox",
            managed_identity_client_id="receiver-identity",
            timeout_seconds=7,
            client_factory=lambda **kwargs: FakeClient(
                fake_receiver, captured, **kwargs
            ),
            dead_letter_sub_queue="dead-letter",
        )
        result = receiver.receive_one(self.expected(message), action="complete")
        self.assertEqual(result["settlement"], "complete")
        self.assertEqual(fake_receiver.actions[0][0], "complete")
        self.assertEqual(captured["receiver"]["session_id"], SESSION_ID)
        self.assertNotIn("sub_queue", captured["receiver"])
        self.assertEqual(captured["client"]["retry_total"], 2)

    def test_receiver_abandons_mismatch_and_dead_letters_only_active_message(self):
        message = FakeMessage()
        message.application_properties[b"payload_sha256"] = b"0" * 64
        fake_receiver = FakeReceiver(message)
        receiver = AzureServiceBusGateReceiver(
            "sentinel-live.servicebus.windows.net",
            "governance-outbox",
            managed_identity_client_id="receiver-identity",
            client_factory=lambda **kwargs: FakeClient(fake_receiver, {}, **kwargs),
            dead_letter_sub_queue="dead-letter",
        )
        expected = self.expected(message)
        with self.assertRaises(LiveGateError):
            receiver.receive_one(expected, action="complete")
        self.assertEqual(fake_receiver.actions[0][0], "abandon")

        valid = FakeMessage()
        dlq_receiver = FakeReceiver(valid)
        receiver = AzureServiceBusGateReceiver(
            "sentinel-live.servicebus.windows.net",
            "governance-outbox",
            managed_identity_client_id="receiver-identity",
            client_factory=lambda **kwargs: FakeClient(dlq_receiver, {}, **kwargs),
            dead_letter_sub_queue="dead-letter",
        )
        result = receiver.receive_one(self.expected(valid), action="dead-letter")
        self.assertEqual(result["settlement"], "dead-letter")
        self.assertEqual(dlq_receiver.actions[0][0], "dead-letter")
        expected = self.expected(valid)
        with self.assertRaises(ValueError):
            receiver.receive_one(
                expected, action="dead-letter", from_dead_letter=True
            )

        dlq_message = FakeMessage()
        dlq_message.dead_letter_reason = DLQ_REASON
        dlq_message.dead_letter_error_description = DLQ_DESCRIPTION
        dlq_receiver = FakeReceiver(dlq_message)
        receiver = AzureServiceBusGateReceiver(
            "sentinel-live.servicebus.windows.net",
            "governance-outbox",
            managed_identity_client_id="receiver-identity",
            client_factory=lambda **kwargs: FakeClient(dlq_receiver, {}, **kwargs),
            dead_letter_sub_queue="dead-letter",
        )
        result = receiver.receive_one(
            self.expected(dlq_message), action="complete", from_dead_letter=True
        )
        self.assertEqual(result["source"], "dead-letter")
        self.assertEqual(
            result["dead_letter_reason"], "SentinelGRCSyntheticGateFailure"
        )
        self.assertEqual(len(result["dead_letter_description_sha256"]), 64)
        self.assertNotIn("dead_letter_error_description", result)

        for invalid_description in (
            DLQ_DESCRIPTION + " ",
            DLQ_DESCRIPTION.lower(),
            DLQ_DESCRIPTION[:-1],
            None,
            1,
        ):
            with self.subTest(invalid_description=invalid_description):
                changed = FakeMessage()
                changed.dead_letter_reason = DLQ_REASON
                changed.dead_letter_error_description = invalid_description
                changed_receiver = FakeReceiver(changed)
                gate = AzureServiceBusGateReceiver(
                    "sentinel-live.servicebus.windows.net",
                    "governance-outbox",
                    managed_identity_client_id="receiver-identity",
                    client_factory=lambda **kwargs: FakeClient(
                        changed_receiver, {}, **kwargs
                    ),
                    dead_letter_sub_queue="dead-letter",
                )
                expected = self.expected(changed)
                with self.assertRaisesRegex(LiveGateError, "contract"):
                    gate.receive_one(
                        expected,
                        action="complete",
                        from_dead_letter=True,
                    )
                self.assertEqual(
                    [action[0] for action in changed_receiver.actions],
                    ["abandon"],
                )

    def test_postgres_snapshot_binds_migrations_schema_and_application_read(self):
        with tempfile.TemporaryDirectory() as temp:
            migration = Path(temp) / "001_probe.sql"
            migration.write_text("CREATE TABLE probe(id text);\n", encoding="utf-8")
            checksum = hashlib.sha256(
                migration.read_text(encoding="utf-8").encode("utf-8")
            ).hexdigest()
            database = FakePostgresDatabase(
                "source.private.postgres.database.azure.com",
                "001_probe",
                checksum,
            )
            snapshot = self.verifier(database, Path(temp)).snapshot(
                "LIVE-GATE", "LIVE-GATE-FINDING-001"
            )
        self.assertEqual(snapshot["migration_checksums"], {"001_probe": checksum})
        self.assertEqual(
            snapshot["required_table_count"], len(REQUIRED_POSTGRES_TABLES)
        )
        self.assertEqual(
            snapshot["synthetic_tables"]["findings"]["count"], 0
        )
        self.assertEqual(len(snapshot["application_read_sha256"]), 64)
        self.assertEqual(len(snapshot["target_identity_hmac_sha256"]), 64)
        self.assertNotIn("database_url", snapshot)
        self.assertTrue(database.connection.rolled_back)
        self.assertTrue(database.connection.closed)
        self.assertEqual(
            database.connection.asserted_prefix_parameters,
            ("LIVE-GATE", "LIVE-GATE"),
        )
        self.assertEqual(
            database.connection.executed_sql[0],
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
        )
        self.assertIn(
            "current_setting('transaction_isolation')",
            database.connection.executed_sql[1],
        )
        self.assertIn(
            "current_database() AS database_name",
            database.connection.executed_sql[2],
        )

    def test_postgres_snapshot_fails_closed_on_transaction_or_target_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            migration = Path(temp) / "001_probe.sql"
            migration.write_text("CREATE TABLE probe(id text);\n", encoding="utf-8")
            checksum = hashlib.sha256(
                migration.read_text(encoding="utf-8").encode("utf-8")
            ).hexdigest()
            wrong_isolation = FakePostgresDatabase(
                "source.private.postgres.database.azure.com",
                "001_probe",
                checksum,
                isolation_level="read committed",
            )
            verifier = self.verifier(wrong_isolation, Path(temp))
            with self.assertRaisesRegex(LiveGateError, "read-only"):
                verifier.snapshot("LIVE-GATE", "LIVE-GATE-FINDING-001")
            self.assertTrue(wrong_isolation.connection.rolled_back)
            self.assertTrue(wrong_isolation.connection.closed)

            database = FakePostgresDatabase(
                "source.private.postgres.database.azure.com",
                "001_probe",
                checksum,
            )
            migrations_dir = Path(temp)
            with self.assertRaisesRegex(ValueError, "expected target"):
                PostgresRestoreVerifier(
                    database,
                    migrations_dir,
                    expected_target_resource_id=(
                        "/subscriptions/00000000-0000-4000-8000-000000000001/"
                        "resourceGroups/staging/providers/"
                        "Microsoft.DBforPostgreSQL/flexibleServers/source"
                    ),
                    expected_hostname="alias.private.postgres.database.azure.com",
                    evidence_hmac_key="harness-test-hmac-key-32-bytes!!",
                )

    def test_target_hmac_distinguishes_database_and_resource_without_disclosure(self):
        with tempfile.TemporaryDirectory() as temp:
            migration = Path(temp) / "001_probe.sql"
            migration.write_text("CREATE TABLE probe(id text);\n", encoding="utf-8")
            checksum = hashlib.sha256(
                migration.read_text(encoding="utf-8").encode("utf-8")
            ).hexdigest()
            first = FakePostgresDatabase(
                "shared.private.postgres.database.azure.com",
                "001_probe",
                checksum,
                database_name="source_db",
                database_oid=16384,
            )
            second = FakePostgresDatabase(
                "shared.private.postgres.database.azure.com",
                "001_probe",
                checksum,
                database_name="restored_db",
                database_oid=16385,
            )
            first_snapshot = self.verifier(
                first, Path(temp), "source"
            ).snapshot("LIVE-GATE", "LIVE-GATE-FINDING-001")
            second_snapshot = self.verifier(
                second, Path(temp), "restored"
            ).snapshot("LIVE-GATE", "LIVE-GATE-FINDING-001")
        self.assertNotEqual(
            first_snapshot["target_identity_hmac_sha256"],
            second_snapshot["target_identity_hmac_sha256"],
        )
        serialized = json.dumps([first_snapshot, second_snapshot])
        self.assertNotIn("shared.private", serialized)
        self.assertNotIn("source_db", serialized)
        self.assertNotIn("restored_db", serialized)

    def test_restore_comparison_requires_isolated_identical_snapshot(self):
        source = {
            "schema_version": "sentinel.live_gate.postgres_restore.v2",
            "observed_at": "2026-09-01T00:00:00.000Z",
            "target_identity_hmac_sha256": "a" * 64,
            "migration_checksums": {"001": "b" * 64},
            "required_table_count": 17,
            "synthetic_prefix": "LIVE-GATE",
            "synthetic_tables": {
                table: {"count": 1 if table == "findings" else 0, "sha256": "c" * 64}
                for table in SYNTHETIC_TABLE_KEYS
            },
            "application_read_sha256": "d" * 64,
        }
        restored = copy.deepcopy(source)
        restored["observed_at"] = "2026-09-01T00:10:00.000Z"
        restored["target_identity_hmac_sha256"] = "e" * 64
        result = verify_restore_snapshot(source, restored)
        self.assertEqual(result["verdict"], "PASS")

        same_target = copy.deepcopy(restored)
        same_target["target_identity_hmac_sha256"] = source[
            "target_identity_hmac_sha256"
        ]
        with self.assertRaisesRegex(LiveGateError, "not isolated"):
            verify_restore_snapshot(source, same_target)
        mismatched = copy.deepcopy(restored)
        mismatched["synthetic_tables"]["findings"]["count"] = 0
        with self.assertRaisesRegex(LiveGateError, "synthetic_tables"):
            verify_restore_snapshot(source, mismatched)


if __name__ == "__main__":
    unittest.main()

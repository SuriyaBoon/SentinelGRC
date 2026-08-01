import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from governance_core import ActorContext, GovernanceCore
from human_identity import HumanIdentityStore
from migration_runner import PostgresMigrationRunner
from persistence import Database
from production_contract import Settings
from runtime_app import SentinelRuntime


POSTGRES_URL = os.getenv("SENTINEL_TEST_POSTGRES_URL", "")


@unittest.skipUnless(
    POSTGRES_URL, "SENTINEL_TEST_POSTGRES_URL is required"
)
class PostgresIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.database = Database(
            POSTGRES_URL, pool_min_size=1, pool_max_size=12
        )
        self.migrations = PostgresMigrationRunner(
            self.database,
            str(Path(__file__).parent / "migrations" / "postgresql"),
        )
        self.migrations.apply()
        with closing(self.database.connect()) as db:
            db.execute(
                """
                TRUNCATE TABLE
                    audit_exports, governance_outbox, pipeline_jobs, connector_events,
                    user_api_keys, users, closure_records,
                    verification_records, governance_evidence, action_items,
                    approval_records, risk_treatments, risk_records,
                    governance_events, findings
                CASCADE
                """
            )
            db.commit()
        self.core = GovernanceCore(database=self.database)
        self.identities = HumanIdentityStore(database=self.database)
        self.analyst = ActorContext("analyst-1", "analyst")
        self.owner = ActorContext("owner-1", "risk_owner")
        self.approver = ActorContext("approver-1", "approver")

    def tearDown(self):
        self.database.close()

    def test_migrations_are_checksum_protected_and_idempotent(self):
        self.assertEqual(self.migrations.apply(), [])
        status = self.migrations.status()
        self.assertEqual(
            [row["migration_id"] for row in status],
            [
                "001_canonical_governance",
                "002_runtime_delivery",
                "003_evidence_objects",
                "004_immutable_audit_exports",
                "005_service_bus_outbox",
            ],
        )
        self.assertEqual(len(status[0]["checksum"]), 64)
        GovernanceCore(database=self.database).create_finding(
            "PG-AUDIT-BACKFILL",
            "CTRL-AUDIT",
            "ASSET-AUDIT",
            "Backfill existing event",
            "owner-audit",
            "high",
            self.analyst,
        )
        with closing(self.database.connect()) as db:
            db.execute("DROP TABLE audit_exports")
            db.execute(
                "DELETE FROM schema_migrations "
                "WHERE migration_id = '004_immutable_audit_exports'"
            )
            db.commit()
        self.assertEqual(
            self.migrations.apply(),
            ["004_immutable_audit_exports"],
        )
        with closing(self.database.connect()) as db:
            count = db.execute(
                "SELECT COUNT(*) AS count FROM audit_exports "
                "WHERE event_id IN (SELECT event_id FROM governance_events "
                "WHERE finding_id = 'PG-AUDIT-BACKFILL')"
            ).fetchone()["count"]
            db.rollback()
        self.assertEqual(count, 1)
        with tempfile.TemporaryDirectory() as temp:
            changed = Path(temp) / "001_canonical_governance.sql"
            changed.write_text("SELECT 1;\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "migration checksum mismatch"
            ):
                PostgresMigrationRunner(
                    self.database, temp
                ).apply()

    def test_staging_runtime_composes_postgres_without_sqlite_fallback(self):
        class ReadyVerifier:
            def ready(self):
                return True

        class ReadyEvidenceStore:
            def ready(self):
                return True

            def persist(self, content):
                raise AssertionError("not used by runtime composition test")

        class ReadyAuditArchive:
            def ready(self):
                return True

            def persist_event(self, event):
                raise AssertionError("not used by runtime composition test")

        with tempfile.TemporaryDirectory() as temp:
            settings = Settings(
                environment="staging",
                database_url=POSTGRES_URL,
                identity_database_url=POSTGRES_URL,
                evidence_dir=temp,
                oidc_issuer="https://login.microsoftonline.com/tenant/v2.0",
                oidc_audience="api://sentinel",
                oidc_tenant_id="00000000-0000-0000-0000-000000000001",
                oidc_jwks_url="https://login.microsoftonline.com/tenant/keys",
                evidence_store_url="https://account.blob.core.windows.net/evidence",
                audit_archive_url=(
                    "https://account.blob.core.windows.net/audit-archive"
                ),
                azure_managed_identity_client_id=(
                    "00000000-0000-0000-0000-000000000002"
                ),
                service_bus_namespace=(
                    "sentinel-staging.servicebus.windows.net"
                ),
                service_bus_queue="governance-outbox",
            )
            runtime = SentinelRuntime(
                settings,
                ReadyVerifier(),
                ReadyEvidenceStore(),
                ReadyAuditArchive(),
            )
            try:
                self.assertEqual(
                    runtime.governance_database.dialect, "postgresql"
                )
                self.assertIs(
                    runtime.governance_database,
                    runtime.identity_database,
                )
                self.assertEqual(runtime.readiness()["status"], "not_ready")
                runtime.outbox_queue.heartbeat("staging-worker")
                self.assertEqual(runtime.readiness()["status"], "ready")
            finally:
                runtime.governance_database.close()

    def test_identity_and_full_governance_lifecycle_persist(self):
        self.identities.create_user("analyst-1", "analyst")
        secret = self.identities.issue_api_key("analyst-1", "key-1")
        actor = self.identities.authenticate("key-1", secret)
        self.assertEqual(actor.actor_id, "analyst-1")
        self.assertEqual(actor.auth_method, "api_key")

        finding_id = "PG-LIFECYCLE-1"
        self.core.create_finding(
            finding_id,
            "CTRL-1",
            "ASSET-1",
            "PostgreSQL lifecycle",
            self.owner.actor_id,
            "high",
            actor,
        )
        self.core.assess_risk(finding_id, self.owner, "high", "high")
        self.core.propose_treatment(
            finding_id,
            self.owner,
            "mitigate",
            "Apply the control",
            "team-1",
            "2027-01-01",
        )
        self.core.approve_treatment(
            finding_id, self.approver, "approved", "authorised"
        )
        self.core.start_action(finding_id, self.owner, "engineer-1")
        self.core.submit_evidence(
            finding_id, self.owner, "change-record", b"verified change"
        )
        self.core.verify(
            finding_id,
            ActorContext("verifier-1", "analyst"),
            True,
            "control restored",
        )
        result = self.core.close(
            finding_id, self.approver, "independently verified"
        )
        self.assertEqual(result["status"], "closed")
        self.assertTrue(self.core.verify_event_chain(finding_id))
        self.assertEqual(len(self.core.list_events(finding_id)), 8)

    def test_failed_mutation_rolls_back_state_and_event(self):
        finding_id = "PG-ROLLBACK-1"
        self.core.create_finding(
            finding_id,
            "CTRL-2",
            "ASSET-2",
            "Rollback proof",
            self.owner.actor_id,
            "medium",
            self.analyst,
        )
        with patch.object(
            self.core, "_event", side_effect=RuntimeError("forced failure")
        ):
            with self.assertRaisesRegex(RuntimeError, "forced failure"):
                self.core.assess_risk(
                    finding_id, self.owner, "medium", "medium"
                )
        self.assertEqual(self.core.get_finding(finding_id)["status"], "open")
        self.assertEqual(len(self.core.list_events(finding_id)), 1)
        with closing(self.database.connect()) as db:
            count = db.execute(
                "SELECT COUNT(*) AS count FROM risk_records "
                "WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()["count"]
            db.rollback()
        self.assertEqual(count, 0)

    def test_concurrent_reassessment_is_idempotent_and_chain_is_ordered(self):
        finding_id = "PG-CONCURRENT-1"

        def ingest(index):
            return self.core.upsert_finding(
                finding_id,
                "CTRL-3",
                "ASSET-3",
                f"Concurrent reassessment {index}",
                self.owner.actor_id,
                "high",
                self.analyst,
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(ingest, range(8)))

        self.assertEqual(len(results), 8)
        self.assertEqual(len(self.core.list_findings()), 1)
        events = self.core.list_events(finding_id)
        self.assertEqual(len(events), 8)
        self.assertEqual(
            [event["event_sequence"] for event in events],
            list(range(1, 9)),
        )
        self.assertTrue(self.core.verify_event_chain(finding_id))


if __name__ == "__main__":
    unittest.main()

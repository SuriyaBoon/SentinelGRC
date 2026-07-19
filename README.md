# SentinelGRC

**Continuous security governance for Windows enterprise environments.**

SentinelGRC turns endpoint security checks into an auditable governance loop:

1. Define a security control and its owner.
2. Collect endpoint posture evidence.
3. Evaluate compliance and business risk.
4. Preserve tamper-evident evidence records.
5. Produce a remediation queue and an executive-ready summary.

This is a portfolio lab aligned to governance concepts. It does not claim ISO certification or replace an organisation's ISMS.

## Phase 1–5

The platform covers endpoint control evaluation, asset-aware risk, read-only Windows posture collection, HMAC-authenticated ingestion, AD access review, and SLA-based remediation tickets.

## Phase 6: persistent state and per-agent key lifecycle

state_store.py adds SQLite-backed state for replay nonces and accepted payload hashes. The ingestion API returns the same evidence ID when the same payload is submitted again. Runtime databases and evidence are ignored by Git.

agent_keys.py stores only key metadata and lifecycle status. Secret material is returned once at registration and must be placed in a secret manager or protected environment configuration.

Register a key:

```bash
python agent_keys.py --db sentinelgrc-state.db register --agent-id WS-001 --key-id ws-001-v1
```

Start ingestion with a JSON map of active key IDs to secrets:

```powershell
$env:SENTINELGRC_AGENT_KEYS_JSON = '{"ws-001-v1":"load-this-from-a-secret-manager"}'
python ingestion_api.py serve --state-db .\runtime\sentinelgrc-state.db
```

Send from the matching agent:

```powershell
$env:SENTINELGRC_AGENT_KEY_ID = "ws-001-v1"
$env:SENTINELGRC_AGENT_SECRET = "load-this-from-a-secret-manager"
python posture_client.py .\posture.json
```

Revoke a key immediately:

```bash
python agent_keys.py --db sentinelgrc-state.db revoke --key-id ws-001-v1
```

The API rejects unknown or revoked key IDs. For multi-instance deployment, replace SQLite with a shared transactional store and put the service behind TLS/mTLS.

## Phase 7: end-to-end orchestration

`pipeline.py` connects the controls, governance, evidence, and remediation modules into one repeatable run:

```text
posture + AD review
        ↓
control evaluation + asset-aware risk
        ↓
hash-chained evidence ledger
        ↓
remediation queue + SLA tickets
        ↓
executive report
```

Run the complete pipeline:

```bash
python pipeline.py run --posture sample_posture.json --controls controls.json --assets assets.json --access-review sample_ad_access_review.json --ledger runtime/evidence-ledger.jsonl --remediation runtime/remediation-queue.json --tickets runtime/tickets.json --report runtime/executive-report.json --state-db runtime/sentinelgrc-state.db
```

The pipeline stores a run fingerprint in SQLite. Reprocessing the same posture, controls, assets, and access review returns `duplicate` and does not append another ledger record.

## Phase 7.2: automatic inbox worker

`ingestion_api.py` writes accepted posture evidence to `evidence-inbox`. Run the worker as a separate process to automatically execute the full governance pipeline:

```powershell
python pipeline_worker.py serve --inbox evidence-inbox --controls controls.json --assets assets.json --access-review sample_ad_access_review.json --ledger runtime/evidence-ledger.jsonl --state-db runtime/sentinelgrc-state.db --remediation-dir runtime/remediation --tickets-dir runtime/tickets --reports-dir runtime/reports --interval 30
```

The worker is deliberately decoupled from the HTTP API. Jobs are persisted in SQLite with a lease, retry counter, and dead-letter state. A failed job is retried up to `--max-attempts` and then remains visible as `dead` for operator review. This keeps ingestion responsive, supports retries, and allows multiple worker instances when the state store is migrated to a shared transactional database. The current worker is a polling lab implementation; production deployment should use a durable queue, service supervisor, TLS/mTLS, and centralized logging.

Expire accepted-risk exceptions as a scheduled governance job:

```bash
python governance.py expire --queue runtime/remediation/WS-001.json --output runtime/remediation/WS-001.json
```

Run this command from a scheduler after reviewing the output. Expired exceptions return to `open` and must generate a new remediation decision.


## Phase 8: authenticated governance lifecycle

`governance_core.py` provides the Phase 1 enterprise governance backbone. It keeps findings, evidence submissions, and governance events in a relational SQLite store while the existing pipeline remains the security-domain evaluator.

The lifecycle is intentionally role-gated:

```text
finding
  -> risk assessed
  -> treatment proposed
  -> authorized approval
  -> remediation action
  -> evidence submitted
  -> independent verification
  -> verified / accepted
  -> closed
```

Actors are passed as trusted `ActorContext` values from the application authentication layer. The module does not accept approval, verification, or closure identities from a finding payload. It enforces separation of duties: the risk owner cannot approve the same finding, and an implementer/evidence submitter cannot be the verifier. Each lifecycle event includes actor, role, authentication method, and a per-finding hash-chain link.

Example:

```python
from governance_core import ActorContext, GovernanceCore

core = GovernanceCore("runtime/governance.db")
owner = ActorContext("risk-owner-1", "risk_owner")
approver = ActorContext("approver-1", "approver")
verifier = ActorContext("verifier-1", "analyst")
```

This is a governance-core lab, not a production identity provider. Production still requires OIDC/SSO, MFA, short-lived tokens, PostgreSQL, a secret manager, immutable audit export, backups/restore tests, monitoring, and security assessment. The framework language is “aligned with” and “supports audit readiness”; it does not claim ISO certification.

## Enterprise baseline

- `audit_log.py` provides a separate append-only, hash-chained operational audit trail for pipeline completion events.
- `job_queue.py` provides durable queue state, leases, retries, and dead-letter visibility.
- `pipeline.py` remains the deterministic governance engine; evidence integrity and operational audit are separate controls.
- `docs/enterprise-deployment.md` defines the production boundary, required TLS/mTLS, identity, storage, retention, logging, and recovery controls.


## Enterprise domain packs

`security_pack.py` normalizes endpoint posture, AD access review, vulnerability, and network exposure observations into the shared governance finding contract.

`domain_packs.py` defines the reusable contract for the next packs:

- Privacy: data inventory, retention, processor and breach observations
- BCM: BIA, RTO/RPO, backup and recovery evidence
- ITSM: incidents, problems, changes, SLA and service availability
- Vendor: vendor scope, questionnaires, contractual controls and offboarding
- Cloud: IAM, public exposure, encryption, logging, backup and drift
- Data: classification, quality, lineage, retention and access

All packs require a stable observation identity, control, asset, title, severity and accountable owner. Closed/resolved observations are ignored, and identical observations produce the same finding ID. The packs emit data only; approval, remediation, evidence verification and closure remain centralized in `governance_core.py`.


## Executive reporting

`reporting.py` produces a sanitized KPI/KRI contract from normalized findings:

- closure rate;
- overdue findings;
- verification failures;
- critical/high open risk;
- status, severity and domain distribution.

The report contains finding IDs and aggregate metrics only. Evidence content and secret material are not copied into executive output.


## Connector boundary

`connectors.py` defines the integration boundary for SIEM, AD/Entra, cloud, ITSM, vendor and other source systems. Connector events require:

- source and stable event ID;
- HMAC signature verification before reservation;
- JSON object payload and size limit;
- persistent event reservation for replay/idempotence.

The gateway returns only `accepted` or `duplicate` and keeps payload handling separate from the governance lifecycle. Production connectors should use a managed secret/key service, TLS, rate limiting, structured observability and a shared transactional event store.

## Security boundaries

The service remains deliberately conservative:

- no automatic AD changes;
- no automatic endpoint remediation;
- no credentials or user files in posture evidence;
- loopback bind by default;
- strict payload size and schema validation;
- persistent replay protection;
- idempotent evidence ingestion;
- per-agent key ID and revocation;
- CI tests for authentication, replay, ledger integrity, idempotency, and SLA generation.

## Run tests

```bash
python -m unittest discover -v -p "test_*.py"
```

GitHub Actions validates the Python tests and parses both PowerShell agents on every push and pull request.

## Standards mapping

The catalogue illustrates how implementation evidence can be mapped to:

- ISO/IEC 27001:2022 and ISO/IEC 27002:2022
- NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover
- ISO 22301 continuity objectives (future DR-assurance module)

## Planned modules

- SIEM alert correlation from LogWatcher and SOC-Homelab
- backup/DR assurance from Backup-dr-lab
- change approval and evidence closure

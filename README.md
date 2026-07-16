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

## Phase 6: persistent state and key lifecycle

state_store.py adds SQLite-backed state for:

- replay nonces that survive process restarts;
- accepted payload hashes for idempotent evidence ingestion;
- WAL mode and transactional writes.

The ingestion API now accepts --state-db and returns the same evidence ID when the same payload is submitted again. The state database is runtime data and must not be committed to Git.

agent_keys.py manages key metadata and generates a secret once during registration. Secret material is deliberately not stored in SQLite; place it in a secret manager or protected environment configuration. Keys can be revoked by key ID.

```bash
python agent_keys.py --db sentinelgrc-state.db register --agent-id WS-001
python agent_keys.py --db sentinelgrc-state.db revoke --key-id <key-id>
```

Run the ingestion service with persistent state:

```powershell
$env:SENTINELGRC_INGESTION_SECRET = "load-from-a-secret-manager"
python ingestion_api.py serve --state-db .\runtime\sentinelgrc-state.db
```

For a multi-instance deployment, replace SQLite nonce state with a shared transactional store such as PostgreSQL or Redis and put the service behind TLS/mTLS.

## Security boundaries

The service remains deliberately conservative:

- no automatic AD changes;
- no automatic endpoint remediation;
- no credentials or user files in posture evidence;
- loopback bind by default;
- strict payload size and schema validation;
- CI tests for authentication, replay, ledger integrity, idempotency, and SLA generation.

## Run tests

```bash
python -m unittest -v test_sentinelgrc.py test_governance.py test_ingestion_api.py test_workflow.py test_state_store.py
```

GitHub Actions validates the Python tests and parses both PowerShell agents on every push and pull request.

## Standards mapping

The catalogue illustrates how implementation evidence can be mapped to:

- ISO/IEC 27001:2022 and ISO/IEC 27002:2022
- NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover
- ISO 22301 continuity objectives (future DR-assurance module)

## Planned modules

- runtime agent key ID integration with the HMAC API
- SIEM alert correlation from LogWatcher and SOC-Homelab
- backup/DR assurance from Backup-dr-lab
- change approval and evidence closure

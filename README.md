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
python -m unittest -v test_sentinelgrc.py test_governance.py test_ingestion_api.py test_workflow.py test_state_store.py test_agent_keys.py
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

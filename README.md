# SentinelGRC

SentinelGRC is a security governance concept platform that turns security observations into an authenticated, auditable risk-to-evidence workflow.

It is a portfolio lab. It does not claim ISO certification, production readiness, or replacement of an organisation's ISMS.

## Concept validation

The first product integration is validated with LogWatcher sample events:

```text
20 Windows-style events
        ->
LogWatcher detection
        ->
3 business alerts
        ->
SentinelGRC staging connector
        ->
3 governance findings
        ->
Replay
        ↓
0 duplicate findings / 3 reassessments
```

Observed result:

```text
LogWatcher: 20 events, 3 alerts
Sentinel first run: 3 created, 0 reassessed, 0 errors
Sentinel replay: 0 created, 3 reassessed, 0 errors
```

The sanitized evidence is in [`docs/evidence/concept-validation/`](docs/evidence/concept-validation/).

## Repository layout

```text
scripts/      CLI entrypoints and operational runners
docs/         architecture, deployment, and validation documentation
tests         test modules kept at the repository root for the current unittest discovery contract
runtime/      local runtime state; ignored by Git
```

Core modules remain importable at the repository root for the current Phase 1 compatibility contract. Run entrypoints with `python -m scripts.<name>` so imports work consistently from the repository root.

## Run the concept test

From the LogWatcher repository:

```powershell
python -m logwatcher.cli report `
  --events sample_data/sample_events.jsonl `
  --config config.example.json `
  -o runtime/report.json `
  --alerts-output runtime/alerts.jsonl
```

From SentinelGRC:

```powershell
python -m scripts.staging_logwatcher `
  --events ..\LogWatcher\runtime\alerts.jsonl `
  --input-kind alert `
  --governance-db runtime/concept-governance.db
```

Run the Sentinel command twice. The second run must reassess the same three findings rather than create duplicates.

## Governance lifecycle

```text
Finding
  -> Risk assessment
  -> Treatment proposal
  -> Role-gated approval
  -> Remediation action
  -> Evidence submission
  -> Independent verification
  -> Closure
```

The server-side actor boundary prevents request bodies from choosing the approver, verifier, or closer. Separation of duties prevents the risk owner from approving the same finding and prevents an implementer/evidence submitter from verifying their own work.

## Current capabilities

- Security control and posture evaluation
- Asset-aware risk scoring
- Windows posture and AD access-review contracts
- HMAC agent authentication and replay protection
- Idempotent ingestion and stable finding identity
- Relational governance workflow on SQLite for lab use
- Hash-chained governance and evidence records
- Role-gated approval and separation of duties
- Retry/dead-letter job handling
- Alert-level LogWatcher staging integration
- Executive reporting and sanitized concept evidence

## Validation

The repository test suite currently passes 85 tests with Python's unittest discovery. GitHub Actions also validates the main branch.

```powershell
python -m unittest discover -v -p "test_*.py"
```

## Production boundary

The repository is intentionally a lab/concept implementation. A production deployment still requires PostgreSQL or another shared transactional database, OIDC/SSO and MFA, short-lived tokens, encrypted evidence storage, a durable queue, secret management, TLS/WAF, immutable audit export, backup/restore testing, monitoring, and a security assessment.

The current LogWatcher path validates an alert export. It does not claim live Elastic availability, Windows fleet coverage, SIEM archival, or enterprise-wide governance integration.

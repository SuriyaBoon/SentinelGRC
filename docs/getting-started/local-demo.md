# Local demonstration guide

Run commands from the repository root. Examples are local/synthetic unless explicitly stated; cloud instructions are not authorization.

## Commands used

The lab workflow uses the standard library, while PostgreSQL and Azure adapters
use the pinned packages in `requirements.txt`. GitHub Actions validates the
code with Python 3.12.

### 1. Initialise a local runtime area

```powershell
git clone https://github.com/SuriyaBoon/SentinelGRC.git
cd SentinelGRC
python --version
python -m pip install --require-hashes --requirement requirements-hashed.txt
python -m pip install --require-hashes --requirement requirements-assessment-hashed.txt
New-Item -ItemType Directory -Force runtime | Out-Null
```

### 2. Evaluate the bundled posture fixture

```powershell
python -m scripts.governance assess `
  --posture sample_posture.json `
  --controls controls.json `
  --assets assets.json `
  --output runtime/control-assessment.json
```

### 3. Run the end-to-end control pipeline

```powershell
python -m scripts.pipeline run `
  --posture sample_posture.json `
  --controls controls.json `
  --assets assets.json `
  --access-review sample_ad_access_review.json `
  --ledger runtime/evidence-ledger.jsonl `
  --remediation runtime/remediation-queue.json `
  --tickets runtime/tickets.json `
  --report runtime/executive-report.json `
  --state-db sentinelgrc-state.db `
  --audit-log runtime/audit-log.jsonl `
  --governance-db runtime/governance.db
```

### 4. Reproduce the LogWatcher concept validation

The tracked alert fixture is the sanitized output from the LogWatcher sample scenario.

```powershell
python -m scripts.staging_logwatcher `
  --events docs/evidence/concept-validation/alerts.jsonl `
  --input-kind alert `
  --governance-db runtime/concept-governance.db
```

Run the exact same command a second time against the same database to test replay idempotency.

### 5. Run tests and inspect generated evidence

```powershell
python -m unittest discover -v -p "test_*.py"

python audit_worker.py --max-items 100

# Publish governance events to create-only local lab files
python outbox_worker.py --max-items 100

# Explicit operator recovery for a reviewed dead-letter export
python audit_worker.py `
  --requeue-export "<32-character-export-id>" `
  --confirm "REQUEUE <32-character-export-id>"

# Exact operator recovery for a reviewed broker-outbox dead letter
python outbox_worker.py `
  --requeue-outbox "<32-character-outbox-id>" `
  --confirm "REQUEUE OUTBOX <32-character-outbox-id>"

Get-Content runtime/executive-report.json
Get-Content runtime/remediation-queue.json
Get-Content runtime/evidence-ledger.jsonl
Get-Content docs/evidence/concept-validation/SHA256SUMS.txt
Get-FileHash docs/evidence/concept-validation/*.png, docs/evidence/concept-validation/*.json* -Algorithm SHA256
```

Runtime databases, reports, queues, and ledgers are intentionally ignored by Git. They may contain local machine metadata and should not be committed.

### 6. Run the offline staging-assurance package

This command validates the strict `security_alert.v1` fixture, proves first
ingestion and replay behavior, completes one synthetic governance lifecycle,
and drains its transactional outbox to a create-only local publisher. It does
not construct an Azure client or mutate cloud resources.

```powershell
python -m scripts.staging_assurance `
  --policy config/staging-assurance.example.json `
  --alerts docs/evidence/staging-readiness/logwatcher-security-alert.v1.jsonl `
  --output runtime/staging-assurance/offline-report.json
```

Passing offline checks return `READY_FOR_MANUAL_AZURE_STAGING`, while live and
production decisions remain `NO_GO`. See
[`docs/azure/staging-assurance.md`](../azure/staging-assurance.md) for the four-track
deployment, reliability, first-integration, and operations/security plan.

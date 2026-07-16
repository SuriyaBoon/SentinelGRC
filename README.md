# SentinelGRC

**Continuous security governance for Windows enterprise environments.**

SentinelGRC turns endpoint security checks into an auditable governance loop:

1. Define a security control and its owner.
2. Collect endpoint posture evidence.
3. Evaluate compliance and business risk.
4. Preserve tamper-evident evidence records.
5. Produce a remediation queue and an executive-ready summary.

This is a portfolio lab aligned to governance concepts. It does not claim ISO certification or replace an organisation's ISMS.

## Phase 1: Governance evidence engine

The first increment builds on the ideas in `home-lab-v4` (Windows Security Posture Auditor). It accepts structured endpoint posture data, maps it to a control catalogue, scores findings by asset criticality, and writes a hash-chained evidence ledger.

## Phase 2: Asset-aware remediation governance

Phase 2 adds an asset registry with business owner, technical owner, service, criticality, data classification, and environment. Findings are enriched with this metadata so a failed control on a production finance asset can be prioritised differently from a low-criticality training device.

It also adds exception governance. A risk exception requires a named approver, written reason, future expiry date, and explicit `accepted-risk` status.

```bash
python governance.py assess --controls controls.json --posture sample_posture.json --assets assets.json --output remediation-queue.json
```

## Phase 3: Secure endpoint evidence collection

`agent/Export-SecurityPosture.ps1` is a read-only Windows endpoint collector based on `home-lab-v4`. It collects only security posture facts, makes no network calls, does not collect credentials or user files, does not auto-remediate, and fails closed when a required check cannot be collected.

```powershell
.\agent\Export-SecurityPosture.ps1 -OutputPath .\posture.json
```

## Phase 4: Authenticated posture ingestion

`ingestion_api.py` accepts posture JSON only when the request contains HMAC-SHA256 over the exact request body, a timestamp within a five-minute replay window, a unique nonce, a valid schema, and a payload under 64 KiB.

The API binds to loopback by default and refuses non-loopback binding unless explicitly overridden. Put it behind TLS before network exposure.

```powershell
$env:SENTINELGRC_INGESTION_SECRET = "use-a-secret-manager-in-real-deployments"
python ingestion_api.py serve
python posture_client.py .\posture.json
```

## Phase 5: Identity governance and SLA workflow

`agent/Export-ADAccessReview.ps1` reads AD users and selected privileged groups without modifying them. It reports stale accounts, enabled state, and privileged membership. It never disables an account or changes group membership.

`workflow.py` converts open control findings and stale identity findings into reviewable tickets:

```bash
python workflow.py --remediation remediation-queue.json --access-review ad-access-review.json --output tickets.json
```

Priority targets are explicit:

- critical: 15-minute response / 4-hour resolution
- high: 30-minute response / 8-hour resolution
- medium: 4-hour response / 24-hour resolution
- low: 8-hour response / 72-hour resolution

All tickets include an owner, asset/service context, evidence reference, due times, and `auto_remediation: false`.

## Run tests

```bash
python -m unittest -v test_sentinelgrc.py test_governance.py test_ingestion_api.py test_workflow.py
```

GitHub Actions validates the Python tests and parses both PowerShell agents on every push and pull request.

## Standards mapping

The catalogue illustrates how implementation evidence can be mapped to:

- ISO/IEC 27001:2022 and ISO/IEC 27002:2022
- NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover
- ISO 22301 continuity objectives (future DR-assurance module)

## Planned modules

- SIEM alert correlation (from LogWatcher and SOC-Homelab)
- backup/DR assurance (from Backup-dr-lab)
- change approval and evidence closure

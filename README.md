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

`agent/Export-SecurityPosture.ps1` is a read-only Windows endpoint collector based on `home-lab-v4`. It:

- collects only security posture facts;
- makes no network calls;
- does not collect credentials, private keys, user files, or file contents;
- does not auto-remediate;
- writes only the fields defined by `schemas/posture.schema.json`;
- fails closed when a required check cannot be collected.

Run locally on an elevated Windows PowerShell session:

```powershell
.\agent\Export-SecurityPosture.ps1 -OutputPath .\posture.json
```

The security boundary and future requirements for authenticated ingestion are documented in [docs/security-model.md](docs/security-model.md).

## Run tests

```bash
python -m unittest -v test_sentinelgrc.py test_governance.py
```

GitHub Actions also validates the Python tests and parses the PowerShell agent on every push and pull request.

## Standards mapping

The catalogue illustrates how implementation evidence can be mapped to:

- ISO/IEC 27001:2022 and ISO/IEC 27002:2022
- NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover
- ISO 22301 continuity objectives (future DR-assurance module)

## Planned modules

- authenticated posture ingestion API
- AD lifecycle and access-review automation (from `home-lab-v2`)
- SIEM alert correlation (from LogWatcher and SOC-Homelab)
- ticket, exception and SLA workflow (from Helpdesk-Simulator)
- backup/DR assurance (from Backup-dr-lab)

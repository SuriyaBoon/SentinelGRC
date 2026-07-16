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

```text
Windows posture collector -> posture JSON -> SentinelGRC evaluator
                                           |-> evidence ledger
                                           |-> remediation queue
                                           `-> governance summary
```

## Phase 2: Asset-aware remediation governance

Phase 2 adds a small asset registry with business owner, technical owner, service, criticality, data classification, and environment. Findings are enriched with this metadata so a failed control on a production finance asset can be prioritised differently from a low-criticality training device.

It also adds exception governance. A risk exception requires:

- named approver
- written business reason
- future expiry date
- explicit `accepted-risk` status

Run the Phase 2 assessment:

```bash
python governance.py assess --controls controls.json --posture sample_posture.json --assets assets.json --output remediation-queue.json
```

The command exits non-zero while open findings remain. That makes it suitable for a CI quality gate.

## Run the Phase 1 demo

```bash
python sentinelgrc.py evaluate --controls controls.json --posture sample_posture.json --ledger evidence-ledger.jsonl
python sentinelgrc.py verify-ledger --ledger evidence-ledger.jsonl
```

The evaluator uses only the Python standard library.

```bash
python -m unittest -v test_sentinelgrc.py test_governance.py
```

The sample intentionally contains failed controls, so the assessment prints a remediation queue and returns a non-zero exit status.

## Standards mapping

The starter catalogue illustrates how implementation evidence can be mapped to:

- ISO/IEC 27001:2022 and ISO/IEC 27002:2022
- NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover
- ISO 22301 continuity objectives (future DR-assurance module)

## Planned modules

- Windows endpoint agent (evolution of `home-lab-v4`)
- AD lifecycle and access-review automation (from `home-lab-v2`)
- SIEM alert correlation (from LogWatcher and SOC-Homelab)
- Ticket, exception and SLA workflow (from Helpdesk-Simulator)
- Backup/DR assurance (from Backup-dr-lab)

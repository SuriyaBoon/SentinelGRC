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

## Run the demo

```bash
python sentinelgrc.py evaluate --controls controls.json --posture sample_posture.json --ledger evidence-ledger.jsonl
python sentinelgrc.py verify-ledger --ledger evidence-ledger.jsonl
```

The evaluator uses only the Python standard library.

```bash
python -m unittest -v test_sentinelgrc.py
```

The sample intentionally contains two failed controls, so the evaluate command returns a non-zero exit status after printing the remediation queue.

## Standards mapping

The starter catalogue illustrates how implementation evidence can be mapped to:

- ISO/IEC 27001:2022 and ISO/IEC 27002:2022
- NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover
- ISO 22301 continuity objectives (future DR-assurance module)

## Planned modules

- Windows endpoint agent (evolution of `home-lab-v4`)
- Asset and criticality inventory (from `home-lab-v5`)
- AD lifecycle and access-review automation (from `home-lab-v2`)
- SIEM alert correlation (from LogWatcher and SOC-Homelab)
- Ticket, exception and SLA workflow (from Helpdesk-Simulator)
- Backup/DR assurance (from Backup-dr-lab)

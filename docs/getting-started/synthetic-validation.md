# Synthetic validation evidence

### Synthetic-lab integration proof

The tracked evidence package is in [`docs/evidence/concept-validation`](../evidence/concept-validation/).

| File | What it proves |
| --- | --- |
| [`01-logwatcher-report.png`](../evidence/concept-validation/01-logwatcher-report.png) | A sanitized LogWatcher run processed 20 Windows-style events and fired 3 alerts. |
| [`02-sentinel-replay.png`](../evidence/concept-validation/02-sentinel-replay.png) | First Sentinel ingestion created 3 findings; replay created 0 findings and reassessed 3. |
| [`alerts.jsonl`](../evidence/concept-validation/alerts.jsonl) | The three structured alert records submitted to the staging connector. |
| [`report.json`](../evidence/concept-validation/report.json) | Machine-readable totals for the source scenario, including 20 events and 3 alerts. |
| [`SHA256SUMS.txt`](../evidence/concept-validation/SHA256SUMS.txt) | SHA-256 checksums for the tracked screenshots and data files. |

![LogWatcher processed 20 sample events and generated 3 alerts](../evidence/concept-validation/01-logwatcher-report.png)

![SentinelGRC created three findings once and reassessed them on replay](../evidence/concept-validation/02-sentinel-replay.png)

The validated scenario is deliberately bounded:

```text
Source scenario: 20 sample events -> 3 alerts
First Sentinel run: 3 findings created, 0 reassessed, 0 errors
Replay of the same alerts: 0 findings created, 3 reassessed, 0 errors
```

This is evidence of synthetic-lab alert normalization and idempotent finding handling. It is not evidence of a live Windows fleet, Elastic, SIEM, or production environment.

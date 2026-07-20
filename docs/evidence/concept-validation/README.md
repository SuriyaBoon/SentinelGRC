# Concept validation evidence

This folder contains sanitized, reproducible evidence for the LogWatcher → SentinelGRC concept test.

## Evidence set

- `01-logwatcher-report.png` — LogWatcher processed 20 events and fired 3 alerts.
- `02-sentinel-replay.png` — Sentinel created 3 findings on the first run and reassessed 3 on replay.
- `report.json` — sanitized machine-readable report.
- `alerts.jsonl` — three alert records used by the Sentinel staging connector.
- `SHA256SUMS.txt` — hashes for the tracked evidence files using relative filenames only.

The SQLite database and PowerShell transcript remain local-only. They are excluded because they are runtime artifacts and may contain machine/path metadata.

## Acceptance criteria

```text
LogWatcher: 20 events / 3 alerts
First Sentinel run: 3 created / 0 reassessed / 0 errors
Replay: 0 created / 3 reassessed / 0 errors
```

This evidence validates concept-level detection, alert normalization, finding creation, stable identity, and replay idempotency. It is not production or live Elastic evidence.

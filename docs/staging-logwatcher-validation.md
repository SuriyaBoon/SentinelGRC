# Staging validation: LogWatcher → SentinelGRC

This is the first real product integration path. It validates the LogWatcher alert contract before connecting a live Elastic/Windows environment.

## 1. Generate the product alert export

From the LogWatcher repository, run the detector against the historical/synthetic event export:

```powershell
python -m logwatcher.cli report \
  --events sample_data/sample_events.jsonl \
  --config config.example.json \
  -o runtime/logwatcher-report.json \
  --alerts-output runtime/logwatcher-alerts.jsonl
```

The raw event file contains 20 Windows-style events. LogWatcher aggregates those events into business alerts. The alert export is the correct input for Sentinel findings; raw events remain useful for connector diagnostics and noise analysis.

## 2. Run the Sentinel staging harness

From SentinelGRC:

```powershell
python -m scripts.staging_logwatcher \
  --events ..\\LogWatcher\\runtime\\logwatcher-alerts.jsonl \
  --input-kind alert \
  --governance-db runtime/staging-governance.db
```

The harness reports:

- events read;
- findings created;
- findings reassessed;
- ignored events;
- malformed-line errors;
- stable finding IDs.

Expected result for the repository sample:

```text
events_read=3
findings_created=3
findings_reassessed=0
ignored=0
errors=0
```

Run the same command again against the same database. Expected result:

```text
findings_created=0
findings_reassessed=3
errors=0
```

## 3. Validate the lifecycle

Use the authenticated Governance API to assess, propose treatment, approve, start action, submit evidence, verify with another actor, and close the finding. Do not place actor fields in the request body.

Expected flow:

```text
LogWatcher alert
→ Sentinel finding
→ risk owner assessment
→ treatment proposal
→ approver decision
→ action
→ evidence metadata/hash
→ independent verification
→ closure
```

## 4. Required staging scenarios

Run at least:

- repeated identical alert: finding reassessment, no duplicate finding;
- brute-force alert: high/critical mapping;
- account lockout alert: identity-control mapping;
- privilege escalation alert: critical mapping;
- malformed JSONL: counted as error;
- unauthorized approval: rejected;
- self-approval/self-verification: rejected;
- failed verification: finding returns to remediation;
- evidence hash mismatch: rejected by verification process;
- worker/pipeline failure: retry and recovery verified.

This harness proves the connector and governance boundary. It does not prove Elastic production availability, Windows event collection, WAF/TLS, PostgreSQL, backup/restore or SIEM archive behavior.

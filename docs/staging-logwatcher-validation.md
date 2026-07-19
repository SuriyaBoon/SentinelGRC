# Staging validation: LogWatcher → SentinelGRC

This is the first real product integration path. It validates the native LogWatcher JSONL schema before connecting a live Elastic/Windows environment.

## 1. Prepare the product export

From the LogWatcher repository:

```powershell
python -m logwatcher report --events sample_data/sample_events.jsonl --config config.example.json
```

For the first Sentinel staging test, use the raw JSONL export at:

```text
LogWatcher/sample_data/sample_events.jsonl
```

## 2. Run the Sentinel staging harness

From SentinelGRC:

```powershell
python staging_logwatcher.py --events ..\LogWatcher\sample_data\sample_events.jsonl --governance-db runtime\staging-governance.db
```

The harness reports:

- events read;
- findings created;
- findings reassessed;
- ignored events;
- malformed-line errors;
- stable finding IDs.

## 3. Validate the lifecycle

Use the authenticated Governance API to assess, propose treatment, approve, start action, submit evidence, verify with another actor, and close the finding. Do not place actor fields in the request body.

Expected flow:

```text
LogWatcher 4625
→ SEC-AUTH finding
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

- repeated identical event: finding reassessment, no duplicate finding;
- brute-force event: high/critical mapping;
- malformed JSONL: counted as error;
- unauthorized approval: rejected;
- self-approval/self-verification: rejected;
- failed verification: finding returns to remediation;
- evidence hash mismatch: rejected by verification process;
- worker/pipeline failure: retry and recovery verified.

This harness proves the connector and governance boundary. It does not prove Elastic production availability, Windows event collection, WAF/TLS, PostgreSQL, backup/restore or SIEM archive behavior.

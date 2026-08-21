# Pipeline Worker Dead-Job Recovery

This procedure is an operator-controlled recovery path for a managed evidence
job that was moved to `dead` after committed-byte verification failed. The
worker must never retry or requeue this condition automatically.

## Preconditions

1. Identify one dead `pipeline_jobs` row by its exact `payload_path`.
2. Confirm the related `accepted_payloads` record is `committed`.
3. Restore the evidence file from an approved source and verify its SHA-256
   equals the committed `payload_hash`.
4. Record the incident, operator identity, approval, original job ID, committed
   hash, and repaired file hash in the governance audit trail.

## Reviewed action

After approval, use a transaction that targets only the reviewed dead row and
sets it back to `pending`, clears its lease and last error, and resets attempts
only when policy explicitly permits another attempt. Do not delete the row,
change `payload_path`, modify the committed hash, or insert a duplicate row to
bypass the unique-path constraint.

Run the worker once and retain the resulting queue transition and pipeline
evidence. If verification fails again, leave the row dead and open a new
incident. Production automation for this procedure remains disabled until the
Azure live-validation and pilot gates approve it.

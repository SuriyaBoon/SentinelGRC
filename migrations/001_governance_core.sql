-- SentinelGRC PostgreSQL governance foundation
-- Apply with a migration runner in production; do not edit applied migrations.

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    control_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    title TEXT NOT NULL,
    risk_owner TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    treatment_type TEXT,
    treatment_reason TEXT,
    due_date DATE,
    action_owner TEXT,
    implementer TEXT,
    evidence_submitter TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS governance_evidence (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    source TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'submitted'
);

CREATE TABLE IF NOT EXISTS governance_events (
    event_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    auth_method TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    details_json JSONB NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS connector_events (
    event_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_governance_events_finding
    ON governance_events(finding_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_findings_status_severity
    ON findings(status, severity);

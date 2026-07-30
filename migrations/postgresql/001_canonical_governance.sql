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
    due_date TEXT,
    action_owner TEXT,
    implementer TEXT,
    evidence_submitter TEXT,
    created_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_records (
    risk_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL UNIQUE REFERENCES findings(finding_id),
    likelihood TEXT NOT NULL,
    impact TEXT NOT NULL,
    owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS risk_treatments (
    treatment_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    treatment_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_approval'
);

CREATE TABLE IF NOT EXISTS approval_records (
    approval_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    decision TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS action_items (
    action_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    owner TEXT NOT NULL,
    implementer TEXT,
    due_date TEXT,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS governance_evidence (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    source TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    submitted_at DOUBLE PRECISION NOT NULL,
    status TEXT NOT NULL DEFAULT 'submitted'
);

CREATE TABLE IF NOT EXISTS verification_records (
    verification_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    verifier_id TEXT NOT NULL,
    result TEXT NOT NULL,
    notes TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS closure_records (
    closure_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    closed_by TEXT NOT NULL,
    reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS governance_events (
    event_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    event_sequence INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    auth_method TEXT NOT NULL,
    occurred_at DOUBLE PRECISION NOT NULL,
    details_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    UNIQUE(finding_id, event_sequence)
);

CREATE INDEX IF NOT EXISTS idx_events_finding
    ON governance_events(finding_id, event_sequence);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS user_api_keys (
    key_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    secret_hash TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

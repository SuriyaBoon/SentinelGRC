ALTER TABLE governance_evidence
    ADD COLUMN IF NOT EXISTS object_key TEXT,
    ADD COLUMN IF NOT EXISTS size_bytes INTEGER,
    ADD COLUMN IF NOT EXISTS etag TEXT;

ALTER TABLE governance_evidence
    DROP CONSTRAINT IF EXISTS governance_evidence_size_positive;

ALTER TABLE governance_evidence
    ADD CONSTRAINT governance_evidence_size_positive
    CHECK (size_bytes IS NULL OR size_bytes > 0);

CREATE INDEX IF NOT EXISTS idx_governance_evidence_object
    ON governance_evidence(object_key)
    WHERE object_key IS NOT NULL;

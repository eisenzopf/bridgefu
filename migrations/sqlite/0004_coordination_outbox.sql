-- Standalone parity for the authoritative coordination outbox. Timestamps are
-- database-derived Unix epoch milliseconds.
ALTER TABLE repository_metadata RENAME TO repository_metadata_v3;
CREATE TABLE repository_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 4),
    epoch INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    provider_receipt_sequence INTEGER NULL CHECK (provider_receipt_sequence > 0)
);
INSERT INTO repository_metadata(
    singleton,
    schema_version,
    epoch,
    provider_receipt_sequence
)
SELECT singleton, 4, epoch, provider_receipt_sequence
FROM repository_metadata_v3;
DROP TABLE repository_metadata_v3;

CREATE TABLE coordination_outbox (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    recorded_at_ms INTEGER NOT NULL,
    claim_projector TEXT,
    claim_generation INTEGER NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    claimed_at_ms INTEGER,
    claim_expires_at_ms INTEGER,
    applied_at_ms INTEGER,
    CHECK (
        (claim_projector IS NULL AND claimed_at_ms IS NULL AND claim_expires_at_ms IS NULL)
        OR
        (claim_projector IS NOT NULL AND claimed_at_ms IS NOT NULL AND claim_expires_at_ms IS NOT NULL)
    ),
    CHECK (claim_expires_at_ms IS NULL OR claim_expires_at_ms > claimed_at_ms),
    CHECK (applied_at_ms IS NULL OR applied_at_ms >= recorded_at_ms)
);

CREATE INDEX coordination_outbox_pending
    ON coordination_outbox (deployment_id, sequence)
    WHERE applied_at_ms IS NULL;

-- Acquiring this row as the first write in a transaction gives standalone
-- claimers deterministic BEGIN-IMMEDIATE-equivalent serialization.
CREATE TABLE coordination_projection_locks (
    deployment_id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL DEFAULT 0
);

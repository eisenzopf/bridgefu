PRAGMA foreign_keys = OFF;

-- Execution-plan version 3 adds a complete credential-free Amazon Connect
-- start specification inside call_execution_plans.body. Historical version-1
-- and version-2 bodies are intentionally not rewritten: inventing a profile,
-- attributes, or display name would turn inspection-only state into runnable
-- external work.
ALTER TABLE repository_metadata RENAME TO repository_metadata_v7;
CREATE TABLE repository_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 8),
    epoch INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    provider_receipt_sequence INTEGER NULL CHECK (provider_receipt_sequence > 0)
);
INSERT INTO repository_metadata(
    singleton,
    schema_version,
    epoch,
    provider_receipt_sequence
)
SELECT singleton, 8, epoch, provider_receipt_sequence
FROM repository_metadata_v7;
DROP TABLE repository_metadata_v7;

PRAGMA foreign_keys = ON;

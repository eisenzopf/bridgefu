-- Version-two execution plans carry the exact redacted principal fingerprint
-- that authorized outbound work. Existing plans remain NULL deliberately:
-- there is no safe authority to infer during migration, so outbound recovery
-- fails closed until those calls are terminated or recreated.
ALTER TABLE repository_metadata RENAME TO repository_metadata_v5;
CREATE TABLE repository_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 6),
    epoch INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    provider_receipt_sequence INTEGER NULL CHECK (provider_receipt_sequence > 0)
);
INSERT INTO repository_metadata(
    singleton,
    schema_version,
    epoch,
    provider_receipt_sequence
)
SELECT singleton, 6, epoch, provider_receipt_sequence
FROM repository_metadata_v5;
DROP TABLE repository_metadata_v5;

ALTER TABLE call_execution_plans
    ADD COLUMN authorization_principal_fingerprint BLOB NULL
    CHECK (
        authorization_principal_fingerprint IS NULL
        OR length(authorization_principal_fingerprint) = 32
    );

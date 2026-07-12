-- Version-two execution plans carry the exact redacted principal fingerprint
-- that authorized outbound work. Existing plans remain NULL deliberately:
-- there is no safe authority to infer during migration, so outbound recovery
-- fails closed until those calls are terminated or recreated.
ALTER TABLE repository_metadata
    DROP CONSTRAINT repository_metadata_schema_version_check;
UPDATE repository_metadata SET schema_version = 6 WHERE singleton = TRUE;
ALTER TABLE repository_metadata
    ADD CONSTRAINT repository_metadata_schema_version_check CHECK (schema_version = 6);

ALTER TABLE call_execution_plans
    ADD COLUMN authorization_principal_fingerprint BYTEA NULL
    CHECK (
        authorization_principal_fingerprint IS NULL
        OR octet_length(authorization_principal_fingerprint) = 32
    );

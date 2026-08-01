-- Execution-plan version 3 adds a complete credential-free Amazon Connect
-- start specification inside call_execution_plans.body. Historical version-1
-- and version-2 bodies are intentionally not rewritten: inventing a profile,
-- attributes, or display name would turn inspection-only state into runnable
-- external work.
ALTER TABLE repository_metadata
    DROP CONSTRAINT repository_metadata_schema_version_check;
UPDATE repository_metadata SET schema_version = 8 WHERE singleton = TRUE;
ALTER TABLE repository_metadata
    ADD CONSTRAINT repository_metadata_schema_version_check CHECK (schema_version = 8);

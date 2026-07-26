-- One logical provider leg owns two independently idempotent Telnyx calls:
-- the SIP/RTP media call and the linked remote-destination call. Preserve
-- legacy rows as the primary media role while replacing the old one-row-per-
-- generation constraint with role-aware uniqueness.
ALTER TABLE provider_references
    ADD COLUMN reference_role TEXT NOT NULL DEFAULT 'media'
        CHECK (reference_role IN ('media', 'destination'));
ALTER TABLE provider_references
    ALTER COLUMN reference_role DROP DEFAULT;

ALTER TABLE external_references
    ADD COLUMN reference_role TEXT NOT NULL DEFAULT 'media'
        CHECK (reference_role IN ('media', 'destination'));
ALTER TABLE external_references
    ALTER COLUMN reference_role DROP DEFAULT;
ALTER TABLE external_references
    DROP CONSTRAINT external_references_call_id_leg_id_binding_generation_key;
ALTER TABLE external_references
    ADD CONSTRAINT external_references_call_leg_generation_role_key
        UNIQUE(call_id, leg_id, binding_generation, reference_role);

ALTER TABLE repository_metadata
    DROP CONSTRAINT repository_metadata_schema_version_check;
UPDATE repository_metadata SET schema_version = 7 WHERE singleton = TRUE;
ALTER TABLE repository_metadata
    ADD CONSTRAINT repository_metadata_schema_version_check CHECK (schema_version = 7);

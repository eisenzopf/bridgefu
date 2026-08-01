ALTER TABLE repository_metadata
    DROP CONSTRAINT repository_metadata_schema_version_check;
UPDATE repository_metadata SET schema_version = 10 WHERE singleton = TRUE;
ALTER TABLE repository_metadata
    ADD CONSTRAINT repository_metadata_schema_version_check CHECK (schema_version = 10);

CREATE TABLE initial_contexts (
    tenant_id TEXT NOT NULL,
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    target_leg_id UUID NOT NULL,
    target_binding_generation BIGINT NOT NULL CHECK (target_binding_generation > 0),
    source_connection_id TEXT NOT NULL,
    source_leg_id UUID NOT NULL,
    source_binding_generation BIGINT NOT NULL CHECK (source_binding_generation > 0),
    message_id TEXT NOT NULL CHECK (
        octet_length(message_id) BETWEEN 1 AND 128
        AND message_id !~ '[[:cntrl:]]'
    ),
    recorded_at TIMESTAMPTZ NOT NULL,
    envelope_bytes BIGINT NOT NULL CHECK (envelope_bytes BETWEEN 1 AND 16384),
    header_count BIGINT NOT NULL CHECK (header_count BETWEEN 0 AND 32),
    body JSONB NOT NULL,
    PRIMARY KEY(call_id, target_leg_id, target_binding_generation),
    UNIQUE(call_id, message_id),
    FOREIGN KEY(call_id, target_leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE,
    FOREIGN KEY(call_id, source_leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE,
    CHECK (source_leg_id <> target_leg_id)
);

CREATE INDEX initial_contexts_owner_idx
    ON initial_contexts(tenant_id, call_id, target_leg_id, target_binding_generation);

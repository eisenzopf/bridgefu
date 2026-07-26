PRAGMA foreign_keys = OFF;

ALTER TABLE repository_metadata RENAME TO repository_metadata_v8;
CREATE TABLE repository_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 10),
    epoch INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    provider_receipt_sequence INTEGER NULL CHECK (provider_receipt_sequence > 0)
);
INSERT INTO repository_metadata(
    singleton,
    schema_version,
    epoch,
    provider_receipt_sequence
)
SELECT singleton, 10, epoch, provider_receipt_sequence
FROM repository_metadata_v8;
DROP TABLE repository_metadata_v8;

CREATE TABLE initial_contexts (
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    target_leg_id TEXT NOT NULL,
    target_binding_generation INTEGER NOT NULL CHECK (target_binding_generation > 0),
    source_connection_id TEXT NOT NULL,
    source_leg_id TEXT NOT NULL,
    source_binding_generation INTEGER NOT NULL CHECK (source_binding_generation > 0),
    message_id TEXT NOT NULL CHECK (
        length(message_id) BETWEEN 1 AND 128
        AND instr(message_id, char(0)) = 0
        AND instr(message_id, char(10)) = 0
        AND instr(message_id, char(13)) = 0
    ),
    recorded_at TEXT NOT NULL,
    envelope_bytes INTEGER NOT NULL CHECK (envelope_bytes BETWEEN 1 AND 16384),
    header_count INTEGER NOT NULL CHECK (header_count BETWEEN 0 AND 32),
    body TEXT NOT NULL,
    PRIMARY KEY(call_id, target_leg_id, target_binding_generation),
    UNIQUE(call_id, message_id),
    FOREIGN KEY(call_id, target_leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE,
    FOREIGN KEY(call_id, source_leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE,
    CHECK (source_leg_id <> target_leg_id)
);

CREATE INDEX initial_contexts_owner_idx
    ON initial_contexts(tenant_id, call_id, target_leg_id, target_binding_generation);

PRAGMA foreign_keys = ON;

PRAGMA foreign_keys = OFF;

-- One logical provider leg owns two independently idempotent Telnyx calls:
-- the SIP/RTP media call and the linked remote-destination call. Preserve
-- legacy rows as the primary media role while replacing the old one-row-per-
-- generation constraint with role-aware uniqueness.
ALTER TABLE provider_references
    ADD COLUMN reference_role TEXT NOT NULL DEFAULT 'media'
        CHECK (reference_role IN ('media', 'destination'));

ALTER TABLE external_references RENAME TO external_references_v6;
CREATE TABLE external_references (
    reference_kind TEXT NOT NULL,
    reference_namespace TEXT NOT NULL,
    reference_value TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES call_execution_plans(call_id) ON DELETE CASCADE,
    leg_id TEXT NOT NULL,
    binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
    reference_role TEXT NOT NULL CHECK (reference_role IN ('media', 'destination')),
    effect_id TEXT NOT NULL UNIQUE REFERENCES outbox(effect_id) ON DELETE RESTRICT,
    bound_at TEXT NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY(reference_kind, reference_namespace, reference_value),
    UNIQUE(call_id, leg_id, binding_generation, reference_role),
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);
INSERT INTO external_references(
    reference_kind,
    reference_namespace,
    reference_value,
    tenant_id,
    call_id,
    leg_id,
    binding_generation,
    reference_role,
    effect_id,
    bound_at,
    body
)
SELECT
    reference_kind,
    reference_namespace,
    reference_value,
    tenant_id,
    call_id,
    leg_id,
    binding_generation,
    'media',
    effect_id,
    bound_at,
    body
FROM external_references_v6;
DROP TABLE external_references_v6;

ALTER TABLE repository_metadata RENAME TO repository_metadata_v6;
CREATE TABLE repository_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 7),
    epoch INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    provider_receipt_sequence INTEGER NULL CHECK (provider_receipt_sequence > 0)
);
INSERT INTO repository_metadata(
    singleton,
    schema_version,
    epoch,
    provider_receipt_sequence
)
SELECT singleton, 7, epoch, provider_receipt_sequence
FROM repository_metadata_v6;
DROP TABLE repository_metadata_v6;

PRAGMA foreign_keys = ON;

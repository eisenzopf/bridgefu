PRAGMA foreign_keys = OFF;

ALTER TABLE repository_metadata RENAME TO repository_metadata_v10;
CREATE TABLE repository_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 11),
    epoch INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    provider_receipt_sequence INTEGER NULL CHECK (provider_receipt_sequence > 0)
);
INSERT INTO repository_metadata(singleton, schema_version, epoch, provider_receipt_sequence)
SELECT singleton, 11, epoch, provider_receipt_sequence FROM repository_metadata_v10;
DROP TABLE repository_metadata_v10;

CREATE TABLE broadcasts (
    broadcast_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    source_leg_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_fence INTEGER NOT NULL CHECK (worker_fence > 0),
    transport TEXT NOT NULL CHECK (transport IN ('moqt', 'uctp_quic')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'deleting', 'deleted', 'failed')),
    specification TEXT NOT NULL CHECK (json_valid(specification)),
    runtime TEXT CHECK (runtime IS NULL OR json_valid(runtime)),
    failure_code TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    create_idempotency_digest BLOB NOT NULL CHECK (length(create_idempotency_digest) = 32),
    create_request_digest BLOB NOT NULL CHECK (length(create_request_digest) = 32),
    UNIQUE (tenant_id, create_idempotency_digest),
    FOREIGN KEY(call_id, source_leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);

CREATE INDEX broadcasts_owner_idx ON broadcasts(tenant_id, broadcast_id);
CREATE INDEX broadcasts_worker_idx ON broadcasts(worker_id, worker_fence, state, updated_at);

CREATE TABLE broadcast_commands (
    command_id TEXT PRIMARY KEY,
    broadcast_id TEXT NOT NULL REFERENCES broadcasts(broadcast_id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    worker_fence INTEGER NOT NULL CHECK (worker_fence > 0),
    kind TEXT NOT NULL CHECK (kind IN ('start', 'stop')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'succeeded', 'failed')),
    available_at TEXT NOT NULL,
    claim_generation INTEGER NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    claimed_at TEXT,
    claim_expires_at TEXT,
    completed_at TEXT,
    failure_code TEXT,
    CHECK (
        (state <> 'claimed' AND claimed_at IS NULL AND claim_expires_at IS NULL)
        OR
        (state = 'claimed' AND claimed_at IS NOT NULL AND claim_expires_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX broadcast_commands_one_start
    ON broadcast_commands(broadcast_id) WHERE kind = 'start';
CREATE UNIQUE INDEX broadcast_commands_one_stop
    ON broadcast_commands(broadcast_id) WHERE kind = 'stop';
CREATE INDEX broadcast_commands_claim_idx
    ON broadcast_commands(worker_id, worker_fence, state, available_at);

CREATE TABLE broadcast_operation_receipts (
    tenant_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('delete')),
    idempotency_digest BLOB NOT NULL CHECK (length(idempotency_digest) = 32),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    broadcast_id TEXT NOT NULL REFERENCES broadcasts(broadcast_id) ON DELETE CASCADE,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id, operation, idempotency_digest)
);

PRAGMA foreign_keys = ON;

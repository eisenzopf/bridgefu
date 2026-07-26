ALTER TABLE repository_metadata
    DROP CONSTRAINT repository_metadata_schema_version_check;
UPDATE repository_metadata SET schema_version = 11 WHERE singleton = TRUE;
ALTER TABLE repository_metadata
    ADD CONSTRAINT repository_metadata_schema_version_check CHECK (schema_version = 11);

CREATE TABLE broadcasts (
    broadcast_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    source_leg_id UUID NOT NULL,
    worker_id UUID NOT NULL,
    worker_fence BIGINT NOT NULL CHECK (worker_fence > 0),
    transport TEXT NOT NULL CHECK (transport IN ('moqt', 'uctp_quic')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'deleting', 'deleted', 'failed')),
    specification JSONB NOT NULL,
    runtime JSONB,
    failure_code TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    create_idempotency_digest BYTEA NOT NULL CHECK (octet_length(create_idempotency_digest) = 32),
    create_request_digest BYTEA NOT NULL CHECK (octet_length(create_request_digest) = 32),
    UNIQUE (tenant_id, create_idempotency_digest),
    FOREIGN KEY(call_id, source_leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);

CREATE INDEX broadcasts_owner_idx ON broadcasts(tenant_id, broadcast_id);
CREATE INDEX broadcasts_worker_idx ON broadcasts(worker_id, worker_fence, state, updated_at);

CREATE TABLE broadcast_commands (
    command_id UUID PRIMARY KEY,
    broadcast_id UUID NOT NULL REFERENCES broadcasts(broadcast_id) ON DELETE CASCADE,
    worker_id UUID NOT NULL,
    worker_fence BIGINT NOT NULL CHECK (worker_fence > 0),
    kind TEXT NOT NULL CHECK (kind IN ('start', 'stop')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'succeeded', 'failed')),
    available_at TIMESTAMPTZ NOT NULL,
    claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    claimed_at TIMESTAMPTZ,
    claim_expires_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
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
    idempotency_digest BYTEA NOT NULL CHECK (octet_length(idempotency_digest) = 32),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    broadcast_id UUID NOT NULL REFERENCES broadcasts(broadcast_id) ON DELETE CASCADE,
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(tenant_id, operation, idempotency_digest)
);

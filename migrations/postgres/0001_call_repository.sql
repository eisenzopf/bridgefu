CREATE TABLE repository_metadata (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    schema_version BIGINT NOT NULL CHECK (schema_version = 1),
    epoch BIGINT NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    provider_receipt_sequence BIGINT NULL CHECK (provider_receipt_sequence > 0)
);
INSERT INTO repository_metadata(singleton, schema_version) VALUES (TRUE, 1);

CREATE TABLE workers (
    worker_id UUID PRIMARY KEY,
    fence BIGINT NOT NULL CHECK (fence > 0),
    max_calls BIGINT NOT NULL CHECK (max_calls > 0),
    reserved_calls BIGINT NOT NULL CHECK (reserved_calls >= 0 AND reserved_calls <= max_calls),
    draining BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    body JSONB NOT NULL
);

CREATE TABLE calls (
    call_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    aggregate_version BIGINT NOT NULL CHECK (aggregate_version >= 0),
    call_state TEXT NOT NULL,
    body JSONB NOT NULL
);
CREATE INDEX calls_tenant_idx ON calls(tenant_id, call_id);

CREATE TABLE legs (
    leg_id UUID PRIMARY KEY,
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    binding_generation BIGINT NOT NULL CHECK (binding_generation > 0),
    leg_state TEXT NOT NULL,
    body JSONB NOT NULL,
    UNIQUE(call_id, leg_id)
);
CREATE INDEX legs_call_idx ON legs(call_id);

CREATE TABLE worker_assignments (
    call_id UUID PRIMARY KEY REFERENCES calls(call_id) ON DELETE CASCADE,
    worker_id UUID NOT NULL REFERENCES workers(worker_id),
    worker_fence BIGINT NOT NULL CHECK (worker_fence > 0),
    assigned_at TIMESTAMPTZ NOT NULL,
    released_at TIMESTAMPTZ NULL,
    body JSONB NOT NULL
);
CREATE INDEX worker_assignments_worker_idx
    ON worker_assignments(worker_id, worker_fence, released_at);

CREATE TABLE connection_bindings (
    connection_id TEXT PRIMARY KEY,
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    leg_id UUID NOT NULL,
    binding_generation BIGINT NOT NULL CHECK (binding_generation > 0),
    principal_fingerprint BYTEA NOT NULL CHECK (octet_length(principal_fingerprint) = 32),
    body JSONB NOT NULL,
    UNIQUE(call_id, leg_id),
    UNIQUE(principal_fingerprint, call_id, leg_id, binding_generation),
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);

CREATE TABLE commands (
    command_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    observed_version BIGINT NOT NULL CHECK (observed_version >= 0),
    result_version BIGINT NOT NULL CHECK (result_version >= 0),
    recorded_at TIMESTAMPTZ NOT NULL,
    body JSONB NOT NULL
);
CREATE INDEX commands_call_idx ON commands(call_id, recorded_at, command_id);

CREATE TABLE idempotency (
    tenant_id TEXT NOT NULL,
    key_digest BYTEA NOT NULL CHECK (octet_length(key_digest) = 32),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    body JSONB NOT NULL,
    PRIMARY KEY(tenant_id, key_digest)
);
CREATE INDEX idempotency_expiry_idx ON idempotency(expires_at);

CREATE TABLE attachments (
    token_digest BYTEA PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    attachment_id UUID NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    leg_id UUID NOT NULL,
    binding_generation BIGINT NOT NULL CHECK (binding_generation > 0),
    worker_id UUID NOT NULL,
    worker_fence BIGINT NOT NULL CHECK (worker_fence > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL,
    body JSONB NOT NULL,
    UNIQUE(call_id, leg_id, binding_generation),
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);
CREATE INDEX attachments_expiry_idx ON attachments(expires_at);

CREATE TABLE provider_references (
    account_key TEXT NOT NULL,
    provider_call_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    leg_id UUID NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL,
    body JSONB NOT NULL,
    PRIMARY KEY(account_key, provider_call_id),
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);

CREATE TABLE provider_events (
    account_key TEXT NOT NULL,
    event_digest BYTEA NOT NULL CHECK (octet_length(event_digest) = 32),
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    provider_call_id TEXT NOT NULL,
    receipt_sequence BIGINT NOT NULL UNIQUE CHECK (receipt_sequence > 0),
    received_at TIMESTAMPTZ NOT NULL,
    event_state TEXT NOT NULL,
    body JSONB NOT NULL,
    PRIMARY KEY(account_key, event_digest)
);
CREATE INDEX provider_events_claim_idx
    ON provider_events(event_state, receipt_sequence);
CREATE INDEX provider_events_reference_idx
    ON provider_events(account_key, provider_call_id, receipt_sequence);

CREATE TABLE provider_completions (
    account_key TEXT NOT NULL,
    event_digest BYTEA NOT NULL CHECK (octet_length(event_digest) = 32),
    completion_kind TEXT NOT NULL CHECK (completion_kind IN ('command', 'terminal_acknowledgement')),
    body JSONB NOT NULL,
    PRIMARY KEY(account_key, event_digest),
    FOREIGN KEY(account_key, event_digest)
        REFERENCES provider_events(account_key, event_digest) ON DELETE RESTRICT
);
CREATE INDEX provider_completions_kind_idx ON provider_completions(completion_kind);

CREATE TABLE used_connection_ids (
    connection_id TEXT PRIMARY KEY
);

CREATE TABLE outbox (
    effect_id UUID PRIMARY KEY,
    command_id UUID NOT NULL REFERENCES commands(command_id) ON DELETE CASCADE,
    ordinal BIGINT NOT NULL CHECK (ordinal >= 0),
    tenant_id TEXT NOT NULL,
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    aggregate_version BIGINT NOT NULL CHECK (aggregate_version >= 0),
    worker_id UUID NOT NULL,
    worker_fence BIGINT NOT NULL CHECK (worker_fence > 0),
    available_at TIMESTAMPTZ NOT NULL,
    outbox_state TEXT NOT NULL,
    body JSONB NOT NULL,
    UNIQUE(command_id, ordinal)
);
CREATE INDEX outbox_claim_idx
    ON outbox(worker_id, worker_fence, outbox_state, available_at);

CREATE TABLE deadlines (
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    deadline_kind TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    tenant_id TEXT NOT NULL,
    due_at TIMESTAMPTZ NOT NULL,
    deadline_state TEXT NOT NULL,
    body JSONB NOT NULL,
    PRIMARY KEY(call_id, deadline_kind, generation)
);
CREATE INDEX deadlines_due_idx ON deadlines(deadline_state, due_at);

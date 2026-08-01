PRAGMA foreign_keys = ON;

CREATE TABLE repository_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    epoch INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    provider_receipt_sequence INTEGER NULL CHECK (provider_receipt_sequence > 0)
);
INSERT INTO repository_metadata(singleton, schema_version) VALUES (1, 1);

CREATE TABLE workers (
    worker_id TEXT PRIMARY KEY,
    fence INTEGER NOT NULL CHECK (fence > 0),
    max_calls INTEGER NOT NULL CHECK (max_calls > 0),
    reserved_calls INTEGER NOT NULL CHECK (reserved_calls >= 0 AND reserved_calls <= max_calls),
    draining INTEGER NOT NULL CHECK (draining IN (0, 1)),
    updated_at TEXT NOT NULL,
    body TEXT NOT NULL
);

CREATE TABLE calls (
    call_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    aggregate_version INTEGER NOT NULL CHECK (aggregate_version >= 0),
    call_state TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX calls_tenant_idx ON calls(tenant_id, call_id);

CREATE TABLE legs (
    leg_id TEXT PRIMARY KEY,
    call_id TEXT NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
    leg_state TEXT NOT NULL,
    body TEXT NOT NULL,
    UNIQUE(call_id, leg_id)
);
CREATE INDEX legs_call_idx ON legs(call_id);

CREATE TABLE worker_assignments (
    call_id TEXT PRIMARY KEY REFERENCES calls(call_id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL REFERENCES workers(worker_id),
    worker_fence INTEGER NOT NULL CHECK (worker_fence > 0),
    assigned_at TEXT NOT NULL,
    released_at TEXT NULL,
    body TEXT NOT NULL
);
CREATE INDEX worker_assignments_worker_idx
    ON worker_assignments(worker_id, worker_fence, released_at);

CREATE TABLE connection_bindings (
    connection_id TEXT PRIMARY KEY,
    call_id TEXT NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    leg_id TEXT NOT NULL,
    binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
    principal_fingerprint BLOB NOT NULL CHECK (length(principal_fingerprint) = 32),
    body TEXT NOT NULL,
    UNIQUE(call_id, leg_id),
    UNIQUE(principal_fingerprint, call_id, leg_id, binding_generation),
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);

CREATE TABLE commands (
    command_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    observed_version INTEGER NOT NULL CHECK (observed_version >= 0),
    result_version INTEGER NOT NULL CHECK (result_version >= 0),
    recorded_at TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX commands_call_idx ON commands(call_id, recorded_at, command_id);

CREATE TABLE idempotency (
    tenant_id TEXT NOT NULL,
    key_digest BLOB NOT NULL CHECK (length(key_digest) = 32),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    call_id TEXT NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY(tenant_id, key_digest)
);
CREATE INDEX idempotency_expiry_idx ON idempotency(expires_at);

CREATE TABLE attachments (
    token_digest BLOB PRIMARY KEY CHECK (length(token_digest) = 32),
    attachment_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    leg_id TEXT NOT NULL,
    binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
    worker_id TEXT NOT NULL,
    worker_fence INTEGER NOT NULL CHECK (worker_fence > 0),
    expires_at TEXT NOT NULL,
    consumed_at TEXT NULL,
    revoked_at TEXT NULL,
    body TEXT NOT NULL,
    UNIQUE(call_id, leg_id, binding_generation),
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);
CREATE INDEX attachments_expiry_idx ON attachments(expires_at);

CREATE TABLE provider_references (
    account_key TEXT NOT NULL,
    provider_call_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    leg_id TEXT NOT NULL,
    bound_at TEXT NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY(account_key, provider_call_id),
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);

CREATE TABLE provider_events (
    account_key TEXT NOT NULL,
    event_digest BLOB NOT NULL CHECK (length(event_digest) = 32),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    provider_call_id TEXT NOT NULL,
    receipt_sequence INTEGER NOT NULL UNIQUE CHECK (receipt_sequence > 0),
    received_at TEXT NOT NULL,
    event_state TEXT NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY(account_key, event_digest)
);
CREATE INDEX provider_events_claim_idx
    ON provider_events(event_state, receipt_sequence);
CREATE INDEX provider_events_reference_idx
    ON provider_events(account_key, provider_call_id, receipt_sequence);

CREATE TABLE provider_completions (
    account_key TEXT NOT NULL,
    event_digest BLOB NOT NULL CHECK (length(event_digest) = 32),
    completion_kind TEXT NOT NULL CHECK (completion_kind IN ('command', 'terminal_acknowledgement')),
    body TEXT NOT NULL,
    PRIMARY KEY(account_key, event_digest),
    FOREIGN KEY(account_key, event_digest)
        REFERENCES provider_events(account_key, event_digest) ON DELETE RESTRICT
);
CREATE INDEX provider_completions_kind_idx ON provider_completions(completion_kind);

CREATE TABLE used_connection_ids (
    connection_id TEXT PRIMARY KEY
);

CREATE TABLE outbox (
    effect_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL REFERENCES commands(command_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    aggregate_version INTEGER NOT NULL CHECK (aggregate_version >= 0),
    worker_id TEXT NOT NULL,
    worker_fence INTEGER NOT NULL CHECK (worker_fence > 0),
    available_at TEXT NOT NULL,
    outbox_state TEXT NOT NULL,
    body TEXT NOT NULL,
    UNIQUE(command_id, ordinal)
);
CREATE INDEX outbox_claim_idx
    ON outbox(worker_id, worker_fence, outbox_state, available_at);

CREATE TABLE deadlines (
    call_id TEXT NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    deadline_kind TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    tenant_id TEXT NOT NULL,
    due_at TEXT NOT NULL,
    deadline_state TEXT NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY(call_id, deadline_kind, generation)
);
CREATE INDEX deadlines_due_idx ON deadlines(deadline_state, due_at);

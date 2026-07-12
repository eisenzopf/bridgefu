PRAGMA foreign_keys = ON;

-- OutboxState::Claimed gained claimed_at after schema 1 shipped.  Preserve
-- recoverability of a v1 in-flight claim by using the effect availability
-- time as the conservative lower bound for the acquisition time.
UPDATE outbox
SET body = json_set(body, '$.state.claimed_at', available_at)
WHERE outbox_state = 'claimed'
  AND json_extract(body, '$.state.state') = 'claimed'
  AND json_type(body, '$.state.claimed_at') IS NULL;

-- Every schema-1 idempotency row is a create-call receipt.  Add the typed
-- receipt to the authoritative JSON before the new Rust type reads it, then
-- expose the receipt/operation kinds as drift-detectable columns.
UPDATE idempotency
SET body = json_set(
    body,
    '$.row.receipt',
    json('{"receipt":"create_call"}')
)
WHERE json_type(body, '$.row.receipt') IS NULL;
ALTER TABLE idempotency
    ADD COLUMN receipt_kind TEXT NOT NULL DEFAULT 'create_call'
        CHECK (receipt_kind IN ('create_call', 'service_command', 'control_command'));
ALTER TABLE idempotency
    ADD COLUMN operation_kind TEXT NOT NULL DEFAULT 'create_call'
        CHECK (operation_kind IN ('create_call', 'hangup_call', 'transfer_call', 'dtmf_call'));

ALTER TABLE repository_metadata RENAME TO repository_metadata_v1;
CREATE TABLE repository_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
    epoch INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    provider_receipt_sequence INTEGER NULL CHECK (provider_receipt_sequence > 0)
);
INSERT INTO repository_metadata(
    singleton,
    schema_version,
    epoch,
    provider_receipt_sequence
)
SELECT singleton, 2, epoch, provider_receipt_sequence
FROM repository_metadata_v1;
DROP TABLE repository_metadata_v1;

CREATE TABLE call_execution_plans (
    call_id TEXT PRIMARY KEY REFERENCES calls(call_id) ON DELETE CASCADE,
    plan_version INTEGER NOT NULL CHECK (plan_version > 0),
    first_leg_id TEXT NOT NULL,
    first_endpoint_kind TEXT NOT NULL,
    second_leg_id TEXT NOT NULL,
    second_endpoint_kind TEXT NOT NULL,
    body TEXT NOT NULL,
    CHECK (first_leg_id <> second_leg_id),
    FOREIGN KEY(call_id, first_leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE,
    FOREIGN KEY(call_id, second_leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);

CREATE TABLE service_command_results (
    command_id TEXT PRIMARY KEY REFERENCES commands(command_id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES call_execution_plans(call_id) ON DELETE CASCADE,
    recorded_at TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX service_command_results_call_idx
    ON service_command_results(call_id, recorded_at, command_id);

CREATE TABLE service_effect_payloads (
    effect_id TEXT PRIMARY KEY REFERENCES outbox(effect_id) ON DELETE CASCADE,
    command_id TEXT NOT NULL REFERENCES service_command_results(command_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    payload_kind TEXT NOT NULL,
    body TEXT NOT NULL,
    UNIQUE(command_id, ordinal)
);

CREATE TABLE control_sequences (
    call_id TEXT NOT NULL REFERENCES call_execution_plans(call_id) ON DELETE CASCADE,
    leg_id TEXT NOT NULL,
    binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
    last_sequence INTEGER NOT NULL CHECK (last_sequence > 0),
    body TEXT NOT NULL,
    PRIMARY KEY(call_id, leg_id, binding_generation),
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);

CREATE TABLE control_commands (
    command_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES call_execution_plans(call_id) ON DELETE CASCADE,
    leg_id TEXT NOT NULL,
    binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
    worker_id TEXT NOT NULL REFERENCES workers(worker_id),
    worker_fence INTEGER NOT NULL CHECK (worker_fence > 0),
    control_kind TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    effect_id TEXT NOT NULL UNIQUE,
    body TEXT NOT NULL,
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);
CREATE INDEX control_commands_call_idx
    ON control_commands(call_id, leg_id, binding_generation, recorded_at, command_id);

CREATE TABLE control_outbox (
    effect_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE REFERENCES control_commands(command_id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES call_execution_plans(call_id) ON DELETE CASCADE,
    leg_id TEXT NOT NULL,
    binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
    worker_id TEXT NOT NULL REFERENCES workers(worker_id),
    worker_fence INTEGER NOT NULL CHECK (worker_fence > 0),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    available_at TEXT NOT NULL,
    outbox_state TEXT NOT NULL,
    body TEXT NOT NULL,
    UNIQUE(call_id, leg_id, binding_generation, sequence),
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);
CREATE INDEX control_outbox_claim_idx
    ON control_outbox(worker_id, worker_fence, outbox_state, available_at);

CREATE TABLE outbound_binding_results (
    operation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES call_execution_plans(call_id) ON DELETE CASCADE,
    leg_id TEXT NOT NULL,
    binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
    worker_id TEXT NOT NULL REFERENCES workers(worker_id),
    worker_fence INTEGER NOT NULL CHECK (worker_fence > 0),
    connection_id TEXT NOT NULL UNIQUE REFERENCES used_connection_ids(connection_id),
    transport_kind TEXT NOT NULL,
    bound_at TEXT NOT NULL,
    body TEXT NOT NULL,
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);

CREATE TABLE external_references (
    reference_kind TEXT NOT NULL,
    reference_namespace TEXT NOT NULL,
    reference_value TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES call_execution_plans(call_id) ON DELETE CASCADE,
    leg_id TEXT NOT NULL,
    binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
    effect_id TEXT NOT NULL UNIQUE REFERENCES outbox(effect_id) ON DELETE RESTRICT,
    bound_at TEXT NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY(reference_kind, reference_namespace, reference_value),
    UNIQUE(call_id, leg_id, binding_generation),
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);

CREATE TABLE reconciliation_results (
    effect_id TEXT PRIMARY KEY,
    effect_source TEXT NOT NULL CHECK (effect_source IN ('call', 'control')),
    tenant_id TEXT NOT NULL,
    call_id TEXT NOT NULL REFERENCES call_execution_plans(call_id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL REFERENCES workers(worker_id),
    worker_fence INTEGER NOT NULL CHECK (worker_fence > 0),
    result_kind TEXT NOT NULL CHECK (result_kind IN ('succeeded', 'failed')),
    reconciled_at TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX reconciliation_results_call_idx
    ON reconciliation_results(call_id, reconciled_at, effect_id);

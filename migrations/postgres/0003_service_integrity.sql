-- Preserve service ownership independently of the execution-plan row. A
-- missing plan must fail closed instead of making raw compatibility methods
-- treat the call as legacy-managed.
ALTER TABLE calls
    ADD COLUMN service_managed BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE calls
SET service_managed = TRUE
WHERE call_id IN (SELECT call_id FROM call_execution_plans);

-- Expired operation receipts leave a compact immutable proof rather than
-- making historical command claims indistinguishable from premature deletion.
CREATE TABLE retired_operation_claims (
    command_id UUID PRIMARY KEY,
    receipt_kind TEXT NOT NULL
        CHECK (receipt_kind IN ('service_command', 'control_command')),
    tenant_id TEXT NOT NULL,
    key_digest BYTEA NOT NULL CHECK (octet_length(key_digest) = 32),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    call_id UUID NOT NULL REFERENCES calls(call_id) ON DELETE CASCADE,
    operation_kind TEXT NOT NULL
        CHECK (operation_kind IN ('hangup_call', 'transfer_call', 'dtmf_call')),
    expires_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ NOT NULL,
    body JSONB NOT NULL,
    CHECK (retired_at >= expires_at)
);
CREATE INDEX retired_operation_claims_key_idx
    ON retired_operation_claims(tenant_id, key_digest);
CREATE INDEX retired_operation_claims_call_idx
    ON retired_operation_claims(call_id, command_id);

-- Automatic DTMF cancellation is not an executor reconciliation, so retain
-- exact evidence of the core command that retired the target binding.
CREATE TABLE control_outbox_retirements (
    effect_id UUID PRIMARY KEY REFERENCES control_outbox(effect_id) ON DELETE CASCADE,
    command_id UUID NOT NULL REFERENCES commands(command_id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    call_id UUID NOT NULL REFERENCES call_execution_plans(call_id) ON DELETE CASCADE,
    leg_id UUID NOT NULL,
    binding_generation BIGINT NOT NULL CHECK (binding_generation > 0),
    retired_at TIMESTAMPTZ NOT NULL,
    failure_code TEXT NOT NULL,
    body JSONB NOT NULL,
    FOREIGN KEY(call_id, leg_id) REFERENCES legs(call_id, leg_id) ON DELETE CASCADE
);
CREATE INDEX control_outbox_retirements_command_idx
    ON control_outbox_retirements(command_id, effect_id);

ALTER TABLE repository_metadata
    DROP CONSTRAINT repository_metadata_schema_version_check;
UPDATE repository_metadata SET schema_version = 3 WHERE singleton = TRUE;
ALTER TABLE repository_metadata
    ADD CONSTRAINT repository_metadata_schema_version_check CHECK (schema_version = 3);

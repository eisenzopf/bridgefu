-- Durable, ordered handoff from authoritative PostgreSQL transactions to
-- Redis projections and payload-free wakeups. Redis is never written in the
-- same request path as the authoritative mutation.
ALTER TABLE repository_metadata
    DROP CONSTRAINT repository_metadata_schema_version_check;
UPDATE repository_metadata SET schema_version = 4 WHERE singleton = TRUE;
ALTER TABLE repository_metadata
    ADD CONSTRAINT repository_metadata_schema_version_check CHECK (schema_version = 4);

CREATE TABLE coordination_outbox (
    sequence BIGSERIAL PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    recorded_at_ms BIGINT NOT NULL,
    claim_projector TEXT,
    claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    claimed_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    applied_at_ms BIGINT,
    CHECK (
        (claim_projector IS NULL AND claimed_at_ms IS NULL AND claim_expires_at_ms IS NULL)
        OR
        (claim_projector IS NOT NULL AND claimed_at_ms IS NOT NULL AND claim_expires_at_ms IS NOT NULL)
    ),
    CHECK (claim_expires_at_ms IS NULL OR claim_expires_at_ms > claimed_at_ms),
    CHECK (applied_at_ms IS NULL OR applied_at_ms >= recorded_at_ms)
);

CREATE INDEX coordination_outbox_pending
    ON coordination_outbox (deployment_id, sequence)
    WHERE applied_at_ms IS NULL;

-- Existing v3 workers are expired at migration time by setting the new
-- authoritative expiry to their last update. A process must re-register and
-- advance the fence after upgrade.
ALTER TABLE workers
    ADD COLUMN lease_expires_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch';
UPDATE workers
SET lease_expires_at = updated_at,
    body = jsonb_set(body, '{lease_expires_at}', to_jsonb(updated_at), TRUE);
ALTER TABLE workers ALTER COLUMN lease_expires_at DROP DEFAULT;
CREATE INDEX workers_admission_idx
    ON workers (draining, lease_expires_at, reserved_calls, max_calls, worker_id);

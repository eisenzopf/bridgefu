-- Service-managed provider callbacks retain a distinct replay receipt. Rebuild
-- the table because SQLite cannot widen an existing CHECK constraint in place.
ALTER TABLE provider_completions RENAME TO provider_completions_v4;

CREATE TABLE provider_completions (
    account_key TEXT NOT NULL,
    event_digest BLOB NOT NULL CHECK (length(event_digest) = 32),
    completion_kind TEXT NOT NULL CHECK (
        completion_kind IN (
            'command',
            'terminal_acknowledgement',
            'service_reconciliation'
        )
    ),
    body TEXT NOT NULL,
    PRIMARY KEY(account_key, event_digest),
    FOREIGN KEY(account_key, event_digest)
        REFERENCES provider_events(account_key, event_digest) ON DELETE RESTRICT
);

INSERT INTO provider_completions(account_key, event_digest, completion_kind, body)
SELECT account_key, event_digest, completion_kind, body
FROM provider_completions_v4;

DROP TABLE provider_completions_v4;
CREATE INDEX provider_completions_kind_idx ON provider_completions(completion_kind);

ALTER TABLE repository_metadata RENAME TO repository_metadata_v4;
CREATE TABLE repository_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 5),
    epoch INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    provider_receipt_sequence INTEGER NULL CHECK (provider_receipt_sequence > 0)
);
INSERT INTO repository_metadata(
    singleton,
    schema_version,
    epoch,
    provider_receipt_sequence
)
SELECT singleton, 5, epoch, provider_receipt_sequence
FROM repository_metadata_v4;
DROP TABLE repository_metadata_v4;

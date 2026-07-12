-- Service-managed provider callbacks retain a distinct replay receipt.
ALTER TABLE provider_completions
    DROP CONSTRAINT provider_completions_completion_kind_check;
ALTER TABLE provider_completions
    ADD CONSTRAINT provider_completions_completion_kind_check CHECK (
        completion_kind IN (
            'command',
            'terminal_acknowledgement',
            'service_reconciliation'
        )
    );

ALTER TABLE repository_metadata
    DROP CONSTRAINT repository_metadata_schema_version_check;
UPDATE repository_metadata SET schema_version = 5 WHERE singleton = TRUE;
ALTER TABLE repository_metadata
    ADD CONSTRAINT repository_metadata_schema_version_check CHECK (schema_version = 5);

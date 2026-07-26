CREATE TABLE amazon_connect_cleanup_authority (
    profile_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    contact_id TEXT NOT NULL,
    retained_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (profile_id, instance_id, contact_id)
);

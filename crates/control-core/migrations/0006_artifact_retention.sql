ALTER TABLE fabric_uploads
    ADD COLUMN touched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN reclaiming boolean NOT NULL DEFAULT false;

CREATE INDEX fabric_upload_retention ON fabric_uploads (touched_at, id);

CREATE TABLE fabric_artifact_pins (
    upload_id text NOT NULL REFERENCES fabric_finalized_artifacts (upload_id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('workflow', 'key_context', 'audit')),
    holder text NOT NULL,
    expires_unix_ms bigint NOT NULL CHECK (expires_unix_ms >= 0),
    PRIMARY KEY (upload_id, kind, holder)
);

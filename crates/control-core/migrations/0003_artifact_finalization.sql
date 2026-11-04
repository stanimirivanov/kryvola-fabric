CREATE TABLE fabric_finalized_artifacts (
    upload_id text PRIMARY KEY REFERENCES fabric_uploads (id),
    manifest_digest text NOT NULL,
    canonical_manifest bytea NOT NULL
);

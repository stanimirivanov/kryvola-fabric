CREATE TABLE fabric_revoked_release_approvals (
    approval_digest text PRIMARY KEY CHECK (approval_digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE fabric_disclosure_decisions (
    disclosure_id text PRIMARY KEY CHECK (disclosure_id ~ '^[0-9a-f]{64}$'),
    output_manifest_digest text NOT NULL,
    output_upload_id text NOT NULL,
    canonical_authorization bytea NOT NULL CHECK (octet_length(canonical_authorization) BETWEEN 1 AND 32768),
    canonical_signature bytea NOT NULL CHECK (octet_length(canonical_signature) BETWEEN 1 AND 2048)
);

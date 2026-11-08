CREATE TABLE fabric_execution_receipts (
    tenant_scope text NOT NULL,
    operation_id text NOT NULL,
    execution_id text NOT NULL,
    -- The receipt survives ordinary artifact reclamation.
    output_upload_id text NOT NULL UNIQUE,
    receipt_digest text NOT NULL,
    canonical_receipt bytea NOT NULL CHECK (octet_length(canonical_receipt) BETWEEN 1 AND 32768),
    canonical_signature bytea NOT NULL CHECK (octet_length(canonical_signature) BETWEEN 1 AND 2048),
    PRIMARY KEY (tenant_scope, operation_id, execution_id),
    FOREIGN KEY (tenant_scope, operation_id, execution_id)
        REFERENCES fabric_executions (tenant_scope, operation_id, execution_id)
);

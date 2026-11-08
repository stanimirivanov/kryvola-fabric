CREATE TABLE fabric_execution_output_uploads (
    tenant_scope text NOT NULL,
    operation_id text NOT NULL,
    execution_id text NOT NULL,
    workload text NOT NULL,
    manifest_digest text NOT NULL,
    reserved_bytes bigint NOT NULL,
    -- Retain the binding after reclamation so an execution cannot reserve again.
    upload_id text NOT NULL UNIQUE,
    PRIMARY KEY (tenant_scope, operation_id, execution_id),
    FOREIGN KEY (tenant_scope, operation_id, execution_id)
        REFERENCES fabric_executions (tenant_scope, operation_id, execution_id)
);

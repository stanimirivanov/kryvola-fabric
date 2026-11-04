CREATE TABLE fabric_executions (
    tenant_scope text NOT NULL,
    operation_id text NOT NULL,
    execution_id text NOT NULL,
    attempt_epoch numeric(20, 0) NOT NULL,
    PRIMARY KEY (tenant_scope, operation_id, execution_id),
    FOREIGN KEY (tenant_scope, operation_id, attempt_epoch)
        REFERENCES fabric_attempts (tenant_scope, operation_id, attempt_epoch)
);

CREATE TABLE fabric_selected_results (
    tenant_scope text NOT NULL,
    operation_id text NOT NULL,
    execution_id text NOT NULL,
    upload_id text NOT NULL UNIQUE REFERENCES fabric_finalized_artifacts (upload_id),
    PRIMARY KEY (tenant_scope, operation_id),
    FOREIGN KEY (tenant_scope, operation_id, execution_id)
        REFERENCES fabric_executions (tenant_scope, operation_id, execution_id)
);

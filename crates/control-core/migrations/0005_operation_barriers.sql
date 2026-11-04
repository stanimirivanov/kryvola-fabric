CREATE TABLE fabric_operation_barriers (
    tenant_scope text NOT NULL,
    operation_id text NOT NULL,
    fence numeric(20, 0) NOT NULL CHECK (fence BETWEEN 1 AND 18446744073709551615),
    recovery_epoch numeric(20, 0),
    cancel_key text,
    PRIMARY KEY (tenant_scope, operation_id),
    UNIQUE (tenant_scope, cancel_key),
    FOREIGN KEY (tenant_scope, operation_id) REFERENCES fabric_operations (tenant_scope, operation_id),
    CHECK (recovery_epoch IS NOT NULL OR cancel_key IS NOT NULL)
);

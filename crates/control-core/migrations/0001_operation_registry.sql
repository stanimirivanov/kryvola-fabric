CREATE TABLE fabric_operations (
    tenant_scope text NOT NULL,
    operation_id text NOT NULL,
    idempotency_key text NOT NULL,
    intent jsonb NOT NULL,
    inputs jsonb NOT NULL,
    PRIMARY KEY (tenant_scope, operation_id),
    UNIQUE (tenant_scope, idempotency_key)
);

CREATE TABLE fabric_attempts (
    tenant_scope text NOT NULL,
    operation_id text NOT NULL,
    attempt_epoch numeric(20, 0) NOT NULL CHECK (attempt_epoch BETWEEN 1 AND 18446744073709551615),
    fence numeric(20, 0) NOT NULL CHECK (fence = attempt_epoch),
    lease_expires_unix_ms numeric(20, 0) NOT NULL CHECK (lease_expires_unix_ms BETWEEN 0 AND 18446744073709551615),
    retired boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_scope, operation_id, attempt_epoch),
    FOREIGN KEY (tenant_scope, operation_id) REFERENCES fabric_operations (tenant_scope, operation_id)
);

CREATE UNIQUE INDEX fabric_one_current_attempt
    ON fabric_attempts (tenant_scope, operation_id) WHERE NOT retired;

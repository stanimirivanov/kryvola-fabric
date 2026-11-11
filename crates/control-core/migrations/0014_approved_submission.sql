CREATE TABLE fabric_key_contexts (
    reference jsonb PRIMARY KEY,
    tenant_scope text NOT NULL,
    context_id text NOT NULL,
    immutable_version text NOT NULL,
    canonical_context bytea NOT NULL,
    UNIQUE (tenant_scope, context_id, immutable_version)
);

CREATE TABLE fabric_submission_plans (
    reference jsonb PRIMARY KEY,
    tenant_scope text NOT NULL,
    plan_id text NOT NULL,
    immutable_version text NOT NULL,
    canonical_plan bytea NOT NULL,
    UNIQUE (tenant_scope, plan_id, immutable_version)
);

CREATE TABLE fabric_compute_approvals (
    tenant_scope text NOT NULL,
    approval_digest text NOT NULL,
    registration jsonb NOT NULL,
    PRIMARY KEY (tenant_scope, approval_digest)
);

CREATE TABLE fabric_input_reservations (
    tenant_scope text NOT NULL,
    workload text NOT NULL,
    key_context_ref jsonb NOT NULL,
    idempotency_key text NOT NULL,
    upload_id text NOT NULL UNIQUE,
    scope jsonb NOT NULL,
    byte_length bigint NOT NULL,
    PRIMARY KEY (tenant_scope, workload, key_context_ref, idempotency_key)
);

CREATE TABLE fabric_approved_admissions (
    tenant_scope text NOT NULL,
    operation_id text NOT NULL,
    intent jsonb NOT NULL,
    upload_ids text[] NOT NULL,
    PRIMARY KEY (tenant_scope, operation_id),
    FOREIGN KEY (tenant_scope, operation_id) REFERENCES fabric_operations
);

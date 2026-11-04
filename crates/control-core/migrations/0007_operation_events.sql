CREATE TABLE fabric_outbox (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_scope text NOT NULL,
    operation_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('operation_created','result_selected','cancelled','recovery_fenced')),
    published boolean NOT NULL DEFAULT false,
    UNIQUE (tenant_scope, operation_id, kind),
    FOREIGN KEY (tenant_scope, operation_id) REFERENCES fabric_operations (tenant_scope, operation_id)
);
CREATE INDEX fabric_outbox_pending ON fabric_outbox (id) WHERE NOT published;

CREATE TABLE fabric_inbox (
    subscriber text NOT NULL,
    event_id bigint NOT NULL REFERENCES fabric_outbox (id),
    PRIMARY KEY (subscriber, event_id)
);

-- Replay wakeups for durable state already present at upgrade.
INSERT INTO fabric_outbox (tenant_scope, operation_id, kind)
SELECT tenant_scope, operation_id, 'operation_created' FROM fabric_operations;
INSERT INTO fabric_outbox (tenant_scope, operation_id, kind)
SELECT tenant_scope, operation_id, 'result_selected' FROM fabric_selected_results;
INSERT INTO fabric_outbox (tenant_scope, operation_id, kind)
SELECT tenant_scope, operation_id, 'recovery_fenced' FROM fabric_operation_barriers
WHERE recovery_epoch IS NOT NULL;
INSERT INTO fabric_outbox (tenant_scope, operation_id, kind)
SELECT tenant_scope, operation_id, 'cancelled' FROM fabric_operation_barriers
WHERE cancel_key IS NOT NULL;

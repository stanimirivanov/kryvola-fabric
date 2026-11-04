CREATE TABLE fabric_upload_tenants (
    tenant_scope text PRIMARY KEY
);
CREATE TABLE fabric_uploads (
    id text PRIMARY KEY,
    tenant_scope text NOT NULL REFERENCES fabric_upload_tenants (tenant_scope),
    certificate text NOT NULL,
    scope jsonb NOT NULL,
    reserved_bytes bigint NOT NULL CHECK (reserved_bytes BETWEEN 1 AND 1073741824),
    received_bytes bigint NOT NULL DEFAULT 0 CHECK (received_bytes BETWEEN 0 AND reserved_bytes)
);
CREATE INDEX fabric_upload_tenant ON fabric_uploads (tenant_scope);
CREATE TABLE fabric_upload_parts (
    upload_id text NOT NULL REFERENCES fabric_uploads (id) ON DELETE CASCADE,
    part_index integer NOT NULL CHECK (part_index BETWEEN 0 AND 1023),
    PRIMARY KEY (upload_id, part_index)
);

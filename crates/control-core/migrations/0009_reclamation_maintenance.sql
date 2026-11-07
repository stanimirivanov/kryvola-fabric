ALTER TABLE fabric_uploads ADD COLUMN reclaim_attempted_at timestamptz;
CREATE INDEX fabric_upload_reclaim_order
    ON fabric_uploads (reclaim_attempted_at NULLS FIRST, touched_at, id);

-- Keep only the identifier needed to revisit private object prefixes. The
-- upload and its quota reservation can be deleted independently.
CREATE TABLE fabric_reclaim_tombstones (
    id text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX fabric_reclaim_tombstone_order ON fabric_reclaim_tombstones (checked_at, id);

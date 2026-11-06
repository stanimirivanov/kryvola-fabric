-- NULL preserves the original staging/{upload_id}/{part_index} layout.
ALTER TABLE fabric_upload_parts ADD COLUMN IF NOT EXISTS object_key text;

-- Quiesce writers first. Preserve the column and finalized data on rollback.
LOCK TABLE fabric_upload_parts IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM fabric_upload_parts p
               WHERE p.object_key IS NOT NULL AND NOT EXISTS
               (SELECT 1 FROM fabric_finalized_artifacts f WHERE f.upload_id = p.upload_id)) THEN
        RAISE EXCEPTION 'DRAIN_MAPPED_STAGING_REQUIRED';
    END IF;
END $$;
-- SQLx removes version 8 from its ledger after this succeeds. Keeping the nullable
-- column lets old writers use their original layout and makes reapplication safe.

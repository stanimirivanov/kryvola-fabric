use std::time::Instant;

use serde_json::Value;

use super::{finalize, *};
use crate::{authorization::now_unix_ms, limits::CONTROL_BYTES, registry::Registry};

impl UploadStore {
    /// Call only after redeeming the exact compute-read scope.
    pub(crate) async fn read_compute_input(
        &self,
        scope: &Value,
        part: Option<u16>,
        expires: u64,
        provider_deadline: Instant,
    ) -> Result<Vec<u8>> {
        let mut tx = self.pool.begin().await?;
        let lease = match Registry::artifact_deadline(&mut tx, scope).await {
            Ok(deadline) => deadline,
            Err(error) => {
                // Keep durable lease retirement, just as for upload admission.
                tx.commit().await?;
                return Err(registry_error(error));
            }
        };
        let check_live = || {
            if Instant::now() >= lease {
                Err(UploadError::AttemptExpired)
            } else if Instant::now() >= provider_deadline
                || !now_unix_ms().is_some_and(|now| now < expires)
            {
                Err(UploadError::Denied)
            } else {
                Ok(())
            }
        };
        check_live()?;

        let tenant = scope["attempt"]["tenant_scope"].as_str();
        let operation = scope["attempt"]["operation_id"].as_str();
        let digest = scope["manifest_digest"]
            .as_str()
            .ok_or(UploadError::Denied)?;
        let (approved, context): (bool, String) = sqlx::query_as(
            "SELECT inputs ? $3, intent->'key_context_ref'->>'key_context_digest'
             FROM fabric_operations WHERE tenant_scope=$1 AND operation_id=$2",
        )
        .bind(tenant)
        .bind(operation)
        .bind(digest)
        .fetch_one(&mut *tx)
        .await?;
        if !approved {
            return Err(UploadError::Denied);
        }

        // Hold the operation fence and the upload row until admission. GC takes
        // the upload row exclusively before it can mark or remove these bytes.
        let (id, canonical): (String, Option<Vec<u8>>) = sqlx::query_as(
            "SELECT u.id, CASE WHEN octet_length(f.canonical_manifest) <= $3
                                THEN f.canonical_manifest END
             FROM fabric_finalized_artifacts f JOIN fabric_uploads u ON u.id=f.upload_id
             WHERE u.tenant_scope=$1 AND f.manifest_digest=$2 AND NOT u.reclaiming
             ORDER BY u.id LIMIT 1 FOR SHARE OF u",
        )
        .bind(tenant)
        .bind(digest)
        .bind(CONTROL_BYTES as i32)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(UploadError::NotFound)?;
        let bytes = self
            .verified_read(
                (&id, canonical),
                (tenant, &context, digest),
                part,
                check_live,
            )
            .await?;
        check_live()?;
        tx.commit().await?;
        check_live()?;
        Ok(bytes)
    }
    pub(super) async fn verified_read(
        &self,
        (id, canonical): (&str, Option<Vec<u8>>),
        (tenant, context, digest): (Option<&str>, &str, &str),
        part: Option<u16>,
        check_live: impl Fn() -> Result<()>,
    ) -> Result<Vec<u8>> {
        let canonical = canonical.ok_or(UploadError::Unavailable)?;
        if finalize::digest(b"kryvola/manifest/v2\0", &[&canonical]) != digest {
            return Err(UploadError::Unavailable);
        }
        let manifest = finalize::manifest(&canonical).map_err(|_| UploadError::Unavailable)?;
        if manifest["tenant_scope"].as_str() != tenant
            || manifest["key_context_digest"].as_str() != Some(context)
        {
            return Err(UploadError::Denied);
        }
        Ok(if let Some(index) = part {
            let chunk = manifest["ordered_chunk_entries"]
                .get(usize::from(index))
                .ok_or(UploadError::NotFound)?;
            let length = finalize::number(&chunk["byte_length"])
                .ok()
                .filter(|length| (1..=CHUNK_MAX_BYTES as u64).contains(length))
                .ok_or(UploadError::Unavailable)?;
            if finalize::number(&chunk["index"]) != Ok(u64::from(index)) {
                return Err(UploadError::Unavailable);
            }
            check_live()?;
            let key = Path::from(format!("immutable/{id}/{index}"));
            let bytes = finalize::read_exact_object(self.objects.as_ref(), &key, length as usize)
                .await
                .map_err(|_| UploadError::Unavailable)?;
            if chunk["chunk_digest"]
                != finalize::digest(
                    b"kryvola/chunk/v1\0",
                    &[
                        &u64::from(index).to_le_bytes(),
                        &length.to_le_bytes(),
                        &bytes,
                    ],
                )
            {
                return Err(UploadError::Unavailable);
            }
            bytes
        } else {
            canonical
        })
    }
}

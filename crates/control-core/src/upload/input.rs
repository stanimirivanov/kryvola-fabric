use object_store::ObjectStoreExt;
use serde_json::Value;

use super::*;

impl UploadStore {
    pub(crate) fn registry(&self) -> crate::registry::Registry {
        crate::registry::Registry::new(self.pool.clone())
    }

    pub(crate) async fn input_scope(
        &self,
        tenant: &str,
        workload: &str,
        id: &str,
    ) -> Result<Value> {
        sqlx::query_scalar(
            "SELECT scope FROM fabric_uploads WHERE id=$1 AND tenant_scope=$2
             AND certificate=$3 AND scope->>'purpose'='INPUT_UPLOAD' AND NOT reclaiming",
        )
        .bind(id)
        .bind(tenant)
        .bind(workload)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(UploadError::Denied)
    }

    pub(super) async fn input_reservation_retry(
        tx: &mut Transaction<'_, Postgres>,
        permit: &UploadPermit,
        bytes: i64,
    ) -> Result<Option<String>> {
        let saved: Option<(String, Value, i64)> = sqlx::query_as(
            "SELECT upload_id,scope,byte_length FROM fabric_input_reservations
             WHERE tenant_scope=$1 AND workload=$2 AND key_context_ref=$3 AND idempotency_key=$4",
        )
        .bind(&permit.tenant)
        .bind(&permit.certificate)
        .bind(&permit.scope["key_context_ref"])
        .bind(permit.scope["idempotency_key"].as_str())
        .fetch_optional(&mut **tx)
        .await?;
        let Some((id, scope, length)) = saved else {
            return Ok(None);
        };
        if scope != permit.scope || length != bytes {
            return Err(UploadError::IdempotencyConflict);
        }
        let open: Option<bool> =
            sqlx::query_scalar("SELECT NOT reclaiming FROM fabric_uploads WHERE id=$1 FOR SHARE")
                .bind(&id)
                .fetch_optional(&mut **tx)
                .await?;
        if open != Some(true) {
            return Err(UploadError::IdempotencyConflict);
        }
        Ok(Some(id))
    }

    pub(super) async fn record_input_reservation(
        tx: &mut Transaction<'_, Postgres>,
        permit: &UploadPermit,
        id: &str,
        bytes: i64,
    ) -> Result<()> {
        sqlx::query("INSERT INTO fabric_input_reservations VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(&permit.tenant)
            .bind(&permit.certificate)
            .bind(&permit.scope["key_context_ref"])
            .bind(permit.scope["idempotency_key"].as_str())
            .bind(id)
            .bind(&permit.scope)
            .bind(bytes)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    pub(super) async fn input_manifest_retry(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: &str,
        bytes: &[u8],
    ) -> Result<Option<Result<()>>> {
        let stored: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT canonical_manifest FROM fabric_finalized_artifacts WHERE upload_id=$1",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
        let saved = if let Some(stored) = stored {
            stored
        } else {
            let path = Path::from(format!("staging/{id}/manifest"));
            let head = match timeout(IO_TIMEOUT, self.objects.head(&path)).await {
                Ok(Ok(head)) => head,
                Ok(Err(object_store::Error::NotFound { .. })) => return Ok(None),
                _ => return Err(UploadError::Unavailable),
            };
            if head.size != bytes.len() as u64 {
                return Ok(Some(Err(UploadError::IdempotencyConflict)));
            }
            finalize::read_exact_object(self.objects.as_ref(), &path, bytes.len()).await?
        };
        Ok(Some(if saved == bytes {
            Ok(())
        } else {
            Err(UploadError::IdempotencyConflict)
        }))
    }

    pub(super) async fn existing_input_part(
        tx: &mut Transaction<'_, Postgres>,
        id: &str,
        index: u16,
    ) -> Result<Option<Path>> {
        let saved: Option<String> = sqlx::query_scalar(
            "SELECT object_key FROM fabric_upload_parts WHERE upload_id=$1 AND part_index=$2",
        )
        .bind(id)
        .bind(i32::from(index))
        .fetch_optional(&mut **tx)
        .await?;
        Ok(saved.map(Path::from))
    }

    pub(super) async fn check_input_part(
        &self,
        key: &Path,
        length: usize,
        body: impl AsyncRead + Unpin,
    ) -> Result<()> {
        let head = timeout(IO_TIMEOUT, self.objects.head(key))
            .await
            .map_err(|_| UploadError::Unavailable)?
            .map_err(|_| UploadError::Unavailable)?;
        if head.size != length as u64 {
            return Err(UploadError::IdempotencyConflict);
        }
        let saved = finalize::read_exact_object(self.objects.as_ref(), key, length).await?;
        let mut proposed = Vec::new();
        timeout(
            IO_TIMEOUT,
            body.take(length as u64 + 1).read_to_end(&mut proposed),
        )
        .await
        .map_err(|_| UploadError::Unavailable)?
        .map_err(|_| UploadError::Integrity)?;
        if saved != proposed {
            return Err(UploadError::IdempotencyConflict);
        }
        Ok(())
    }
}

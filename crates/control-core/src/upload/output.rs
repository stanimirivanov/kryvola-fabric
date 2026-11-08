use std::time::Instant;

use serde_json::Value;

use super::{Result, UploadError, UploadStore, check_permit, registry_error};
use crate::{authorization::UploadPermit, registry::Registry};

#[derive(sqlx::FromRow)]
pub(super) struct OutputBinding {
    pub upload_id: String,
    pub workload: String,
    pub manifest_digest: String,
    pub reserved_bytes: i64,
    pub available: bool,
    pub present: bool,
}

pub(super) async fn binding(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &Value,
) -> Result<Option<OutputBinding>> {
    let attempt = &scope["attempt"];
    Ok(sqlx::query_as(
        "SELECT b.upload_id, b.workload, b.manifest_digest, b.reserved_bytes,
                EXISTS (SELECT 1 FROM fabric_uploads u
                        WHERE u.id=b.upload_id AND NOT u.reclaiming) AS available,
                EXISTS (SELECT 1 FROM fabric_uploads u WHERE u.id=b.upload_id) AS present
         FROM fabric_execution_output_uploads b
         WHERE b.tenant_scope=$1 AND b.operation_id=$2 AND b.execution_id=$3",
    )
    .bind(attempt["tenant_scope"].as_str())
    .bind(attempt["operation_id"].as_str())
    .bind(scope["execution_id"].as_str())
    .fetch_optional(&mut **tx)
    .await?)
}

pub(super) async fn record(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    permit: &UploadPermit,
    execution: &str,
    upload: &str,
    size: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO fabric_execution_output_uploads
         (tenant_scope, operation_id, execution_id, workload, manifest_digest, reserved_bytes, upload_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&permit.tenant)
    .bind(permit.scope["attempt"]["operation_id"].as_str())
    .bind(execution)
    .bind(&permit.certificate)
    .bind(permit.scope["manifest_digest"].as_str())
    .bind(size)
    .bind(upload)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

impl UploadStore {
    pub(crate) async fn output_deadline(&self, scope: &Value, workload: &str) -> Result<Instant> {
        let mut tx = self.pool.begin().await?;
        let deadline = match Registry::artifact_deadline(&mut tx, scope).await {
            Ok(deadline) => deadline,
            Err(error) => {
                tx.commit().await?;
                return Err(registry_error(error));
            }
        };
        let attempt = &scope["attempt"];
        let epoch: String = sqlx::query_scalar(
            "SELECT attempt_epoch::text FROM fabric_executions
             WHERE tenant_scope=$1 AND operation_id=$2 AND execution_id=$3",
        )
        .bind(attempt["tenant_scope"].as_str())
        .bind(attempt["operation_id"].as_str())
        .bind(scope["execution_id"].as_str())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(UploadError::NotFound)?;
        if attempt["attempt_epoch"] != epoch {
            return Err(UploadError::StaleFence);
        }
        let saved = binding(&mut tx, scope).await?;
        if scope["target"]["action"] == "RESERVE" {
            if let Some(saved) = saved {
                if saved.workload != workload {
                    return Err(UploadError::Denied);
                }
                if !saved.available || scope["manifest_digest"] != saved.manifest_digest {
                    return Err(UploadError::IdempotencyConflict);
                }
            }
        } else {
            let saved = saved
                .filter(|row| {
                    row.available || (row.present && scope["target"]["action"] == "ABORT")
                })
                .ok_or(UploadError::NotFound)?;
            if saved.workload != workload
                || scope["manifest_digest"] != saved.manifest_digest
                || scope["target"]["upload_id"] != saved.upload_id
            {
                return Err(UploadError::Denied);
            }
        }
        tx.commit().await?;
        Ok(deadline)
    }
}

pub(super) async fn reservation_retry(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    permit: &UploadPermit,
    bytes: i64,
) -> Result<Option<String>> {
    let Some(saved) = binding(tx, &permit.scope).await? else {
        return Ok(None);
    };
    if saved.workload != permit.certificate {
        return Err(UploadError::Denied);
    }
    if !saved.available
        || permit.scope["manifest_digest"] != saved.manifest_digest
        || saved.reserved_bytes != bytes
    {
        return Err(UploadError::IdempotencyConflict);
    }
    // Serialize a recovered response with reclaim marking as well as fencing.
    let row: Option<String> = sqlx::query_scalar(
        "SELECT id FROM fabric_uploads WHERE id=$1 AND NOT reclaiming FOR SHARE",
    )
    .bind(&saved.upload_id)
    .fetch_optional(&mut **tx)
    .await?;
    check_permit(permit)?;
    row.map(Some).ok_or(UploadError::IdempotencyConflict)
}

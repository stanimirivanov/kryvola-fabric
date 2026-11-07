use super::*;

#[derive(Clone, Copy)]
pub struct ExecutionTarget<'a> {
    pub workflow_epoch: u64,
    pub attempt_epoch: u64,
    pub fence: u64,
    pub execution_id: &'a str,
    pub plan_digest: &'a str,
    pub policy_digest: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedResult {
    pub execution_id: String,
    pub attempt_epoch: u64,
    pub upload_id: String,
    pub manifest_digest: String,
}

pub(super) async fn read_selection<'e>(
    db: impl sqlx::PgExecutor<'e>,
    key: OperationKey<'_>,
) -> Result<Option<SelectedResult>> {
    sqlx::query(
        "SELECT s.execution_id, e.attempt_epoch::text AS epoch, s.upload_id, a.manifest_digest
         FROM fabric_selected_results s
         JOIN fabric_executions e USING (tenant_scope, operation_id, execution_id)
         JOIN fabric_finalized_artifacts a USING (upload_id)
         WHERE s.tenant_scope = $1 AND s.operation_id = $2",
    )
    .bind(key.tenant_scope)
    .bind(key.operation_id)
    .fetch_optional(db)
    .await?
    .map(|row| {
        Ok(SelectedResult {
            execution_id: row.try_get("execution_id")?,
            attempt_epoch: read_u64(&row, "epoch")?,
            upload_id: row.try_get("upload_id")?,
            manifest_digest: row.try_get("manifest_digest")?,
        })
    })
    .transpose()
}

async fn lock_context(
    tx: &mut Transaction<'_, Postgres>,
    key: OperationKey<'_>,
    target: ExecutionTarget<'_>,
) -> Result<String> {
    let id = target.execution_id.as_bytes();
    if id.len() > 128
        || !id.first().is_some_and(u8::is_ascii_alphanumeric)
        || !id
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(c))
    {
        return Err(RegistryError::InvalidIntent);
    }
    let operation: Json<Value> = sqlx::query_scalar(
        "SELECT intent FROM fabric_operations WHERE tenant_scope = $1 AND operation_id = $2 FOR UPDATE",
    )
    .bind(key.tenant_scope).bind(key.operation_id)
    .fetch_optional(&mut **tx).await?.ok_or(RegistryError::NotFound)?;
    super::barriers::require_open(tx, key).await?;
    if operation["workflow_epoch"].as_str() != Some(&target.workflow_epoch.to_string()) {
        return Err(RegistryError::StaleWorkflow);
    }
    if operation["plan_ref"]["plan_digest"] != target.plan_digest
        || operation["policy_digest"] != target.policy_digest
    {
        return Err(RegistryError::CandidateMismatch);
    }
    operation["key_context_ref"]["key_context_digest"]
        .as_str()
        .map(str::to_owned)
        .ok_or(RegistryError::Unavailable)
}

async fn require_live(
    tx: &mut Transaction<'_, Postgres>,
    key: OperationKey<'_>,
    target: ExecutionTarget<'_>,
) -> Result<()> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut **tx)
            .await?;
    let now = u64::try_from(now).map_err(|_| RegistryError::Unavailable)?;
    match current_attempt(tx, key, now).await? {
        Some((lease, retired))
            if lease.attempt_epoch == target.attempt_epoch && lease.fence == target.fence =>
        {
            if retired {
                Err(RegistryError::AttemptExpired)
            } else {
                Ok(())
            }
        }
        _ => Err(RegistryError::StaleFence),
    }
}

impl Registry {
    pub async fn selected_result(&self, key: OperationKey<'_>) -> Result<Option<SelectedResult>> {
        read_selection(&self.pool, key).await
    }

    pub async fn register_execution(
        &self,
        key: OperationKey<'_>,
        target: ExecutionTarget<'_>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        lock_context(&mut tx, key, target).await?;
        if read_selection(&mut *tx, key).await?.is_some() {
            return Err(RegistryError::SelectionConflict);
        }
        if let Err(error) = require_live(&mut tx, key, target).await {
            tx.commit().await?;
            return Err(error);
        }
        let epoch = target.attempt_epoch.to_string();
        sqlx::query(
            "INSERT INTO fabric_executions (tenant_scope, operation_id, execution_id, attempt_epoch)
             VALUES ($1,$2,$3,$4::text::numeric) ON CONFLICT DO NOTHING",
        ).bind(key.tenant_scope).bind(key.operation_id).bind(target.execution_id).bind(&epoch)
            .execute(&mut *tx).await?;
        let saved: String = sqlx::query_scalar(
            "SELECT attempt_epoch::text FROM fabric_executions
             WHERE tenant_scope = $1 AND operation_id = $2 AND execution_id = $3",
        )
        .bind(key.tenant_scope)
        .bind(key.operation_id)
        .bind(target.execution_id)
        .fetch_one(&mut *tx)
        .await?;
        if saved != epoch {
            return Err(RegistryError::StaleFence);
        }
        tx.commit().await?;
        Ok(())
    }

    /// The authenticated coordinator attests which execution produced this upload.
    pub async fn select_result(
        &self,
        key: OperationKey<'_>,
        target: ExecutionTarget<'_>,
        upload_id: &str,
        manifest_digest: &str,
    ) -> Result<SelectedResult> {
        self.select_candidate(key, target, Some(upload_id), manifest_digest)
            .await
    }

    pub(crate) async fn select_by_digest(
        &self,
        key: OperationKey<'_>,
        target: ExecutionTarget<'_>,
        manifest_digest: &str,
    ) -> Result<SelectedResult> {
        self.select_candidate(key, target, None, manifest_digest)
            .await
    }

    async fn select_candidate(
        &self,
        key: OperationKey<'_>,
        target: ExecutionTarget<'_>,
        upload_id: Option<&str>,
        manifest_digest: &str,
    ) -> Result<SelectedResult> {
        let mut tx = self.pool.begin().await?;
        let context = lock_context(&mut tx, key, target).await?;
        if let Some(saved) = read_selection(&mut *tx, key).await? {
            return if saved.execution_id == target.execution_id
                && saved.attempt_epoch == target.attempt_epoch
                && saved.manifest_digest == manifest_digest
                && upload_id.is_none_or(|id| id == saved.upload_id)
                && target.fence == saved.attempt_epoch
            {
                Ok(saved)
            } else {
                Err(RegistryError::SelectionConflict)
            };
        }
        if let Err(error) = require_live(&mut tx, key, target).await {
            tx.commit().await?;
            return Err(error);
        }

        // Serialize the artifact pin with reclamation. Keep the operation -> upload lock order.
        let scope = serde_json::json!({
            "manifest_digest": manifest_digest, "purpose": "COMPUTE_WRITE",
            "attempt": {
                "tenant_scope": key.tenant_scope, "operation_id": key.operation_id,
                "workflow_epoch": target.workflow_epoch.to_string(),
                "attempt_epoch": target.attempt_epoch.to_string(),
                "fence": target.fence.to_string(),
            }
        });
        let upload_id: String = sqlx::query_scalar(
            "SELECT u.id FROM fabric_finalized_artifacts a JOIN fabric_uploads u ON u.id = a.upload_id
             WHERE ($1::text IS NULL OR u.id = $1) AND u.tenant_scope = $2
               AND a.manifest_digest = $3 AND u.scope @> $4 AND NOT u.reclaiming
               AND convert_from(a.canonical_manifest, 'UTF8')::jsonb->>'key_context_digest' = $5
             ORDER BY u.id LIMIT 1 FOR UPDATE OF u",
        ).bind(upload_id).bind(key.tenant_scope).bind(manifest_digest).bind(Json(scope)).bind(context)
            .fetch_optional(&mut *tx).await?.ok_or(RegistryError::CandidateMismatch)?;
        let result = SelectedResult {
            execution_id: target.execution_id.to_owned(),
            attempt_epoch: target.attempt_epoch,
            upload_id,
            manifest_digest: manifest_digest.to_owned(),
        };

        let inserted = sqlx::query(
            "INSERT INTO fabric_selected_results (tenant_scope, operation_id, execution_id, upload_id)
             SELECT e.tenant_scope, e.operation_id, e.execution_id, $4
             FROM fabric_executions e JOIN fabric_attempts a USING (tenant_scope, operation_id, attempt_epoch)
             WHERE e.tenant_scope = $1 AND e.operation_id = $2 AND e.execution_id = $3
               AND a.fence = $5::text::numeric AND NOT a.retired
               AND a.lease_expires_unix_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)
             ON CONFLICT DO NOTHING",
        ).bind(key.tenant_scope).bind(key.operation_id).bind(target.execution_id).bind(&result.upload_id)
            .bind(target.fence.to_string()).execute(&mut *tx).await?;
        if inserted.rows_affected() != 1 {
            let status = require_live(&mut tx, key, target).await;
            tx.commit().await?;
            return Err(status.err().unwrap_or(RegistryError::CandidateMismatch));
        }
        super::events::enqueue(&mut tx, key, "result_selected").await?;
        tx.commit().await?;
        Ok(result)
    }
}

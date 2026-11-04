use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cancellation {
    Pending,
    Cancelled { fence: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryFence {
    pub fence: u64,
    pub successor_epoch: u64,
}

// All callers hold the operation row lock before reading or writing the barrier.
async fn read(
    tx: &mut Transaction<'_, Postgres>,
    key: OperationKey<'_>,
) -> Result<Option<sqlx::postgres::PgRow>> {
    Ok(sqlx::query(
        "SELECT fence::text AS fence, recovery_epoch::text AS recovery_epoch, cancel_key
         FROM fabric_operation_barriers WHERE tenant_scope = $1 AND operation_id = $2",
    )
    .bind(key.tenant_scope)
    .bind(key.operation_id)
    .fetch_optional(&mut **tx)
    .await?)
}

pub(super) async fn require_open(
    tx: &mut Transaction<'_, Postgres>,
    key: OperationKey<'_>,
) -> Result<()> {
    match read(tx, key).await? {
        Some(row) if row.try_get::<Option<&str>, _>("cancel_key")?.is_some() => {
            Err(RegistryError::Cancelled)
        }
        Some(_) => Err(RegistryError::RecoveryFenced),
        None => Ok(()),
    }
}

async fn lock(tx: &mut Transaction<'_, Postgres>, key: OperationKey<'_>) -> Result<u64> {
    let row = sqlx::query(
        "SELECT intent->>'workflow_epoch' AS workflow FROM fabric_operations
         WHERE tenant_scope = $1 AND operation_id = $2 FOR UPDATE",
    )
    .bind(key.tenant_scope)
    .bind(key.operation_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(RegistryError::NotFound)?;
    read_u64(&row, "workflow")
}

async fn next_fence(tx: &mut Transaction<'_, Postgres>, key: OperationKey<'_>) -> Result<u64> {
    let latest: String = sqlx::query_scalar(
        "SELECT COALESCE(max(fence), 0)::text FROM fabric_attempts
         WHERE tenant_scope = $1 AND operation_id = $2",
    )
    .bind(key.tenant_scope)
    .bind(key.operation_id)
    .fetch_one(&mut **tx)
    .await?;
    increment(latest.parse().map_err(|_| RegistryError::Unavailable)?)
}

fn increment(value: u64) -> Result<u64> {
    value.checked_add(1).ok_or(RegistryError::EpochConflict)
}

async fn retire(tx: &mut Transaction<'_, Postgres>, key: OperationKey<'_>) -> Result<()> {
    sqlx::query("UPDATE fabric_attempts SET retired = true WHERE tenant_scope = $1 AND operation_id = $2 AND NOT retired")
        .bind(key.tenant_scope).bind(key.operation_id).execute(&mut **tx).await?;
    Ok(())
}

impl Registry {
    /// Shared barrier for authenticated owner and administrative cancellation callers.
    pub async fn cancel_operation(
        &self,
        key: OperationKey<'_>,
        idempotency_key: &str,
    ) -> Result<Cancellation> {
        match self.commit_cancel(key, idempotency_key).await {
            Ok(fence) => Ok(Cancellation::Cancelled { fence }),
            Err(RegistryError::Unavailable) => Ok(Cancellation::Pending),
            Err(error) => Err(error),
        }
    }

    async fn commit_cancel(&self, key: OperationKey<'_>, idempotency_key: &str) -> Result<u64> {
        let id = idempotency_key.as_bytes();
        if id.len() > 128
            || !id.first().is_some_and(u8::is_ascii_alphanumeric)
            || !id
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(c))
        {
            return Err(RegistryError::InvalidIntent);
        }
        let mut tx = self.pool.begin().await?;
        lock(&mut tx, key).await?;
        let fence = if let Some(row) = read(&mut tx, key).await? {
            let fence = read_u64(&row, "fence")?;
            if let Some(saved) = row.try_get::<Option<&str>, _>("cancel_key")? {
                if saved != idempotency_key {
                    return Err(RegistryError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(fence);
            }
            increment(fence)?
        } else {
            next_fence(&mut tx, key).await?
        };
        sqlx::query(
            "INSERT INTO fabric_operation_barriers (tenant_scope, operation_id, fence, cancel_key)
             VALUES ($1,$2,$3::text::numeric,$4)
             ON CONFLICT (tenant_scope, operation_id) DO UPDATE
             SET fence = EXCLUDED.fence, cancel_key = EXCLUDED.cancel_key",
        )
        .bind(key.tenant_scope)
        .bind(key.operation_id)
        .bind(fence.to_string())
        .bind(idempotency_key)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .is_some_and(|db| db.is_unique_violation())
            {
                RegistryError::IdempotencyConflict
            } else {
                RegistryError::Unavailable
            }
        })?;
        retire(&mut tx, key).await?;
        super::events::enqueue(&mut tx, key, "cancelled").await?;
        tx.commit().await?;
        Ok(fence)
    }

    /// Quarantine the old operation. The successor epoch is a recovery target, not admission.
    pub async fn fence_for_recovery(
        &self,
        key: OperationKey<'_>,
        workflow_epoch: u64,
    ) -> Result<RecoveryFence> {
        let mut tx = self.pool.begin().await?;
        if lock(&mut tx, key).await? != workflow_epoch {
            return Err(RegistryError::StaleWorkflow);
        }
        if let Some(row) = read(&mut tx, key).await? {
            if row.try_get::<Option<&str>, _>("cancel_key")?.is_some() {
                return Err(RegistryError::Cancelled);
            }
            let saved = RecoveryFence {
                fence: read_u64(&row, "fence")?,
                successor_epoch: read_u64(&row, "recovery_epoch")?,
            };
            tx.commit().await?;
            return Ok(saved);
        }
        let fence = next_fence(&mut tx, key).await?;
        let successor_epoch = increment(workflow_epoch)?;
        sqlx::query(
            "INSERT INTO fabric_operation_barriers (tenant_scope, operation_id, fence, recovery_epoch)
             VALUES ($1,$2,$3::text::numeric,$4::text::numeric)",
        ).bind(key.tenant_scope).bind(key.operation_id).bind(fence.to_string())
            .bind(successor_epoch.to_string()).execute(&mut *tx).await?;
        retire(&mut tx, key).await?;
        super::events::enqueue(&mut tx, key, "recovery_fenced").await?;
        tx.commit().await?;
        Ok(RecoveryFence {
            fence,
            successor_epoch,
        })
    }
}

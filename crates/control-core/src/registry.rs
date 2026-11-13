//! PostgreSQL operation and attempt registry for trusted coordinator callers.

mod barriers;
mod events;
pub use barriers::{Cancellation, RecoveryFence};
pub use events::{Broker, Delivery, DeliveryRef};
mod receipt;
mod release;
pub(crate) use release::Trust;
pub use release::{ReleasePolicy, ReleaseRequest, disclosure_id};
mod selection;
pub(crate) mod submission;
pub use selection::{ExecutionTarget, SelectedResult};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction, types::Json};

use crate::{check_control_size, wire::ControlValidator};

const LEASE_MS: u64 = 30_000;
type Result<T> = std::result::Result<T, RegistryError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    InvalidIntent,
    Forbidden,
    IdempotencyConflict,
    NotFound,
    StaleWorkflow,
    EpochConflict,
    AttemptExpired,
    StaleFence,
    CandidateMismatch,
    SelectionConflict,
    Cancelled,
    RecoveryFenced,
    Unavailable,
}

impl From<sqlx::Error> for RegistryError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

#[derive(Clone, Copy)]
pub struct OperationKey<'a> {
    pub tenant_scope: &'a str,
    pub operation_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRecord {
    pub operation: Value,
    pub input_manifest_digests: Vec<String>,
}

pub struct OperationIntent {
    record: OperationRecord,
    tenant: String,
    operation: String,
    idempotency: String,
    workflow: u64,
}

fn string(value: &Value, field: &str) -> Result<String> {
    value[field]
        .as_str()
        .map(str::to_owned)
        .ok_or(RegistryError::InvalidIntent)
}

impl OperationIntent {
    pub fn new(
        validator: &ControlValidator,
        operation: Value,
        input_manifest_digests: Vec<String>,
    ) -> Result<Self> {
        if !(1..=128).contains(&input_manifest_digests.len())
            || input_manifest_digests.iter().any(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            || check_control_size(operation.to_string().len(), false).is_err()
        {
            return Err(RegistryError::InvalidIntent);
        }
        validator
            .validate_operation(&operation)
            .map_err(|_| RegistryError::InvalidIntent)?;
        Ok(Self {
            tenant: string(&operation, "tenant_scope")?,
            operation: string(&operation, "operation_id")?,
            idempotency: string(&operation, "idempotency_key")?,
            workflow: string(&operation, "workflow_epoch")?
                .parse()
                .map_err(|_| RegistryError::InvalidIntent)?,
            record: OperationRecord {
                operation,
                input_manifest_digests,
            },
        })
    }

    pub fn key(&self) -> OperationKey<'_> {
        OperationKey {
            tenant_scope: &self.tenant,
            operation_id: &self.operation,
        }
    }

    pub fn workflow_epoch(&self) -> u64 {
        self.workflow
    }

    pub fn record(&self) -> &OperationRecord {
        &self.record
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptLease {
    pub attempt_epoch: u64,
    pub fence: u64,
    pub expires_unix_ms: u64,
}

pub struct Registry {
    pool: PgPool,
}

fn read_operation(row: sqlx::postgres::PgRow) -> Result<OperationRecord> {
    Ok(OperationRecord {
        operation: row.try_get::<Json<Value>, _>("intent")?.0,
        input_manifest_digests: row.try_get::<Json<Vec<String>>, _>("inputs")?.0,
    })
}

fn read_u64(row: &sqlx::postgres::PgRow, column: &str) -> Result<u64> {
    row.try_get::<&str, _>(column)?
        .parse()
        .map_err(|_| RegistryError::Unavailable)
}

impl Registry {
    pub(crate) fn pool(&self) -> PgPool {
        self.pool.clone()
    }
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!()
            .run(&self.pool)
            .await
            .map_err(|_| RegistryError::Unavailable)
    }

    pub async fn create_operation(&self, intent: &OperationIntent) -> Result<OperationRecord> {
        let mut tx = self.pool.begin().await?;
        let (saved, _) = Self::record_operation(&mut tx, intent).await?;
        tx.commit().await?;
        Ok(saved)
    }

    async fn record_operation(
        tx: &mut Transaction<'_, Postgres>,
        intent: &OperationIntent,
    ) -> Result<(OperationRecord, bool)> {
        let key = intent.key();
        let inserted = sqlx::query(
            "INSERT INTO fabric_operations (tenant_scope, operation_id, idempotency_key, intent, inputs) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(key.tenant_scope)
        .bind(key.operation_id)
        .bind(&intent.idempotency)
        .bind(Json(&intent.record.operation))
        .bind(Json(&intent.record.input_manifest_digests))
        .execute(&mut **tx)
        .await?;
        let row = sqlx::query(
            "SELECT intent, inputs FROM fabric_operations WHERE tenant_scope = $1 AND idempotency_key = $2",
        )
        .bind(key.tenant_scope)
        .bind(&intent.idempotency)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(RegistryError::IdempotencyConflict)?;
        let saved = read_operation(row)?;
        if saved != *intent.record() {
            return Err(RegistryError::IdempotencyConflict);
        }
        if inserted.rows_affected() == 1 {
            events::enqueue(tx, key, "operation_created").await?;
        }
        Ok((saved, inserted.rows_affected() == 1))
    }

    pub async fn lookup_operation(&self, key: OperationKey<'_>) -> Result<Option<OperationRecord>> {
        sqlx::query("SELECT intent, inputs FROM fabric_operations WHERE tenant_scope = $1 AND operation_id = $2")
            .bind(key.tenant_scope)
            .bind(key.operation_id)
            .fetch_optional(&self.pool)
            .await?
            .map(read_operation)
            .transpose()
    }

    /// Metadata projection only; even RELEASED does not authorize an artifact read.
    pub async fn public_status(&self, key: OperationKey<'_>) -> Result<Option<String>> {
        sqlx::query_scalar("SELECT CASE
            WHEN EXISTS (SELECT 1 FROM fabric_operation_barriers b WHERE b.tenant_scope=o.tenant_scope AND b.operation_id=o.operation_id AND b.cancel_key IS NOT NULL) THEN 'CANCELLED'
            WHEN EXISTS (
                SELECT 1 FROM fabric_selected_results s
                JOIN fabric_disclosure_decisions d ON d.output_upload_id=s.upload_id
                JOIN fabric_finalized_artifacts a ON a.upload_id=s.upload_id
                WHERE s.tenant_scope=o.tenant_scope AND s.operation_id=o.operation_id
                  AND d.output_manifest_digest=a.manifest_digest
                  AND (convert_from(d.canonical_authorization,'UTF8')::jsonb->>'tenant_scope')=o.tenant_scope
                  AND (convert_from(d.canonical_authorization,'UTF8')::jsonb->>'operation_id')=o.operation_id
                  AND (convert_from(d.canonical_authorization,'UTF8')::jsonb->>'workflow_epoch')=(o.intent->>'workflow_epoch')
            ) THEN 'RELEASED'
            WHEN EXISTS (SELECT 1 FROM fabric_selected_results s WHERE s.tenant_scope=o.tenant_scope AND s.operation_id=o.operation_id) THEN 'COMPUTE_SELECTED'
            WHEN (intent->>'deadline_unix_ms')::numeric <= floor(extract(epoch FROM clock_timestamp())*1000) THEN 'EXPIRED'
            ELSE NULL END FROM fabric_operations o WHERE tenant_scope=$1 AND operation_id=$2")
            .bind(key.tenant_scope).bind(key.operation_id).fetch_optional(&self.pool).await?
            .ok_or(RegistryError::NotFound)
    }

    pub(crate) async fn artifact_deadline(
        tx: &mut Transaction<'_, Postgres>,
        scope: &Value,
    ) -> Result<std::time::Instant> {
        Self::lock_artifact_attempt(tx, &scope["attempt"], false).await
    }

    async fn lock_artifact_attempt(
        tx: &mut Transaction<'_, Postgres>,
        attempt: &Value,
        allow_selected: bool,
    ) -> Result<std::time::Instant> {
        let tenant = string(attempt, "tenant_scope")?;
        let operation = string(attempt, "operation_id")?;
        let key = OperationKey {
            tenant_scope: &tenant,
            operation_id: &operation,
        };
        let number = |field: &str| -> Result<u64> {
            string(attempt, field)?
                .parse()
                .map_err(|_| RegistryError::InvalidIntent)
        };
        let row = sqlx::query("SELECT intent->>'workflow_epoch' AS workflow, intent->>'deadline_unix_ms' AS deadline FROM fabric_operations WHERE tenant_scope=$1 AND operation_id=$2 FOR UPDATE")
            .bind(&tenant).bind(&operation).fetch_optional(&mut **tx).await?.ok_or(RegistryError::NotFound)?;
        if read_u64(&row, "workflow")? != number("workflow_epoch")? {
            return Err(RegistryError::StaleWorkflow);
        }
        barriers::require_open(tx, key).await?;
        if !allow_selected && selection::read_selection(&mut **tx, key).await?.is_some() {
            return Err(RegistryError::SelectionConflict);
        }
        let started = std::time::Instant::now();
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
                .fetch_one(&mut **tx)
                .await?;
        let now = u64::try_from(now).map_err(|_| RegistryError::Unavailable)?;
        let (lease, retired) = current_attempt(tx, key, now)
            .await?
            .ok_or(RegistryError::StaleFence)?;
        if retired || now >= read_u64(&row, "deadline")? {
            return Err(RegistryError::AttemptExpired);
        }
        if lease.attempt_epoch != number("attempt_epoch")? || lease.fence != number("fence")? {
            return Err(RegistryError::StaleFence);
        }
        Ok(started
            + std::time::Duration::from_millis(
                lease.expires_unix_ms.min(read_u64(&row, "deadline")?) - now,
            ))
    }

    /// The caller is the authenticated workflow authority, not a worker or an activity retry.
    pub async fn ensure_attempt(
        &self,
        key: OperationKey<'_>,
        workflow: u64,
        epoch: u64,
    ) -> Result<AttemptLease> {
        self.lease(key, workflow, epoch, None).await
    }

    pub async fn renew_attempt(
        &self,
        key: OperationKey<'_>,
        workflow: u64,
        epoch: u64,
        fence: u64,
    ) -> Result<AttemptLease> {
        self.lease(key, workflow, epoch, Some(fence)).await
    }

    async fn lease(
        &self,
        key: OperationKey<'_>,
        workflow: u64,
        epoch: u64,
        renewal: Option<u64>,
    ) -> Result<AttemptLease> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT intent->>'workflow_epoch' AS workflow, intent->>'deadline_unix_ms' AS deadline \
             FROM fabric_operations WHERE tenant_scope = $1 AND operation_id = $2 FOR UPDATE",
        )
        .bind(key.tenant_scope)
        .bind(key.operation_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(RegistryError::NotFound)?;
        if read_u64(&row, "workflow")? != workflow {
            return Err(RegistryError::StaleWorkflow);
        }
        barriers::require_open(&mut tx, key).await?;
        if selection::read_selection(&mut *tx, key).await?.is_some() {
            return Err(RegistryError::SelectionConflict);
        }
        let deadline = read_u64(&row, "deadline")?;
        let now = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&mut *tx)
        .await?;
        let now = u64::try_from(now).map_err(|_| RegistryError::Unavailable)?;

        let current = current_attempt(&mut tx, key, now).await?;
        let outcome = if let Some((lease, false)) =
            current.filter(|(lease, _)| lease.attempt_epoch == epoch)
        {
            match renewal {
                None => Ok(lease),
                Some(fence) if fence != lease.fence => Err(RegistryError::StaleFence),
                Some(_) => {
                    let expires = lease
                        .expires_unix_ms
                        .max(now.saturating_add(LEASE_MS).min(deadline));
                    sqlx::query("UPDATE fabric_attempts SET lease_expires_unix_ms = $4::text::numeric \
                                 WHERE tenant_scope = $1 AND operation_id = $2 AND attempt_epoch = $3::text::numeric")
                        .bind(key.tenant_scope).bind(key.operation_id).bind(epoch.to_string())
                        .bind(expires.to_string()).execute(&mut *tx).await?;
                    Ok(AttemptLease {
                        expires_unix_ms: expires,
                        ..lease
                    })
                }
            }
        } else if current.is_some_and(|(lease, _)| epoch <= lease.attempt_epoch) || now >= deadline
        {
            Err(RegistryError::AttemptExpired)
        } else if renewal.is_some() {
            Err(RegistryError::StaleFence)
        } else if current.is_some_and(|(_, retired)| !retired)
            || current.map_or(Some(1), |(lease, _)| lease.attempt_epoch.checked_add(1))
                != Some(epoch)
        {
            Err(RegistryError::EpochConflict)
        } else {
            let expires = now.saturating_add(LEASE_MS).min(deadline);
            sqlx::query(
                "INSERT INTO fabric_attempts (tenant_scope, operation_id, attempt_epoch, fence, lease_expires_unix_ms) \
                 VALUES ($1, $2, $3::text::numeric, $3::text::numeric, $4::text::numeric)",
            )
            .bind(key.tenant_scope).bind(key.operation_id).bind(epoch.to_string())
            .bind(expires.to_string()).execute(&mut *tx).await?;
            Ok(AttemptLease {
                attempt_epoch: epoch,
                fence: epoch,
                expires_unix_ms: expires,
            })
        };
        // Commit retirement even when this call returns an expired or conflicting outcome.
        tx.commit().await?;
        outcome
    }
}

/// The operation row must already be locked in this transaction.
async fn current_attempt(
    tx: &mut Transaction<'_, Postgres>,
    key: OperationKey<'_>,
    now: u64,
) -> Result<Option<(AttemptLease, bool)>> {
    sqlx::query(
        "UPDATE fabric_attempts SET retired = true WHERE tenant_scope = $1 AND operation_id = $2 \
         AND NOT retired AND lease_expires_unix_ms <= $3::text::numeric",
    )
    .bind(key.tenant_scope)
    .bind(key.operation_id)
    .bind(now.to_string())
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "SELECT attempt_epoch::text AS epoch, fence::text AS fence, lease_expires_unix_ms::text AS expires, retired \
         FROM fabric_attempts WHERE tenant_scope = $1 AND operation_id = $2 ORDER BY attempt_epoch DESC LIMIT 1",
    )
    .bind(key.tenant_scope).bind(key.operation_id).fetch_optional(&mut **tx).await?
    .map(|row| {
        Ok((AttemptLease {
            attempt_epoch: read_u64(&row, "epoch")?,
            fence: read_u64(&row, "fence")?,
            expires_unix_ms: read_u64(&row, "expires")?,
        }, row.try_get("retired")?))
    }).transpose()
}

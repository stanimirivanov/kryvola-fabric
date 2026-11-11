//! Private staged uploads. No staged object is an artifact reference.

use std::{sync::Arc, time::Duration};

use futures_util::TryStreamExt;
use object_store::{ObjectStore, PutMode, path::Path};
use ring::rand::{SecureRandom, SystemRandom};
use sqlx::{PgPool, Postgres, Row, Transaction, types::Json};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::timeout,
};

mod compute_read;
pub(crate) mod finalize;
mod input;
mod multipart;
mod output;
mod release_read;
mod retention;
use crate::{
    authorization::UploadPermit,
    limits::{ARTIFACT_MAX_BYTES, CHUNK_MAX_BYTES},
};
pub use finalize::FinalizedArtifact;
pub use retention::{PinKind, ReclaimReport};

const IO_TIMEOUT: Duration = Duration::from_secs(15);
type Result<T> = std::result::Result<T, UploadError>;

#[derive(Debug, PartialEq, Eq)]
pub enum UploadError {
    Denied,
    NotFound,
    AttemptExpired,
    StaleFence,
    Size,
    Quota,
    Conflict,
    IdempotencyConflict,
    Integrity,
    Unavailable,
}

impl From<sqlx::Error> for UploadError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

pub struct UploadStore {
    pool: PgPool,
    objects: Arc<dyn ObjectStore>,
    tenant_quota_bytes: u64,
    fenced: bool,
}

fn registry_error(error: crate::registry::RegistryError) -> UploadError {
    use crate::registry::RegistryError;
    match error {
        RegistryError::NotFound => UploadError::NotFound,
        RegistryError::AttemptExpired => UploadError::AttemptExpired,
        RegistryError::Unavailable => UploadError::Unavailable,
        _ => UploadError::StaleFence,
    }
}

fn check_permit(permit: &UploadPermit) -> Result<()> {
    if permit.live() {
        Ok(())
    } else {
        Err(UploadError::Denied)
    }
}

impl UploadStore {
    pub fn new(pool: PgPool, objects: Arc<dyn ObjectStore>, tenant_quota_bytes: u64) -> Self {
        Self {
            pool,
            objects,
            tenant_quota_bytes,
            fenced: false,
        }
    }

    pub(crate) fn fenced(pool: PgPool, objects: Arc<dyn ObjectStore>, quota: u64) -> Self {
        Self {
            pool,
            objects,
            tenant_quota_bytes: quota,
            fenced: true,
        }
    }
    async fn begin(&self, permit: &mut UploadPermit) -> Result<Transaction<'static, Postgres>> {
        check_permit(permit)?;
        let mut tx = self.pool.begin().await?;
        if permit.scope["purpose"] == "INPUT_UPLOAD" {
            let context =
                crate::registry::submission::key_context(&mut tx, &permit.scope["key_context_ref"])
                    .await
                    .map_err(|error| match error {
                        crate::registry::RegistryError::Unavailable => UploadError::Unavailable,
                        _ => UploadError::Denied,
                    })?;
            if context["owner_identity"] != permit.scope["owner_identity"] {
                return Err(UploadError::Denied);
            }
        } else if self.fenced {
            match crate::registry::Registry::artifact_deadline(&mut tx, &permit.scope).await {
                Ok(deadline) => permit.bound_deadline(deadline),
                Err(error) => {
                    tx.commit().await?; // Persist observed expiry retirement even on denial.
                    return Err(registry_error(error));
                }
            }
        }
        check_permit(permit)?;
        Ok(tx)
    }

    pub async fn put_manifest(
        &self,
        mut permit: UploadPermit,
        id: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let value = finalize::manifest(bytes)?;
        if value["tenant_scope"] != permit.tenant {
            return Err(UploadError::Denied);
        }
        if permit.scope["purpose"] == "INPUT_UPLOAD"
            && (value["key_context_digest"]
                != permit.scope["key_context_ref"]["key_context_digest"]
                || value["artifact_kind"] != permit.scope["artifact_kind"])
        {
            return Err(UploadError::Denied);
        }
        if permit.scope["manifest_digest"] != finalize::digest(b"kryvola/manifest/v2\0", &[bytes]) {
            return Err(if permit.scope["purpose"] == "INPUT_UPLOAD" {
                UploadError::IdempotencyConflict
            } else {
                UploadError::Denied
            });
        }
        let mut tx = self.begin(&mut permit).await?;
        lock_upload(&mut tx, &permit, id, self.fenced, UploadAccess::Write).await?;
        if permit.scope["purpose"] == "INPUT_UPLOAD"
            && let Some(saved) = self.input_manifest_retry(&mut tx, id, bytes).await?
        {
            check_permit(&permit)?;
            return saved;
        }
        if is_finalized(&mut tx, id).await? {
            return Err(UploadError::Conflict);
        }
        check_permit(&permit)?;
        timeout(
            IO_TIMEOUT,
            self.objects.put_opts(
                &Path::from(format!("staging/{id}/manifest")),
                bytes.to_vec().into(),
                PutMode::Create.into(),
            ),
        )
        .await
        .map_err(|_| UploadError::Unavailable)?
        .map_err(|error| match error {
            object_store::Error::AlreadyExists { .. }
            | object_store::Error::Precondition { .. } => UploadError::Conflict,
            _ => UploadError::Unavailable,
        })?;
        check_permit(&permit)?;
        sqlx::query("UPDATE fabric_uploads SET touched_at=clock_timestamp() WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn reserve(&self, mut permit: UploadPermit, bytes: usize) -> Result<String> {
        check_permit(&permit)?;
        if !(1..=ARTIFACT_MAX_BYTES).contains(&bytes) {
            return Err(UploadError::Size);
        }
        let bytes = bytes as i64;
        let mut tx = self.begin(&mut permit).await?;
        let execution = permit.scope["execution_id"].as_str();
        if execution.is_some()
            && let Some(id) = output::reservation_retry(&mut tx, &permit, bytes).await?
        {
            tx.commit().await?;
            return Ok(id);
        }
        // Take the same tenant row lock for every admission, including the first.
        sqlx::query("INSERT INTO fabric_upload_tenants VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(&permit.tenant)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT tenant_scope FROM fabric_upload_tenants WHERE tenant_scope = $1 FOR UPDATE",
        )
        .bind(&permit.tenant)
        .fetch_one(&mut *tx)
        .await?;
        if permit.scope["purpose"] == "INPUT_UPLOAD"
            && let Some(id) = Self::input_reservation_retry(&mut tx, &permit, bytes).await?
        {
            check_permit(&permit)?;
            tx.commit().await?;
            return Ok(id);
        }
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(sum(reserved_bytes), 0)::bigint FROM fabric_uploads WHERE tenant_scope = $1",
        ).bind(&permit.tenant).fetch_one(&mut *tx).await?;
        if used as u64 + bytes as u64 > self.tenant_quota_bytes {
            return Err(UploadError::Quota);
        }
        let mut random = [0; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| UploadError::Unavailable)?;
        let id = hex::encode(random);
        check_permit(&permit)?;
        sqlx::query(
            "INSERT INTO fabric_uploads (id, tenant_scope, certificate, scope, reserved_bytes) VALUES ($1, $2, $3, $4, $5)",
        ).bind(&id).bind(&permit.tenant).bind(&permit.certificate).bind(Json(&permit.scope))
            .bind(bytes).execute(&mut *tx).await?;
        // Check after inserting, so a concurrent deletion of a colliding live
        // upload cannot make its tombstoned identity available for reuse.
        let tombstoned: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM fabric_reclaim_tombstones WHERE id=$1)",
        )
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
        if tombstoned {
            return Err(UploadError::Unavailable);
        }
        if let Some(execution) = execution {
            output::record(&mut tx, &permit, execution, &id, bytes).await?;
            check_permit(&permit)?;
        }
        if permit.scope["purpose"] == "INPUT_UPLOAD" {
            Self::record_input_reservation(&mut tx, &permit, &id, bytes).await?;
            check_permit(&permit)?;
        }
        tx.commit().await?;
        Ok(id)
    }

    pub async fn put_part(
        &self,
        mut permit: UploadPermit,
        id: &str,
        index: u16,
        declared: usize,
        body: impl AsyncRead + Unpin,
    ) -> Result<()> {
        if index > 1023 || !(1..=CHUNK_MAX_BYTES).contains(&declared) {
            return Err(UploadError::Size);
        }
        let mut tx = self.begin(&mut permit).await?;
        let upload = lock_upload(&mut tx, &permit, id, self.fenced, UploadAccess::Write).await?;
        if permit.scope["purpose"] == "INPUT_UPLOAD"
            && let Some(key) = Self::existing_input_part(&mut tx, id, index).await?
        {
            self.check_input_part(&key, declared, body).await?;
            check_permit(&permit)?;
            return Ok(());
        }
        if is_finalized(&mut tx, id).await? {
            return Err(UploadError::Conflict);
        }
        let remaining: i64 = upload.try_get("remaining")?;
        // The marker and byte accounting are committed only after object creation.
        let mut nonce = [0; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| UploadError::Unavailable)?;
        let key = Path::from(format!("staging/{id}/{index}/{}", hex::encode(nonce)));
        let inserted =
            sqlx::query("INSERT INTO fabric_upload_parts (upload_id, part_index, object_key) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                .bind(id)
                .bind(i32::from(index))
                .bind(key.as_ref())
                .execute(&mut *tx)
                .await?;
        if inserted.rows_affected() != 1 {
            return Err(UploadError::Conflict);
        }

        if declared as i64 > remaining {
            return Err(UploadError::Size);
        }

        let staged = multipart::stage(self.objects.clone(), key, declared, body, || {
            check_permit(&permit)
        })
        .await?;
        sqlx::query("UPDATE fabric_uploads SET received_bytes = received_bytes + $2, touched_at = clock_timestamp() WHERE id = $1")
            .bind(id)
            .bind(declared as i64)
            .execute(&mut *tx)
            .await?;
        check_permit(&permit)?;
        staged.retain_for_commit();
        tx.commit().await?;
        Ok(())
    }

    pub async fn abort(&self, mut permit: UploadPermit, id: &str) -> Result<()> {
        let mut tx = self.begin(&mut permit).await?;
        lock_upload(&mut tx, &permit, id, self.fenced, UploadAccess::Abort).await?;
        if is_finalized(&mut tx, id).await? {
            return Err(UploadError::Conflict);
        }
        retention::mark(&mut tx, id).await?;
        check_permit(&permit)?;
        tx.commit().await?;
        self.sweep(id).await?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum UploadAccess {
    Write,
    Abort,
}

async fn lock_upload(
    tx: &mut Transaction<'_, Postgres>,
    permit: &UploadPermit,
    id: &str,
    fenced: bool,
    access: UploadAccess,
) -> Result<sqlx::postgres::PgRow> {
    check_permit(permit)?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(UploadError::Denied);
    }
    let row = sqlx::query(
        "SELECT reserved_bytes, reserved_bytes - received_bytes AS remaining FROM fabric_uploads \
         WHERE id = $1 AND tenant_scope = $2 AND certificate = $3 AND scope = $4 AND (NOT reclaiming OR $5) FOR UPDATE",
    )
    .bind(id)
    .bind(&permit.tenant)
    .bind(&permit.certificate)
    .bind(Json(&permit.scope))
    .bind(matches!(access, UploadAccess::Abort))
    .fetch_optional(&mut **tx)
    .await?;
    let row = match row {
        Some(row) => row,
        None if fenced => {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM fabric_uploads WHERE id=$1)")
                    .bind(id)
                    .fetch_one(&mut **tx)
                    .await?;
            return Err(if exists {
                UploadError::Denied
            } else {
                UploadError::NotFound
            });
        }
        None => return Err(UploadError::Denied),
    };
    check_permit(permit)?;
    Ok(row)
}

async fn is_finalized(tx: &mut Transaction<'_, Postgres>, id: &str) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM fabric_finalized_artifacts WHERE upload_id = $1)",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await?)
}

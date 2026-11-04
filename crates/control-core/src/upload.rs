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

mod finalize;
mod retention;
use crate::{
    authorization::UploadPermit,
    limits::{ARTIFACT_MAX_BYTES, CHUNK_MAX_BYTES},
};
pub use finalize::FinalizedArtifact;
pub use retention::PinKind;

const IO_TIMEOUT: Duration = Duration::from_secs(15);
type Result<T> = std::result::Result<T, UploadError>;

#[derive(Debug, PartialEq, Eq)]
pub enum UploadError {
    Denied,
    Size,
    Quota,
    Conflict,
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
        }
    }

    pub async fn reserve(&self, permit: UploadPermit, bytes: usize) -> Result<String> {
        check_permit(&permit)?;
        if !(1..=ARTIFACT_MAX_BYTES).contains(&bytes) {
            return Err(UploadError::Size);
        }
        let bytes = bytes as i64;
        let mut tx = self.pool.begin().await?;
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
        tx.commit().await?;
        Ok(id)
    }

    pub async fn put_part(
        &self,
        permit: UploadPermit,
        id: &str,
        index: u16,
        declared: usize,
        body: impl AsyncRead + Unpin,
    ) -> Result<()> {
        if index > 1023 || !(1..=CHUNK_MAX_BYTES).contains(&declared) {
            return Err(UploadError::Size);
        }
        let mut tx = self.pool.begin().await?;
        let upload = lock_upload(&mut tx, &permit, id).await?;
        if is_finalized(&mut tx, id).await? {
            return Err(UploadError::Conflict);
        }
        let remaining: i64 = upload.try_get("remaining")?;
        // The marker and byte accounting are committed only after object creation.
        let inserted =
            sqlx::query("INSERT INTO fabric_upload_parts VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(id)
                .bind(i32::from(index))
                .execute(&mut *tx)
                .await?;
        if inserted.rows_affected() != 1 {
            return Err(UploadError::Conflict);
        }

        if declared as i64 > remaining {
            return Err(UploadError::Size);
        }

        let mut data = Vec::with_capacity(declared + 1);
        timeout(
            IO_TIMEOUT,
            body.take(declared as u64 + 1).read_to_end(&mut data),
        )
        .await
        .map_err(|_| UploadError::Unavailable)?
        .map_err(|_| UploadError::Unavailable)?;
        if data.len() != declared {
            return Err(UploadError::Size);
        }
        check_permit(&permit)?;
        let key = Path::from(format!("staging/{id}/{index}"));
        timeout(
            IO_TIMEOUT,
            self.objects
                .put_opts(&key, data.into(), PutMode::Create.into()),
        )
        .await
        .map_err(|_| UploadError::Unavailable)?
        .map_err(|error| match error {
            object_store::Error::AlreadyExists { .. }
            | object_store::Error::Precondition { .. } => UploadError::Conflict,
            _ => UploadError::Unavailable,
        })?;
        sqlx::query("UPDATE fabric_uploads SET received_bytes = received_bytes + $2, touched_at = clock_timestamp() WHERE id = $1")
            .bind(id)
            .bind(declared as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn abort(&self, permit: UploadPermit, id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        lock_upload(&mut tx, &permit, id).await?;
        if is_finalized(&mut tx, id).await? {
            return Err(UploadError::Conflict);
        }
        retention::mark(&mut tx, id).await?;
        tx.commit().await?;
        self.sweep(id).await?;
        Ok(())
    }
}

async fn lock_upload(
    tx: &mut Transaction<'_, Postgres>,
    permit: &UploadPermit,
    id: &str,
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
         WHERE id = $1 AND tenant_scope = $2 AND certificate = $3 AND scope = $4 AND NOT reclaiming FOR UPDATE",
    )
    .bind(id)
    .bind(&permit.tenant)
    .bind(&permit.certificate)
    .bind(Json(&permit.scope))
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(UploadError::Denied)?;
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

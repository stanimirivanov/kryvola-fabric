use super::*;

const MAINTENANCE_BATCH: i64 = 4;

#[derive(serde::Serialize)]
pub struct ReclaimReport {
    mode: &'static str,
    eligible_uploads: usize,
    tombstones_due: usize,
    reclaimed_uploads: usize,
    tombstones_swept: usize,
    pub failures: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum PinKind {
    Workflow,
    KeyContext,
    Audit,
}

impl PinKind {
    fn name(self) -> &'static str {
        match self {
            Self::Workflow => "workflow",
            Self::KeyContext => "key_context",
            Self::Audit => "audit",
        }
    }
}

// Shared by the dry run and the locked eligibility recheck.
const ELIGIBLE: &str = "SELECT u.id FROM fabric_uploads u
    WHERE ($2::text IS NULL OR u.id = $2)
    AND (u.reclaiming OR u.touched_at <= clock_timestamp() - make_interval(secs => $1::float8))
    AND NOT EXISTS (SELECT 1 FROM fabric_selected_results s WHERE s.upload_id = u.id)
    AND NOT EXISTS (
        SELECT 1 FROM fabric_artifact_pins p WHERE p.upload_id = u.id
          AND p.expires_unix_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)
    ) ORDER BY u.reclaim_attempted_at NULLS FIRST, u.touched_at, u.id LIMIT $3";

pub(super) async fn mark(tx: &mut Transaction<'_, Postgres>, id: &str) -> Result<()> {
    sqlx::query("UPDATE fabric_uploads SET reclaiming = true WHERE id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

impl UploadStore {
    /// Internal coordinator API. The caller authenticates the retention owner.
    pub async fn pin(
        &self,
        tenant: &str,
        id: &str,
        kind: PinKind,
        holder: &str,
        expires_unix_ms: i64,
    ) -> Result<()> {
        if holder.is_empty() || holder.len() > 128 {
            return Err(UploadError::Denied);
        }
        let mut tx = self.pool.begin().await?;
        let open: Option<bool> = sqlx::query_scalar(
            "SELECT NOT reclaiming FROM fabric_uploads WHERE id = $1 AND tenant_scope = $2 FOR UPDATE",
        ).bind(id).bind(tenant).fetch_optional(&mut *tx).await?;
        if open != Some(true) || !is_finalized(&mut tx, id).await? {
            return Err(UploadError::Denied);
        }
        let saved = sqlx::query(
            "INSERT INTO fabric_artifact_pins (upload_id, kind, holder, expires_unix_ms)
             SELECT $1, $2, $3, $4 WHERE $4 > floor(extract(epoch FROM clock_timestamp()) * 1000)
             ON CONFLICT (upload_id, kind, holder) DO UPDATE
             SET expires_unix_ms = greatest(fabric_artifact_pins.expires_unix_ms, EXCLUDED.expires_unix_ms)",
        ).bind(id).bind(kind.name()).bind(holder).bind(expires_unix_ms).execute(&mut *tx).await?;
        if saved.rows_affected() != 1 {
            return Err(UploadError::Denied);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Preview one bounded batch. Reclaim always rechecks under lock.
    pub async fn eligible_for_reclaim(&self, retention_seconds: u32) -> Result<Vec<String>> {
        self.eligible_batch(retention_seconds, 100).await
    }

    async fn eligible_batch(&self, retention_seconds: u32, limit: i64) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(ELIGIBLE)
            .bind(f64::from(retention_seconds))
            .bind(None::<&str>)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }

    /// Run one operator pass. A preview touches neither SQL state nor object storage.
    pub async fn reclamation_pass(
        &self,
        retention_seconds: u32,
        delete: bool,
    ) -> Result<ReclaimReport> {
        let uploads = self
            .eligible_batch(retention_seconds, MAINTENANCE_BATCH)
            .await?;
        let tombstones: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM fabric_reclaim_tombstones ORDER BY checked_at, id LIMIT $1",
        )
        .bind(MAINTENANCE_BATCH)
        .fetch_all(&self.pool)
        .await?;
        let mut report = ReclaimReport {
            mode: if delete { "delete" } else { "report" },
            eligible_uploads: uploads.len(),
            tombstones_due: tombstones.len(),
            reclaimed_uploads: 0,
            tombstones_swept: 0,
            failures: 0,
        };
        if delete {
            for id in uploads {
                match self.reclaim(&id, retention_seconds).await {
                    Ok(true) => report.reclaimed_uploads += 1,
                    Ok(false) => {} // The locked recheck may observe a new pin.
                    Err(_) => report.failures += 1,
                }
            }
            for id in tombstones {
                match self.revisit_tombstone(&id).await {
                    Ok(()) => report.tombstones_swept += 1,
                    Err(_) => report.failures += 1,
                }
            }
        }
        Ok(report)
    }

    async fn revisit_tombstone(&self, id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // Even a failed S3 sweep rotates to the back so other IDs get a turn.
        sqlx::query(
            "UPDATE fabric_reclaim_tombstones SET checked_at=clock_timestamp() WHERE id=$1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        let outcome = self.delete_objects(id).await;
        tx.commit().await?;
        outcome
    }

    /// Explicit maintenance action. The durable marker fences pins and writers before any S3 delete.
    pub async fn reclaim(&self, id: &str, retention_seconds: u32) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let locked: Option<String> =
            sqlx::query_scalar("SELECT id FROM fabric_uploads WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        if locked.is_none() {
            return Ok(false);
        }
        let eligible = sqlx::query_scalar::<_, String>(ELIGIBLE)
            .bind(f64::from(retention_seconds))
            .bind(id)
            .bind(1_i64)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if !eligible {
            return Ok(false);
        }
        sqlx::query("UPDATE fabric_uploads SET reclaiming=true, reclaim_attempted_at=clock_timestamp() WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.sweep(id).await
    }

    pub(super) async fn sweep(&self, id: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let marked: Option<bool> =
            sqlx::query_scalar("SELECT reclaiming FROM fabric_uploads WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        if marked != Some(true) {
            return Ok(false);
        }
        // Keep quota until both prefixes have cleared and the tombstone commits.
        self.delete_objects(id).await?;
        sqlx::query("INSERT INTO fabric_reclaim_tombstones (id) VALUES ($1)")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM fabric_finalized_artifacts WHERE upload_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM fabric_uploads WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn delete_objects(&self, id: &str) -> Result<()> {
        for namespace in ["staging", "immutable"] {
            let prefix = Path::from(format!("{namespace}/{id}"));
            let paths = self
                .objects
                .list(Some(&prefix))
                .map_ok(|entry| entry.location);
            timeout(
                IO_TIMEOUT,
                self.objects
                    .delete_stream(Box::pin(paths))
                    .try_for_each(|_| async { Ok(()) }),
            )
            .await
            .map_err(|_| UploadError::Unavailable)?
            .map_err(|_| UploadError::Unavailable)?;
        }
        Ok(())
    }
}

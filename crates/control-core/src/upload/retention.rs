use super::*;

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
    ) ORDER BY u.touched_at, u.id LIMIT 100";

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
        Ok(sqlx::query_scalar(ELIGIBLE)
            .bind(f64::from(retention_seconds))
            .bind(None::<&str>)
            .fetch_all(&self.pool)
            .await?)
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
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if !eligible {
            return Ok(false);
        }
        mark(&mut tx, id).await?;
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
        // S3 deletion is repeatable after a timeout or process failure. Keep the marker
        // and quota reservation until both prefixes have been cleared.
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
}

use serde_json::Value;

use super::*;
use crate::{
    authorization::{ConsumerGrant, now_unix_ms},
    limits::CONTROL_BYTES,
    registry::{Registry, RegistryError},
};

impl UploadStore {
    pub(crate) async fn read_released_output(
        &self,
        scope: &Value,
        part: Option<u16>,
        grant: &ConsumerGrant,
        check_transport: impl Fn() -> Result<()>,
    ) -> Result<Vec<u8>> {
        check_transport()?;
        let mut tx = self.pool.begin().await?;
        let (id, context, start, end) = Registry::lock_release_read(&mut tx, scope, grant)
            .await
            .map_err(|error| match error {
                RegistryError::Unavailable => UploadError::Unavailable,
                _ => UploadError::Denied,
            })?;
        let check_live = || {
            check_transport()?;
            if !now_unix_ms().is_some_and(|now| (start..end).contains(&now)) {
                return Err(UploadError::Denied);
            }
            Ok(())
        };
        check_live()?;
        let tenant = scope["tenant_scope"].as_str().ok_or(UploadError::Denied)?;
        let digest = scope["output_manifest_digest"]
            .as_str()
            .ok_or(UploadError::Denied)?;
        let canonical: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT CASE WHEN octet_length(f.canonical_manifest) <= $4 THEN f.canonical_manifest END
             FROM fabric_finalized_artifacts f JOIN fabric_uploads u ON u.id=f.upload_id
             WHERE u.id=$1 AND u.tenant_scope=$2 AND f.manifest_digest=$3 AND NOT u.reclaiming
             FOR SHARE OF u",
        ).bind(&id).bind(tenant).bind(digest).bind(CONTROL_BYTES as i32)
            .fetch_optional(&mut *tx).await?.flatten();
        let bytes = self
            .verified_read(
                (&id, canonical),
                (Some(tenant), &context, digest),
                part,
                check_live,
            )
            .await?;
        check_live()?;
        tx.commit().await?;
        check_live()?;
        Ok(bytes)
    }
}

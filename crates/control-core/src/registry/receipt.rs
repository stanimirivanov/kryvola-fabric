use std::{collections::HashSet, time::Instant};

use serde_json::Value;

use super::{Registry, RegistryError, Result};
use crate::{limits::CONTROL_BYTES, receipt::SignedReceipt, upload::finalize};

impl Registry {
    pub(crate) async fn persist_receipt(
        &self,
        body: &Value,
        workload: &str,
        receipt: &SignedReceipt,
        authorized: impl Fn() -> bool,
    ) -> Result<()> {
        let attempt = &body["attempt"];
        let tenant = attempt["tenant_scope"].as_str();
        let operation = attempt["operation_id"].as_str();
        let execution = body["execution_id"].as_str();
        let upload = body["output_upload_id"].as_str();
        let value = &receipt.value;
        for field in [
            "tenant_scope",
            "operation_id",
            "workflow_epoch",
            "attempt_epoch",
            "fence",
        ] {
            if value[field] != attempt[field] {
                return Err(RegistryError::Forbidden);
            }
        }
        if value["execution_id"] != body["execution_id"] {
            return Err(RegistryError::Forbidden);
        }
        let output = match value["output_manifest_digests"]
            .as_array()
            .map(Vec::as_slice)
        {
            Some([digest]) => digest.as_str(),
            _ => return Err(RegistryError::Forbidden),
        };
        let mut tx = self.pool.begin().await?;
        let lease = match Self::lock_artifact_attempt(&mut tx, attempt, true).await {
            Ok(deadline) => deadline,
            Err(error) => {
                tx.commit().await?; // Preserve observed attempt retirement.
                return Err(if error == RegistryError::StaleWorkflow {
                    RegistryError::StaleFence
                } else {
                    error
                });
            }
        };
        let (intent, approved): (Value, Value) = sqlx::query_as(
            "SELECT intent, inputs FROM fabric_operations WHERE tenant_scope=$1 AND operation_id=$2",
        ).bind(tenant).bind(operation).fetch_one(&mut *tx).await?;
        let inputs = value["input_manifest_digests"]
            .as_array()
            .ok_or(RegistryError::InvalidIntent)?;
        let approved = approved.as_array().ok_or(RegistryError::Unavailable)?;
        let mut seen = HashSet::new();
        if ["logical_job_id", "stage_id", "policy_digest"]
            .iter()
            .any(|field| value[*field] != intent[*field])
            || value["plan_digest"] != intent["plan_ref"]["plan_digest"]
            || value["key_context_digest"] != intent["key_context_ref"]["key_context_digest"]
            || inputs
                .iter()
                .any(|digest| !seen.insert(digest.as_str()) || !approved.contains(digest))
        {
            return Err(RegistryError::Forbidden);
        }
        let registered: String = sqlx::query_scalar(
            "SELECT attempt_epoch::text FROM fabric_executions
             WHERE tenant_scope=$1 AND operation_id=$2 AND execution_id=$3",
        )
        .bind(tenant)
        .bind(operation)
        .bind(execution)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(RegistryError::NotFound)?;
        if attempt["attempt_epoch"] != registered {
            return Err(RegistryError::StaleFence);
        }
        let saved: Option<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT output_upload_id, canonical_receipt, canonical_signature
             FROM fabric_execution_receipts WHERE tenant_scope=$1 AND operation_id=$2 AND execution_id=$3",
        ).bind(tenant).bind(operation).bind(execution).fetch_optional(&mut *tx).await?;
        let check_live = || {
            if Instant::now() >= lease {
                Err(RegistryError::AttemptExpired)
            } else if !authorized() {
                Err(RegistryError::Forbidden)
            } else {
                Ok(())
            }
        };
        if let Some((id, payload, envelope)) = &saved
            && (Some(id.as_str()) != upload
                || *payload != receipt.payload
                || *envelope != receipt.envelope)
        {
            check_live()?;
            return Err(RegistryError::IdempotencyConflict);
        }
        // Lock against reclamation until the provenance binding commits.
        let (owner, scope, digest, canonical): (String, Value, String, Option<Vec<u8>>) =
            sqlx::query_as(
                "SELECT u.certificate, u.scope, f.manifest_digest,
                CASE WHEN octet_length(f.canonical_manifest) <= $3 THEN f.canonical_manifest END
             FROM fabric_uploads u JOIN fabric_finalized_artifacts f ON f.upload_id=u.id
             WHERE u.id=$1 AND u.tenant_scope=$2 AND NOT u.reclaiming FOR SHARE OF u",
            )
            .bind(upload)
            .bind(tenant)
            .bind(CONTROL_BYTES as i32)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(RegistryError::NotFound)?;
        if owner != workload
            || scope["attempt"] != *attempt
            || scope["purpose"] != "COMPUTE_WRITE"
            || scope["manifest_digest"] != digest
            || Some(digest.as_str()) != output
        {
            return Err(RegistryError::Forbidden);
        }
        let canonical = canonical.ok_or(RegistryError::Unavailable)?;
        if finalize::digest(b"kryvola/manifest/v2\0", &[&canonical]) != digest {
            return Err(RegistryError::Unavailable);
        }
        let manifest = finalize::manifest(&canonical).map_err(|_| RegistryError::Unavailable)?;
        if manifest["artifact_kind"] != "CIPHERTEXT"
            || manifest["tenant_scope"] != attempt["tenant_scope"]
            || manifest["key_context_digest"] != value["key_context_digest"]
        {
            return Err(RegistryError::Forbidden);
        }
        check_live()?;
        if saved.is_some() {
            return Ok(());
        }
        let added = sqlx::query(
            "INSERT INTO fabric_execution_receipts
             (tenant_scope, operation_id, execution_id, output_upload_id, receipt_digest, canonical_receipt, canonical_signature)
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
        ).bind(tenant).bind(operation).bind(execution).bind(upload).bind(&receipt.digest)
            .bind(&receipt.payload).bind(&receipt.envelope).execute(&mut *tx).await?.rows_affected();
        if added != 1 {
            return Err(RegistryError::IdempotencyConflict);
        }
        check_live()?;
        tx.commit().await?;
        Ok(())
    }
}

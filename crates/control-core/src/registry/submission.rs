use std::{collections::HashSet, sync::OnceLock};

use serde_json::json;

use super::*;
use crate::{
    authorization::{SubmissionGrant, now_unix_ms},
    receipt::{canonical, commitment, verify_signature},
    upload::finalize,
};

static KEY_CONTEXT: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
static PLAN: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
static APPROVAL: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
static CONSENT: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();

pub(crate) async fn key_context(
    tx: &mut Transaction<'_, Postgres>,
    reference: &Value,
) -> Result<Value> {
    let raw: Vec<u8> = sqlx::query_scalar(
        "SELECT canonical_context FROM fabric_key_contexts WHERE reference=$1 FOR SHARE",
    )
    .bind(reference)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(RegistryError::Forbidden)?;
    serde_json::from_slice(&raw).map_err(|_| RegistryError::Unavailable)
}

async fn persist_metadata(
    tx: &mut Transaction<'_, Postgres>,
    reference: &Value,
    raw: &[u8],
    context: bool,
) -> Result<()> {
    let (insert, select, field) = if context {
        (
            "INSERT INTO fabric_key_contexts VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            "SELECT canonical_context FROM fabric_key_contexts WHERE reference=$1",
            "key_context_id",
        )
    } else {
        (
            "INSERT INTO fabric_submission_plans VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            "SELECT canonical_plan FROM fabric_submission_plans WHERE reference=$1",
            "plan_id",
        )
    };
    sqlx::query(insert)
        .bind(reference)
        .bind(string(reference, "tenant_scope")?)
        .bind(string(reference, field)?)
        .bind(string(reference, "immutable_version")?)
        .bind(raw)
        .execute(&mut **tx)
        .await?;
    let existing: Option<Vec<u8>> = sqlx::query_scalar(select)
        .bind(reference)
        .fetch_optional(&mut **tx)
        .await?;
    if existing.as_deref() != Some(raw) {
        return Err(RegistryError::IdempotencyConflict);
    }
    Ok(())
}

struct Approved {
    plan: Value,
    plan_bytes: Vec<u8>,
    approval: Value,
    start: u64,
    expires: u64,
}

fn approved(body: &Value, grant: &SubmissionGrant) -> Result<Approved> {
    let (plan_bytes, plan) = canonical(
        &body["plan_base64url"],
        32768,
        &PLAN,
        include_str!("../../../../contracts/spec/canonical/v2/plan.schema.json"),
    )?;
    let (consent_bytes, consent) = canonical(
        &body["consent_base64url"],
        8192,
        &CONSENT,
        include_str!("../../../../contracts/spec/consent-declaration.schema.json"),
    )?;
    let (approval_bytes, approval) = canonical(
        &body["approval_base64url"],
        8192,
        &APPROVAL,
        include_str!("../../../../contracts/spec/canonical/v3/approval.schema.json"),
    )?;
    let (_, approval_digest) = verify_signature(
        &body["signature_base64url"],
        &approval_bytes,
        "approval",
        grant.owner.fields(),
    )?;
    let plan_digest = commitment("plan", 2, &plan_bytes);
    if body["approval_digest"] != approval_digest
        || body["plan_ref"]["plan_digest"] != plan_digest
        || body["plan_ref"]["tenant_scope"] != grant.tenant_scope
        || plan["tenant_scope"] != grant.tenant_scope
        || approval["plan_digest"] != plan_digest
        || approval["subject_digest"] != plan_digest
        || approval["subject_kind"] != "plan"
        || approval["purpose"] != "COMPUTE"
        || plan["security_profile"] != "FHE-Q1"
        || plan["arithmetic"] != "EXACT_MODULAR"
        || plan["precision"] != json!({"dtype":"uint8","fractional_bits":"0","overflow":"WRAP"})
        || grant.evidence_policy != "NONE"
        || !consent["accepted_leakage"]
            .as_array()
            .is_some_and(|leakage| leakage.iter().collect::<HashSet<_>>().len() == 7)
        || approval["policy_digest"] != grant.policy_digest
        || approval["policy_epoch"] != grant.policy_epoch
        || approval["evidence_policy_digest"] != grant.evidence_policy_digest
        || approval["consent_digest"] != commitment("blob", 1, &consent_bytes)
        || [
            "tenant_scope",
            "key_context_digest",
            "model_digest",
            "program_digest",
            "consent_digest",
            "evidence_policy_digest",
        ]
        .iter()
        .any(|field| approval[*field] != plan[*field])
    {
        return Err(RegistryError::Forbidden);
    }
    let time = |field| {
        string(&approval, field)?
            .parse::<u64>()
            .map_err(|_| RegistryError::InvalidIntent)
    };
    Ok(Approved {
        plan,
        plan_bytes,
        start: time("valid_from_unix_ms")?,
        expires: time("expires_unix_ms")?,
        approval,
    })
}

impl Approved {
    fn check_current(&self, live: &impl Fn() -> Result<()>) -> Result<()> {
        live()?;
        if now_unix_ms().is_some_and(|now| (self.start..self.expires).contains(&now)) {
            Ok(())
        } else {
            Err(RegistryError::Forbidden)
        }
    }
}

async fn require_approval_open(tx: &mut Transaction<'_, Postgres>, digest: &str) -> Result<()> {
    super::release::lock_approval(tx, digest).await?;
    let revoked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM fabric_revoked_release_approvals WHERE approval_digest=$1)",
    )
    .bind(digest)
    .fetch_one(&mut **tx)
    .await?;
    if revoked {
        return Err(RegistryError::Forbidden);
    }
    Ok(())
}

impl Registry {
    pub(crate) async fn register_key_context(
        &self,
        body: &Value,
        grant: &SubmissionGrant,
        live: impl Fn() -> Result<()>,
    ) -> Result<Value> {
        let (raw, context) = canonical(
            &body["key_context_base64url"],
            16384,
            &KEY_CONTEXT,
            include_str!("../../../../contracts/spec/canonical/key-context.schema.json"),
        )?;
        let reference = &body["key_context_ref"];
        if reference["key_context_digest"] != commitment("key-context", 1, &raw)
            || context["tenant_scope"] != grant.tenant_scope
            || context["owner_identity"] != grant.owner_identity
            || ["tenant_scope", "key_context_id", "key_epoch"]
                .iter()
                .any(|field| reference[*field] != context[*field])
        {
            return Err(RegistryError::Forbidden);
        }
        let mut tx = self.pool.begin().await?;
        persist_metadata(&mut tx, reference, &raw, true).await?;
        live()?;
        tx.commit().await?;
        Ok(reference.clone())
    }

    pub(crate) async fn register_compute_approval(
        &self,
        body: &Value,
        grant: &SubmissionGrant,
        live: impl Fn() -> Result<()>,
    ) -> Result<Value> {
        let approval = approved(body, grant)?;
        let digest = string(body, "approval_digest")?;
        let mut tx = self.pool.begin().await?;
        require_approval_open(&mut tx, &digest).await?;
        persist_metadata(&mut tx, &body["plan_ref"], &approval.plan_bytes, false).await?;
        sqlx::query("INSERT INTO fabric_compute_approvals VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(&grant.tenant_scope)
            .bind(&digest)
            .bind(body)
            .execute(&mut *tx)
            .await?;
        let saved: Value = sqlx::query_scalar(
            "SELECT registration FROM fabric_compute_approvals WHERE tenant_scope=$1 AND approval_digest=$2",
        ).bind(&grant.tenant_scope).bind(&digest).fetch_one(&mut *tx).await?;
        if saved != *body {
            return Err(RegistryError::IdempotencyConflict);
        }
        approval.check_current(&live)?;
        tx.commit().await?;
        Ok(json!({"schema_version":"1","approval_digest":digest}))
    }

    pub(crate) async fn admit_approved(
        &self,
        validator: &ControlValidator,
        body: &Value,
        grant: &SubmissionGrant,
        workload: &str,
        live: impl Fn() -> Result<()>,
    ) -> Result<OperationRecord> {
        let operation = &body["operation"];
        if operation["tenant_scope"] != grant.tenant_scope {
            return Err(RegistryError::Forbidden);
        }
        let ciphertexts = body["input_manifest_digests"]
            .as_array()
            .ok_or(RegistryError::InvalidIntent)?;
        let evaluation = string(body, "evaluation_key_manifest_digest")?;
        let inputs = std::iter::once(Ok(evaluation))
            .chain(ciphertexts.iter().map(|digest| {
                digest
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(RegistryError::InvalidIntent)
            }))
            .collect::<Result<Vec<_>>>()?;
        if inputs.iter().collect::<HashSet<_>>().len() != inputs.len() {
            return Err(RegistryError::InvalidIntent);
        }
        let intent = OperationIntent::new(validator, operation.clone(), inputs.clone())?;
        let key = intent.key();
        let digest = string(body, "approval_digest")?;
        let mut tx = self.pool.begin().await?;
        require_approval_open(&mut tx, &digest).await?;
        let prior: Option<(Value, Vec<String>)> = sqlx::query_as(
            "SELECT a.intent,a.upload_ids FROM fabric_approved_admissions a JOIN fabric_operations o USING (tenant_scope,operation_id)
             WHERE a.tenant_scope=$1 AND (a.operation_id=$2 OR o.idempotency_key=$3)",
        ).bind(key.tenant_scope).bind(key.operation_id).bind(&intent.idempotency)
            .fetch_optional(&mut *tx).await?;
        if prior.as_ref().is_some_and(|(intent, _)| intent != body) {
            return Err(RegistryError::IdempotencyConflict);
        }
        let registration: Value = sqlx::query_scalar(
            "SELECT registration FROM fabric_compute_approvals WHERE tenant_scope=$1 AND approval_digest=$2",
        ).bind(key.tenant_scope).bind(&digest).fetch_optional(&mut *tx).await?
            .ok_or(RegistryError::Forbidden)?;
        let approved = approved(&registration, grant)?;
        let approval = &approved.approval;
        let reference = &operation["key_context_ref"];
        let context = key_context(&mut tx, reference).await?;
        if registration["plan_ref"] != operation["plan_ref"]
            || context["owner_identity"] != grant.owner_identity
            || context["security_profile"] != approved.plan["security_profile"]
            || context["parameters"] != approved.plan["parameters"]
            || approved.plan["input_manifest_digests"] != body["input_manifest_digests"]
            || approval["key_context_digest"] != reference["key_context_digest"]
            || [
                "tenant_scope",
                "logical_job_id",
                "operation_id",
                "workflow_epoch",
                "policy_digest",
            ]
            .iter()
            .any(|field| approval[*field] != operation[*field])
            || ["recipient", "output_stage", "disclosure_index"]
                .iter()
                .any(|field| approval[*field] != operation["disclosure_identity"][*field])
            || approval["output_stage"] != operation["stage_id"]
        {
            return Err(RegistryError::Forbidden);
        }
        approved.check_current(&live)?;
        let deadline = string(operation, "deadline_unix_ms")?
            .parse::<i64>()
            .map_err(|_| RegistryError::InvalidIntent)?;
        if !now_unix_ms().is_some_and(|now| now < deadline as u64 && deadline > 0) {
            return Err(RegistryError::Forbidden);
        }
        let mut ordered = inputs.iter().enumerate().collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|(_, digest)| *digest);
        let mut upload_ids = vec![String::new(); inputs.len()];
        for (index, digest) in ordered {
            let (id, raw): (String, Vec<u8>) = sqlx::query_as(
                "SELECT u.id,f.canonical_manifest FROM fabric_uploads u
                 JOIN fabric_finalized_artifacts f ON f.upload_id=u.id
                 WHERE u.tenant_scope=$1 AND u.certificate=$2 AND NOT u.reclaiming
                   AND f.manifest_digest=$3 AND u.scope->>'purpose'='INPUT_UPLOAD'
                   AND u.scope->'key_context_ref'=$4 AND ($5::text IS NULL OR u.id=$5) ORDER BY u.id LIMIT 1 FOR UPDATE OF u",
            ).bind(key.tenant_scope).bind(workload).bind(digest).bind(reference)
                .bind(prior.as_ref().and_then(|(_, ids)| ids.get(index)))
                .fetch_optional(&mut *tx).await?.ok_or(RegistryError::Forbidden)?;
            let manifest = finalize::manifest(&raw).map_err(|_| RegistryError::Unavailable)?;
            if manifest["key_context_digest"] != reference["key_context_digest"]
                || manifest["tenant_scope"] != grant.tenant_scope
                || (index != 0
                    && (manifest["precision"] != approved.plan["precision"]
                        || manifest["shape"] != approved.plan["input_shape"]
                        || manifest["arithmetic"] != approved.plan["arithmetic"]))
                || manifest["artifact_kind"]
                    != if index == 0 {
                        "EVALUATION_KEY"
                    } else {
                        "CIPHERTEXT"
                    }
                || (index == 0
                    && manifest["full_blob_digest"] != context["evaluation_key_blob_digest"])
            {
                return Err(RegistryError::Forbidden);
            }
            upload_ids[index] = id;
        }
        let (saved, created) = Self::record_operation(&mut tx, &intent).await?;
        if created {
            sqlx::query("INSERT INTO fabric_approved_admissions VALUES($1,$2,$3,$4)")
                .bind(key.tenant_scope)
                .bind(key.operation_id)
                .bind(body)
                .bind(&upload_ids)
                .execute(&mut *tx)
                .await?;
            for id in &upload_ids {
                sqlx::query("INSERT INTO fabric_artifact_pins VALUES($1,'workflow',$2,$3) ON CONFLICT DO NOTHING")
                    .bind(id).bind(key.operation_id).bind(deadline).execute(&mut *tx).await?;
            }
        } else {
            let existing: Option<(Value,Vec<String>)> = sqlx::query_as(
                "SELECT intent, upload_ids FROM fabric_approved_admissions WHERE tenant_scope=$1 AND operation_id=$2",
            ).bind(key.tenant_scope).bind(key.operation_id).fetch_optional(&mut *tx).await?;
            if existing.as_ref() != Some(&(body.clone(), upload_ids)) {
                return Err(RegistryError::IdempotencyConflict);
            }
        }
        approved.check_current(&live)?;
        if !now_unix_ms().is_some_and(|now| now < deadline as u64) {
            return Err(RegistryError::Forbidden);
        }
        tx.commit().await?;
        Ok(saved)
    }
}

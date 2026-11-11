//! Coordinator-only disclosure decision. No artifact read capability is minted.
use std::sync::OnceLock;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;
use serde_json::json;

use super::*;
use crate::receipt::{canonical, commitment, signature_preimage, verify_signature};

static AUTHORIZATION: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
const AUTHORIZATION_SCHEMA: &str =
    include_str!("../../../../contracts/spec/canonical/v3/release-authorization.schema.json");

const IDENTITY: [&str; 5] = [
    "tenant_scope",
    "logical_job_id",
    "output_stage",
    "recipient",
    "disclosure_index",
];
const CONTEXT: [&str; 10] = [
    "tenant_scope",
    "logical_job_id",
    "operation_id",
    "workflow_epoch",
    "session_epoch",
    "plan_digest",
    "model_digest",
    "key_context_digest",
    "program_digest",
    "policy_digest",
];

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Trust {
    signer: String,
    key_id: String,
    key_epoch: String,
    public_key_hex: String,
}

impl Trust {
    pub(crate) fn fields(&self) -> (&str, &str, &str, &str) {
        (
            &self.signer,
            &self.key_id,
            &self.key_epoch,
            &self.public_key_hex,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePolicy {
    approval_base64url: Value,
    signature_base64url: Value,
    owner: Trust,
    receipt: Trust,
    coordinator: Trust,
    coordinator_seed_hex: String,
    policy_digest: String,
    policy_epoch: String,
    evidence_policy: String,
    evidence_policy_digest: String,
    consent: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequest {
    tenant_scope: String,
    operation_id: String,
    workflow_epoch: String,
    execution_id: String,
    output_manifest_digest: String,
}

fn compact(mut value: Value) -> Result<Vec<u8>> {
    value.sort_all_objects();
    serde_json::to_vec(&value).map_err(|_| RegistryError::InvalidIntent)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn disclosure_id(identity: &Value) -> Result<String> {
    let object = identity.as_object().ok_or(RegistryError::InvalidIntent)?;
    if object.len() != IDENTITY.len() + 1
        || identity["schema_version"] != "1"
        || identity["disclosure_index"] != "0"
        || !IDENTITY.iter().all(|k| {
            identity[*k].as_str().is_some_and(|s| {
                !s.is_empty()
                    && s.len() <= 128
                    && s.as_bytes()[0].is_ascii_alphanumeric()
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            })
        })
    {
        return Err(RegistryError::InvalidIntent);
    }
    Ok(commitment(
        "disclosure-identity",
        3,
        &compact(identity.clone())?,
    ))
}

pub(super) async fn lock_approval(tx: &mut Transaction<'_, Postgres>, digest: &str) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(digest)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn signed_decision(value: &Value, policy: &ReleasePolicy) -> Result<(Vec<u8>, Vec<u8>)> {
    let kind = "release-authorization";
    let payload = compact(value.clone())?;
    canonical(
        &json!(URL_SAFE_NO_PAD.encode(&payload)),
        32768,
        &AUTHORIZATION,
        AUTHORIZATION_SCHEMA,
    )?;
    let signer = &policy.coordinator;
    let seed = hex::decode(&policy.coordinator_seed_hex).map_err(|_| RegistryError::Forbidden)?;
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| RegistryError::Forbidden)?;
    if hex::encode(key.public_key().as_ref()) != signer.public_key_hex {
        return Err(RegistryError::Forbidden);
    }
    let mut header = json!({
        "schema_version":"3", "algorithm":"Ed25519", "payload_kind":kind,
        "payload_digest": commitment(kind, 3, &payload),
        "signer":signer.signer, "key_id":signer.key_id, "key_epoch":signer.key_epoch,
    });
    let preimage = signature_preimage(kind, &compact(header.clone())?, &payload);
    header["signature"] = json!(URL_SAFE_NO_PAD.encode(key.sign(&preimage)));
    let (envelope, _) = verify_signature(
        &json!(URL_SAFE_NO_PAD.encode(compact(header)?)),
        &payload,
        kind,
        signer.fields(),
    )?;
    Ok((payload, envelope))
}

impl Registry {
    pub async fn revoke_release_approval(&self, approval: &str) -> Result<()> {
        if !digest(approval) {
            return Err(RegistryError::InvalidIntent);
        }
        let mut tx = self.pool.begin().await?;
        lock_approval(&mut tx, approval).await?;
        sqlx::query(
            "INSERT INTO fabric_revoked_release_approvals VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(approval)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn commit_release(
        &self,
        request: &ReleaseRequest,
        policy: &ReleasePolicy,
    ) -> Result<Value> {
        static APPROVAL: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
        static RECEIPT: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
        static CONSENT: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
        let (approval_bytes, approval) = canonical(
            &policy.approval_base64url,
            32768,
            &APPROVAL,
            include_str!("../../../../contracts/spec/canonical/v3/approval.schema.json"),
        )?;
        let (_, approval_digest) = verify_signature(
            &policy.signature_base64url,
            &approval_bytes,
            "approval",
            policy.owner.fields(),
        )?;
        let consent = compact(policy.consent.clone())?;
        canonical(
            &json!(URL_SAFE_NO_PAD.encode(&consent)),
            32768,
            &CONSENT,
            include_str!("../../../../contracts/spec/consent-declaration.schema.json"),
        )?;
        if policy.owner.public_key_hex == policy.receipt.public_key_hex
            || policy.owner.public_key_hex == policy.coordinator.public_key_hex
            || policy.receipt.public_key_hex == policy.coordinator.public_key_hex
            || policy.evidence_policy != "NONE"
            || policy.consent["allow_unverified_release"] != true
            || approval["consent_digest"] != commitment("blob", 1, &consent)
            || approval["evidence_policy_digest"] != policy.evidence_policy_digest
            || approval["policy_digest"] != policy.policy_digest
            || approval["policy_epoch"] != policy.policy_epoch
            || approval["purpose"] != "RELEASE"
            || approval["subject_kind"] != "plan"
            || approval["subject_digest"] != approval["plan_digest"]
        {
            return Err(RegistryError::Forbidden);
        }
        let key = OperationKey {
            tenant_scope: &request.tenant_scope,
            operation_id: &request.operation_id,
        };
        let mut tx = self.pool.begin().await?;
        let operation: Value = sqlx::query_scalar(
            "SELECT intent FROM fabric_operations WHERE tenant_scope=$1 AND operation_id=$2 FOR UPDATE",
        ).bind(key.tenant_scope).bind(key.operation_id).fetch_optional(&mut *tx).await?
            .ok_or(RegistryError::NotFound)?;
        super::barriers::require_open(&mut tx, key).await?;
        lock_approval(&mut tx, &approval_digest).await?;
        let revoked: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM fabric_revoked_release_approvals WHERE approval_digest=$1)",
        ).bind(&approval_digest).fetch_one(&mut *tx).await?;
        if revoked || operation["workflow_epoch"] != request.workflow_epoch {
            return Err(RegistryError::Forbidden);
        }
        let selected = super::selection::read_selection(&mut *tx, key)
            .await?
            .ok_or(RegistryError::NotFound)?;
        if selected.execution_id != request.execution_id
            || selected.manifest_digest != request.output_manifest_digest
        {
            return Err(RegistryError::CandidateMismatch);
        }
        let (upload, receipt_digest, payload, signature, fence): (String, String, Vec<u8>, Vec<u8>, String) =
            sqlx::query_as(
                "SELECT r.output_upload_id,r.receipt_digest,r.canonical_receipt,r.canonical_signature,a.fence::text
                 FROM fabric_execution_receipts r JOIN fabric_executions e USING (tenant_scope,operation_id,execution_id)
                 JOIN fabric_attempts a USING (tenant_scope,operation_id,attempt_epoch)
                 WHERE r.tenant_scope=$1 AND r.operation_id=$2 AND r.execution_id=$3",
            ).bind(key.tenant_scope).bind(key.operation_id).bind(&selected.execution_id)
                .fetch_optional(&mut *tx).await?.ok_or(RegistryError::NotFound)?;
        let (_, receipt) = canonical(
            &json!(URL_SAFE_NO_PAD.encode(&payload)),
            32768,
            &RECEIPT,
            include_str!("../../../../contracts/spec/canonical/v3/receipt.schema.json"),
        )?;
        let (_, verified_digest) = verify_signature(
            &json!(URL_SAFE_NO_PAD.encode(signature)),
            &payload,
            "receipt",
            policy.receipt.fields(),
        )?;
        let identity = &operation["disclosure_identity"];
        let id = disclosure_id(identity)?;
        if upload != selected.upload_id
            || receipt_digest != verified_digest
            || receipt["signer"] != policy.receipt.signer
            || receipt["attempt_epoch"]
                .as_str()
                .and_then(|epoch| epoch.parse::<u64>().ok())
                != Some(selected.attempt_epoch)
            || receipt["fence"] != fence
            || receipt["execution_id"] != selected.execution_id
            || receipt["output_manifest_digests"] != json!([selected.manifest_digest])
            || receipt["evidence_status"] != "NOT_REQUESTED"
            || receipt["evidence_journal_digests"] != json!([])
            || receipt["stage_id"] != operation["stage_id"]
            || receipt["stage_id"] != identity["output_stage"]
            || receipt["plan_digest"] != operation["plan_ref"]["plan_digest"]
            || receipt["key_context_digest"] != operation["key_context_ref"]["key_context_digest"]
            || [
                "tenant_scope",
                "operation_id",
                "logical_job_id",
                "workflow_epoch",
                "policy_digest",
            ]
            .iter()
            .any(|k| receipt[*k] != operation[*k])
            || CONTEXT
                .iter()
                .chain(["policy_epoch", "consent_digest", "evidence_policy_digest"].iter())
                .any(|k| receipt[*k] != approval[*k])
            || IDENTITY.iter().any(|k| approval[*k] != identity[*k])
        {
            return Err(RegistryError::Forbidden);
        }
        let valid = |field: &str| {
            approval[field]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or(RegistryError::InvalidIntent)
        };
        let (start, end) = (valid("valid_from_unix_ms")?, valid("expires_unix_ms")?);
        let mut decision = json!({
            "schema_version":"3", "object_type":"release-authorization",
            "output_manifest_digest":selected.manifest_digest, "approval_digest":approval_digest,
            "receipt_digest":receipt_digest, "assurance":"CONFIDENTIALITY_ONLY",
        });
        for field in CONTEXT.into_iter().chain(IDENTITY).chain([
            "policy_epoch",
            "consent_digest",
            "evidence_policy_digest",
            "valid_from_unix_ms",
            "expires_unix_ms",
        ]) {
            decision[field] = approval[field].clone();
        }
        for field in ["attempt_epoch", "fence", "execution_id"] {
            decision[field] = receipt[field].clone();
        }
        let (payload, signature) = signed_decision(&decision, policy)?;
        sqlx::query(
            "INSERT INTO fabric_disclosure_decisions VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
        ).bind(&id).bind(&selected.manifest_digest).bind(&selected.upload_id)
            .bind(payload).bind(signature).execute(&mut *tx).await?;
        let saved: String = sqlx::query_scalar(
            "SELECT output_manifest_digest FROM fabric_disclosure_decisions WHERE disclosure_id=$1",
        )
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
        if saved != selected.manifest_digest {
            return Err(RegistryError::IdempotencyConflict);
        }
        let now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&mut *tx)
        .await?;
        if !u64::try_from(now).is_ok_and(|now| (start..end).contains(&now)) {
            return Err(RegistryError::Forbidden);
        }
        tx.commit().await?;
        Ok(json!({"outcome":"RELEASED","disclosure_id":id}))
    }
}

impl Registry {
    pub(crate) async fn lock_release_read(
        tx: &mut Transaction<'_, Postgres>,
        scope: &Value,
        grant: &crate::authorization::ConsumerGrant,
    ) -> Result<(String, String, u64, u64)> {
        let id = string(scope, "disclosure_id")?;
        let (upload, digest, payload, envelope): (String, String, Vec<u8>, Vec<u8>) =
            sqlx::query_as(
                "SELECT output_upload_id,output_manifest_digest,canonical_authorization,
                canonical_signature FROM fabric_disclosure_decisions WHERE disclosure_id=$1",
            )
            .bind(&id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(RegistryError::Forbidden)?;
        let (_, decision) = canonical(
            &json!(URL_SAFE_NO_PAD.encode(&payload)),
            32768,
            &AUTHORIZATION,
            AUTHORIZATION_SCHEMA,
        )?;
        verify_signature(
            &json!(URL_SAFE_NO_PAD.encode(envelope)),
            &payload,
            "release-authorization",
            grant.coordinator.fields(),
        )?;
        if ["tenant_scope", "recipient", "output_manifest_digest"]
            .iter()
            .any(|field| decision[*field] != scope[*field])
            || decision["output_manifest_digest"] != digest
            || decision["policy_digest"] != grant.policy_digest
            || decision["policy_epoch"] != grant.policy_epoch
        {
            return Err(RegistryError::Forbidden);
        }
        let tenant = string(scope, "tenant_scope")?;
        let operation_id = string(&decision, "operation_id")?;
        let key = OperationKey {
            tenant_scope: &tenant,
            operation_id: &operation_id,
        };
        let operation: Value = sqlx::query_scalar(
            "SELECT intent FROM fabric_operations WHERE tenant_scope=$1 AND operation_id=$2 FOR SHARE",
        ).bind(&tenant).bind(&operation_id).fetch_optional(&mut **tx).await?
            .ok_or(RegistryError::Forbidden)?;
        super::barriers::require_open(tx, key).await?;
        let identity = &operation["disclosure_identity"];
        if disclosure_id(identity)? != id
            || IDENTITY
                .iter()
                .any(|field| identity[*field] != decision[*field])
            || operation["workflow_epoch"] != decision["workflow_epoch"]
            || operation["policy_digest"] != decision["policy_digest"]
            || operation["plan_ref"]["plan_digest"] != decision["plan_digest"]
            || operation["key_context_ref"]["key_context_digest"] != decision["key_context_digest"]
        {
            return Err(RegistryError::Forbidden);
        }
        let approval = string(&decision, "approval_digest")?;
        lock_approval(tx, &approval).await?;
        let revoked: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM fabric_revoked_release_approvals WHERE approval_digest=$1)",
        ).bind(&approval).fetch_one(&mut **tx).await?;
        if revoked {
            return Err(RegistryError::Forbidden);
        }
        let time = |name| {
            string(&decision, name)?
                .parse::<u64>()
                .map_err(|_| RegistryError::InvalidIntent)
        };
        Ok((
            upload,
            string(&decision, "key_context_digest")?,
            time("valid_from_unix_ms")?,
            time("expires_unix_ms")?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_signature_preimage_matches_spec() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../contracts/spec/fixtures/canonical-disclosure-v3.json"
        ))
        .unwrap();
        let payload = compact(fixture["authorization"].clone()).unwrap();
        assert_eq!(
            payload,
            fixture["canonical_utf8"].as_str().unwrap().as_bytes()
        );
        let header = compact(fixture["header"].clone()).unwrap();
        let preimage = signature_preimage("release-authorization", &header, &payload);
        assert_eq!(
            blake3::hash(&preimage).to_hex().as_str(),
            fixture["preimage_blake3"]
        );
    }
}

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kryvola_fabric_core::registry::{
    OperationKey, Registry, RegistryError, ReleasePolicy, ReleaseRequest,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

fn canonical(mut value: Value) -> Vec<u8> {
    value.sort_all_objects();
    serde_json::to_vec(&value).unwrap()
}

fn hash(domain: &[u8], bytes: &[u8]) -> String {
    blake3::Hasher::new()
        .update(domain)
        .update(bytes)
        .finalize()
        .to_hex()
        .to_string()
}

fn sign(kind: &str, body: &Value, signer: &str, seed: u8) -> (Vec<u8>, Vec<u8>, String, Value) {
    let body = canonical(body.clone());
    let digest = hash(format!("kryvola/{kind}/v3\0").as_bytes(), &body);
    let key = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let mut header = json!({"schema_version":"3","algorithm":"Ed25519","payload_kind":kind,
        "signer":signer,"key_id":"fixture","key_epoch":"1","payload_digest":digest});
    let metadata = canonical(header.clone());
    let mut preimage = format!("kryvola/signature/{kind}/v3\0").into_bytes();
    for value in [&metadata, &body] {
        preimage.extend_from_slice(&(value.len() as u64).to_le_bytes());
        preimage.extend_from_slice(value);
    }
    header["signature"] = json!(URL_SAFE_NO_PAD.encode(key.sign(&preimage)));
    let trust = json!({"signer":signer,"key_id":"fixture","key_epoch":"1",
        "public_key_hex":hex::encode(key.public_key().as_ref())});
    (body, canonical(header), digest, trust)
}

async fn fixture(pool: &PgPool, epoch: u64, output_tag: u64) -> (Value, Value, String) {
    let id = format!("release-op-{epoch}");
    let output = format!("{output_tag:064x}");
    let owner = "release-tenant";
    let original: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spec/fixtures/canonical-approval-receipt-v3.json"
    ))
    .unwrap();
    let disclosure: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spec/fixtures/canonical-disclosure-v3.json"
    ))
    .unwrap();
    let consent: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spec/fixtures/fhe-q1-consent.json"
    ))
    .unwrap();
    let now = kryvola_fabric_core::authorization::now_unix_ms().unwrap();
    let mut identity = disclosure["identity"].clone();
    identity["tenant_scope"] = json!(owner);
    let mut approval = original["objects"][0]["value"].clone();
    let mut receipt = original["objects"][1]["value"].clone();
    for field in ["tenant_scope", "logical_job_id"] {
        approval[field] = identity[field].clone();
        receipt[field] = identity[field].clone();
    }
    for field in ["output_stage", "recipient", "disclosure_index"] {
        approval[field] = identity[field].clone();
    }
    for value in [&mut approval, &mut receipt] {
        value["operation_id"] = json!(id);
        value["workflow_epoch"] = json!(epoch.to_string());
        value["consent_digest"] = json!(hash(b"kryvola/blob/v1\0", &canonical(consent.clone())));
    }
    approval["purpose"] = json!("RELEASE");
    approval["subject_kind"] = json!("plan");
    approval["subject_digest"] = approval["plan_digest"].clone();
    approval["valid_from_unix_ms"] = json!((now - 1000).to_string());
    approval["expires_unix_ms"] = json!((now + 90_000).to_string());
    receipt["stage_id"] = identity["output_stage"].clone();
    receipt["signer"] = json!("worker");
    receipt["execution_id"] = json!("exec");
    receipt["fence"] = json!("1");
    receipt["attempt_epoch"] = json!("1");
    receipt["output_manifest_digests"] = json!([output]);
    receipt["evidence_status"] = json!("NOT_REQUESTED");
    receipt["evidence_journal_digests"] = json!([]);
    for field in [
        "plan_digest",
        "policy_epoch",
        "policy_digest",
        "model_digest",
        "key_context_digest",
        "session_epoch",
        "program_digest",
        "evidence_policy_digest",
    ] {
        receipt[field] = approval[field].clone();
    }
    let (a, sig, approval_digest, owner_trust) = sign("approval", &approval, "owner", 1);
    let (r, rs, digest, worker) = sign("receipt", &receipt, "worker", 2);
    let (_, _, _, coordinator) = sign("release-authorization", &json!({}), "coordinator", 3);
    let operation = json!({"tenant_scope":owner,"operation_id":id,"workflow_epoch":epoch.to_string(),
        "stage_id":identity["output_stage"],"logical_job_id":identity["logical_job_id"],
        "policy_digest":approval["policy_digest"],"disclosure_identity":identity,
        "plan_ref":{"plan_digest":approval["plan_digest"]},
        "key_context_ref":{"key_context_digest":approval["key_context_digest"]}});
    sqlx::query("INSERT INTO fabric_operations VALUES($1,$2,$2,$3,'[]')")
        .bind(owner)
        .bind(&id)
        .bind(operation)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO fabric_attempts VALUES($1,$2,1,1,0,true)")
        .bind(owner)
        .bind(&id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO fabric_executions VALUES($1,$2,'exec',1)")
        .bind(owner)
        .bind(&id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO fabric_upload_tenants VALUES($1) ON CONFLICT DO NOTHING")
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO fabric_uploads (id,tenant_scope,certificate,scope,reserved_bytes)
        VALUES($2,$1,'fixture','{}',1)",
    )
    .bind(owner)
    .bind(&id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO fabric_finalized_artifacts (upload_id,manifest_digest,canonical_manifest)
        VALUES($1,$2,''::bytea)",
    )
    .bind(&id)
    .bind(&output)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO fabric_selected_results VALUES($1,$2,'exec',$2)")
        .bind(owner)
        .bind(&id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO fabric_execution_receipts VALUES($1,$2,'exec',$2,$3,$4,$5)")
        .bind(owner)
        .bind(&id)
        .bind(digest)
        .bind(r)
        .bind(rs)
        .execute(pool)
        .await
        .unwrap();
    let request = json!({"tenant_scope":owner,"operation_id":id,"workflow_epoch":epoch.to_string(),
        "execution_id":"exec","output_manifest_digest":output});
    let policy = json!({"approval_base64url":URL_SAFE_NO_PAD.encode(a),
        "signature_base64url":URL_SAFE_NO_PAD.encode(sig),"owner":owner_trust,
        "receipt":worker,"coordinator":coordinator,"coordinator_seed_hex":"03".repeat(32),
        "policy_digest":approval["policy_digest"],"policy_epoch":approval["policy_epoch"],
        "evidence_policy":"NONE","evidence_policy_digest":approval["evidence_policy_digest"],
        "consent":consent});
    (request, policy, approval_digest)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn exact_release_transaction() {
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(super::fixture_options())
        .await
        .unwrap();
    let registry = Registry::new(pool.clone());
    registry.migrate().await.unwrap();
    let (request, policy, approval) = fixture(&pool, 1, 1).await;
    let commit = |request: Value, policy: Value| {
        let registry = &registry;
        async move {
            let request: ReleaseRequest = serde_json::from_value(request).unwrap();
            let policy: ReleasePolicy = serde_json::from_value(policy).unwrap();
            registry.commit_release(&request, &policy).await
        }
    };
    let mut unsupported = policy.clone();
    unsupported["evidence_policy"] = json!("PROOF_REQUIRED");
    assert_eq!(
        commit(request.clone(), unsupported).await,
        Err(RegistryError::Forbidden)
    );
    let mut wrong = request.clone();
    wrong["output_manifest_digest"] = json!("0".repeat(64));
    assert_eq!(
        commit(wrong, policy.clone()).await,
        Err(RegistryError::CandidateMismatch)
    );
    let mut tampered = policy.clone();
    let mut bytes = URL_SAFE_NO_PAD
        .decode(tampered["approval_base64url"].as_str().unwrap())
        .unwrap();
    let mut document: Value = serde_json::from_slice(&bytes).unwrap();
    document["recipient"] = json!("intruder");
    bytes = canonical(document);
    tampered["approval_base64url"] = json!(URL_SAFE_NO_PAD.encode(bytes));
    assert_eq!(
        commit(request.clone(), tampered).await,
        Err(RegistryError::Forbidden)
    );
    let (a, b) = tokio::join!(
        commit(request.clone(), policy.clone()),
        commit(request.clone(), policy.clone())
    );
    let decision = a.unwrap();
    assert_eq!(decision["outcome"], "RELEASED");
    assert_eq!(decision, b.unwrap());
    let (replayed, replayed_policy, _) = fixture(&pool, 2, 1).await;
    assert_eq!(commit(replayed, replayed_policy).await.unwrap(), decision);
    let (next, next_policy, _) = fixture(&pool, 3, 3).await;
    assert_eq!(
        commit(next.clone(), next_policy.clone()).await,
        Err(RegistryError::IdempotencyConflict)
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM fabric_disclosure_decisions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    registry.revoke_release_approval(&approval).await.unwrap();
    assert_eq!(commit(request, policy).await, Err(RegistryError::Forbidden));
    registry
        .cancel_operation(
            OperationKey {
                tenant_scope: "release-tenant",
                operation_id: "release-op-3",
            },
            "release-cancel",
        )
        .await
        .unwrap();
    assert_eq!(
        commit(next, next_policy).await,
        Err(RegistryError::Cancelled)
    );
}

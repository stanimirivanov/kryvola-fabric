use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kryvola_fabric_core::registry::{
    OperationKey, Registry, RegistryError, ReleasePolicy, ReleaseRequest,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

pub(super) fn canonical(mut value: Value) -> Vec<u8> {
    value.sort_all_objects();
    serde_json::to_vec(&value).unwrap()
}

pub(super) fn hash(domain: &[u8], bytes: &[u8]) -> String {
    blake3::Hasher::new()
        .update(domain)
        .update(bytes)
        .finalize()
        .to_hex()
        .to_string()
}

pub(super) fn sign(
    kind: &str,
    body: &Value,
    signer: &str,
    seed: u8,
) -> (Vec<u8>, Vec<u8>, String, Value) {
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

fn consumer_manifest() -> Value {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spec/fixtures/canonical-modular-v2.json"
    ))
    .unwrap();
    let mut manifest = corpus["objects"][0]["value"].clone();
    manifest["tenant_scope"] = json!("release-tenant");
    manifest
}

async fn fixture(pool: &PgPool, epoch: u64, output_tag: u64) -> (Value, Value, String) {
    let id = format!("release-op-{epoch}");
    let manifest = (output_tag == 0).then(consumer_manifest);
    let manifest_bytes = manifest
        .as_ref()
        .map(|value| canonical(value.clone()))
        .unwrap_or_default();
    let output = if manifest.is_some() {
        hash(b"kryvola/manifest/v2\0", &manifest_bytes)
    } else {
        format!("{output_tag:064x}")
    };
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
    if output_tag == 0 {
        identity["logical_job_id"] = json!(format!("consumer-{epoch}"));
    }
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
    if let Some(manifest) = manifest {
        approval["key_context_digest"] = manifest["key_context_digest"].clone();
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
        VALUES($1,$2,$3)",
    )
    .bind(&id)
    .bind(&output)
    .bind(manifest_bytes)
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
    let key = OperationKey {
        tenant_scope: "release-tenant",
        operation_id: "release-op-1",
    };
    assert_eq!(
        registry.public_status(key).await.unwrap().as_deref(),
        Some("COMPUTE_SELECTED")
    );
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
    assert_eq!(
        registry.public_status(key).await.unwrap().as_deref(),
        Some("RELEASED"),
        "the public lifecycle must expose the committed release"
    );
    assert_eq!(decision, b.unwrap());
    let (replayed, replayed_policy, _) = fixture(&pool, 2, 1).await;
    assert_eq!(commit(replayed, replayed_policy).await.unwrap(), decision);
    assert_eq!(
        registry
            .public_status(OperationKey {
                tenant_scope: "release-tenant",
                operation_id: "release-op-2",
            })
            .await
            .unwrap()
            .as_deref(),
        Some("COMPUTE_SELECTED"),
        "replaying a logical decision must not release another physical upload"
    );
    let (next, next_policy, _) = fixture(&pool, 3, 3).await;
    assert_eq!(
        commit(next.clone(), next_policy.clone()).await,
        Err(RegistryError::IdempotencyConflict)
    );
    let changed = OperationKey {
        tenant_scope: "release-tenant",
        operation_id: "release-op-3",
    };
    assert_eq!(
        registry.public_status(changed).await.unwrap().as_deref(),
        Some("COMPUTE_SELECTED"),
        "another output under the same disclosure identity remains unreleased"
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
    assert_eq!(
        registry.public_status(changed).await.unwrap().as_deref(),
        Some("CANCELLED")
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and S3"]
async fn released_output_reads() {
    use axum::{
        body::{Body, to_bytes},
        extract::Request,
        http::StatusCode,
    };
    use kryvola_fabric_core::{
        authorization::{Authorizer, now_unix_ms, sha256_hex},
        registry::disclosure_id,
        runtime_contract::RuntimeValidator,
        upload_http::UploadApi,
    };
    use object_store::{ObjectStoreExt, path::Path};
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant},
    };

    let pool = PgPoolOptions::new()
        .connect_with(super::fixture_options())
        .await
        .unwrap();
    let registry = Registry::new(pool.clone());
    registry.migrate().await.unwrap();
    let (request, policy, approval) = fixture(&pool, 11, 0).await;
    let identity: Value = sqlx::query_scalar(
        "SELECT intent->'disclosure_identity' FROM fabric_operations WHERE operation_id='release-op-11'",
    ).fetch_one(&pool).await.unwrap();
    let scope = json!({"schema_version":"1","tenant_scope":identity["tenant_scope"],
        "recipient":identity["recipient"],"disclosure_id":disclosure_id(&identity).unwrap(),
        "output_manifest_digest":request["output_manifest_digest"]});
    let dir = PathBuf::from(std::env::var_os("FABRIC_FIXTURE_PG_SOCKET").unwrap());
    let config = dir.with_file_name("consumer-storage.json");
    fs::write(&config, json!({
        "endpoint":std::env::var("FABRIC_FIXTURE_S3_ENDPOINT").unwrap(),
        "access_key_id":std::env::var("AWS_ACCESS_KEY_ID").unwrap(),
        "secret_access_key":std::env::var("AWS_SECRET_ACCESS_KEY").unwrap(),
        "bucket":"fabric-runtime","region":"us-east-1","tenant_quota_bytes":1024,"allow_http":true
    }).to_string()).unwrap();
    let api = UploadApi::connect(pool.clone(), config.to_str().unwrap()).unwrap();
    let policy_path = dir.with_file_name("consumer-policy.json");
    let auth = Authorizer::new(policy_path.clone()).unwrap();
    let peer = "spiffe://fixture.test/owner".parse().unwrap();
    let worker = "spiffe://fixture.test/worker".parse().unwrap();
    let now = now_unix_ms().unwrap();
    let grant = |number: u8, index: Option<u16>, target: &Value| {
        json!({
            "spiffe_id":"spiffe://fixture.test/owner", "token_sha256":sha256_hex(format!("{number:064x}").as_bytes()),
            "scope":target, "part_index":index,"expires_unix_ms":now+60_000,
            "policy_digest":policy["policy_digest"],"policy_epoch":policy["policy_epoch"],
            "coordinator":policy["coordinator"]
        })
    };
    let mut wrong = scope.clone();
    wrong["recipient"] = json!("intruder");
    let mut guessed = scope.clone();
    guessed["output_manifest_digest"] = json!("b".repeat(64));
    let mut stale = grant(12, None, &scope);
    stale["policy_epoch"] = json!("9");
    let compute = |number: u8, purpose: &str| {
        json!({
            "spiffe_id":"spiffe://fixture.test/owner","token_sha256":sha256_hex(format!("{number:064x}").as_bytes()),
            "expires_unix_ms":now+60_000,"scope":{"schema_version":"1","attempt":{"schema_version":"1",
            "tenant_scope":"release-tenant","operation_id":"release-op-11","workflow_epoch":"11",
            "attempt_epoch":"1","fence":"1"},"manifest_digest":scope["output_manifest_digest"],"purpose":purpose}
        })
    };
    fs::write(&policy_path, json!({
        "boot_id":auth.boot_id(),"grants":[compute(8,"COMPUTE_READ"),compute(9,"EVIDENCE_READ")],
        "consumer_grants":[grant(1,None,&scope),grant(2,None,&scope),grant(3,Some(0),&scope),
            grant(4,None,&wrong),grant(5,None,&guessed),grant(6,None,&scope),grant(7,None,&scope),
            grant(10,Some(1),&scope),grant(11,None,&scope),stale]
    }).to_string()).unwrap();
    let schemas = RuntimeValidator::new().unwrap();
    let read = |number: u8, scope: &Value, path: &str, workload| {
        api.handle_read(
            Request::post(format!("/v1/released-outputs/{path}"))
                .header("Authorization", format!("Bearer {number:064x}"))
                .body(Body::from(scope.to_string()))
                .unwrap(),
            (
                workload,
                &auth,
                now + 60_000,
                Instant::now() + Duration::from_secs(10),
            ),
            &schemas,
        )
    };
    assert_eq!(
        read(1, &scope, "manifest", &peer).await.status(),
        StatusCode::FORBIDDEN
    );
    let policy_value: ReleasePolicy = serde_json::from_value(policy.clone()).unwrap();
    registry
        .commit_release(&serde_json::from_value(request).unwrap(), &policy_value)
        .await
        .unwrap();
    for (token, body, workload) in [
        (4, &wrong, &peer),
        (5, &guessed, &peer),
        (8, &scope, &peer),
        (9, &scope, &peer),
        (6, &scope, &worker),
        (12, &scope, &peer),
    ] {
        assert_eq!(
            read(token, body, "manifest", workload).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        read(3, &scope, "manifest", &peer).await.status(),
        StatusCode::FORBIDDEN
    );
    let response = read(2, &scope, "manifest", &peer).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .as_ref(),
        canonical(consumer_manifest())
    );
    assert_eq!(
        read(2, &scope, "manifest", &peer).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        read(10, &scope, "parts/1", &peer).await.status(),
        StatusCode::NOT_FOUND
    );
    super::fixture_objects()
        .put(
            &Path::from("immutable/release-op-11/0"),
            axum::body::Bytes::from_static(&[0, 1, 2, 255]).into(),
        )
        .await
        .unwrap();
    let response = read(3, &scope, "parts/0", &peer).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 4).await.unwrap().as_ref(),
        &[0, 1, 2, 255]
    );
    registry.revoke_release_approval(&approval).await.unwrap();
    assert_eq!(
        read(7, &scope, "manifest", &peer).await.status(),
        StatusCode::FORBIDDEN
    );
    let (cancelled, cancelled_policy, _) = fixture(&pool, 12, 0).await;
    let cancelled_policy = serde_json::from_value(cancelled_policy).unwrap();
    let decision = registry
        .commit_release(
            &serde_json::from_value(cancelled).unwrap(),
            &cancelled_policy,
        )
        .await
        .unwrap();
    let mut cancelled_scope = scope.clone();
    cancelled_scope["disclosure_id"] = decision["disclosure_id"].clone();
    let mut local_policy: Value = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    local_policy["consumer_grants"]
        .as_array_mut()
        .unwrap()
        .push(grant(13, None, &cancelled_scope));
    fs::write(&policy_path, local_policy.to_string()).unwrap();
    registry
        .cancel_operation(
            OperationKey {
                tenant_scope: "release-tenant",
                operation_id: "release-op-12",
            },
            "cancel-consumer-fixture",
        )
        .await
        .unwrap();
    assert_eq!(
        read(13, &cancelled_scope, "manifest", &peer).await.status(),
        StatusCode::FORBIDDEN
    );
    pool.close().await;
    let outage = read(11, &scope, "manifest", &peer).await;
    assert_eq!(outage.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        to_bytes(outage.into_body(), 65536)
            .await
            .unwrap()
            .starts_with(b"{")
    );
}

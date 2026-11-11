use super::release::{canonical, hash, sign};
use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kryvola_fabric_core::{
    authorization::{Authorizer, now_unix_ms, sha256_hex},
    registry::Registry,
    runtime_contract::RuntimeValidator,
    upload_http::UploadApi,
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use std::{
    cell::Cell,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

fn fixture(path: &str) -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/spec/fixtures");
    serde_json::from_slice(&fs::read(root.join(path)).unwrap()).unwrap()
}
fn object(corpus: &str, kind: &str) -> Value {
    fixture(corpus)["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["kind"] == kind)
        .unwrap()["value"]
        .clone()
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and S3"]
async fn approved_submission_lifecycle() {
    let pool = PgPoolOptions::new()
        .connect_with(super::fixture_options())
        .await
        .unwrap();
    let registry = Registry::new(pool.clone());
    registry.migrate().await.unwrap();
    let directory = PathBuf::from(std::env::var_os("FABRIC_FIXTURE_PG_SOCKET").unwrap());
    let s3 = directory.with_file_name("submission-storage");
    let policy = directory.with_file_name("submission-policy");
    fs::write(
        &s3,
        json!({
            "endpoint":std::env::var("FABRIC_FIXTURE_S3_ENDPOINT").unwrap(),
            "access_key_id":std::env::var("AWS_ACCESS_KEY_ID").unwrap(),
            "secret_access_key":std::env::var("AWS_SECRET_ACCESS_KEY").unwrap(),
            "bucket":"fabric-runtime","region":"us-east-1","tenant_quota_bytes":8,"allow_http":true,
        })
        .to_string(),
    )
    .unwrap();
    let api = UploadApi::connect(pool.clone(), s3.to_str().unwrap()).unwrap();
    let auth = Authorizer::new(policy.clone()).unwrap();
    let schema = RuntimeValidator::new().unwrap();
    let peer = "spiffe://fixture.test/submitter".parse().unwrap();
    let now = now_unix_ms().unwrap();
    let mut approval = object("canonical-approval-receipt-v3.json", "approval");
    let mut plan = object("canonical-modular-v2.json", "plan");
    let mut key = object("canonical-corpus.json", "key-context");
    let tenant = "submission-fixture";
    let owner = "approved-owner";
    let pair = b"pair";
    let eval = b"eval";
    key["tenant_scope"] = json!(tenant);
    key["owner_identity"] = json!(owner);
    key["parameters"] = plan["parameters"].clone();
    key["native_codec_version"] = json!("tfhe-rs-1.8.1");
    key["evaluation_key_blob_digest"] = json!(hash(b"kryvola/blob/v1\0", eval));
    let key_bytes = canonical(key.clone());
    let context = json!({"schema_version":"1","tenant_scope":tenant,"key_context_id":key["key_context_id"],
        "immutable_version":"v1","key_epoch":key["key_epoch"],
        "key_context_digest":hash(b"kryvola/key-context/v1\0",&key_bytes)});
    let register = json!({"schema_version":"1","key_context_ref":context,
        "key_context_base64url":URL_SAFE_NO_PAD.encode(key_bytes)});
    let mut operation = fixture("control.json")["Operation"].clone();
    operation["tenant_scope"] = json!(tenant);
    operation["key_context_ref"] = context.clone();
    operation["workflow_epoch"] = json!("1");
    operation["operation_id"] = json!("sdk-op");
    operation["disclosure_identity"]["tenant_scope"] = json!(tenant);
    operation["deadline_unix_ms"] = json!((now + 120_000).to_string());
    let make_manifest = |kind: &str, data: &[u8]| {
        let mut manifest = object("canonical-modular-v2.json", "manifest");
        manifest["tenant_scope"] = json!(tenant);
        manifest["key_context_digest"] = context["key_context_digest"].clone();
        manifest["parameters"] = key["parameters"].clone();
        manifest["native_codec_version"] = key["native_codec_version"].clone();
        manifest["artifact_kind"] = json!(kind);
        manifest["shape"] = json!(["2"]);
        manifest["full_blob_digest"] = json!(hash(b"kryvola/blob/v1\0", data));
        let chunk = [
            0u64.to_le_bytes().as_slice(),
            4u64.to_le_bytes().as_slice(),
            data,
        ]
        .concat();
        manifest["ordered_chunk_entries"][0]["chunk_digest"] =
            json!(hash(b"kryvola/chunk/v1\0", &chunk));
        canonical(manifest)
    };
    let evaluation = make_manifest("EVALUATION_KEY", eval);
    let ciphertext = make_manifest("CIPHERTEXT", pair);
    let eval_digest = hash(b"kryvola/manifest/v2\0", &evaluation);
    let input_digest = hash(b"kryvola/manifest/v2\0", &ciphertext);
    let consent = canonical(fixture("fhe-q1-consent.json"));
    plan["tenant_scope"] = json!(tenant);
    plan["key_context_digest"] = context["key_context_digest"].clone();
    plan["consent_digest"] = json!(hash(b"kryvola/blob/v1\0", &consent));
    plan["input_shape"] = json!(["2"]);
    plan["input_manifest_digests"] = json!([input_digest]);
    let plan_bytes = canonical(plan.clone());
    let plan_digest = hash(b"kryvola/plan/v2\0", &plan_bytes);
    operation["plan_ref"]["tenant_scope"] = json!(tenant);
    operation["plan_ref"]["plan_digest"] = json!(plan_digest);
    for field in [
        "tenant_scope",
        "logical_job_id",
        "operation_id",
        "workflow_epoch",
        "policy_digest",
    ] {
        approval[field] = operation[field].clone();
    }
    for field in ["recipient", "output_stage", "disclosure_index"] {
        approval[field] = operation["disclosure_identity"][field].clone();
    }
    for field in [
        "key_context_digest",
        "model_digest",
        "program_digest",
        "consent_digest",
        "evidence_policy_digest",
    ] {
        approval[field] = plan[field].clone();
    }
    approval["subject_kind"] = json!("plan");
    approval["subject_digest"] = json!(plan_digest);
    approval["plan_digest"] = json!(plan_digest);
    approval["purpose"] = json!("COMPUTE");
    approval["valid_from_unix_ms"] = json!((now - 1000).to_string());
    approval["expires_unix_ms"] = json!((now + 120_000).to_string());
    let (payload, signature, approval_digest, trust) = sign("approval", &approval, owner, 8);
    let approval_request = json!({"schema_version":"1","plan_ref":operation["plan_ref"],
        "approval_digest":approval_digest,"plan_base64url":URL_SAFE_NO_PAD.encode(plan_bytes),
        "consent_base64url":URL_SAFE_NO_PAD.encode(consent),"approval_base64url":URL_SAFE_NO_PAD.encode(payload),
        "signature_base64url":URL_SAFE_NO_PAD.encode(signature)});
    let admit = json!({"schema_version":"1","operation":operation,"approval_digest":approval_digest,
        "evaluation_key_manifest_digest":eval_digest,"input_manifest_digests":[input_digest]});
    let serial = Cell::new(0u64);
    let call = |method: Method, path: &str, action: &str, target: &Value, bytes: Vec<u8>| {
        serial.set(serial.get() + 1);
        let token = format!("{:064x}", serial.get());
        fs::write(&policy, json!({"boot_id":auth.boot_id(),"grants":[],
            "owner_submission_grants":[{"spiffe_id":"spiffe://fixture.test/submitter",
            "token_sha256":sha256_hex(token.as_bytes()),"action":action,"target":target,
            "tenant_scope":tenant,"owner_identity":owner,"owner":trust,"policy_digest":approval["policy_digest"],
            "policy_epoch":approval["policy_epoch"],"evidence_policy_digest":approval["evidence_policy_digest"],
            "evidence_policy":"NONE","expires_unix_ms":now_unix_ms().unwrap()+60_000}]
        }).to_string()).unwrap();
        api.handle_submission(
            Request::builder()
                .method(method)
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Length", bytes.len())
                .body(Body::from(bytes))
                .unwrap(),
            (
                &peer,
                &auth,
                now + 120_000,
                Instant::now() + Duration::from_secs(20),
            ),
            &schema,
        )
    };
    for _ in 0..2 {
        assert_eq!(
            call(
                Method::POST,
                "/v1/key-contexts",
                "KEY_CONTEXT_REGISTER",
                &context,
                canonical(register.clone())
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    let target = json!({"plan_ref":operation["plan_ref"],"approval_digest":approval_digest});
    let (status, reply) = call(
        Method::POST,
        "/v1/compute-approvals",
        "COMPUTE_APPROVAL_REGISTER",
        &target,
        canonical(approval_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let request = |body: &Value| {
        call(
            Method::POST,
            "/v1/operations/admit",
            "APPROVED_OPERATION_ADMIT",
            body,
            canonical(body.clone()),
        )
    };
    assert_eq!(request(&admit).await.0, StatusCode::FORBIDDEN);
    for (kind, data, manifest, digest) in [
        ("EVALUATION_KEY", eval, evaluation, &eval_digest),
        ("CIPHERTEXT", pair, ciphertext, &input_digest),
    ] {
        let reserve = json!({"schema_version":"1","key_context_ref":context,"idempotency_key":kind,
            "manifest_digest":digest,"artifact_kind":kind,"byte_length":data.len()});
        let reserve_call = || {
            call(
                Method::POST,
                "/v1/input-uploads",
                "INPUT_UPLOAD_RESERVE",
                &reserve,
                canonical(reserve.clone()),
            )
        };
        let (status, first) = reserve_call().await;
        assert_eq!(status, StatusCode::CREATED, "{first}");
        assert_eq!(reserve_call().await, (status, first.clone()));
        let mut over_quota = reserve.clone();
        over_quota["idempotency_key"] = json!("extra");
        over_quota["byte_length"] = json!(9);
        assert_eq!(
            call(
                Method::POST,
                "/v1/input-uploads",
                "INPUT_UPLOAD_RESERVE",
                &over_quota,
                canonical(over_quota.clone())
            )
            .await
            .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        let response: Value = serde_json::from_str(&first).unwrap();
        let id = response["upload_id"].as_str().unwrap();
        let part = format!("/v1/input-uploads/{id}/parts/0");
        let part_target = json!({"upload_id":id,"part_index":0});
        for _ in 0..2 {
            assert_eq!(
                call(
                    Method::PUT,
                    &part,
                    "INPUT_UPLOAD_PART",
                    &part_target,
                    data.to_vec()
                )
                .await
                .0,
                StatusCode::NO_CONTENT
            );
        }
        assert_eq!(
            call(
                Method::PUT,
                &part,
                "INPUT_UPLOAD_PART",
                &part_target,
                b"evil".to_vec()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let path = format!("/v1/input-uploads/{id}/manifest");
        let target = json!({"upload_id":id});
        let mut wrong_kind: Value = serde_json::from_slice(&manifest).unwrap();
        wrong_kind["artifact_kind"] = json!(if kind == "EVALUATION_KEY" {
            "CIPHERTEXT"
        } else {
            "EVALUATION_KEY"
        });
        assert_eq!(
            call(
                Method::PUT,
                &path,
                "INPUT_UPLOAD_MANIFEST",
                &target,
                canonical(wrong_kind)
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        for _ in 0..2 {
            assert_eq!(
                call(
                    Method::PUT,
                    &path,
                    "INPUT_UPLOAD_MANIFEST",
                    &target,
                    manifest.clone()
                )
                .await
                .0,
                StatusCode::NO_CONTENT
            );
        }
        let finish = format!("/v1/input-uploads/{id}/finalize");
        let body =
            canonical(json!({"schema_version":"1","tenant_scope":tenant,"manifest_digest":digest}));
        for _ in 0..2 {
            let (status, reply) = call(
                Method::POST,
                &finish,
                "INPUT_UPLOAD_FINALIZE",
                &target,
                body.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{reply}");
        }
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM fabric_operations WHERE tenant_scope=$1")
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    let (status, first) = request(&admit).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(request(&admit).await, (status, first));
    let mut changed = admit.clone();
    changed["input_manifest_digests"] = json!(["f".repeat(64)]);
    assert_eq!(request(&changed).await.0, StatusCode::CONFLICT);
    let (inputs, events, pins): (Value,i64,i64) = sqlx::query_as(
        "SELECT o.inputs,(SELECT count(*) FROM fabric_outbox WHERE tenant_scope=$1 AND operation_id='sdk-op'),
         (SELECT count(*) FROM fabric_artifact_pins p JOIN fabric_uploads u ON u.id=p.upload_id
         WHERE p.holder='sdk-op' AND u.tenant_scope=$1) FROM fabric_operations o
         WHERE o.tenant_scope=$1 AND o.operation_id='sdk-op'"
    ).bind(tenant).fetch_one(&pool).await.unwrap();
    assert_eq!(
        (inputs, events, pins),
        (json!([eval_digest, input_digest]), 1, 2)
    );
    registry
        .revoke_release_approval(&approval_digest)
        .await
        .unwrap();
    assert_eq!(request(&admit).await.0, StatusCode::FORBIDDEN);
}

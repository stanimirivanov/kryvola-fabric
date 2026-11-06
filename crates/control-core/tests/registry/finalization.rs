use super::*;
use axum::{body::Body, http::Request};
use kryvola_fabric_core::{
    authorization::{Authorizer, sha256_hex},
    runtime_contract::RuntimeValidator,
    upload_http::UploadApi,
};
use object_store::{ObjectStore, ObjectStoreExt, aws::AmazonS3Builder, path::Path};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Client {
    api: UploadApi,
    auth: Authorizer,
    schemas: RuntimeValidator,
    policy: std::path::PathBuf,
    scope: Value,
    next: u64,
}
impl Client {
    async fn call(&mut self, method: &str, path: &str, bytes: Vec<u8>) -> (u16, Value) {
        self.next += 1;
        let token = format!("{:064x}", self.next);
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 55_000;
        let peer = "spiffe://fabric.test/worker".parse().unwrap();
        std::fs::write(&self.policy, json!({"boot_id":self.auth.boot_id(),"grants":[{
            "spiffe_id":"spiffe://fabric.test/worker", "token_sha256":sha256_hex(token.as_bytes()),
            "scope":self.scope,"expires_unix_ms":expiry
        }]}).to_string()).unwrap();
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Length", bytes.len())
            .body(Body::from(bytes))
            .unwrap();
        let (status, body) = self
            .api
            .handle(
                request,
                (
                    &peer,
                    &self.auth,
                    expiry,
                    Instant::now() + Duration::from_secs(55),
                ),
                &self.schemas,
            )
            .await;
        (
            status.as_u16(),
            if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_str(&body).unwrap()
            },
        )
    }
}
fn hash(domain: &[u8], pieces: &[&[u8]]) -> String {
    let mut state = blake3::Hasher::new();
    state.update(domain);
    for piece in pieces {
        state.update(piece);
    }
    state.finalize().to_hex().to_string()
}

#[tokio::test]
#[ignore = "requires the isolated PostgreSQL/S3 fixture from runtime_integration.py ci"]
async fn verified_finalization() {
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(fixture_options())
        .await
        .unwrap();
    let registry = Registry::new(pool.clone());
    registry.migrate().await.unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spec/fixtures/control.json"
    ))
    .unwrap();
    let mut operation = fixture["Operation"].clone();
    let tenant = "tenant-finalization-r1";
    operation["tenant_scope"] = json!(tenant);
    for field in ["plan_ref", "key_context_ref", "disclosure_identity"] {
        operation[field]["tenant_scope"] = json!(tenant);
    }
    operation["operation_id"] = json!("finalization-r1");
    operation["idempotency_key"] = json!("finalization-r1");
    operation["deadline_unix_ms"] = json!(
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            + 120_000)
            .to_string()
    );
    let validator = ControlValidator::new().unwrap();
    registry
        .create_operation(
            &OperationIntent::new(&validator, operation, vec!["a".repeat(64)]).unwrap(),
        )
        .await
        .unwrap();
    let key = OperationKey {
        tenant_scope: tenant,
        operation_id: "finalization-r1",
    };
    let lease = registry.ensure_attempt(key, 0, 1).await.unwrap();
    let socket = std::path::PathBuf::from(std::env::var_os("FABRIC_FIXTURE_PG_SOCKET").unwrap());
    let directory = socket.parent().unwrap().join("finalization-r1");
    std::fs::create_dir_all(&directory).unwrap();
    let config = directory.join("s3.json");
    std::fs::write(&config, json!({"endpoint":std::env::var("FABRIC_FIXTURE_S3_ENDPOINT").unwrap(),
        "bucket":"fabric-runtime","region":"us-east-1","allow_http":true,"tenant_quota_bytes":1073741824,
        "access_key_id":std::env::var("AWS_ACCESS_KEY_ID").unwrap(),"secret_access_key":std::env::var("AWS_SECRET_ACCESS_KEY").unwrap()}).to_string()).unwrap();
    let objects: Arc<dyn ObjectStore> = Arc::new(
        AmazonS3Builder::new()
            .with_endpoint(std::env::var("FABRIC_FIXTURE_S3_ENDPOINT").unwrap())
            .with_bucket_name("fabric-runtime")
            .with_region("us-east-1")
            .with_access_key_id(std::env::var("AWS_ACCESS_KEY_ID").unwrap())
            .with_secret_access_key(std::env::var("AWS_SECRET_ACCESS_KEY").unwrap())
            .with_allow_http(true)
            .build()
            .unwrap(),
    );
    let policy = directory.join("policy.json");
    let auth = Authorizer::new(policy.clone()).unwrap();
    let mut client = Client {
        api: UploadApi::connect(pool.clone(), config.to_str().unwrap()).unwrap(),
        auth,
        schemas: RuntimeValidator::new().unwrap(),
        policy,
        scope: json!({"schema_version":"1","attempt":{"schema_version":"1","tenant_scope":tenant,
            "operation_id":"finalization-r1","workflow_epoch":"0","attempt_epoch":"1","fence":lease.fence.to_string()},
            "manifest_digest":"a".repeat(64),"purpose":"COMPUTE_WRITE"}),
        next: 0,
    };
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spec/fixtures/canonical-modular-v2.json"
    ))
    .unwrap();
    for variant in [
        "valid",
        "corrupt",
        "truncated",
        "size",
        "order",
        "offset",
        "index",
        "context",
        "blob",
        "noncanonical",
        "unknown",
    ] {
        registry
            .renew_attempt(key, 0, 1, lease.fence)
            .await
            .unwrap();
        let mut manifest = corpus["objects"][0]["value"].clone();
        manifest["tenant_scope"] = json!(tenant);
        let chunks = [&[0u8, 1][..], &[2u8, 255][..]];
        manifest["ordered_chunk_entries"] = json!(chunks.iter().enumerate().map(|(index,bytes)| json!({
            "index":index.to_string(),"byte_offset":(index*2).to_string(),"byte_length":"2",
            "chunk_digest":hash(b"kryvola/chunk/v1\0", &[&(index as u64).to_le_bytes(), &2u64.to_le_bytes(), bytes])
        })).collect::<Vec<_>>());
        match variant {
            "size" => manifest["serialized_bytes"] = json!("5"),
            "order" => manifest["ordered_chunk_entries"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1),
            "offset" => manifest["ordered_chunk_entries"][1]["byte_offset"] = json!("3"),
            "index" => manifest["ordered_chunk_entries"][1]["index"] = json!("2"),
            "context" => manifest["key_context_digest"] = json!("c".repeat(64)),
            "blob" => manifest["full_blob_digest"] = json!("a".repeat(64)),
            "unknown" => manifest["credential"] = json!("forbidden-fixture-field"),
            _ => {}
        }
        manifest.sort_all_objects();
        let mut canonical = serde_json::to_vec(&manifest).unwrap();
        if variant == "noncanonical" {
            canonical.push(b' ');
        }
        let commitment = hash(b"kryvola/manifest/v2\0", &[&canonical]);
        client.scope["manifest_digest"] = json!(commitment);
        let (status, reserved) = client
            .call(
                "POST",
                "/v1/uploads",
                json!({"schema_version":"1","tenant_scope":tenant,"byte_length":4})
                    .to_string()
                    .into_bytes(),
            )
            .await;
        assert_eq!(status, 201, "{variant}: reservation");
        let id = reserved["upload_id"].as_str().unwrap();
        for (index, bytes) in chunks.iter().enumerate() {
            assert_eq!(
                client
                    .call(
                        "PUT",
                        &format!("/v1/uploads/{id}/parts/{index}"),
                        bytes.to_vec()
                    )
                    .await
                    .0,
                204,
                "{variant}: part"
            );
        }
        if matches!(variant, "corrupt" | "truncated") {
            let mapped: String = sqlx::query_scalar(
                "SELECT object_key FROM fabric_upload_parts WHERE upload_id=$1 AND part_index=1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
            objects
                .put(
                    &Path::from(mapped),
                    if variant == "corrupt" {
                        vec![9, 9]
                    } else {
                        vec![2]
                    }
                    .into(),
                )
                .await
                .unwrap();
        }
        let staged = client
            .call(
                "PUT",
                &format!("/v1/uploads/{id}/manifest"),
                canonical.clone(),
            )
            .await
            .0;
        if matches!(variant, "unknown" | "noncanonical") {
            assert_eq!(staged, 400, "{variant}: staging");
        } else {
            assert_eq!(staged, 204, "{variant}: staging");
        }
        let (status, reference) = client
            .call(
                "POST",
                &format!("/v1/uploads/{id}/finalize"),
                json!({"schema_version":"1","tenant_scope":tenant,"manifest_digest":commitment})
                    .to_string()
                    .into_bytes(),
            )
            .await;
        let saved: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT canonical_manifest FROM fabric_finalized_artifacts WHERE upload_id=$1",
        )
        .bind(id)
        .fetch_optional(&pool)
        .await
        .unwrap();
        if variant == "valid" {
            assert_eq!(status, 200);
            assert_eq!(
                reference,
                json!({"schema_version":"1","manifest_digest":commitment})
            );
            assert_eq!(saved, Some(canonical));
            for (index, expected) in chunks.iter().enumerate() {
                assert_eq!(
                    objects
                        .get(&Path::from(format!("immutable/{id}/{index}")))
                        .await
                        .unwrap()
                        .bytes()
                        .await
                        .unwrap()
                        .as_ref(),
                    *expected
                );
            }
        } else {
            assert_eq!(
                status,
                if variant == "context" { 403 } else { 400 },
                "{variant}: finalization"
            );
            assert_eq!(saved, None, "{variant}: publication forbidden");
            assert_eq!(
                client
                    .call(
                        "POST",
                        &format!("/v1/uploads/{id}/abort"),
                        json!({"schema_version":"1","attempt":client.scope["attempt"]})
                            .to_string()
                            .into_bytes()
                    )
                    .await
                    .0,
                204
            );
        }
    }
}

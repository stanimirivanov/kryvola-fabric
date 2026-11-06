use kryvola_fabric_core::{
    registry::{OperationIntent, OperationKey, Registry, RegistryError},
    wire::ControlValidator,
};
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

fn fixture_options() -> PgConnectOptions {
    PgConnectOptions::new()
        .socket(std::env::var_os("FABRIC_FIXTURE_PG_SOCKET").expect("fixture socket required"))
        .username("postgres")
        .database("postgres")
}

#[tokio::test]
#[ignore = "requires the isolated PostgreSQL instance from runtime_integration.py ci"]
async fn durable_registry() {
    let options = fixture_options();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options.clone())
        .await
        .unwrap();
    let registry = Registry::new(pool.clone());
    registry.migrate().await.unwrap();
    registry.migrate().await.unwrap();

    let fixture: Value = serde_json::from_str(include_str!(
        "../../../contracts/spec/fixtures/control.json"
    ))
    .unwrap();
    let mut operation = fixture["Operation"].clone();
    let now = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let deadline = (now + 20_000) as u64;
    operation["deadline_unix_ms"] = json!(deadline.to_string());
    let validator = ControlValidator::new().unwrap();
    let refs = vec!["a".repeat(64)];
    assert!(OperationIntent::new(&validator, operation.clone(), vec!["secret".into()]).is_err());
    let intent = OperationIntent::new(&validator, operation.clone(), refs.clone()).unwrap();
    let (a, b) = tokio::join!(
        registry.create_operation(&intent),
        registry.create_operation(&intent)
    );
    assert_eq!(a.unwrap(), b.unwrap());
    let conflict = OperationIntent::new(&validator, operation, vec!["b".repeat(64)]).unwrap();
    assert_eq!(
        registry.create_operation(&conflict).await.unwrap_err(),
        RegistryError::IdempotencyConflict,
    );

    let key = intent.key();
    let workflow = intent.workflow_epoch();
    let foreign_key = OperationKey {
        tenant_scope: "foreign",
        ..key
    };
    assert_eq!(registry.lookup_operation(foreign_key).await.unwrap(), None);
    assert_eq!(
        registry.ensure_attempt(foreign_key, workflow, 1).await,
        Err(RegistryError::NotFound),
    );
    assert_eq!(
        registry.ensure_attempt(key, workflow + 1, 1).await,
        Err(RegistryError::StaleWorkflow),
    );
    assert_eq!(
        registry.ensure_attempt(key, workflow, 2).await,
        Err(RegistryError::EpochConflict),
    );
    let (a, b) = tokio::join!(
        registry.ensure_attempt(key, workflow, 1),
        registry.ensure_attempt(key, workflow, 1)
    );
    let first = a.unwrap();
    assert_eq!(first, b.unwrap());
    assert_eq!(first.expires_unix_ms, deadline);
    assert_eq!(
        registry.renew_attempt(key, workflow, 1, first.fence).await,
        Ok(first),
    );
    assert_eq!(
        registry.ensure_attempt(key, workflow, 2).await,
        Err(RegistryError::EpochConflict),
    );
    assert_eq!(
        registry
            .renew_attempt(key, workflow, 1, first.fence + 1)
            .await,
        Err(RegistryError::StaleFence),
    );
    sqlx::query("UPDATE fabric_attempts SET lease_expires_unix_ms = 0")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        registry.renew_attempt(key, workflow, 1, first.fence).await,
        Err(RegistryError::AttemptExpired),
    );

    // Even a later clock/expiry change and process reconnect cannot resurrect an observed expiry.
    sqlx::query("UPDATE fabric_attempts SET lease_expires_unix_ms = $1::text::numeric")
        .bind(deadline.to_string())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let registry = Registry::new(pool);
    assert_eq!(
        registry.lookup_operation(key).await.unwrap(),
        Some(intent.record().clone())
    );
    assert_eq!(
        registry.ensure_attempt(key, workflow, 1).await,
        Err(RegistryError::AttemptExpired),
    );
    let second = registry.ensure_attempt(key, workflow, 2).await.unwrap();
    assert!(second.fence > first.fence);
    assert_eq!(
        registry.renew_attempt(key, workflow, 2, first.fence).await,
        Err(RegistryError::StaleFence),
    );
}

#[tokio::test]
#[ignore = "requires the restarted PostgreSQL instance from runtime_integration.py ci"]
async fn registry_survives_postgres_restart() {
    let pool = PgPoolOptions::new()
        .connect_with(fixture_options())
        .await
        .unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../contracts/spec/fixtures/control.json"
    ))
    .unwrap();
    let op = &fixture["Operation"];
    let key = OperationKey {
        tenant_scope: op["tenant_scope"].as_str().unwrap(),
        operation_id: op["operation_id"].as_str().unwrap(),
    };
    let workflow = op["workflow_epoch"].as_str().unwrap().parse().unwrap();
    let registry = Registry::new(pool);
    registry.migrate().await.unwrap();
    let saved = registry.lookup_operation(key).await.unwrap().unwrap();
    assert_eq!(saved.input_manifest_digests, ["a".repeat(64)]);
    assert_eq!(
        registry.ensure_attempt(key, workflow, 1).await,
        Err(RegistryError::AttemptExpired),
    );
}

#[tokio::test]
#[ignore = "requires the isolated PostgreSQL instance from runtime_integration.py ci"]
async fn bounded_uploads() {
    use futures_util::TryStreamExt;
    use kryvola_fabric_core::{
        authorization::{Authorizer, Scope, sha256_hex},
        upload::{UploadError, UploadStore},
    };
    use object_store::{ObjectStore, ObjectStoreExt, aws::AmazonS3Builder, path::Path};
    use std::{
        path::PathBuf,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    let pool = PgPoolOptions::new()
        .connect_with(fixture_options())
        .await
        .unwrap();
    Registry::new(pool.clone()).migrate().await.unwrap();
    let folder = PathBuf::from(std::env::var_os("FABRIC_FIXTURE_PG_SOCKET").unwrap());
    let path = folder.parent().unwrap().join("upload-test-policy.json");
    let auth = Authorizer::new(path.clone()).unwrap();
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../contracts/spec/fixtures/canonical-modular-v2.json"
    ))
    .unwrap();
    let manifest = &corpus["objects"][0];
    let canonical = hex::decode(manifest["canonical_hex"].as_str().unwrap()).unwrap();
    let scope_json = json!({
        "schema_version":"1","attempt":{"schema_version":"1","tenant_scope":"tenant-fixture",
        "operation_id":"op","workflow_epoch":"1","attempt_epoch":"1","fence":"1"},
        "manifest_digest":manifest["digest"],"purpose":"COMPUTE_WRITE"
    });
    let scope = Scope::decode(scope_json.to_string().as_bytes()).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let permit = |n: u8, certificate: &str| {
        let token = hex::encode([n; 32]);
        let workload: spiffe::SpiffeId = format!("spiffe://fabric.test/{certificate}")
            .parse()
            .unwrap();
        std::fs::write(
            &path,
            json!({"boot_id":auth.boot_id(),"grants":[{
                "spiffe_id":workload.to_string(),"token_sha256":sha256_hex(token.as_bytes()),
                "scope":scope_json,"expires_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64+55_000
            }]})
            .to_string(),
        )
        .unwrap();
        auth.redeem_upload(&workload, &token, &scope).unwrap()
    };

    let objects: Arc<dyn ObjectStore> = Arc::new(
        AmazonS3Builder::new()
            .with_endpoint(std::env::var("FABRIC_FIXTURE_S3_ENDPOINT").unwrap())
            .with_access_key_id(std::env::var("AWS_ACCESS_KEY_ID").unwrap())
            .with_secret_access_key(std::env::var("AWS_SECRET_ACCESS_KEY").unwrap())
            .with_region("us-east-1")
            .with_bucket_name("fabric-runtime")
            .with_allow_http(true)
            .build()
            .unwrap(),
    );
    let store = UploadStore::new(pool.clone(), objects.clone(), 8);
    assert_eq!(
        store.reserve(permit(1, "worker"), 0).await,
        Err(UploadError::Size)
    );
    let (a, b) = tokio::join!(
        store.reserve(permit(2, "worker"), 6),
        store.reserve(permit(3, "worker"), 6)
    );
    let id = match (a, b) {
        (Ok(id), Err(UploadError::Quota)) | (Err(UploadError::Quota), Ok(id)) => id,
        _ => panic!("exactly one reservation must fit"),
    };
    assert_eq!(
        store
            .put_part(permit(4, "other"), &id, 0, 4, &b"data"[..])
            .await,
        Err(UploadError::Denied)
    );
    assert_eq!(
        store
            .put_part(permit(5, "worker"), &id, 0, 4, &b"short"[..2])
            .await,
        Err(UploadError::Size)
    );
    assert_eq!(
        store
            .put_part(permit(6, "worker"), &id, 0, 4, &b"extra"[..])
            .await,
        Err(UploadError::Size)
    );
    store
        .put_part(permit(7, "worker"), &id, 0, 4, &b"data"[..])
        .await
        .unwrap();
    assert_eq!(
        store
            .put_part(permit(8, "worker"), &id, 0, 4, &b"evil"[..])
            .await,
        Err(UploadError::Conflict)
    );
    assert_eq!(
        store
            .put_part(permit(9, "worker"), &id, 1, 3, &b"abc"[..])
            .await,
        Err(UploadError::Size)
    );
    store.abort(permit(10, "worker"), &id).await.unwrap();
    assert!(
        objects
            .list(Some(&Path::from(format!("staging/{id}"))))
            .try_next()
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .put_part(permit(11, "worker"), &id, 1, 1, &b"x"[..])
            .await,
        Err(UploadError::Denied)
    );
    let reusable = store.reserve(permit(12, "worker"), 8).await.unwrap();
    store.abort(permit(13, "worker"), &reusable).await.unwrap();

    let id = store.reserve(permit(14, "worker"), 4).await.unwrap();
    assert_eq!(
        store.finalize(permit(15, "worker"), &id, &canonical).await,
        Err(UploadError::Integrity)
    );
    let mut substituted = canonical.clone();
    substituted.push(b' ');
    assert!(
        store
            .finalize(permit(16, "worker"), &id, &substituted)
            .await
            .is_err()
    );
    store
        .put_part(permit(17, "worker"), &id, 0, 4, &b"bad!"[..])
        .await
        .unwrap();
    assert_eq!(
        store.finalize(permit(18, "worker"), &id, &canonical).await,
        Err(UploadError::Integrity)
    );
    assert!(
        objects
            .list(Some(&Path::from(format!("immutable/{id}"))))
            .try_next()
            .await
            .unwrap()
            .is_none()
    );
    objects
        .put(
            &Path::from(format!("staging/{id}/0")),
            vec![0, 1, 2, 255].into(),
        )
        .await
        .unwrap();

    // Simulate a crash after copying a verified part but before committing metadata.
    objects
        .put(
            &Path::from(format!("immutable/{id}/0")),
            vec![0, 1, 2, 255].into(),
        )
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        store.finalize(permit(19, "worker"), &id, &canonical),
        store.finalize(permit(20, "worker"), &id, &canonical),
    );
    let artifact = a.unwrap();
    assert_eq!(b.unwrap(), artifact);
    assert_eq!(
        artifact.manifest_digest,
        manifest["digest"].as_str().unwrap()
    );
    assert_eq!(artifact.byte_length, 4);
    assert_eq!(
        store.abort(permit(21, "worker"), &id).await,
        Err(UploadError::Conflict)
    );
    assert_eq!(
        store
            .put_part(permit(22, "worker"), &id, 0, 4, &b"evil"[..])
            .await,
        Err(UploadError::Conflict)
    );
    use kryvola_fabric_core::registry::{ExecutionTarget, OperationKey};
    let mut operation: Value = serde_json::from_str::<Value>(include_str!(
        "../../../contracts/spec/fixtures/control.json"
    ))
    .unwrap()["Operation"]
        .clone();
    operation["operation_id"] = json!("op");
    operation["idempotency_key"] = json!("selection");
    operation["workflow_epoch"] = json!("1");
    operation["deadline_unix_ms"] = json!((now + 120_000).to_string());
    let intent = OperationIntent::new(
        &ControlValidator::new().unwrap(),
        operation,
        vec!["a".repeat(64)],
    )
    .unwrap();
    let registry = Registry::new(pool.clone());
    registry.create_operation(&intent).await.unwrap();
    let key = OperationKey {
        tenant_scope: "tenant-fixture",
        operation_id: "op",
    };
    let attempt = registry.ensure_attempt(key, 1, 1).await.unwrap();
    let one = ExecutionTarget {
        workflow_epoch: 1,
        attempt_epoch: 1,
        fence: attempt.fence,
        execution_id: "exec-1",
        plan_digest: &"c".repeat(64),
        policy_digest: &"d".repeat(64),
    };
    let two = ExecutionTarget {
        execution_id: "exec-2",
        ..one
    };
    assert_eq!(
        registry
            .register_execution(key, ExecutionTarget { fence: 9, ..one })
            .await,
        Err(RegistryError::StaleFence)
    );
    registry.register_execution(key, one).await.unwrap();
    registry.register_execution(key, two).await.unwrap();
    assert_eq!(
        registry.select_result(key, one, &id, &"0".repeat(64)).await,
        Err(RegistryError::CandidateMismatch)
    );
    for (target, expected) in [
        (
            ExecutionTarget { fence: 9, ..one },
            RegistryError::StaleFence,
        ),
        (
            ExecutionTarget {
                policy_digest: "wrong",
                ..one
            },
            RegistryError::CandidateMismatch,
        ),
        (
            ExecutionTarget {
                execution_id: "unknown",
                ..one
            },
            RegistryError::CandidateMismatch,
        ),
    ] {
        assert_eq!(
            registry
                .select_result(key, target, &id, &artifact.manifest_digest)
                .await,
            Err(expected),
        );
    }
    assert_eq!(registry.selected_result(key).await.unwrap(), None);
    let second_upload = store.reserve(permit(23, "worker"), 4).await.unwrap();
    store
        .put_part(
            permit(24, "worker"),
            &second_upload,
            0,
            4,
            &[0, 1, 2, 255][..],
        )
        .await
        .unwrap();
    store
        .finalize(permit(25, "worker"), &second_upload, &canonical)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        registry.select_result(key, one, &id, &artifact.manifest_digest),
        registry.select_result(key, two, &second_upload, &artifact.manifest_digest),
    );
    let (winner, target) = match (a, b) {
        (Ok(result), Err(RegistryError::SelectionConflict)) => (result, one),
        (Err(RegistryError::SelectionConflict), Ok(result)) => (result, two),
        _ => panic!("exactly one candidate must win"),
    };
    sqlx::query("UPDATE fabric_attempts SET lease_expires_unix_ms = 0 WHERE operation_id = 'op'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        registry.selected_result(key).await.unwrap(),
        Some(winner.clone())
    );
    assert_eq!(
        registry
            .select_result(key, target, &winner.upload_id, &artifact.manifest_digest)
            .await,
        Ok(winner.clone())
    );
    assert_eq!(
        registry.ensure_attempt(key, 1, 2).await,
        Err(RegistryError::SelectionConflict)
    );
    use kryvola_fabric_core::registry::Cancellation;
    let (left, right, selection) = tokio::join!(
        registry.cancel_operation(key, "cancel-op"),
        registry.cancel_operation(key, "cancel-op"),
        registry.select_result(key, target, &winner.upload_id, &artifact.manifest_digest),
    );
    assert!(selection == Ok(winner.clone()) || selection == Err(RegistryError::Cancelled));
    assert_eq!(
        registry.selected_result(key).await.unwrap(),
        Some(winner.clone())
    );
    assert_eq!(
        registry
            .select_result(key, target, &winner.upload_id, &artifact.manifest_digest)
            .await,
        Err(RegistryError::Cancelled)
    );
    assert_eq!(
        registry.register_execution(key, target).await,
        Err(RegistryError::Cancelled)
    );
    assert_eq!(left, Ok(Cancellation::Cancelled { fence: 2 }));
    assert_eq!(right.unwrap(), Cancellation::Cancelled { fence: 2 });
    assert_eq!(
        registry.ensure_attempt(key, 1, 2).await,
        Err(RegistryError::Cancelled)
    );

    let old = OperationKey {
        tenant_scope: "tenant-fixture",
        operation_id: "operation-1",
    };
    let barrier = registry.fence_for_recovery(old, 0).await.unwrap();
    assert!(barrier.fence > 2);
    assert_eq!(barrier.successor_epoch, 1);
    assert_eq!(registry.fence_for_recovery(old, 0).await, Ok(barrier));
    assert_eq!(
        registry.ensure_attempt(old, 0, 3).await,
        Err(RegistryError::RecoveryFenced)
    );
    assert_eq!(
        registry.cancel_operation(old, "cancel-op").await,
        Err(RegistryError::IdempotencyConflict)
    );
    let recovered_cancel = registry.cancel_operation(old, "cancel-old").await.unwrap();
    assert_eq!(
        recovered_cancel,
        Cancellation::Cancelled {
            fence: barrier.fence + 1
        }
    );

    use kryvola_fabric_core::upload::PinKind;
    let loser = if winner.upload_id == id {
        &second_upload
    } else {
        &id
    };
    let abandoned = store.reserve(permit(26, "worker"), 1).await.unwrap_err();
    assert_eq!(abandoned, UploadError::Quota);
    sqlx::query("UPDATE fabric_uploads SET touched_at = clock_timestamp() - interval '2 hours'")
        .execute(&pool)
        .await
        .unwrap();
    let expires = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        + 30_000) as i64;
    store
        .pin("tenant-fixture", loser, PinKind::Workflow, "job-1", expires)
        .await
        .unwrap();
    assert!(!store.reclaim(loser, 60).await.unwrap());
    assert!(!store.reclaim(&winner.upload_id, 60).await.unwrap());
    sqlx::query("UPDATE fabric_artifact_pins SET expires_unix_ms = 0")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        store
            .eligible_for_reclaim(60)
            .await
            .unwrap()
            .contains(loser)
    );
    let (pin, reclaim) = tokio::join!(
        store.pin("tenant-fixture", loser, PinKind::Audit, "audit-1", expires),
        store.reclaim(loser, 60),
    );
    match (pin, reclaim) {
        (Ok(()), Ok(false)) => {
            sqlx::query("UPDATE fabric_artifact_pins SET expires_unix_ms = 0")
                .execute(&pool)
                .await
                .unwrap();
            assert!(store.reclaim(loser, 60).await.unwrap());
        }
        (Err(UploadError::Denied), Ok(true)) => {}
        _ => panic!("pin and delete cannot both succeed"),
    }
    assert!(!store.reclaim(loser, 60).await.unwrap());
    assert!(
        objects
            .list(Some(&Path::from(format!("immutable/{loser}"))))
            .try_next()
            .await
            .unwrap()
            .is_none()
    );
    let abandoned = store.reserve(permit(27, "worker"), 1).await.unwrap();
    store
        .put_part(permit(28, "worker"), &abandoned, 0, 1, &b"x"[..])
        .await
        .unwrap();
    // Simulate an interrupted sweep after committing the deletion fence.
    sqlx::query("UPDATE fabric_uploads SET reclaiming = true WHERE id = $1")
        .bind(&abandoned)
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.reclaim(&abandoned, 60).await.unwrap());
    assert!(
        objects
            .list(Some(&Path::from(format!("staging/{abandoned}"))))
            .try_next()
            .await
            .unwrap()
            .is_none()
    );
    pool.close().await;
    assert_eq!(
        registry.cancel_operation(key, "cancel-op").await,
        Ok(Cancellation::Pending)
    );
    let reopened = Registry::new(
        PgPoolOptions::new()
            .connect_with(fixture_options())
            .await
            .unwrap(),
    );
    assert_eq!(reopened.cancel_operation(key, "cancel-op").await, left);
}

#[tokio::test]
#[ignore = "requires the PostgreSQL and Redpanda instances from the live gate"]
async fn outbox_round_trip() {
    use kryvola_fabric_core::registry::{Broker, Delivery};
    use rdkafka::{
        ClientConfig,
        producer::{FutureProducer, FutureRecord},
    };
    use std::time::Duration;

    let pool = PgPoolOptions::new()
        .connect_with(fixture_options())
        .await
        .unwrap();
    let registry = Registry::new(pool.clone());
    registry.migrate().await.unwrap();
    let mut config = ClientConfig::new();
    config.set(
        "bootstrap.servers",
        std::env::var("FABRIC_FIXTURE_KAFKA").unwrap(),
    );
    let mut broker =
        Broker::new(&config, "fabric-events", "fabric-events-dead", "fixture").unwrap();
    assert!(registry.publish_one(&broker).await.unwrap());
    // Simulate a send acknowledged by Kafka before PostgreSQL recorded it.
    sqlx::query("UPDATE fabric_outbox SET published = false")
        .execute(&pool)
        .await
        .unwrap();
    assert!(registry.publish_one(&broker).await.unwrap());
    assert_eq!(
        registry.consume_one(&mut broker).await.unwrap(),
        Delivery::Accepted
    );
    assert_eq!(
        registry.consume_one(&mut broker).await.unwrap(),
        Delivery::Duplicate
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM fabric_inbox")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let kinds: i64 = sqlx::query_scalar("SELECT count(DISTINCT kind) FROM fabric_outbox")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kinds, 4);

    // A group with a committed inbox row but no committed Kafka offset replays it.
    sqlx::query("INSERT INTO fabric_inbox SELECT 'fixture-restart', event_id FROM fabric_inbox WHERE subscriber = 'fixture'")
        .execute(&pool).await.unwrap();
    let mut restarted = Broker::new(
        &config,
        "fabric-events",
        "fabric-events-dead",
        "fixture-restart",
    )
    .unwrap();
    assert_eq!(
        registry.consume_one(&mut restarted).await.unwrap(),
        Delivery::Duplicate
    );

    let producer: FutureProducer = config.create().unwrap();
    producer
        .send(
            FutureRecord::to("fabric-events")
                .key("untrusted")
                .payload(br#"{"credentials":"must not reach the DLQ"}"#),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(
        registry.consume_one(&mut broker).await.unwrap(),
        Delivery::Rejected
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM fabric_inbox WHERE subscriber = 'fixture'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

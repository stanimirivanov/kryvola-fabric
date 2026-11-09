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

    let mut racing_operation = intent.record().operation.clone();
    racing_operation["operation_id"] = json!("conflicting-race");
    racing_operation["idempotency_key"] = json!("conflicting-race");
    let left =
        OperationIntent::new(&validator, racing_operation.clone(), vec!["c".repeat(64)]).unwrap();
    let right = OperationIntent::new(&validator, racing_operation, vec!["d".repeat(64)]).unwrap();
    let (a, b) = tokio::join!(
        registry.create_operation(&left),
        registry.create_operation(&right)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(
        (&a, &b),
        (Err(RegistryError::IdempotencyConflict), Ok(_))
            | (Ok(_), Err(RegistryError::IdempotencyConflict))
    ));

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
    let expected = std::path::PathBuf::from(std::env::var_os("FABRIC_FIXTURE_PG_SOCKET").unwrap())
        .parent()
        .unwrap()
        .join("current-attempt.json");
    std::fs::write(
        expected,
        json!({"epoch": second.attempt_epoch, "fence":second.fence,
        "expires":second.expires_unix_ms})
        .to_string(),
    )
    .unwrap();
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
    let registry = Registry::new(pool.clone());
    registry.migrate().await.unwrap();
    let saved = registry.lookup_operation(key).await.unwrap().unwrap();
    assert_eq!(saved.input_manifest_digests, ["a".repeat(64)]);
    assert_eq!(
        registry.ensure_attempt(key, workflow, 1).await,
        Err(RegistryError::AttemptExpired),
    );
    let expected = std::path::PathBuf::from(std::env::var_os("FABRIC_FIXTURE_PG_SOCKET").unwrap())
        .parent()
        .unwrap()
        .join("current-attempt.json");
    let expected: Value = serde_json::from_slice(&std::fs::read(expected).unwrap()).unwrap();
    let current = registry.ensure_attempt(key, workflow, 2).await.unwrap();
    assert_eq!(current.attempt_epoch, expected["epoch"].as_u64().unwrap());
    assert_eq!(current.fence, expected["fence"].as_u64().unwrap());
    assert_eq!(
        current.expires_unix_ms,
        expected["expires"].as_u64().unwrap()
    );
    sqlx::query("UPDATE fabric_attempts SET lease_expires_unix_ms=0 WHERE tenant_scope=$1 AND operation_id=$2")
        .bind(key.tenant_scope).bind(key.operation_id).execute(&pool).await.unwrap();
    assert_eq!(
        registry.ensure_attempt(key, workflow, 2).await,
        Err(RegistryError::AttemptExpired)
    );
    let third = registry.ensure_attempt(key, workflow, 3).await.unwrap();
    assert_eq!(third.attempt_epoch, current.attempt_epoch + 1);
    assert!(third.fence > current.fence);
}

fn fixture_objects() -> std::sync::Arc<dyn object_store::ObjectStore> {
    std::sync::Arc::new(
        object_store::aws::AmazonS3Builder::new()
            .with_endpoint(std::env::var("FABRIC_FIXTURE_S3_ENDPOINT").unwrap())
            .with_access_key_id(std::env::var("AWS_ACCESS_KEY_ID").unwrap())
            .with_secret_access_key(std::env::var("AWS_SECRET_ACCESS_KEY").unwrap())
            .with_region("us-east-1")
            .with_bucket_name("fabric-runtime")
            .with_allow_http(true)
            .build()
            .unwrap(),
    )
}

fn pin_restart_evidence() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os("FABRIC_FIXTURE_PG_SOCKET").unwrap())
        .with_file_name("retention-fixture.json")
}

#[tokio::test]
#[ignore = "requires the isolated PostgreSQL instance from runtime_integration.py ci"]
async fn bounded_uploads() {
    use futures_util::TryStreamExt;
    use kryvola_fabric_core::{
        authorization::{Authorizer, Scope, sha256_hex},
        upload::{UploadError, UploadStore},
    };
    use object_store::{ObjectStoreExt, path::Path};
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    let pool = PgPoolOptions::new()
        .connect_with(fixture_options())
        .await
        .unwrap();
    Registry::new(pool.clone()).migrate().await.unwrap();
    // The down migration preserves schema/data but restores old SQLx-ledger compatibility.
    sqlx::migrate!().undo(&pool, 7).await.unwrap();
    let version: i64 =
        sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE version <= 8")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(version, 7);
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

    let objects = fixture_objects();
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
    let staged_key: String = sqlx::query_scalar(
        "SELECT object_key FROM fabric_upload_parts WHERE upload_id=$1 AND part_index=0",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut rollback = pool.begin().await.unwrap();
    assert!(
        sqlx::raw_sql(include_str!(
            "../migrations/0008_multipart_staging.down.sql"
        ))
        .execute(&mut *rollback)
        .await
        .is_err()
    );
    rollback.rollback().await.unwrap();
    assert!(staged_key.starts_with(&format!("staging/{id}/0/")));
    assert_eq!(
        objects
            .get(&Path::from(staged_key))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        b"data"
    );
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
    // A database failure after object deletion leaves the durable marker and quota intact.
    sqlx::raw_sql(
        "CREATE FUNCTION fail_fixture_upload_delete() RETURNS trigger LANGUAGE plpgsql AS
         $$ BEGIN RAISE EXCEPTION 'fixture delete failure'; END; $$;
         CREATE TRIGGER fail_fixture_upload_delete BEFORE DELETE ON fabric_uploads
         FOR EACH ROW EXECUTE FUNCTION fail_fixture_upload_delete();",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        store.abort(permit(30, "worker"), &id).await,
        Err(UploadError::Unavailable)
    );
    let marked: (bool, i64) =
        sqlx::query_as("SELECT reclaiming, reserved_bytes FROM fabric_uploads WHERE id=$1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(marked, (true, 6));
    assert_eq!(
        store.abort(permit(31, "other-worker"), &id).await,
        Err(UploadError::Denied)
    );
    assert_eq!(
        store
            .put_part(permit(32, "worker"), &id, 1, 1, &b"x"[..])
            .await,
        Err(UploadError::Denied)
    );
    assert!(
        objects
            .list(Some(&Path::from(format!("staging/{id}"))))
            .try_next()
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("DROP TRIGGER fail_fixture_upload_delete ON fabric_uploads")
        .execute(&pool)
        .await
        .unwrap();
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
    // Simulate a pre-migration staged row: legacy bytes and a NULL mapping.
    let mapped: String = sqlx::query_scalar(
        "SELECT object_key FROM fabric_upload_parts WHERE upload_id=$1 AND part_index=0",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .unwrap();
    objects.delete(&Path::from(mapped)).await.unwrap();
    sqlx::query("UPDATE fabric_upload_parts SET object_key=NULL WHERE upload_id=$1")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
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
    // Each expiring pin must protect its own artifact independently after restart.
    let retention = UploadStore::new(pool.clone(), objects.clone(), 32);
    let mut protected = vec![winner.upload_id];
    for (index, kind) in [PinKind::Workflow, PinKind::KeyContext, PinKind::Audit]
        .into_iter()
        .enumerate()
    {
        let n = 40 + 3 * index as u8;
        let id = retention.reserve(permit(n, "worker"), 4).await.unwrap();
        retention
            .put_part(permit(n + 1, "worker"), &id, 0, 4, &[0, 1, 2, 255][..])
            .await
            .unwrap();
        retention
            .finalize(permit(n + 2, "worker"), &id, &canonical)
            .await
            .unwrap();
        sqlx::query("UPDATE fabric_uploads SET touched_at = clock_timestamp() - interval '2 hours' WHERE id=$1")
            .bind(&id).execute(&pool).await.unwrap();
        assert!(
            retention
                .eligible_for_reclaim(60)
                .await
                .unwrap()
                .contains(&id)
        );
        retention
            .pin(
                "tenant-fixture",
                &id,
                kind,
                "restart-fixture",
                expires + 600_000,
            )
            .await
            .unwrap();
        // A stale eligibility report cannot overrule a pin that committed in the meantime.
        assert!(!retention.reclaim(&id, 60).await.unwrap());
        protected.push(id);
    }
    std::fs::write(
        pin_restart_evidence(),
        serde_json::to_vec(&protected).unwrap(),
    )
    .unwrap();
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
#[ignore = "requires the live gate to restart PostgreSQL after bounded_uploads"]
async fn pins_survive_postgres_restart() {
    use futures_util::TryStreamExt;
    use kryvola_fabric_core::upload::UploadStore;
    use object_store::path::Path;

    let protected: Vec<String> =
        serde_json::from_slice(&std::fs::read(pin_restart_evidence()).unwrap()).unwrap();
    assert_eq!(protected.len(), 4);
    let pool = PgPoolOptions::new()
        .connect_with(fixture_options())
        .await
        .unwrap();
    let objects = fixture_objects();
    let store = UploadStore::new(pool.clone(), objects.clone(), 32);
    let eligible = store.eligible_for_reclaim(60).await.unwrap();
    for id in &protected {
        assert!(!eligible.contains(id));
        assert!(!store.reclaim(id, 60).await.unwrap());
        assert!(
            objects
                .list(Some(&Path::from(format!("immutable/{id}"))))
                .try_next()
                .await
                .unwrap()
                .is_some()
        );
    }

    for id in &protected[1..] {
        let expired =
            sqlx::query("UPDATE fabric_artifact_pins SET expires_unix_ms=0 WHERE upload_id=$1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        assert_eq!(expired.rows_affected(), 1);
        assert!(store.reclaim(id, 60).await.unwrap());
        assert!(!store.reclaim(id, 60).await.unwrap());
        assert!(
            objects
                .list(Some(&Path::from(format!("immutable/{id}"))))
                .try_next()
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(!store.reclaim(&protected[0], 60).await.unwrap());
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
    let Delivery::Accepted(accepted) = registry.consume_one(&mut broker).await.unwrap() else {
        panic!("expected a durable reference");
    };
    let operation = registry
        .lookup_operation(accepted.operation_key())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(operation.operation["operation_id"], accepted.operation_id);
    assert_eq!(operation.operation["tenant_scope"], accepted.tenant_scope);
    assert_eq!(
        registry
            .pending_deliveries("fixture", 1)
            .await
            .unwrap()
            .as_slice(),
        std::slice::from_ref(&accepted)
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
    sqlx::query("INSERT INTO fabric_inbox (subscriber, event_id) SELECT 'fixture-restart', event_id FROM fabric_inbox WHERE subscriber = 'fixture'")
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

    assert!(
        registry
            .acknowledge_delivery("fixture", &accepted)
            .await
            .unwrap()
    );
    assert!(
        !registry
            .acknowledge_delivery("fixture", &accepted)
            .await
            .unwrap()
    );

    assert_eq!(
        registry
            .pending_deliveries("fixture-restart", 1)
            .await
            .unwrap()
            .as_slice(),
        std::slice::from_ref(&accepted)
    );
    let mut mismatched = accepted.clone();
    mismatched.operation_id.push_str("-other");
    assert!(
        !registry
            .acknowledge_delivery("fixture-restart", &mismatched)
            .await
            .unwrap()
    );

    // A fresh SQL client can find committed outbox rows even if they never reached Kafka.
    let reopened = Registry::new(pool.clone());
    let pending = reopened.pending_deliveries("fixture", 2).await.unwrap();
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().all(|reference| reference.id != accepted.id));
    for reference in pending {
        let published: bool = sqlx::query_scalar("SELECT published FROM fabric_outbox WHERE id=$1")
            .bind(reference.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!published);
        assert!(
            reopened
                .lookup_operation(reference.operation_key())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            reopened
                .acknowledge_delivery("fixture", &reference)
                .await
                .unwrap()
        );
    }
    assert_eq!(
        reopened.pending_deliveries("fixture", 0).await,
        Err(RegistryError::InvalidIntent)
    );
    assert_eq!(
        reopened.pending_deliveries("fixture", 101).await,
        Err(RegistryError::InvalidIntent)
    );

    // Kafka receipt after SQL reconciliation is still a duplicate.
    assert!(registry.publish_one(&broker).await.unwrap());
    assert_eq!(
        registry.consume_one(&mut broker).await.unwrap(),
        Delivery::Duplicate
    );
    assert_eq!(
        registry
            .lookup_operation(accepted.operation_key())
            .await
            .unwrap(),
        Some(operation)
    );

    let producer: FutureProducer = config.create().unwrap();
    let legacy = json!({"version": 1, "id": accepted.id, "tenant_scope": accepted.tenant_scope,
        "operation_id": accepted.operation_id, "kind": accepted.kind});
    let key = format!(
        "{}:{}{}",
        accepted.tenant_scope.len(),
        accepted.tenant_scope,
        accepted.operation_id
    );
    producer
        .send(
            FutureRecord::to("fabric-events")
                .key(&key)
                .payload(&legacy.to_string()),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(
        registry.consume_one(&mut broker).await.unwrap(),
        Delivery::Duplicate
    );

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
    assert_eq!(count, 3);
}

#[path = "registry/finalization.rs"]
mod finalization;

#[tokio::test]
#[ignore = "requires PostgreSQL and S3 from the live gate"]
async fn bounded_reclamation_maintenance() {
    use object_store::{ObjectStoreExt, path::Path};
    use std::{fs, path::PathBuf, process::Command};

    let pool = PgPoolOptions::new()
        .connect_with(fixture_options())
        .await
        .unwrap();
    Registry::new(pool.clone()).migrate().await.unwrap();
    let objects = fixture_objects();
    let socket = PathBuf::from(std::env::var_os("FABRIC_FIXTURE_PG_SOCKET").unwrap());
    let db = socket.with_file_name("reclaim-db");
    let s3 = socket.with_file_name("reclaim-s3");
    fs::write(
        &db,
        format!(
            "postgresql://postgres@localhost/postgres?host={}",
            socket.display()
        ),
    )
    .unwrap();
    fs::write(
        &s3,
        json!({
            "endpoint": std::env::var("FABRIC_FIXTURE_S3_ENDPOINT").unwrap(),
            "access_key_id": std::env::var("AWS_ACCESS_KEY_ID").unwrap(),
            "secret_access_key": std::env::var("AWS_SECRET_ACCESS_KEY").unwrap(),
            "bucket": "fabric-runtime", "region": "us-east-1",
            "tenant_quota_bytes": 32, "allow_http": true
        })
        .to_string(),
    )
    .unwrap();

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fabric-runtime"))
            .arg("--reclaim")
            .arg(&db)
            .arg(&s3)
            .arg("86400")
            .args(args)
            .output()
            .unwrap()
    };
    let report = |args: &[&str]| {
        let output = run(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };

    let tenant = "maintenance-fixture";
    sqlx::query("INSERT INTO fabric_upload_tenants VALUES ($1)")
        .bind(tenant)
        .execute(&pool)
        .await
        .unwrap();
    let ids: Vec<_> = (1..=11).map(|n| format!("{n:032x}")).collect();
    let key = |id: &str, prefix: &str| Path::from(format!("{prefix}/{id}/probe"));
    for (i, id) in ids.iter().enumerate() {
        sqlx::query(
            "INSERT INTO fabric_uploads
            (id, tenant_scope, certificate, scope, reserved_bytes, touched_at, reclaiming)
            VALUES ($1,$2,'fixture','{}',1,clock_timestamp() - interval '2 days',$3)",
        )
        .bind(id)
        .bind(tenant)
        .bind(i == 0)
        .execute(&pool)
        .await
        .unwrap();
        objects
            .put(&key(id, "staging"), b"original".as_slice().into())
            .await
            .unwrap();
    }
    let pinned = ids.last().unwrap();
    sqlx::query("INSERT INTO fabric_finalized_artifacts VALUES ($1,'fixture','')")
        .bind(pinned)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO fabric_artifact_pins VALUES ($1,'audit','fixture',9223372036854775807)",
    )
    .bind(pinned)
    .execute(&pool)
    .await
    .unwrap();
    objects
        .put(&key(pinned, "immutable"), b"pinned".as_slice().into())
        .await
        .unwrap();

    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM fabric_uploads WHERE tenant_scope=$1")
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    assert!(!run(&["--deleet"]).status.success());
    let preview = report(&[]);
    assert_eq!(preview["mode"], "report");
    assert_eq!(preview["eligible_uploads"], 4);
    assert_eq!(count().await, 11);
    for id in &ids {
        assert!(objects.head(&key(id, "staging")).await.is_ok());
    }

    // Inject a repeatable failure at SQL deletion. Subsequent candidates must
    // still make progress, and a fresh invocation must resume the failed row.
    sqlx::raw_sql(
        "CREATE FUNCTION fail_fixture_maintenance() RETURNS trigger LANGUAGE plpgsql AS
        $$ BEGIN IF OLD.id='00000000000000000000000000000001'
        THEN RAISE EXCEPTION 'fixture cleanup failure'; END IF; RETURN OLD; END; $$;
        CREATE TRIGGER fail_fixture_maintenance BEFORE DELETE ON fabric_uploads
        FOR EACH ROW EXECUTE FUNCTION fail_fixture_maintenance()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let failed = run(&["--delete"]);
    assert!(!failed.status.success());
    let progress: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(progress["failures"], 1);
    assert_eq!(progress["reclaimed_uploads"], 3);
    assert_eq!(count().await, 8);
    let rotated = report(&["--delete"]);
    assert_eq!(rotated["reclaimed_uploads"], 4);
    assert_eq!(count().await, 4);

    sqlx::query("DROP TRIGGER fail_fixture_maintenance ON fabric_uploads")
        .execute(&pool)
        .await
        .unwrap();

    for _ in 0..8 {
        if count().await == 1 {
            break;
        }
        let progress = report(&["--delete"]);
        assert_eq!(progress["mode"], "delete");
        assert!(progress["reclaimed_uploads"].as_u64().unwrap() <= 4);
        assert!(progress["tombstones_swept"].as_u64().unwrap() <= 4);
    }
    assert_eq!(count().await, 1);

    // Simulate requests that finish writing after metadata and quota were removed.
    for prefix in ["staging", "immutable"] {
        objects
            .put(&key(&ids[0], prefix), b"late".as_slice().into())
            .await
            .unwrap();
    }
    assert!(report(&[])["tombstones_due"].as_u64().unwrap() > 0);
    assert!(objects.head(&key(&ids[0], "staging")).await.is_ok());
    for _ in 0..12 {
        report(&["--delete"]);
        if objects.head(&key(&ids[0], "staging")).await.is_err() {
            break;
        }
    }
    for prefix in ["staging", "immutable"] {
        assert!(matches!(
            objects.head(&key(&ids[0], prefix)).await,
            Err(object_store::Error::NotFound { .. })
        ));
        assert!(objects.head(&key(pinned, prefix)).await.is_ok());
    }
}

#[path = "registry/messaging.rs"]
mod messaging;

#[path = "registry/broker_crash.rs"]
mod broker_crash;

#[test]
fn release_disclosure_id_matches_spec_and_excludes_epochs() {
    use kryvola_fabric_core::registry::disclosure_id;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../contracts/spec/fixtures/canonical-disclosure-v3.json"
    ))
    .unwrap();
    assert_eq!(
        disclosure_id(&fixture["identity"]).unwrap(),
        fixture["disclosure_id"]
    );
    assert!(disclosure_id(&fixture["authorization"]).is_err());
}

#[path = "registry/release.rs"]
mod release;

#[path = "registry/submission.rs"]
mod submission;

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

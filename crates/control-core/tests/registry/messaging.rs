use super::*;
use rdkafka::{
    ClientConfig, Message, Offset, TopicPartitionList,
    consumer::{Consumer, StreamConsumer},
    producer::{FutureProducer, FutureRecord},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::Duration,
};

struct Worker(Child);

impl Worker {
    fn start(db: &Path, config: &Path) -> Self {
        Self(
            Command::new(env!("CARGO_BIN_EXE_fabric-runtime"))
                .arg("--messaging")
                .arg(db)
                .arg(config)
                .spawn()
                .unwrap(),
        )
    }

    fn check_running(&mut self) {
        assert!(
            self.0.try_wait().unwrap().is_none(),
            "messaging worker exited"
        );
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redpanda from the live gate"]
async fn runtime_messaging_workers() {
    let pool = PgPoolOptions::new()
        .connect_with(fixture_options())
        .await
        .unwrap();
    let registry = Registry::new(pool.clone());
    registry.migrate().await.unwrap();
    let socket = PathBuf::from(std::env::var_os("FABRIC_FIXTURE_PG_SOCKET").unwrap());
    let db = socket.with_file_name("messaging-db");
    let config = socket.with_file_name("messaging-config");
    fs::write(
        &db,
        format!(
            "postgresql://postgres@localhost/postgres?host={}",
            socket.display()
        ),
    )
    .unwrap();
    let endpoint = std::env::var("FABRIC_FIXTURE_KAFKA").unwrap();
    let subscriber = "worker-fixture";
    let write_config = |bootstrap: &str| {
        fs::write(
            &config,
            json!({
                "bootstrap_servers": bootstrap,
                "topic": "fabric-worker-events",
                "dead_letter_topic": "fabric-worker-dead",
                "subscriber": subscriber,
                "allow_loopback_plaintext": true
            })
            .to_string(),
        )
        .unwrap();
    };
    let mut operation: Value = serde_json::from_str::<Value>(include_str!(
        "../../../../contracts/spec/fixtures/control.json"
    ))
    .unwrap()["Operation"]
        .clone();
    operation["operation_id"] = json!("messaging-worker");
    operation["idempotency_key"] = json!("messaging-worker");
    let intent = OperationIntent::new(
        &ControlValidator::new().unwrap(),
        operation,
        vec!["a".repeat(64)],
    )
    .unwrap();
    registry.create_operation(&intent).await.unwrap();
    let id: i64 =
        sqlx::query_scalar("SELECT id FROM fabric_outbox WHERE operation_id='messaging-worker'")
            .fetch_one(&pool)
            .await
            .unwrap();

    // Hold a loopback socket that never speaks Kafka.
    let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    write_config(&unavailable.local_addr().unwrap().to_string());
    let mut worker = Worker::start(&db, &config);
    let handled = || async {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM fabric_inbox WHERE subscriber=$1 AND event_id=$2 AND handled)"
        ).bind(subscriber).bind(id).fetch_one(&pool).await.unwrap()
    };
    tokio::time::timeout(Duration::from_secs(7), async {
        while !handled().await {
            worker.check_running();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let published = || async {
        sqlx::query_scalar::<_, bool>("SELECT published FROM fabric_outbox WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    assert!(!published().await);

    let stop = |worker: &Worker| {
        assert!(
            Command::new("kill")
                .args(["-TERM", &worker.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    };
    async fn wait_for_exit(worker: &mut Worker) {
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                if let Some(status) = worker.0.try_wait().unwrap() {
                    assert!(
                        status.success(),
                        "worker did not shut down cleanly: {status}"
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
    }
    stop(&worker);
    wait_for_exit(&mut worker).await;

    let mut staged = pool.begin().await.unwrap();
    let rolled_back_id: i64 = sqlx::query_scalar(
        "INSERT INTO fabric_outbox (tenant_scope,operation_id,kind)
         VALUES ($1,$2,'cancelled') RETURNING id",
    )
    .bind(intent.key().tenant_scope)
    .bind(intent.key().operation_id)
    .fetch_one(&mut *staged)
    .await
    .unwrap();

    write_config(&endpoint);
    let mut worker = Worker::start(&db, &config);
    tokio::time::timeout(Duration::from_secs(25), async {
        while !published().await {
            worker.check_running();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        registry
            .lookup_operation(intent.key())
            .await
            .unwrap()
            .unwrap(),
        *intent.record()
    );
    let mut kafka = ClientConfig::new();
    kafka
        .set("bootstrap.servers", &endpoint)
        .set("group.id", "worker-fixture-probe");
    let consumer: StreamConsumer = kafka.create().unwrap();
    let mut partitions = TopicPartitionList::new();
    partitions
        .add_partition_offset("fabric-worker-events", 0, Offset::Beginning)
        .unwrap();
    consumer.assign(&partitions).unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let record = consumer.recv().await.unwrap();
            let value: Value = serde_json::from_slice(record.payload().unwrap()).unwrap();
            let event = value["id"].as_str().unwrap();
            assert_ne!(event, rolled_back_id.to_string());
            if event == id.to_string() {
                break;
            }
        }
    })
    .await
    .unwrap();
    staged.rollback().await.unwrap();

    let (_, end) = consumer
        .fetch_watermarks("fabric-worker-dead", 0, Duration::from_secs(5))
        .unwrap();
    let mut partitions = TopicPartitionList::new();
    partitions
        .add_partition_offset("fabric-worker-dead", 0, Offset::Offset(end))
        .unwrap();
    consumer.assign(&partitions).unwrap();
    let producer: FutureProducer = kafka.create().unwrap();
    let key = format!(
        "{}:{}{}",
        intent.key().tenant_scope.len(),
        intent.key().tenant_scope,
        intent.key().operation_id
    );
    let mut oversized = json!({
        "version": 1, "id": id, "tenant_scope": intent.key().tenant_scope,
        "operation_id": intent.key().operation_id, "kind": "operation_created"
    })
    .to_string()
    .into_bytes();
    // Valid legacy JSON above the application cap, still below the broker record cap.
    oversized.resize(64 * 1024 - 1024 + 1 - key.len(), b' ');
    producer
        .send(
            FutureRecord::to("fabric-worker-events")
                .key(&key)
                .payload(&oversized),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    let rejected = tokio::time::timeout(Duration::from_secs(15), consumer.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rejected.key(), Some(b"rejected".as_slice()));
    assert_eq!(
        rejected.payload(),
        Some(br#"{"version":1,"code":"REJECTED_EVENT"}"#.as_slice())
    );
    assert!(rejected.headers().is_none());
    drop(rejected);

    stop(&worker);
    wait_for_exit(&mut worker).await;
}

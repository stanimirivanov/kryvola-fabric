use super::*;
use kryvola_fabric_core::registry::{Broker, Delivery};
use rdkafka::{
    ClientConfig, Message, Offset, TopicPartitionList,
    consumer::{Consumer, StreamConsumer},
    producer::{FutureProducer, FutureRecord},
};
use std::{
    os::unix::process::ExitStatusExt,
    process::{Child, Command},
    time::Duration,
};

const TOPIC: &str = "fabric-crash-events";
const DEAD: &str = "fabric-crash-dead";
const GROUP: &str = "fabric-crash-group";
const DEADLINE: Duration = Duration::from_secs(20);

fn client() -> ClientConfig {
    let mut config = ClientConfig::new();
    config
        .set(
            "bootstrap.servers",
            std::env::var("FABRIC_FIXTURE_KAFKA").unwrap(),
        )
        .set("group.id", GROUP)
        .set("session.timeout.ms", "6000");
    config
}

async fn pool() -> sqlx::PgPool {
    PgPoolOptions::new()
        .connect_with(fixture_options().database("broker_crash"))
        .await
        .unwrap()
}

struct Probe(Child);

impl Probe {
    fn start(phase: &str) -> Self {
        Self(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--nocapture",
                    "--exact",
                    "broker_crash::broker_crash_child",
                ])
                .env("FABRIC_FIXTURE_CRASH_PHASE", phase)
                .spawn()
                .unwrap(),
        )
    }

    fn kill(&mut self) {
        self.0.kill().unwrap();
        assert_eq!(self.0.wait().unwrap().signal(), Some(9));
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "launched only by the broker crash campaign"]
async fn broker_crash_child() {
    let phase = std::env::var("FABRIC_FIXTURE_CRASH_PHASE").expect("fixture phase required");
    let registry = Registry::new(pool().await);
    let group = if phase == "publish" {
        "crash-publisher"
    } else {
        GROUP
    };
    let mut broker = Broker::new(&client(), TOPIC, DEAD, group).unwrap();
    match phase.as_str() {
        "publish" => {
            eprintln!(
                "fixture publish returned {:?}",
                registry.publish_one(&broker).await
            );
        }
        "consume" => {
            eprintln!(
                "fixture consume returned {:?}",
                registry.poll_delivery(&mut broker, DEADLINE).await
            );
        }
        _ => panic!("unknown crash phase"),
    }
    std::future::pending::<()>().await;
}

async fn receive_id(consumer: &StreamConsumer) -> (i64, i64) {
    let message = tokio::time::timeout(DEADLINE, consumer.recv())
        .await
        .unwrap()
        .unwrap();
    let body: Value = serde_json::from_slice(message.payload().unwrap()).unwrap();
    (
        body["id"].as_str().unwrap().parse().unwrap(),
        message.offset(),
    )
}

async fn until(label: &str, mut condition: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(DEADLINE, async {
        while !condition().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label} was not reached"));
}

async fn wait_for_gate(pool: &sqlx::PgPool, key: i64) {
    until("advisory gate", async || {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory'
             AND classid=0 AND objid=$1::bigint::oid AND NOT granted)",
        )
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap()
    })
    .await;
}

fn docker(action: &str) {
    let id = std::env::var("FABRIC_FIXTURE_REDPANDA_CONTAINER").unwrap();
    assert!(id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let result = Command::new("timeout")
        .args(["30s", "docker", action, &id])
        .output()
        .unwrap();
    assert!(result.status.success(), "fixture broker {action} failed");
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redpanda"]
async fn broker_crash_convergence() {
    let admin = PgPoolOptions::new()
        .connect_with(fixture_options())
        .await
        .unwrap();
    sqlx::query("CREATE DATABASE broker_crash")
        .execute(&admin)
        .await
        .unwrap();
    let pool = pool().await;
    let registry = Registry::new(pool.clone());
    registry.migrate().await.unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spec/fixtures/control.json"
    ))
    .unwrap();
    let intent = OperationIntent::new(
        &ControlValidator::new().unwrap(),
        fixture["Operation"].clone(),
        vec!["a".repeat(64)],
    )
    .unwrap();
    registry.create_operation(&intent).await.unwrap();
    let event_id: i64 = sqlx::query_scalar("SELECT id FROM fabric_outbox")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(6501)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION pause_mark() RETURNS trigger LANGUAGE plpgsql AS
        $$ BEGIN PERFORM pg_advisory_xact_lock(6501); RETURN NEW; END; $$;
        CREATE TRIGGER pause_mark BEFORE UPDATE ON fabric_outbox FOR EACH ROW EXECUTE FUNCTION pause_mark()")
        .execute(&pool).await.unwrap();

    let config = client();
    let mut observer_config = config.clone();
    observer_config
        .set("group.id", "crash-observer")
        .set("enable.auto.commit", "false");
    let observer: StreamConsumer = observer_config.create().unwrap();
    let mut partitions = TopicPartitionList::new();
    partitions
        .add_partition_offset(TOPIC, 0, Offset::Beginning)
        .unwrap();
    observer.assign(&partitions).unwrap();
    let mut publisher = Probe::start("publish");
    assert_eq!(receive_id(&observer).await, (event_id, 0));
    wait_for_gate(&pool, 6501).await;
    publisher.kill();
    let published: bool = sqlx::query_scalar("SELECT published FROM fabric_outbox")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!published);
    gate.rollback().await.unwrap();
    let broker = Broker::new(&config, TOPIC, DEAD, "crash-publisher-replay").unwrap();
    until("publisher replay", async || {
        registry.publish_one(&broker).await.unwrap()
    })
    .await;
    assert_eq!(receive_id(&observer).await, (event_id, 1));
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT published FROM fabric_outbox")
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    drop(observer);
    drop(broker);

    sqlx::raw_sql("CREATE FUNCTION pause_receipt() RETURNS trigger LANGUAGE plpgsql AS
        $$ BEGIN PERFORM pg_advisory_xact_lock(6502); RETURN NEW; END; $$;
        CREATE TRIGGER pause_receipt BEFORE INSERT ON fabric_inbox FOR EACH ROW EXECUTE FUNCTION pause_receipt()")
        .execute(&pool).await.unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(6502)")
        .execute(&mut *gate)
        .await
        .unwrap();
    let inbox_count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM fabric_inbox WHERE subscriber=$1")
            .bind(GROUP)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let mut consumer = Probe::start("consume");
    wait_for_gate(&pool, 6502).await;
    assert_eq!(inbox_count().await, 0);
    docker("kill");
    gate.rollback().await.unwrap();
    until("committed inbox", async || inbox_count().await == 1).await;
    consumer.kill();

    docker("start");
    let observer: StreamConsumer = config.create().unwrap();
    until("broker recovery", async || {
        observer
            .fetch_watermarks(TOPIC, 0, Duration::from_secs(1))
            .ok()
            == Some((0, 2))
    })
    .await;
    let offsets = observer
        .committed_offsets(partitions.clone(), Duration::from_secs(10))
        .unwrap();
    assert_eq!(
        offsets.find_partition(TOPIC, 0).unwrap().offset(),
        Offset::Invalid
    );
    drop(observer);
    let mut broker = Broker::new(&config, TOPIC, DEAD, GROUP).unwrap();
    for _ in 0..2 {
        assert_eq!(
            registry.consume_one(&mut broker).await.unwrap(),
            Delivery::Duplicate
        );
    }
    let offsets: StreamConsumer = config.create().unwrap();
    let committed = offsets
        .committed_offsets(partitions, Duration::from_secs(10))
        .unwrap();
    assert_eq!(
        committed.find_partition(TOPIC, 0).unwrap().offset(),
        Offset::Offset(2)
    );
    drop(offsets);
    assert_eq!(inbox_count().await, 1);
    assert_eq!(
        registry.lookup_operation(intent.key()).await.unwrap(),
        Some(intent.record().clone())
    );

    check_reordered_and_missing(
        &registry,
        &pool,
        &config,
        &mut broker,
        fixture["Operation"].clone(),
    )
    .await;
    check_dead_letter(&registry, &config, &mut broker, event_id, intent.key()).await;
}

async fn check_reordered_and_missing(
    registry: &Registry,
    pool: &sqlx::PgPool,
    config: &ClientConfig,
    broker: &mut Broker,
    mut operation: Value,
) {
    let validator = ControlValidator::new().unwrap();
    operation["operation_id"] = json!("reordered");
    operation["idempotency_key"] = json!("reordered");
    let reordered =
        OperationIntent::new(&validator, operation.clone(), vec!["b".repeat(64)]).unwrap();
    registry.create_operation(&reordered).await.unwrap();
    registry
        .cancel_operation(reordered.key(), "crash-cancel")
        .await
        .unwrap();
    operation["operation_id"] = json!("missing");
    operation["idempotency_key"] = json!("missing");
    let missing = OperationIntent::new(&validator, operation, vec!["c".repeat(64)]).unwrap();
    registry.create_operation(&missing).await.unwrap();

    let pending = registry.pending_deliveries(GROUP, 8).await.unwrap();
    let events: Vec<_> = pending
        .iter()
        .filter(|event| event.operation_id == "reordered")
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].kind, "operation_created");
    assert_eq!(events[1].kind, "cancelled");
    let producer: FutureProducer = config.create().unwrap();
    for (index, event) in [events[1], events[0], events[1]].into_iter().enumerate() {
        let body = json!({"version":1, "id":event.id, "tenant_scope":event.tenant_scope,
            "operation_id":event.operation_id, "kind":event.kind})
        .to_string();
        let key = format!(
            "{}:{}{}",
            event.tenant_scope.len(),
            event.tenant_scope,
            event.operation_id
        );
        producer
            .send(
                FutureRecord::to(TOPIC).key(&key).payload(&body),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        let expected = if index == 2 {
            Delivery::Duplicate
        } else {
            Delivery::Accepted(event.clone())
        };
        assert_eq!(registry.consume_one(broker).await.unwrap(), expected);
        assert_eq!(
            registry
                .public_status(reordered.key())
                .await
                .unwrap()
                .as_deref(),
            Some("CANCELLED")
        );
    }

    let pending = registry.pending_deliveries(GROUP, 8).await.unwrap();
    assert_eq!(pending.len(), 4);
    let absent = pending
        .iter()
        .find(|event| event.operation_id == "missing")
        .unwrap();
    let broker_state: (bool, bool) = sqlx::query_as(
        "SELECT published, EXISTS (SELECT 1 FROM fabric_inbox WHERE event_id=$1 AND subscriber=$2)
         FROM fabric_outbox WHERE id=$1",
    )
    .bind(absent.id)
    .bind(GROUP)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(broker_state, (false, false));
    for event in &pending {
        assert!(
            registry
                .lookup_operation(event.operation_key())
                .await
                .unwrap()
                .is_some()
        );
        assert!(registry.acknowledge_delivery(GROUP, event).await.unwrap());
        assert!(!registry.acknowledge_delivery(GROUP, event).await.unwrap());
    }
    assert!(
        registry
            .pending_deliveries(GROUP, 8)
            .await
            .unwrap()
            .is_empty()
    );
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM fabric_operations), (SELECT count(*) FROM fabric_outbox),
         (SELECT count(*) FROM fabric_inbox WHERE subscriber=$1 AND handled)",
    )
    .bind(GROUP)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(counts, (3, 4, 4));
}

async fn check_dead_letter(
    registry: &Registry,
    config: &ClientConfig,
    broker: &mut Broker,
    id: i64,
    key: OperationKey<'_>,
) {
    let producer: FutureProducer = config.create().unwrap();
    let partition = format!(
        "{}:{}{}",
        key.tenant_scope.len(),
        key.tenant_scope,
        key.operation_id
    );
    let mut body = json!({"version":1, "id":id, "tenant_scope":key.tenant_scope,
        "operation_id":key.operation_id, "kind":"operation_created"})
    .to_string()
    .into_bytes();
    body.resize(64513 - partition.len(), b' ');
    producer
        .send(
            FutureRecord::to(TOPIC).key(&partition).payload(&body),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(
        registry.consume_one(broker).await.unwrap(),
        Delivery::Rejected
    );

    let mut observer_config = config.clone();
    observer_config
        .set("group.id", "crash-dead-observer")
        .set("enable.auto.commit", "false");
    let observer: StreamConsumer = observer_config.create().unwrap();
    let mut partitions = TopicPartitionList::new();
    partitions
        .add_partition_offset(DEAD, 0, Offset::Beginning)
        .unwrap();
    observer.assign(&partitions).unwrap();
    let record = tokio::time::timeout(DEADLINE, observer.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.key(), Some(b"rejected".as_slice()));
    assert_eq!(
        record.payload(),
        Some(br#"{"version":1,"code":"REJECTED_EVENT"}"#.as_slice())
    );
    assert!(record.headers().is_none());
    assert_eq!(record.offset(), 0);
}

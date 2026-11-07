use std::{sync::OnceLock, time::Duration};

use rdkafka::{
    ClientConfig, Message,
    consumer::{CommitMode, Consumer, StreamConsumer},
    producer::{FutureProducer, FutureRecord},
};
use serde::{Deserialize, Serialize};

use super::*;
use crate::limits::CONTROL_BYTES;

const WAIT: Duration = Duration::from_secs(15);
// Reserve space for Kafka record and batch framing. Application records have no headers.
const MESSAGE_BYTES: usize = CONTROL_BYTES - 1024;

const NOTIFICATION_SCHEMA: &str =
    include_str!("../../../../contracts/spec/notifications/v2/Notification.schema.json");

/// Reference to a committed outbox event. Resolve the current operation through SQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRef {
    pub id: i64,
    pub tenant_scope: String,
    pub operation_id: String,
    pub kind: String,
}

impl DeliveryRef {
    fn from_row(row: sqlx::postgres::PgRow) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_scope: row.try_get("tenant_scope")?,
            operation_id: row.try_get("operation_id")?,
            kind: row.try_get("kind")?,
        })
    }

    pub fn operation_key(&self) -> OperationKey<'_> {
        OperationKey {
            tenant_scope: &self.tenant_scope,
            operation_id: &self.operation_id,
        }
    }

    fn key(&self) -> String {
        format!(
            "{}:{}{}",
            self.tenant_scope.len(),
            self.tenant_scope,
            self.operation_id
        )
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let wire = Notification {
            id: self.id.to_string(),
            kind: self.kind.clone(),
            operation_id: self.operation_id.clone(),
            tenant_scope: self.tenant_scope.clone(),
            version: 2,
        };
        let value = serde_json::to_value(&wire).map_err(|_| RegistryError::Unavailable)?;
        if !valid_notification(&value) {
            return Err(RegistryError::Unavailable);
        }
        serde_json::to_vec(&wire).map_err(|_| RegistryError::Unavailable)
    }
}

// Declaration order is canonical JSON field order. The schema constrains all
// strings to ASCII alphabets with no JSON escapes.
#[derive(Deserialize, Serialize)]
struct Notification {
    id: String,
    kind: String,
    operation_id: String,
    tenant_scope: String,
    version: u8,
}

fn valid_notification(value: &Value) -> bool {
    static VALIDATOR: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema = serde_json::from_str(NOTIFICATION_SCHEMA).ok()?;
            jsonschema::validator_for(&schema).ok()
        })
        .as_ref()
        .is_some_and(|validator| validator.is_valid(value))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyNotification {
    version: u8,
    id: i64,
    tenant_scope: String,
    operation_id: String,
    kind: String,
}

fn decode_notification(body: &[u8]) -> Option<DeliveryRef> {
    let value: Value = serde_json::from_slice(body).ok()?;
    if value.get("version")?.as_u64()? == 1 {
        // Deserialize the original bytes, preserving i64 and rejecting duplicate fields.
        let wire: LegacyNotification = serde_json::from_slice(body).ok()?;
        return (wire.version == 1 && wire.id > 0).then_some(DeliveryRef {
            id: wire.id,
            kind: wire.kind,
            operation_id: wire.operation_id,
            tenant_scope: wire.tenant_scope,
        });
    }
    if !valid_notification(&value) {
        return None;
    }
    let wire: Notification = serde_json::from_value(value).ok()?;
    if serde_json::to_vec(&wire).ok()? != body {
        return None;
    }
    Some(DeliveryRef {
        id: wire.id.parse().ok()?,
        kind: wire.kind,
        operation_id: wire.operation_id,
        tenant_scope: wire.tenant_scope,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    Accepted(DeliveryRef),
    Duplicate,
    Rejected,
}

fn valid_subscriber(subscriber: &str) -> bool {
    !subscriber.is_empty() && subscriber.len() <= 249 && !subscriber.contains('\0')
}

pub struct Broker {
    producer: FutureProducer,
    consumer: StreamConsumer,
    topic: String,
    dead_letter: String,
    subscriber: String,
    blocked: bool,
}

impl Broker {
    pub fn new(
        config: &ClientConfig,
        topic: &str,
        dead_letter: &str,
        subscriber: &str,
    ) -> Result<Self> {
        if topic.is_empty()
            || dead_letter.is_empty()
            || topic == dead_letter
            || !valid_subscriber(subscriber)
        {
            return Err(RegistryError::InvalidIntent);
        }
        let mut producer_config = config.clone();
        producer_config
            .set("acks", "all")
            .set("message.timeout.ms", "10000")
            .set("message.max.bytes", CONTROL_BYTES.to_string())
            .set("compression.codec", "none");
        let producer = producer_config
            .create()
            .map_err(|_| RegistryError::Unavailable)?;
        let mut consumer_config = config.clone();
        consumer_config
            .set("group.id", subscriber)
            .set("enable.auto.commit", "false")
            .set("enable.auto.offset.store", "false")
            .set("auto.offset.reset", "earliest")
            .set("socket.timeout.ms", "10000")
            .set("enable.partition.eof", "false");
        let consumer: StreamConsumer = consumer_config
            .create()
            .map_err(|_| RegistryError::Unavailable)?;
        consumer
            .subscribe(&[topic])
            .map_err(|_| RegistryError::Unavailable)?;
        Ok(Self {
            producer,
            consumer,
            topic: topic.into(),
            dead_letter: dead_letter.into(),
            subscriber: subscriber.into(),
            blocked: false,
        })
    }

    async fn send(&self, topic: &str, key: &str, body: &[u8]) -> Result<()> {
        if body.len().saturating_add(key.len()) > MESSAGE_BYTES {
            return Err(RegistryError::InvalidIntent);
        }
        self.producer
            .send(FutureRecord::to(topic).key(key).payload(body), WAIT)
            .await
            .map_err(|_| RegistryError::Unavailable)?;
        Ok(())
    }
}

pub(super) async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    key: OperationKey<'_>,
    kind: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO fabric_outbox (tenant_scope, operation_id, kind) VALUES ($1,$2,$3)")
        .bind(key.tenant_scope)
        .bind(key.operation_id)
        .bind(kind)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

impl Registry {
    pub async fn publish_one(&self, broker: &Broker) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        // Publishing only changes a non-key field. Let inbox foreign-key
        // checks proceed while a publisher waits for the broker.
        let Some(row) = sqlx::query(
            "SELECT id, tenant_scope, operation_id, kind FROM fabric_outbox
             WHERE NOT published ORDER BY id LIMIT 1 FOR NO KEY UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(false);
        };
        let event = DeliveryRef::from_row(row)?;
        let body = event.encode()?;
        broker.send(&broker.topic, &event.key(), &body).await?;
        sqlx::query("UPDATE fabric_outbox SET published = true WHERE id = $1")
            .bind(event.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Repair a missed wakeup using the retained registry outbox, not broker history.
    pub async fn requeue_operation_events(&self, key: OperationKey<'_>) -> Result<()> {
        sqlx::query("UPDATE fabric_outbox SET published = false WHERE tenant_scope = $1 AND operation_id = $2")
            .bind(key.tenant_scope).bind(key.operation_id).execute(&self.pool).await?;
        Ok(())
    }

    /// Read committed wakeups awaiting this subscriber, including events never sent
    /// to Kafka and inbox receipts whose application handling did not finish.
    pub async fn pending_deliveries(
        &self,
        subscriber: &str,
        limit: u32,
    ) -> Result<Vec<DeliveryRef>> {
        if !valid_subscriber(subscriber) || !(1..=100).contains(&limit) {
            return Err(RegistryError::InvalidIntent);
        }
        sqlx::query(
            "SELECT o.id, o.tenant_scope, o.operation_id, o.kind FROM fabric_outbox o
             WHERE NOT EXISTS (SELECT 1 FROM fabric_inbox i
                 WHERE i.subscriber = $1 AND i.event_id = o.id AND i.handled)
             ORDER BY o.id LIMIT $2",
        )
        .bind(subscriber)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(DeliveryRef::from_row)
        .collect()
    }

    /// Acknowledge handling only after the caller has durably reconciled current SQL state.
    /// This records subscriber progress and does not transition the operation.
    pub async fn acknowledge_delivery(
        &self,
        subscriber: &str,
        event: &DeliveryRef,
    ) -> Result<bool> {
        if !valid_subscriber(subscriber) {
            return Err(RegistryError::InvalidIntent);
        }
        let result = sqlx::query(
            "INSERT INTO fabric_inbox (subscriber, event_id, handled)
             SELECT $1, id, true FROM fabric_outbox
             WHERE id=$2 AND tenant_scope=$3 AND operation_id=$4 AND kind=$5
             ON CONFLICT (subscriber, event_id) DO UPDATE SET handled=true
             WHERE NOT fabric_inbox.handled",
        )
        .bind(subscriber)
        .bind(event.id)
        .bind(&event.tenant_scope)
        .bind(&event.operation_id)
        .bind(&event.kind)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn consume_one(&self, broker: &mut Broker) -> Result<Delivery> {
        match self
            .poll_with_commit(broker, WAIT, CommitMode::Sync)
            .await?
        {
            Some(delivery) => Ok(delivery),
            None => {
                broker.blocked = true;
                Err(RegistryError::Unavailable)
            }
        }
    }

    /// A quiet broker is distinct from a failed or interrupted receipt.
    pub async fn poll_delivery(
        &self,
        broker: &mut Broker,
        wait: Duration,
    ) -> Result<Option<Delivery>> {
        self.poll_with_commit(broker, wait, CommitMode::Async).await
    }

    async fn poll_with_commit(
        &self,
        broker: &mut Broker,
        wait: Duration,
        commit_mode: CommitMode,
    ) -> Result<Option<Delivery>> {
        if broker.blocked {
            return Err(RegistryError::Unavailable);
        }
        broker.blocked = true;
        let result = self.consume_record(broker, wait, commit_mode).await;
        // On failure, reopening the group restarts from its committed offset.
        broker.blocked = result.is_err();
        result
    }

    async fn consume_record(
        &self,
        broker: &Broker,
        wait: Duration,
        commit_mode: CommitMode,
    ) -> Result<Option<Delivery>> {
        let Ok(received) = tokio::time::timeout(wait, broker.consumer.recv()).await else {
            return Ok(None);
        };
        let message = received.map_err(|_| RegistryError::Unavailable)?;
        let parsed = message
            .payload()
            .zip(message.key())
            .and_then(|(body, key)| {
                if body.len().saturating_add(key.len()) > MESSAGE_BYTES
                    || message.headers().is_some()
                {
                    return None;
                }
                let event = decode_notification(body)?;
                (event.key().as_bytes() == key).then_some(event)
            });
        let delivery = match parsed {
            Some(event) => self.record_delivery(&broker.subscriber, event).await?,
            None => Delivery::Rejected,
        };
        if delivery == Delivery::Rejected {
            broker
                .send(
                    &broker.dead_letter,
                    "rejected",
                    br#"{"version":1,"code":"REJECTED_EVENT"}"#,
                )
                .await?;
        }
        // Commit only after the durable inbox or the redacted DLQ has acknowledged.
        broker
            .consumer
            .commit_message(&message, commit_mode)
            .map_err(|_| RegistryError::Unavailable)?;
        Ok(Some(delivery))
    }

    async fn record_delivery(&self, subscriber: &str, event: DeliveryRef) -> Result<Delivery> {
        let mut tx = self.pool.begin().await?;
        let saved = sqlx::query(
            "SELECT id, tenant_scope, operation_id, kind FROM fabric_outbox WHERE id = $1",
        )
        .bind(event.id)
        .fetch_optional(&mut *tx)
        .await?
        .map(DeliveryRef::from_row)
        .transpose()?;
        if saved.as_ref() != Some(&event) {
            return Ok(Delivery::Rejected);
        }
        let row = sqlx::query(
            "INSERT INTO fabric_inbox (subscriber, event_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(subscriber)
        .bind(event.id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(if row.rows_affected() == 1 {
            Delivery::Accepted(event)
        } else {
            Delivery::Duplicate
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_wire_matches_spec_and_preserves_legacy_identity() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../contracts/spec/notifications/v2/vector.json"
        ))
        .unwrap();
        let body = fixture["body"].as_str().unwrap();
        let reference = decode_notification(body.as_bytes()).unwrap();
        assert_eq!(reference.id, i64::MAX);
        assert_eq!(reference.key(), fixture["key"].as_str().unwrap());
        assert_eq!(reference.encode().unwrap(), body.as_bytes());
        let legacy = br#"{"version":1,"id":9223372036854775807,"tenant_scope":"tenant:west","operation_id":"op:42","kind":"result_selected"}"#;
        assert_eq!(decode_notification(legacy), Some(reference));

        for invalid in [
            body.replace("9223372036854775807", "9223372036854775808"),
            format!(r#"{{"id":"1",{}"#, &body[1..]),
            format!(" {body}"),
            body.replace(r#""version":2"#, r#""version":2,"credentials":"secret""#),
            body.replace(r#""version":2"#, r#""version":3"#),
        ] {
            assert!(decode_notification(invalid.as_bytes()).is_none());
        }
    }
}

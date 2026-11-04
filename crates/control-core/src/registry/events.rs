use std::time::Duration;

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

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Event {
    version: u8,
    id: i64,
    tenant_scope: String,
    operation_id: String,
    kind: String,
}

impl Event {
    fn from_row(row: sqlx::postgres::PgRow) -> Result<Self> {
        Ok(Self {
            version: 1,
            id: row.try_get("id")?,
            tenant_scope: row.try_get("tenant_scope")?,
            operation_id: row.try_get("operation_id")?,
            kind: row.try_get("kind")?,
        })
    }

    fn key(&self) -> String {
        // Length framing avoids collisions when identifiers contain ':'.
        format!(
            "{}:{}{}",
            self.tenant_scope.len(),
            self.tenant_scope,
            self.operation_id
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    Accepted,
    Duplicate,
    Rejected,
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
            || subscriber.is_empty()
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
        let Some(row) = sqlx::query(
            "SELECT id, tenant_scope, operation_id, kind FROM fabric_outbox
             WHERE NOT published ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(false);
        };
        let event = Event::from_row(row)?;
        let body = serde_json::to_vec(&event).map_err(|_| RegistryError::Unavailable)?;
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

    pub async fn consume_one(&self, broker: &mut Broker) -> Result<Delivery> {
        if broker.blocked {
            return Err(RegistryError::Unavailable);
        }
        broker.blocked = true;
        let result = self.consume_record(broker).await;
        // On failure, reopening the group restarts from its committed offset.
        broker.blocked = result.is_err();
        result
    }

    async fn consume_record(&self, broker: &Broker) -> Result<Delivery> {
        let message = tokio::time::timeout(WAIT, broker.consumer.recv())
            .await
            .map_err(|_| RegistryError::Unavailable)?
            .map_err(|_| RegistryError::Unavailable)?;
        let parsed = message
            .payload()
            .zip(message.key())
            .and_then(|(body, key)| {
                if body.len().saturating_add(key.len()) > MESSAGE_BYTES
                    || message.headers().is_some()
                {
                    return None;
                }
                let event: Event = serde_json::from_slice(body).ok()?;
                (event.version == 1 && event.key().as_bytes() == key).then_some(event)
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
            .commit_message(&message, CommitMode::Sync)
            .map_err(|_| RegistryError::Unavailable)?;
        Ok(delivery)
    }

    async fn record_delivery(&self, subscriber: &str, event: Event) -> Result<Delivery> {
        let mut tx = self.pool.begin().await?;
        let saved = sqlx::query(
            "SELECT id, tenant_scope, operation_id, kind FROM fabric_outbox WHERE id = $1",
        )
        .bind(event.id)
        .fetch_optional(&mut *tx)
        .await?
        .map(Event::from_row)
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
            Delivery::Accepted
        } else {
            Delivery::Duplicate
        })
    }
}

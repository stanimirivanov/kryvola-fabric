use std::{error::Error, fs::File, io::Read, net::SocketAddr, time::Duration};

use kryvola_fabric_core::{
    registry::{Broker, Registry},
    registry_http::connect_pool,
};
use rdkafka::ClientConfig;
use serde::Deserialize;
use tokio::{
    runtime::Builder,
    signal,
    sync::{oneshot, watch},
    time::{sleep, timeout},
};

const BATCH: u32 = 8;
const PAUSE: Duration = Duration::from_millis(500);
const SQL_BUDGET: Duration = Duration::from_secs(8);
const BROKER_BUDGET: Duration = Duration::from_secs(18);
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(20);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    bootstrap_servers: String,
    topic: String,
    dead_letter_topic: String,
    subscriber: String,
    #[serde(default)]
    allow_loopback_plaintext: bool,
    tls_ca_file: Option<String>,
    tls_certificate_file: Option<String>,
    tls_key_file: Option<String>,
}

impl Config {
    fn read(path: &str) -> Result<Self, Box<dyn Error>> {
        const MAX_BYTES: u64 = 16 * 1024;
        if !std::fs::metadata(path)?.is_file() {
            return Err("invalid messaging configuration".into());
        }
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("invalid messaging configuration".into());
        }
        let config: Self = serde_json::from_slice(&bytes)?;
        let identifier = |value: &str| {
            !value.is_empty()
                && value.len() <= 249
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
                && value != "."
                && value != ".."
        };
        let tls_paths = [
            &config.tls_ca_file,
            &config.tls_certificate_file,
            &config.tls_key_file,
        ];
        if config.bootstrap_servers.is_empty()
            || config.bootstrap_servers.len() > 2048
            || config.bootstrap_servers.contains('\0')
            || !identifier(&config.topic)
            || !identifier(&config.dead_letter_topic)
            || !identifier(&config.subscriber)
            || config.topic == config.dead_letter_topic
            || config.tls_certificate_file.is_some() != config.tls_key_file.is_some()
            || tls_paths
                .into_iter()
                .flatten()
                .any(|path| path.is_empty() || path.contains('\0'))
            || (config.allow_loopback_plaintext
                && (tls_paths.iter().any(|path| path.is_some())
                    || !config.bootstrap_servers.split(',').all(|address| {
                        address
                            .parse::<SocketAddr>()
                            .is_ok_and(|addr| addr.ip().is_loopback() && addr.port() != 0)
                    })))
        {
            return Err("invalid messaging configuration".into());
        }
        Ok(config)
    }

    fn client(&self) -> ClientConfig {
        let mut client = ClientConfig::new();
        client
            .set("bootstrap.servers", &self.bootstrap_servers)
            .set("allow.auto.create.topics", "false")
            .set("socket.timeout.ms", "5000")
            .set("session.timeout.ms", "6000")
            .set(
                "security.protocol",
                if self.allow_loopback_plaintext {
                    "plaintext"
                } else {
                    "ssl"
                },
            );
        for (property, path) in [
            ("ssl.ca.location", &self.tls_ca_file),
            ("ssl.certificate.location", &self.tls_certificate_file),
            ("ssl.key.location", &self.tls_key_file),
        ] {
            if let Some(path) = path {
                client.set(property, path);
            }
        }
        client
    }
}

async fn broker_worker(registry: &Registry, config: &Config, client: &ClientConfig) {
    loop {
        match Broker::new(
            client,
            &config.topic,
            &config.dead_letter_topic,
            &config.subscriber,
        ) {
            Ok(mut broker) => 'connected: loop {
                for _ in 0..BATCH {
                    match timeout(BROKER_BUDGET, registry.publish_one(&broker)).await {
                        Ok(Ok(true)) => {}
                        Ok(Ok(false)) => break,
                        _ => {
                            eprintln!("messaging relay retry");
                            break;
                        }
                    }
                }
                for _ in 0..BATCH {
                    match timeout(BROKER_BUDGET, registry.poll_delivery(&mut broker, PAUSE)).await {
                        Ok(Ok(Some(_))) => {}
                        Ok(Ok(None)) => break,
                        _ => break 'connected,
                    }
                }
                sleep(PAUSE).await;
            },
            Err(_) => eprintln!("messaging broker setup retry"),
        }
        eprintln!("messaging consumer reconnect");
        sleep(PAUSE).await;
    }
}

async fn reconciliation_worker(registry: &Registry, subscriber: &str) {
    loop {
        let result = timeout(SQL_BUDGET, async {
            for event in registry.pending_deliveries(subscriber, BATCH).await? {
                // Acknowledge this SQL observation only. Workflow actions have their own fences.
                if registry
                    .lookup_operation(event.operation_key())
                    .await?
                    .is_some()
                {
                    registry.acknowledge_delivery(subscriber, &event).await?;
                }
            }
            Ok::<_, kryvola_fabric_core::registry::RegistryError>(())
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("messaging reconciliation retry");
        }
        sleep(PAUSE).await;
    }
}

pub async fn run(db: &str, path: &str) -> Result<(), Box<dyn Error>> {
    let config = Config::read(path).map_err(|_| "invalid messaging configuration")?;
    let registry = Registry::new(connect_pool(db).await?);
    let subscriber = config.subscriber.clone();
    let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let (stop, mut stopping) = watch::channel(());
    let (finished, mut done) = oneshot::channel();
    let broker_db = db.to_owned();
    // Librdkafka can block while closing groups. Isolate that lane so
    // broker stalls cannot block reconciliation or signal handling.
    let thread = std::thread::Builder::new()
        .name("fabric-broker".into())
        .spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build().ok();
            if let Some(runtime) = runtime {
                let client = config.client();
                runtime.block_on(async {
                    tokio::select! {
                        biased;
                        _ = stopping.changed() => {}
                        _ = async {
                            let pool = loop {
                                match connect_pool(&broker_db).await {
                                    Ok(pool) => break pool,
                                    Err(_) => eprintln!("messaging relay database retry"),
                                }
                                sleep(PAUSE).await;
                            };
                            broker_worker(&Registry::new(pool), &config, &client).await;
                        } => {}
                    }
                });
                drop(runtime);
                let _ = finished.send(());
            }
        })?;
    tokio::select! {
        _ = terminate.recv() => {}
        result = signal::ctrl_c() => result?,
        _ = &mut done => return Err("messaging broker worker stopped".into()),
        _ = reconciliation_worker(&registry, &subscriber) => {}
    }
    let _ = stop.send(());
    timeout(SHUTDOWN_BUDGET, done)
        .await
        .map_err(|_| "messaging shutdown deadline exceeded")?
        .map_err(|_| "messaging broker worker stopped")?;
    thread
        .join()
        .map_err(|_| "messaging broker worker stopped")?;
    Ok(())
}

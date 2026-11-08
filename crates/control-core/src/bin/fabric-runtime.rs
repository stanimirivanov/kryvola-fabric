//! Loopback runtime with an optional workload mTLS boundary.

use std::{
    error::Error,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use kryvola_fabric_core::{
    authorization::{Authorizer, Denial, Scope, now_unix_ms},
    limits::CONTROL_BYTES,
    registry_http::RegistryApi,
    runtime_contract::{RuntimeCode, RuntimeValidator},
    upload_http::UploadApi,
    workload::{Lease, PROVIDER_REFRESH, PROVIDER_TTL, identity_expiry},
};
use spiffe::{SpiffeId, X509Source, X509Svid, x509_source::SvidPicker};
use spiffe_rustls::{LocalOnly, TerminalSourcePolicy, authorizer, mtls_server};
use spiffe_rustls_tokio::TlsAcceptor;
use tokio::{net::TcpListener, sync::Semaphore, time::timeout};
use tokio_rustls::rustls;

#[path = "fabric_runtime/messaging.rs"]
mod messaging;

const BODY_TIMEOUT: Duration = Duration::from_secs(2);

fn reply(status: StatusCode, body: impl Into<String>) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.into(),
    )
        .into_response()
}

fn reject_body() -> Response {
    Denial::Body.audit();
    reply(
        StatusCode::PAYLOAD_TOO_LARGE,
        RuntimeCode::PayloadTooLarge.body(),
    )
}

fn deny(reason: Denial) -> Response {
    reason.audit();
    reply(StatusCode::FORBIDDEN, RuntimeCode::Forbidden.body())
}

fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let token = values.next()?.to_str().ok()?.strip_prefix("Bearer ")?;
    values.next().is_none().then_some(token)
}

async fn boundary(State(runtime): State<Arc<RuntimeValidator>>, request: Request) -> Response {
    handle(request, None, &runtime, None, None).await
}

async fn handle(
    request: Request,
    peer: Option<(&SpiffeId, &Authorizer, u64, Instant)>,
    runtime: &RuntimeValidator,
    registry: Option<&RegistryApi>,
    uploads: Option<&UploadApi>,
) -> Response {
    if let (Some(authorization), Some(api)) = (peer, uploads)
        && UploadApi::matches_read(request.method(), request.uri().path())
    {
        return api.handle_read(request, authorization, runtime).await;
    }
    if let (Some(authorization), Some(api)) = (peer, uploads)
        && UploadApi::matches(request.method(), request.uri().path())
    {
        let (status, body) = api.handle(request, authorization, runtime).await;
        return reply(status, body);
    }
    let authorize =
        request.method() == Method::POST && request.uri() == "/v1/artifact-access/authorize";
    let (headers, body) = request.into_parts();
    let health = headers.method == Method::GET && headers.uri == "/healthz";
    if headers
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse::<u64>().ok())
        .is_some_and(|length| length > CONTROL_BYTES as u64)
    {
        return reject_body();
    }
    match timeout(BODY_TIMEOUT, to_bytes(body, CONTROL_BYTES)).await {
        Err(_) => {
            Denial::Deadline.audit();
            reply(
                StatusCode::REQUEST_TIMEOUT,
                RuntimeCode::InvalidRequest.body(),
            )
        }
        Ok(Err(_)) => reject_body(),
        Ok(Ok(bytes)) if health && bytes.is_empty() => reply(StatusCode::OK, r#"{"status":"ok"}"#),
        Ok(Ok(bytes))
            if peer.is_some()
                && registry.is_some()
                && (RegistryApi::matches(&headers.method, headers.uri.path())
                    || (headers.method == Method::POST
                        && headers.uri.path() == "/v1/executions/receipt")) =>
        {
            let (workload, auth, expiry, deadline) = peer.expect("peer guard");
            if Instant::now() >= deadline {
                return deny(Denial::Provider);
            }
            if !now_unix_ms().is_some_and(|now| now < expiry) {
                return deny(Denial::Identity);
            }
            if headers.uri.query().is_some() {
                Denial::Scope.audit();
                return reply(StatusCode::BAD_REQUEST, RuntimeCode::InvalidRequest.body());
            }
            if headers.method == Method::POST && headers.uri.path() == "/v1/executions/receipt" {
                let (status, body) = registry
                    .expect("registry guard")
                    .handle_receipt(
                        &bytes,
                        (workload, auth, bearer(&headers.headers), expiry, deadline),
                        runtime,
                    )
                    .await;
                return reply(status, body);
            }
            let (status, body) = registry
                .expect("registry guard")
                .handle(
                    &headers.method,
                    headers.uri.path(),
                    &bytes,
                    (workload, auth, bearer(&headers.headers)),
                    runtime,
                )
                .await;
            if Instant::now() >= deadline {
                return deny(Denial::Provider);
            }
            if !now_unix_ms().is_some_and(|now| now < expiry) {
                return deny(Denial::Identity);
            }
            reply(status, body)
        }
        Ok(Ok(bytes)) if authorize && peer.is_some() => {
            let Some((workload, authorizer, identity_expiry, provider_deadline)) = peer else {
                unreachable!()
            };
            if Instant::now() >= provider_deadline {
                return deny(Denial::Provider);
            }
            if !now_unix_ms().is_some_and(|now| now < identity_expiry) {
                return deny(Denial::Identity);
            }
            let Some(token) = bearer(&headers.headers) else {
                return deny(Denial::Credential);
            };
            let scope = runtime
                .decode("AuthorizeArtifactRequest", &bytes)
                .ok()
                .and_then(|_| Scope::decode(&bytes));
            let Some(scope) = scope else {
                Denial::Scope.audit();
                return reply(StatusCode::BAD_REQUEST, RuntimeCode::InvalidRequest.body());
            };
            match authorizer.redeem(workload, token, &scope) {
                // Policy I/O must not let a previously valid identity/lease authorize late.
                Some(_) if Instant::now() >= provider_deadline => deny(Denial::Provider),
                Some(_) if !now_unix_ms().is_some_and(|now| now < identity_expiry) => {
                    deny(Denial::Identity)
                }
                Some(expiry) => reply(
                    StatusCode::OK,
                    format!(r#"{{"schema_version":"1","expires_unix_ms":"{expiry}"}}"#),
                ),
                None => reply(StatusCode::FORBIDDEN, RuntimeCode::Forbidden.body()),
            }
        }
        Ok(Ok(_)) => reply(StatusCode::NOT_FOUND, RuntimeCode::NotFound.body()),
    }
}

// Never fall back to the first identity when a provider supplies several SVIDs.
#[derive(Debug)]
struct IdentityPicker(SpiffeId);

impl SvidPicker for IdentityPicker {
    fn pick_svid(&self, svids: &[Arc<X509Svid>]) -> Option<usize> {
        svids.iter().position(|svid| svid.spiffe_id() == &self.0)
    }
}

// A source can rotate after acquisition; enforce the server lifetime on every resolution.
#[derive(Debug)]
struct BoundedServerCert(Arc<dyn rustls::server::ResolvesServerCert>);
impl rustls::server::ResolvesServerCert for BoundedServerCert {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let key = self.0.resolve(hello)?;
        if key
            .cert
            .first()
            .and_then(|cert| identity_expiry(cert.as_ref(), now_unix_ms()?))
            .is_none()
        {
            Denial::Identity.audit();
            return None;
        }
        Some(key)
    }
}

async fn workload_tls(endpoint: &str, identity: &str) -> Result<TlsAcceptor, Box<dyn Error>> {
    if !endpoint.starts_with("unix://") {
        return Err("Workload API requires a Unix socket endpoint".into());
    }
    let identity: SpiffeId = identity.parse()?;
    let domain = identity.trust_domain().clone();
    let source = timeout(
        Duration::from_secs(10),
        X509Source::builder()
            .endpoint(endpoint)
            .picker(IdentityPicker(identity))
            .build(),
    )
    .await??;
    let svid = source.svid()?;
    if svid
        .cert_chain()
        .first()
        .and_then(|cert| identity_expiry(cert.as_bytes(), now_unix_ms()?))
        .is_none()
    {
        return Err("server SVID validity must be at most 60 seconds".into());
    }
    let mut config = mtls_server(source)
        .authorize(authorizer::trust_domains([domain.as_str()])?)
        .trust_domain_policy(LocalOnly(domain))
        .terminal_source_policy(TerminalSourcePolicy::FailClosed)
        .build()?;
    config.cert_resolver = Arc::new(BoundedServerCert(config.cert_resolver));
    Ok(TlsAcceptor::new(Arc::new(config)))
}

async fn serve_mtls(
    listener: TcpListener,
    initial: TlsAcceptor,
    workload: (String, String),
    refreshed: Instant,
    auth: Arc<Authorizer>,
    runtime: Arc<RuntimeValidator>,
    services: (Option<Arc<RegistryApi>>, Option<Arc<UploadApi>>),
) -> std::io::Result<()> {
    let (registry, uploads) = services;
    let (endpoint, identity) = workload;
    let leases = Arc::new(RwLock::new(Lease {
        value: initial,
        refreshed,
    }));
    let updates = leases.clone();
    tokio::spawn(async move {
        let mut refresh = tokio::time::interval(PROVIDER_REFRESH);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        refresh.tick().await;
        loop {
            refresh.tick().await;
            let refreshed = Instant::now();
            match timeout(Duration::from_secs(3), workload_tls(&endpoint, &identity)).await {
                Ok(Ok(value)) => {
                    if let Ok(mut lease) = updates.write() {
                        *lease = Lease { value, refreshed };
                    }
                }
                _ => Denial::Provider.audit(),
            }
        }
    });
    let capacity = Arc::new(Semaphore::new(64));
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(slot) = capacity.clone().try_acquire_owned() else {
            Denial::Capacity.audit();
            continue;
        };
        let Some(lease) = leases
            .read()
            .ok()
            .filter(|lease| lease.live(Instant::now()))
            .map(|lease| lease.clone())
        else {
            Denial::Provider.audit();
            continue;
        };
        let acceptor = lease.value;
        let provider_deadline = lease.refreshed + PROVIDER_TTL;
        let auth = auth.clone();
        let runtime = runtime.clone();
        let registry = registry.clone();
        let uploads = uploads.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let Ok(Ok((stream, identity))) =
                timeout(Duration::from_secs(3), acceptor.accept(socket)).await
            else {
                Denial::Handshake.audit();
                return;
            };
            let Some(peer) = identity.spiffe_id() else {
                Denial::Identity.audit();
                return;
            };
            let Some(expiry) = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| identity_expiry(cert.as_ref(), now_unix_ms()?))
            else {
                Denial::Identity.audit();
                return;
            };
            let service = service_fn(|request: hyper::Request<hyper::body::Incoming>| async {
                Ok::<_, std::convert::Infallible>(
                    handle(
                        request.map(axum::body::Body::new),
                        Some((peer, &auth, expiry, provider_deadline)),
                        &runtime,
                        registry.as_deref(),
                        uploads.as_deref(),
                    )
                    .await,
                )
            });
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(3))
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service);
            match timeout(Duration::from_secs(8), connection).await {
                Err(_) => Denial::Deadline.audit(),
                Ok(Err(_)) => Denial::Body.audit(),
                Ok(Ok(())) => {}
            }
        });
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if let [mode, remaining @ ..] = args.as_slice()
        && mode == "--reclaim"
    {
        let [db, storage, retention, flags @ ..] = remaining else {
            return Err("usage: fabric-runtime --reclaim DATABASE_URL_FILE S3_CONFIG_FILE RETENTION_SECONDS [--delete] | --messaging DATABASE_URL_FILE KAFKA_CONFIG_FILE".into());
        };
        let delete = match flags {
            [] => false,
            [flag] if flag == "--delete" => true,
            _ => return Err("invalid reclamation flag".into()),
        };
        let seconds: u32 = retention.parse().map_err(|_| "invalid retention seconds")?;
        if seconds == 0 {
            return Err("retention seconds must be positive".into());
        }
        let pool = kryvola_fabric_core::registry_http::connect_pool(db).await?;
        let report = UploadApi::connect(pool, storage)?
            .reclamation_pass(seconds, delete)
            .await?;
        println!("{}", serde_json::to_string(&report)?);
        if report.failures > 0 {
            return Err("reclamation pass had retryable failures".into());
        }
        return Ok(());
    }
    if let [mode, db, config] = args.as_slice()
        && mode == "--messaging"
    {
        return messaging::run(db, config).await;
    }
    let runtime = Arc::new(RuntimeValidator::new()?);
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    match args.as_slice() {
        [] => {
            println!("{}", listener.local_addr()?);
            axum::serve(
                listener,
                Router::new().fallback(boundary).with_state(runtime),
            )
            .await?;
        }
        [mode, endpoint, identity, policy, remaining @ ..] if mode == "--spiffe" => {
            let (registry, uploads) = match remaining {
                [] => (None, None),
                [flag, path] if flag == "--registry" => {
                    (Some(Arc::new(RegistryApi::connect(path).await?)), None)
                }
                [flag, path, storage, config] if flag == "--registry" && storage == "--uploads" => {
                    let registry = Arc::new(RegistryApi::connect(path).await?);
                    let uploads = Arc::new(UploadApi::connect(registry.pool(), config)?);
                    (Some(registry), Some(uploads))
                }
                _ => return Err("invalid registry configuration arguments".into()),
            };
            let refreshed = Instant::now();
            let acceptor = workload_tls(endpoint, identity).await.map_err(|_| {
                Denial::Provider.audit();
                "workload provider unavailable"
            })?;
            let auth = Arc::new(Authorizer::new(policy.into())?);
            println!("{} {}", listener.local_addr()?, auth.boot_id());
            serve_mtls(
                listener,
                acceptor,
                (endpoint.clone(), identity.clone()),
                refreshed,
                auth,
                runtime,
                (registry, uploads),
            )
            .await?;
        }
        _ => {
            return Err(
                "usage: fabric-runtime [--spiffe WORKLOAD_API_ENDPOINT SERVER_SPIFFE_ID POLICY [--registry DATABASE_URL_FILE [--uploads S3_CONFIG_FILE]]] | --reclaim DATABASE_URL_FILE S3_CONFIG_FILE RETENTION_SECONDS [--delete] | --messaging DATABASE_URL_FILE KAFKA_CONFIG_FILE"
                    .into(),
            );
        }
    }
    Ok(())
}

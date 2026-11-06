//! Loopback runtime with an optional workload mTLS boundary.

use std::{error::Error, sync::Arc, time::Duration};

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
    authorization::{Authorizer, Scope},
    limits::CONTROL_BYTES,
    runtime_contract::{RuntimeCode, RuntimeValidator},
};
use spiffe::{SpiffeId, X509Source, X509Svid, x509_source::SvidPicker};
use spiffe_rustls::{LocalOnly, TerminalSourcePolicy, authorizer, mtls_server};
use spiffe_rustls_tokio::TlsAcceptor;
use tokio::{net::TcpListener, sync::Semaphore, time::timeout};

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
    reply(
        StatusCode::PAYLOAD_TOO_LARGE,
        RuntimeCode::PayloadTooLarge.body(),
    )
}

fn deny(reason: &'static str) -> Response {
    eprintln!("runtime_auth_denied {reason}");
    reply(StatusCode::FORBIDDEN, RuntimeCode::Forbidden.body())
}

async fn boundary(State(runtime): State<Arc<RuntimeValidator>>, request: Request) -> Response {
    handle(request, None, &runtime).await
}

async fn handle(
    request: Request,
    peer: Option<(&SpiffeId, &Authorizer)>,
    runtime: &RuntimeValidator,
) -> Response {
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
        Err(_) => reply(
            StatusCode::REQUEST_TIMEOUT,
            RuntimeCode::InvalidRequest.body(),
        ),
        Ok(Err(_)) => reject_body(),
        Ok(Ok(bytes)) if health && bytes.is_empty() => reply(StatusCode::OK, r#"{"status":"ok"}"#),
        Ok(Ok(bytes)) if authorize && peer.is_some() => {
            let Some((workload, authorizer)) = peer else {
                unreachable!()
            };
            let mut values = headers.headers.get_all(header::AUTHORIZATION).iter();
            let token = values
                .next()
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "));
            let Some(token) = token.filter(|_| values.next().is_none()) else {
                return deny("credential");
            };
            let scope = runtime
                .decode("AuthorizeArtifactRequest", &bytes)
                .ok()
                .and_then(|_| Scope::decode(&bytes));
            let Some(scope) = scope else {
                eprintln!("runtime_auth_denied invalid_scope");
                return reply(StatusCode::BAD_REQUEST, RuntimeCode::InvalidRequest.body());
            };
            match authorizer.redeem(workload, token, &scope) {
                Some(expiry) => reply(
                    StatusCode::OK,
                    format!(r#"{{"schema_version":"1","expires_unix_ms":"{expiry}"}}"#),
                ),
                None => deny("policy"),
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
    let config = mtls_server(source)
        .authorize(authorizer::trust_domains([domain.as_str()])?)
        .trust_domain_policy(LocalOnly(domain))
        .terminal_source_policy(TerminalSourcePolicy::FailClosed)
        .build()?;
    Ok(TlsAcceptor::new(Arc::new(config)))
}

async fn serve_mtls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    auth: Arc<Authorizer>,
    runtime: Arc<RuntimeValidator>,
) -> std::io::Result<()> {
    let capacity = Arc::new(Semaphore::new(64));
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(slot) = capacity.clone().try_acquire_owned() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let auth = auth.clone();
        let runtime = runtime.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let Ok(Ok((stream, identity))) =
                timeout(Duration::from_secs(3), acceptor.accept(socket)).await
            else {
                eprintln!("runtime_auth_denied handshake");
                return;
            };
            let Some(peer) = identity.spiffe_id() else {
                eprintln!("runtime_auth_denied identity");
                return;
            };
            let service = service_fn(|request: hyper::Request<hyper::body::Incoming>| async {
                Ok::<_, std::convert::Infallible>(
                    handle(
                        request.map(axum::body::Body::new),
                        Some((peer, &auth)),
                        &runtime,
                    )
                    .await,
                )
            });
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(3))
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service);
            let _ = timeout(Duration::from_secs(8), connection).await;
        });
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let runtime = Arc::new(RuntimeValidator::new()?);
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {
            println!("{}", listener.local_addr()?);
            axum::serve(
                listener,
                Router::new().fallback(boundary).with_state(runtime),
            )
            .await?;
        }
        [mode, endpoint, identity, policy] if mode == "--spiffe" => {
            let acceptor = workload_tls(endpoint, identity).await?;
            let auth = Arc::new(Authorizer::new(policy.into())?);
            println!("{} {}", listener.local_addr()?, auth.boot_id());
            serve_mtls(listener, acceptor, auth, runtime).await?;
        }
        _ => {
            return Err(
                "usage: fabric-runtime [--spiffe WORKLOAD_API_ENDPOINT SERVER_SPIFFE_ID POLICY]"
                    .into(),
            );
        }
    }
    Ok(())
}

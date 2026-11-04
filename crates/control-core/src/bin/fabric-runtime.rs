//! Loopback runtime with an optional workload mTLS boundary.

use std::{error::Error, sync::Arc, time::Duration};

use axum::{
    Router,
    body::to_bytes,
    extract::Request,
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use kryvola_fabric_core::{
    authorization::{Authorizer, Scope, sha256_hex},
    limits::CONTROL_BYTES,
};
use tokio::{net::TcpListener, sync::Semaphore, time::timeout};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
        server::{NoServerSessionStorage, WebPkiClientVerifier},
    },
};

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
        r#"{"error":"BODY_REJECTED"}"#,
    )
}

fn deny(reason: &'static str) -> Response {
    eprintln!("runtime_auth_denied {reason}");
    reply(
        StatusCode::FORBIDDEN,
        r#"{"schema_version":"1","code":"FORBIDDEN"}"#,
    )
}

async fn boundary(request: Request) -> Response {
    handle(request, None).await
}

async fn handle(request: Request, peer: Option<(&str, &Authorizer)>) -> Response {
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
            r#"{"error":"REQUEST_TIMEOUT"}"#,
        ),
        Ok(Err(_)) => reject_body(),
        Ok(Ok(bytes)) if health && bytes.is_empty() => reply(StatusCode::OK, r#"{"status":"ok"}"#),
        Ok(Ok(bytes)) if authorize && peer.is_some() => {
            let Some((certificate, authorizer)) = peer else {
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
            let Some(scope) = Scope::decode(&bytes) else {
                eprintln!("runtime_auth_denied invalid_scope");
                return reply(
                    StatusCode::BAD_REQUEST,
                    r#"{"schema_version":"1","code":"INVALID_REQUEST"}"#,
                );
            };
            match authorizer.redeem(certificate, token, &scope) {
                Some(expiry) => reply(
                    StatusCode::OK,
                    format!(r#"{{"schema_version":"1","expires_unix_ms":"{expiry}"}}"#),
                ),
                None => deny("policy"),
            }
        }
        Ok(Ok(_)) => reply(StatusCode::NOT_FOUND, r#"{"error":"NOT_FOUND"}"#),
    }
}

fn tls_config(cert: &str, key: &str, ca: &str) -> Result<ServerConfig, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    for root in CertificateDer::pem_file_iter(ca)? {
        roots.add(root?)?;
    }
    let chain = CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key)?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(roots.into(), provider.clone()).build()?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(config)
}

async fn serve_mtls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    auth: Arc<Authorizer>,
) -> std::io::Result<()> {
    let capacity = Arc::new(Semaphore::new(64));
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(slot) = capacity.clone().try_acquire_owned() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let Ok(Ok(stream)) = timeout(Duration::from_secs(3), acceptor.accept(socket)).await
            else {
                eprintln!("runtime_auth_denied handshake");
                return;
            };
            let Some(cert) = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
            else {
                eprintln!("runtime_auth_denied handshake");
                return;
            };
            let peer = sha256_hex(cert.as_ref());
            let service = service_fn(|request: hyper::Request<hyper::body::Incoming>| async {
                Ok::<_, std::convert::Infallible>(
                    handle(request.map(axum::body::Body::new), Some((&peer, &auth))).await,
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
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {
            println!("{}", listener.local_addr()?);
            axum::serve(listener, Router::new().fallback(boundary)).await?;
        }
        [mode, cert, key, ca, policy] if mode == "--mtls" => {
            let acceptor = TlsAcceptor::from(Arc::new(tls_config(cert, key, ca)?));
            let auth = Arc::new(Authorizer::new(policy.into())?);
            println!("{} {}", listener.local_addr()?, auth.boot_id());
            serve_mtls(listener, acceptor, auth).await?;
        }
        _ => return Err("usage: fabric-runtime [--mtls CERT KEY CA POLICY]".into()),
    }
    Ok(())
}

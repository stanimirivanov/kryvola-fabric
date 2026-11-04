//! Loopback-only runtime foundation. Workload routes require a future identity layer.

use std::{error::Error, time::Duration};

use axum::{
    Router,
    body::to_bytes,
    extract::Request,
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use kryvola_fabric_core::limits::CONTROL_BYTES;
use tokio::{net::TcpListener, time::timeout};

const BODY_TIMEOUT: Duration = Duration::from_secs(2);

fn reply(status: StatusCode, body: &'static str) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn reject_body() -> Response {
    reply(
        StatusCode::PAYLOAD_TOO_LARGE,
        r#"{"error":"BODY_REJECTED"}"#,
    )
}

async fn boundary(request: Request) -> Response {
    let health = request.method() == Method::GET && request.uri() == "/healthz";
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse::<u64>().ok())
        .is_some_and(|length| length > CONTROL_BYTES as u64)
    {
        return reject_body();
    }
    match timeout(BODY_TIMEOUT, to_bytes(request.into_body(), CONTROL_BYTES)).await {
        Err(_) => reply(
            StatusCode::REQUEST_TIMEOUT,
            r#"{"error":"REQUEST_TIMEOUT"}"#,
        ),
        Ok(Err(_)) => reject_body(),
        Ok(Ok(bytes)) if health && bytes.is_empty() => reply(StatusCode::OK, r#"{"status":"ok"}"#),
        Ok(Ok(_)) => reply(StatusCode::NOT_FOUND, r#"{"error":"NOT_FOUND"}"#),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    println!("{}", listener.local_addr()?);
    axum::serve(listener, Router::new().fallback(boundary)).await?;
    Ok(())
}

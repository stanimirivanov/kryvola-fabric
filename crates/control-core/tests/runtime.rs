use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn loopback_shell_bounds_requests_and_denies_runtime_routes() {
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_fabric-runtime"))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut endpoint = String::new();
    BufReader::new(server.0.stdout.take().unwrap())
        .read_line(&mut endpoint)
        .unwrap();
    assert!(endpoint.starts_with("127.0.0.1:"));

    let request = |request: &[u8]| {
        let mut socket = TcpStream::connect(endpoint.trim()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        socket.write_all(request).unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
        assert!(response.len() < 1024);
        response
    };
    let health = request(b"GET /healthz HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n");
    assert!(health.starts_with("HTTP/1.1 200 "));
    assert!(health.ends_with("{\"status\":\"ok\"}"));
    let denied = request(
        b"POST /v1/operations HTTP/1.1\r\nHost: local\r\nConnection: close\r\nContent-Length: 6\r\n\r\nsecret",
    );
    assert!(denied.starts_with("HTTP/1.1 404 "));
    assert!(!denied.contains("secret"));
    let assert_error = |response: &str, code: &str| {
        let body = response.split_once("\r\n\r\n").unwrap().1;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({"schema_version": "1", "code": code})
        );
    };
    assert_error(&denied, "NOT_FOUND");
    let oversized = request(
        b"POST /v1/operations HTTP/1.1\r\nHost: local\r\nConnection: close\r\nContent-Length: 65537\r\n\r\n",
    );
    assert!(oversized.starts_with("HTTP/1.1 413 "));
    assert_error(&oversized, "PAYLOAD_TOO_LARGE");
    let mut chunked = b"POST /v1/operations HTTP/1.1\r\nHost: local\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n10000\r\n".to_vec();
    chunked.extend(std::iter::repeat_n(b'x', 65536));
    chunked.extend_from_slice(b"\r\n1\r\ny\r\n0\r\n\r\n");
    let chunked = request(&chunked);
    assert!(chunked.starts_with("HTTP/1.1 413 "));
    assert_error(&chunked, "PAYLOAD_TOO_LARGE");
    let stalled = request(
        b"POST /v1/operations HTTP/1.1\r\nHost: local\r\nConnection: close\r\nContent-Length: 1\r\n\r\n",
    );
    assert!(stalled.starts_with("HTTP/1.1 408 "));
    assert_error(&stalled, "INVALID_REQUEST");
}

#[test]
fn released_output_routes_use_closed_published_scope() {
    use axum::http::Method;
    use kryvola_fabric_core::{runtime_contract::RuntimeValidator, upload_http::UploadApi};

    let schemas = RuntimeValidator::new().unwrap();
    let body = serde_json::json!({
        "schema_version":"1","tenant_scope":"tenant","recipient":"owner",
        "disclosure_id":"a".repeat(64),"output_manifest_digest":"b".repeat(64)
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    assert!(schemas.decode("ReadReleasedOutputRequest", &bytes).is_ok());
    assert!(schemas.decode("ReadComputeInputRequest", &bytes).is_err());
    assert!(UploadApi::matches_read(
        &Method::POST,
        "/v1/released-outputs/manifest"
    ));
    assert!(UploadApi::matches_read(
        &Method::POST,
        "/v1/released-outputs/parts/0"
    ));
    assert!(!UploadApi::matches_read(
        &Method::GET,
        "/v1/released-outputs/manifest"
    ));
}

#[test]
fn approved_submission_routes_require_the_published_boundary() {
    use axum::http::Method;
    use kryvola_fabric_core::{runtime_contract::RuntimeValidator, upload_http::UploadApi};
    let schema = RuntimeValidator::new().unwrap();
    let control: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/spec/fixtures/control.json"
    ))
    .unwrap();
    let request = serde_json::json!({"schema_version":"1","operation":control["Operation"],
        "approval_digest":"a".repeat(64),"evaluation_key_manifest_digest":"b".repeat(64),
        "input_manifest_digests":["c".repeat(64)]});
    assert!(
        schema
            .decode(
                "AdmitApprovedOperationRequest",
                request.to_string().as_bytes()
            )
            .is_ok()
    );
    assert!(UploadApi::matches_submission(
        &Method::POST,
        "/v1/operations/admit"
    ));
    assert!(UploadApi::matches_submission(
        &Method::PUT,
        "/v1/input-uploads/id/parts/0"
    ));
    assert!(!UploadApi::matches_submission(
        &Method::POST,
        "/v1/operations"
    ));
}

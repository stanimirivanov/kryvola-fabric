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
    let oversized = request(
        b"POST /v1/operations HTTP/1.1\r\nHost: local\r\nConnection: close\r\nContent-Length: 65537\r\n\r\n",
    );
    assert!(oversized.starts_with("HTTP/1.1 413 "));
    let mut chunked = b"POST /v1/operations HTTP/1.1\r\nHost: local\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n10000\r\n".to_vec();
    chunked.extend(std::iter::repeat_n(b'x', 65536));
    chunked.extend_from_slice(b"\r\n1\r\ny\r\n0\r\n\r\n");
    assert!(request(&chunked).starts_with("HTTP/1.1 413 "));
    let stalled = request(
        b"POST /v1/operations HTTP/1.1\r\nHost: local\r\nConnection: close\r\nContent-Length: 1\r\n\r\n",
    );
    assert!(stalled.starts_with("HTTP/1.1 408 "));
}

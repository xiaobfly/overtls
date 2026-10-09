//! Link 8: `tunnel_path` handling on the server - multiple values, the degenerated empty-string
//! array (COR-01), the single 2048 byte first read (COR-02) and the shipped sample path (SEC-02).

mod common;

use common::{
    DEFAULT_WAIT, HttpTarget, Proc, exchange, free_port, http_target, poll_until, read_until_eof, server_config, spawn_role, wait_tcp,
    work_dir, write_json, ws,
};
use serde_json::json;
use std::{
    io::Write,
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    time::Duration,
};

fn start(name: &str, top: serde_json::Value) -> (Proc, SocketAddr, HttpTarget) {
    let http = http_target("HTTP-TARGET-BODY");
    let port = free_port();
    let value = server_config(port, Some(&format!("http://{}", http.addr)), top, json!({}));
    let dir = work_dir(name);
    let cfg = write_json(&dir, "server.json", &value);
    let proc = spawn_role("server", &cfg, &["-v", "debug"], &dir);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(wait_tcp(addr, DEFAULT_WAIT), "server did not start: {}", proc.logs());
    (proc, addr, http)
}

/// Every entry of a `tunnel_path` array is accepted.
#[test]
fn multiple_tunnel_paths_all_match() {
    let (proc, addr, http) = start("e2e_tunnel_path_multiple", json!({ "tunnel_path": ["/a/", "/b/"] }));

    for path in ["/a/", "/b/"] {
        let handshake = ws::Handshake::new(path, "127.0.0.1");
        let (_ws, header) = ws::Ws::connect(addr, &handshake).expect("ws handshake");
        assert!(
            ws::Ws::status_line(&header).contains("101"),
            "path {path} must match, got: {header:?}\nserver log:\n{}",
            proc.logs()
        );
    }
    assert!(
        http.requests.lock().expect("http lock").is_empty(),
        "matching paths must not be forwarded"
    );
}

/// A `tunnel_path` array that degenerates to zero entries never matches, so every request -
/// including a full WebSocket upgrade - is forwarded to `forward_addr` (COR-01).
#[test]
fn degenerate_empty_string_array_forwards_everything() {
    let (proc, addr, http) = start("e2e_tunnel_path_degenerate", json!({ "tunnel_path": [""] }));

    let handshake = ws::Handshake::new("/t/", "127.0.0.1");
    let response = exchange(addr, &handshake.request(), Duration::from_secs(5));
    let text = String::from_utf8_lossy(&response).to_string();
    assert!(
        text.contains("HTTP-TARGET-BODY"),
        "a degenerated tunnel_path forwards everything, got: {text:?}\nserver log:\n{}",
        proc.logs()
    );
    let requests = http.requests.lock().expect("http lock");
    assert_eq!(requests.len(), 1, "the WebSocket upgrade itself must end up at the forward target");
    assert!(
        requests[0].starts_with(b"GET /t/ HTTP/1.1\r\n"),
        "the whole handshake must be forwarded verbatim, got: {:?}",
        String::from_utf8_lossy(&requests[0])
    );
    assert!(
        requests[0].windows(17).any(|w| w == b"Sec-WebSocket-Key"),
        "metadata of the downgraded handshake leaks to the forward target"
    );
}

/// A handshake whose header block exceeds the single 2048 byte first read is neither answered nor
/// forwarded: the truncated request is parsed as a matching path and the session ends with
/// "invalid handshake" (COR-02, first failure mode).
#[test]
fn oversized_header_block_is_closed_not_forwarded() {
    let (proc, addr, http) = start("e2e_tunnel_path_oversized", json!({}));

    let mut request = b"GET /t/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n".to_vec();
    for _ in 0..40 {
        request.extend_from_slice(b"X-Padding: ");
        request.extend_from_slice(&[b'p'; 100]);
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    assert!(
        request.len() > 2048,
        "the handshake must exceed the first read, len = {}",
        request.len()
    );

    let response = exchange(addr, &request, Duration::from_secs(5));
    assert!(
        response.is_empty(),
        "expected silence, got: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        http.requests.lock().expect("http lock").is_empty(),
        "a truncated matching request must not be forwarded"
    );
    // Current behavior: the truncated handshake is parsed as a matching path, so the session dies
    // in the WebSocket step and the server logs `invalid handshake`.
    // Post-fix expectation: this line disappears (a 400 response is sent, or the request is
    // forwarded instead), which flips this assertion.
    assert!(
        poll_until(Duration::from_secs(5), || proc.logs().contains("invalid handshake")),
        "the server must log the broken handshake:\n{}",
        proc.logs()
    );
}

/// When the first read does not contain the whole request line, `httparse` reports `Partial`, which
/// is treated as "path mismatch": the (matching) tunnel path is served by the camouflage fallback
/// instead, and the fragment is handed to the upstream reverse proxy (COR-02, second failure mode).
#[test]
fn split_request_line_takes_the_fallback_path() {
    let (proc, addr, http) = start("e2e_tunnel_path_split", json!({}));

    let mut stream = TcpStream::connect(addr).expect("connect server");
    stream.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    // The first read only sees "GET /t/", so the request line is incomplete when the path is checked.
    stream.write_all(b"GET /t/").expect("write fragment");
    // Do not rely on a fixed sleep for the ordering: wait until the server's *first* read has been
    // decided as a mismatch (`not match path` is logged right before the fallback is taken). On a
    // slow machine a sleep could expire before the server ever reads, and the complete request line
    // would then produce a 101.
    assert!(
        poll_until(Duration::from_secs(5), || proc.logs().contains("not match path \"/t/\"")),
        "the matching path must have been treated as a mismatch after the first read:\n{}",
        proc.logs()
    );
    stream
        .write_all(b" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
        .expect("write rest");

    let response = read_until_eof(&mut stream, Duration::from_secs(3));
    let text = String::from_utf8_lossy(&response).to_string();
    assert!(
        !text.contains("101"),
        "a matching path must not produce a handshake once the first read was incomplete: {text:?}"
    );
    assert!(
        poll_until(Duration::from_secs(5), || !http.requests.lock().expect("http lock").is_empty()),
        "the fragment must reach the forward target:\n{}",
        proc.logs()
    );
    let requests = http.requests.lock().expect("http lock");
    assert!(
        requests[0].starts_with(b"GET /t/"),
        "the fragment is forwarded verbatim, got: {:?}",
        String::from_utf8_lossy(&requests[0])
    );
}

/// The `tunnel_path` shipped in the sample `config.json` is a fixed, guessable value, and the
/// server accepts it verbatim (SEC-02).
#[test]
fn sample_config_default_path_is_public() {
    let sample: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.json")).expect("sample config"),
    )
    .expect("sample config json");
    assert_eq!(
        sample["tunnel_path"], "/secret-tunnel-path/",
        "SEC-02 regression: re-check this case whenever the shipped sample changes its tunnel_path"
    );

    let (_proc, addr, _http) = start("e2e_tunnel_path_sample", json!({ "tunnel_path": sample["tunnel_path"].clone() }));
    let handshake = ws::Handshake::new("/secret-tunnel-path/", "127.0.0.1");
    let (_ws, header) = ws::Ws::connect(addr, &handshake).expect("ws handshake");
    assert!(
        ws::Ws::status_line(&header).contains("101"),
        "the sample path must be usable as-is, got: {header:?}"
    );
}

//! Link 4: requests whose path does not match `tunnel_path` are forwarded verbatim to
//! `forward_addr` (the nginx/Caddy camouflage), and a matching path that is *not* a WebSocket
//! upgrade is closed without any response (SEC-11).
//!
//! Only the server role is spawned here: the fallback is what an arbitrary HTTP client (scanner,
//! browser, reverse proxy) sees, the overtls client is not part of that path.

mod common;

use common::{exchange, free_port, http_target, poll_until, server_config, spawn_role, wait_tcp, work_dir, write_json};
use std::{net::SocketAddr, time::Duration};

fn start(name: &str) -> (common::Proc, SocketAddr, common::HttpTarget) {
    let http = http_target("HTTP-TARGET-BODY");
    let port = free_port();
    let value = server_config(
        port,
        Some(&format!("http://{}", http.addr)),
        serde_json::json!({}),
        serde_json::json!({}),
    );
    let dir = work_dir(name);
    let cfg = write_json(&dir, "server.json", &value);
    let proc = spawn_role("server", &cfg, &["-v", "debug"], &dir);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(wait_tcp(addr, common::DEFAULT_WAIT), "server did not start: {}", proc.logs());
    (proc, addr, http)
}

/// A request for an unconfigured path reaches the camouflage endpoint unchanged.
#[test]
fn nonmatching_path_is_forwarded() {
    let (proc, addr, http) = start("e2e_forward_nonmatching");

    let response = exchange(
        addr,
        b"GET /random HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        Duration::from_secs(5),
    );
    let text = String::from_utf8_lossy(&response).to_string();
    assert!(
        text.contains("HTTP-TARGET-BODY"),
        "expected the forward target body, got: {text:?}\nserver log:\n{}",
        proc.logs()
    );
    let requests = http.requests.lock().expect("http lock");
    assert_eq!(requests.len(), 1, "the target must receive exactly one request");
    assert!(
        requests[0].starts_with(b"GET /random HTTP/1.1\r\n"),
        "the request must be forwarded verbatim, got: {:?}",
        String::from_utf8_lossy(&requests[0])
    );
}

/// A request for the tunnel path without the WebSocket upgrade is closed without a response, and it
/// is *not* forwarded (SEC-11: no distinguishable answer, no camouflage, no 400).
#[test]
fn matching_path_non_ws_closed_without_response() {
    let (proc, addr, http) = start("e2e_forward_matching_non_ws");

    let response = exchange(
        addr,
        b"GET /t/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        Duration::from_secs(5),
    );
    assert!(
        response.is_empty(),
        "expected an empty answer, got: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        http.requests.lock().expect("http lock").is_empty(),
        "a matching path must never be forwarded"
    );
    assert!(
        poll_until(Duration::from_secs(5), || proc.logs().contains("Connection: upgrade")),
        "server log must report the rejected upgrade:\n{}",
        proc.logs()
    );
}

/// The same path with the full WebSocket upgrade performs the handshake.
#[test]
fn matching_path_ws_gets_101() {
    let (mut proc, addr, http) = start("e2e_forward_matching_ws");

    let handshake = common::ws::Handshake::new("/t/", "127.0.0.1");
    let (_ws, header) = common::ws::Ws::connect(addr, &handshake).expect("ws handshake");
    let status = common::ws::Ws::status_line(&header);
    assert!(status.contains("101"), "expected a 101 handshake, got: {header:?}");
    assert!(
        http.requests.lock().expect("http lock").is_empty(),
        "a matching path must never be forwarded"
    );
    assert!(!proc.exited(), "server must stay alive");
}

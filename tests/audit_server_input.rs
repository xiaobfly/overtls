//! Regression tests for server-side input handling.
//!
//! Findings: SEC-01 (no timeout and no limit on the first read, half-open connections are held
//! forever; a failed listener bind is swallowed by `async_main` and only logged, so the process
//! exits 0), SEC-17 (the path check tolerates 512 headers while the WebSocket handshake parser
//! accepts only 124), SEC-05 (the private-destination guard of the TCP tunnel refuses loopback).
//!
//! Every assertion describes the *current* behavior; a fix must flip it (see the comments).

mod common;

use common::{
    DEFAULT_WAIT, Proc, b64, free_port, http_target, poll_until, server_config, socks5_addr_v4, spawn_role, tcp_echo_server, wait_tcp,
    work_dir, write_json, ws,
};
use serde_json::json;
use std::{
    io::{ErrorKind, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

fn start_server(name: &str) -> (Proc, SocketAddr, common::HttpTarget, PathBuf) {
    let http = http_target("HTTP-TARGET-BODY");
    let port = free_port();
    let value = server_config(port, Some(&format!("http://{}", http.addr)), json!({}), json!({}));
    let dir = work_dir(name);
    let cfg = write_json(&dir, "server.json", &value);
    let proc = spawn_role("server", &cfg, &["-v", "debug"], &dir);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(wait_tcp(addr, DEFAULT_WAIT), "server did not start: {}", proc.logs());
    (proc, addr, http, cfg)
}

/// Build a WebSocket upgrade request for `/t/` with `extra_headers` inserted before the final CRLF.
fn ws_request_with_headers(extra_headers: &[String]) -> Vec<u8> {
    let mut request = b"GET /t/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n".to_vec();
    for header in extra_headers {
        request.extend_from_slice(header.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request
}

/// SEC-01: connections that never send a byte are held forever (single `read_buf` without timeout
/// or limit), while the listener keeps serving new clients.
///
/// The observation window is 12s on purpose: 3s is weaker than any plausible handshake timeout and
/// could not distinguish "no first-byte timeout" from "a short timeout", while 12s pins the
/// absence of a timeout. A fix must close half-open connections far earlier.
#[test]
fn half_open_connections_held() {
    // How long the idle connections are observed before they are considered held forever.
    const HOLD_OBSERVATION: Duration = Duration::from_secs(12);

    let (proc, addr, _http, _cfg) = start_server("audit_server_half_open");

    let mut half_open = Vec::new();
    for _ in 0..5 {
        let stream = TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(Duration::from_millis(300))).expect("timeout");
        half_open.push(stream);
    }
    std::thread::sleep(HOLD_OBSERVATION);

    for (index, stream) in half_open.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        match stream.read(&mut buf) {
            // Current behavior: the server neither answers nor closes an idle connection.
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            other => panic!("half-open connection #{index} was closed: {other:?}\nserver log:\n{}", proc.logs()),
        }
    }

    // The listener is still able to serve a new client.
    let handshake = ws::Handshake::new("/t/", "127.0.0.1");
    let (_ws, header) = ws::Ws::connect(addr, &handshake).expect("ws handshake");
    assert!(
        ws::Ws::status_line(&header).contains("101"),
        "the listener must still serve new clients: {header:?}\n{}",
        proc.logs()
    );
}

/// SEC-17: the same header count passes the path check but fails the handshake parser, and a
/// non-matching path with that many headers is forwarded happily.
#[test]
fn header_count_512_vs_124() {
    let (_proc, addr, http, _cfg) = start_server("audit_server_headers");

    let many_headers: Vec<String> = (0..126).map(|i| format!("X-H{i}: v")).collect();

    // (a) matching path + 126 extra headers: the path check uses 512 slots, tungstenite only 124,
    // so the connection dies without a response instead of performing the upgrade.
    let response = common::exchange(addr, &ws_request_with_headers(&many_headers), Duration::from_secs(5));
    assert!(
        response.is_empty(),
        "expected silence for >124 headers, got: {:?}",
        String::from_utf8_lossy(&response)
    );

    // (b) non-matching path + the same headers: the request is forwarded verbatim, so the
    // inconsistent limits are externally visible.
    let mut request = b"GET /random HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n".to_vec();
    for header in &many_headers {
        request.extend_from_slice(header.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    let response = common::exchange(addr, &request, Duration::from_secs(5));
    let text = String::from_utf8_lossy(&response).to_string();
    assert!(
        text.contains("HTTP-TARGET-BODY"),
        "a non-matching path must still be forwarded: {text:?}"
    );
    let requests = http.requests.lock().expect("http lock");
    assert_eq!(requests[0].len(), request.len(), "the forwarded request must be forwarded verbatim");
}

/// SEC-05: the legacy `Target-Address` handshake path refuses a loopback destination, and the
/// refusal is visible as an immediate close after the (already written) handshake response.
#[test]
fn legacy_target_address_loopback_refused() {
    let (proc, addr, _http, _cfg) = start_server("audit_server_target_address");
    let echo = tcp_echo_server();

    let mut handshake = ws::Handshake::new("/t/", "127.0.0.1");
    handshake.target_address = Some(echo.addr);
    // The legacy path carries the target as base64 SOCKS5 address in the upgrade request.
    let request = String::from_utf8_lossy(&handshake.request()).to_string();
    assert!(
        request.contains(&format!("Target-Address: {}", b64(&socks5_addr_v4(echo.addr)))),
        "legacy target address header missing: {request:?}"
    );

    let (mut socket, header) = ws::Ws::connect(addr, &handshake).expect("ws handshake");
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");

    let started = Instant::now();
    let closed = poll_until(Duration::from_secs(3), || {
        let _ = socket.recv_frame(Duration::from_millis(200));
        socket.is_closed()
    });
    assert!(
        closed && started.elapsed() < Duration::from_secs(3),
        "the session must be closed right after the handshake:\n{}",
        proc.logs()
    );
    assert_eq!(
        echo.connections.load(Ordering::SeqCst),
        0,
        "the loopback destination must not be reached"
    );
    assert!(
        poll_until(Duration::from_secs(5), || proc
            .logs()
            .contains("destination address is private, skipping")),
        "the refusal must be logged:\n{}",
        proc.logs()
    );
}

/// SEC-01 (accept/bind half): when the listen port is already taken, `run_server` fails to bind,
/// `async_main` swallows the error and only logs it, and the process still exits with code 0 -
/// so `systemd` `Restart=on-failure` never fires and a dead service stays dead silently.
///
/// Flip condition: once startup errors propagate out of `async_main`/`main`, the exit code must
/// become non-zero.
#[test]
fn listener_bind_failure_exits_zero() {
    // Hold the port for the whole test so the spawned server cannot bind it.
    let held = TcpListener::bind("127.0.0.1:0").expect("bind port holder");
    let port = held.local_addr().expect("holder address").port();

    let dir = work_dir("audit_server_bind_failure");
    let value = server_config(port, None, json!({}), json!({}));
    let cfg = write_json(&dir, "server.json", &value);
    let mut proc = spawn_role("server", &cfg, &["-v", "debug"], &dir);

    let status = proc
        .wait_timeout(Duration::from_secs(15))
        .unwrap_or_else(|| panic!("a failed bind must terminate the process:\n{}", proc.logs()));
    // Current behavior: `main_body error: ...` is logged but `main` returns Ok -> exit code 0.
    assert_eq!(
        status.code(),
        Some(0),
        "current behavior is exit 0 for a failed bind; a fix must return non-zero:\n{}",
        proc.logs()
    );
    assert!(
        poll_until(Duration::from_secs(5), || {
            let logs = proc.logs();
            logs.contains("failed to bind to") && logs.contains("main_body error")
        }),
        "the bind failure and the swallowed error must both be logged:\n{}",
        proc.logs()
    );
}

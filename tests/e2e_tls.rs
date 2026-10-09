//! Link 5: TLS with the committed test CAs - certificate verification, `cafile` handling,
//! `server_domain` verification and `dangerous_mode` (SEC-07/08/09).
//!
//! The observable used for "the TLS handshake succeeded" is the SOCKS5 greeting reply: the client
//! acquires a WebSocket connection from the pool *before* it answers the local SOCKS5 client, so a
//! failed TLS handshake closes the local connection with no reply at all. The positive case also
//! performs a full UDP round trip through the encrypted tunnel (the UDP link has no
//! private-destination guard, so it works against a loopback echo server).

mod common;

use common::{
    DEFAULT_WAIT, Pair, ca_root, client_config, copy_ca, free_port, poll_until, server_config, start_pair, udp_associate, udp_echo_server,
    udp_recv, udp_send, work_dir,
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::Duration,
};

/// Build a TLS server (leaf of `ca`) plus a client with the given `client_settings` overrides.
fn tls_pair_with_ca(name: &str, ca: &str, client_settings: serde_json::Value) -> (Pair, PathBuf) {
    let dir = work_dir(name);
    let (cert, key) = copy_ca(&dir, ca);
    let srv_port = free_port();
    let client_port = free_port();
    let server_value = server_config(
        srv_port,
        None,
        json!({}),
        json!({ "disable_tls": false, "certfile": cert, "keyfile": key }),
    );
    let mut settings = json!({ "disable_tls": false, "server_domain": "example.com" });
    common::merge(&mut settings, client_settings);
    let client_value = client_config(srv_port, client_port, json!({}), settings);
    let pair = start_pair(name, &server_value, &client_value, srv_port, client_port);
    (pair, dir)
}

/// Build a TLS server (leaf of `ca-a`) plus a client with the given `client_settings` overrides.
fn tls_pair(name: &str, client_settings: serde_json::Value) -> (Pair, PathBuf) {
    tls_pair_with_ca(name, "ca-a", client_settings)
}

/// Ask the local SOCKS5 endpoint for method selection; `None` when the connection is closed
/// without any reply (the client's TLS failures behave that way).
fn greeting_reply(addr: SocketAddr) -> Option<[u8; 2]> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream.write_all(&[0x05, 0x01, 0x00]).ok()?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).ok()?;
    Some(reply)
}

/// Run a UDP round trip through the tunnel (only possible when TLS completed successfully).
fn udp_round_trip(proxy: SocketAddr) -> bool {
    let udp_echo = udp_echo_server();
    let Ok((_control, relay)) = udp_associate(proxy) else {
        return false;
    };
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    if udp_send(&socket, relay, udp_echo.addr, b"TLS-UDP-PING").is_err() {
        return false;
    }
    matches!(udp_recv(&socket, Duration::from_secs(5)), Some((_, payload)) if payload == b"TLS-UDP-PING")
}

/// The leaf of `ca-a` is trusted through `cafile`, `server_domain` matches the DNS SAN, traffic flows.
#[test]
fn tls_positive_ca_a() {
    let (pair, _dir) = tls_pair("e2e_tls_positive", json!({ "cafile": ca_root("ca-a") }));
    assert!(
        pair.server.logs().contains("using TLS"),
        "server must run with TLS:\n{}",
        pair.server.logs()
    );

    assert_eq!(
        greeting_reply(pair.client_addr),
        Some([0x05, 0x00]),
        "a verified TLS tunnel must let the SOCKS5 greeting through:\n{}",
        pair.client.logs()
    );
    assert!(udp_round_trip(pair.client_addr), "UDP traffic must flow through the TLS tunnel");
}

/// A client with a different CA must not complete the handshake (SEC-09 verification works).
#[test]
fn tls_wrong_ca_rejected() {
    let (mut pair, _dir) = tls_pair("e2e_tls_wrong_ca", json!({ "cafile": ca_root("ca-b") }));

    assert_eq!(
        greeting_reply(pair.client_addr),
        None,
        "a foreign CA must be rejected:\n{}",
        pair.client.logs()
    );
    assert!(
        !pair.client.logs().contains("Successfully created new connection"),
        "no tunnel may be established"
    );
    assert!(!pair.client.exited(), "the client must stay alive after a failed handshake");
}

/// A `cafile` pointing at a missing path is silently ignored; the default roots then reject the
/// self-signed leaf (SEC-08).
#[test]
fn tls_missing_cafile_path_ignored() {
    let missing = Path::new("target/test-tmp/does-not-exist/root.crt");
    let (pair, _dir) = tls_pair("e2e_tls_missing_cafile", json!({ "cafile": missing }));

    assert_eq!(
        greeting_reply(pair.client_addr),
        None,
        "a missing cafile must not be trusted:\n{}",
        pair.client.logs()
    );
    assert!(
        !pair.client.logs().contains("main_body error"),
        "the client must not abort:\n{}",
        pair.client.logs()
    );
}

/// SEC-08 (degraded `cafile` forms): an explicitly empty `cafile` (the shipped default value) is
/// silently ignored exactly like a missing path - the built-in roots are used, they reject the
/// self-signed leaf, and the client keeps running.
///
/// Flip condition: a `cafile` that is set but unusable must fail loudly instead of degrading to
/// the built-in roots.
#[test]
fn tls_empty_cafile_uses_builtin_roots() {
    let (mut pair, _dir) = tls_pair("e2e_tls_empty_cafile", json!({ "cafile": "" }));

    assert_eq!(
        greeting_reply(pair.client_addr),
        None,
        "an empty cafile must not add any trust anchor:\n{}",
        pair.client.logs()
    );
    assert!(
        !pair.client.logs().contains("main_body error"),
        "the client must not abort:\n{}",
        pair.client.logs()
    );
    assert!(!pair.client.exited(), "the client must stay alive after the failed handshake");
}

/// SEC-08 (degraded `cafile` forms): a `cafile` pointing at a short, non-PEM file is silently
/// ignored - the content check requires a `-----BEGIN CERTIFICATE-----` prefix (and >100 bytes) -
/// so verification falls back to the built-in roots and the client stays alive.
///
/// Flip condition: a `cafile` that is set but unusable must be reported instead of silently
/// ignored.
#[test]
fn tls_garbage_cafile_file_ignored() {
    let scratch = work_dir("e2e_tls_garbage_cafile_scratch");
    let garbage = scratch.join("garbage-root.crt");
    std::fs::write(&garbage, b"this is not a certificate and stays below one hundred bytes").expect("write garbage cafile");
    assert!(garbage.is_file(), "this case needs an existing (but unusable) file");
    assert!(
        std::fs::metadata(&garbage).expect("metadata").len() < 100,
        "the PEM check only accepts contents longer than 100 bytes"
    );

    let (mut pair, _dir) = tls_pair("e2e_tls_garbage_cafile", json!({ "cafile": garbage }));

    assert_eq!(
        greeting_reply(pair.client_addr),
        None,
        "a garbage cafile must not add any trust anchor:\n{}",
        pair.client.logs()
    );
    assert!(
        !pair.client.logs().contains("main_body error"),
        "the client must not abort:\n{}",
        pair.client.logs()
    );
    assert!(!pair.client.exited(), "the client must stay alive after the failed handshake");
}

/// `server_domain` is verified against the certificate SANs (SEC-09).
#[test]
fn tls_domain_mismatch_rejected() {
    let (pair, _dir) = tls_pair(
        "e2e_tls_domain_mismatch",
        json!({ "cafile": ca_root("ca-a"), "server_domain": "other.example.com" }),
    );

    assert_eq!(
        greeting_reply(pair.client_addr),
        None,
        "a mismatching domain must be rejected:\n{}",
        pair.client.logs()
    );
}

/// SEC-09 (host binding): the verification is bound to `server_domain` only, never to
/// `server_host`. The leaf of `ca-c` carries no IP SAN (SAN is exactly `DNS:example.com`, see
/// `tests/fixtures/README.md`), yet the client reaches it via the IP literal `127.0.0.1` and
/// verifies `example.com`.
///
/// Current behavior: the handshake succeeds. A policy that also bound the verification to
/// `server_host` would have to flip this assertion.
#[test]
fn tls_verification_is_not_bound_to_server_host() {
    let (pair, _dir) = tls_pair_with_ca("e2e_tls_host_not_bound", "ca-c", json!({ "cafile": ca_root("ca-c") }));

    assert_eq!(
        greeting_reply(pair.client_addr),
        Some([0x05, 0x00]),
        "verification must use server_domain only, not server_host (the leaf has no IP SAN):\n{}",
        pair.client.logs()
    );
}

/// `dangerous_mode` skips certificate verification entirely (SEC-07).
#[test]
fn tls_dangerous_mode_bypasses_verification() {
    let (pair, _dir) = tls_pair("e2e_tls_dangerous", json!({ "cafile": ca_root("ca-b"), "dangerous_mode": true }));

    assert_eq!(
        greeting_reply(pair.client_addr),
        Some([0x05, 0x00]),
        "dangerous mode must connect with any certificate:\n{}",
        pair.client.logs()
    );
    assert!(udp_round_trip(pair.client_addr), "the dangerous-mode tunnel must carry traffic");
    assert!(
        poll_until(Duration::from_secs(5), || pair.client.logs().contains("Dangerous mode enabled")),
        "the client must warn about dangerous mode:\n{}",
        pair.client.logs()
    );
}

/// The plaintext fallback is not silently used when TLS is configured (control for the cases above).
#[test]
fn tls_configured_server_does_not_answer_plaintext() {
    let (pair, _dir) = tls_pair("e2e_tls_no_plaintext", json!({ "cafile": ca_root("ca-a") }));

    let response = common::exchange(
        pair.server_addr,
        b"GET /t/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        Duration::from_secs(3),
    );
    assert!(
        std::str::from_utf8(&response).is_err() || !String::from_utf8_lossy(&response).contains("HTTP/1.1"),
        "a TLS listener must not answer a plaintext HTTP request: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(common::wait_tcp(pair.server_addr, DEFAULT_WAIT));
}

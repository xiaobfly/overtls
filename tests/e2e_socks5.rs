//! Links 1-3: SOCKS5 TCP, SOCKS5 UDP and HTTP proxy mode.
//!
//! Current behaviour (measured, see the audit findings SEC-04/SEC-05/COR-11): the server refuses
//! to open TCP connections to private destinations (`src/server.rs` `tcp_stream_from_s5_address`),
//! so a *loopback* target can never be reached through the TCP tunnel - not even inside the test
//! sandbox. The TCP cases therefore assert the client-side protocol behaviour together with the
//! server-side refusal, and the positive in-tunnel data path is covered by the UDP link (no
//! private-destination guard) and by the forward fallback (`tests/e2e_forward_fallback.rs`).

mod common;

use common::{
    HttpTarget, Pair, TcpEcho, client_config, free_port, http_target, poll_until, read_until_eof, server_config, socks5_connect,
    socks5_reply_succeeded, start_pair, tcp_echo_server, udp_associate, udp_echo_server, udp_recv, udp_send,
};
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::atomic::Ordering,
    time::Duration,
};

/// Build a plaintext server + client pair with an HTTP forward target for the fallback path.
fn pair(name: &str) -> (Pair, TcpEcho, HttpTarget) {
    let echo = tcp_echo_server();
    let http = http_target("HTTP-TARGET-BODY");
    let srv_port = free_port();
    let client_port = free_port();
    let server_value = server_config(
        srv_port,
        Some(&format!("http://{}", http.addr)),
        serde_json::json!({}),
        serde_json::json!({}),
    );
    let client_value = client_config(srv_port, client_port, serde_json::json!({}), serde_json::json!({}));
    let pair = start_pair(name, &server_value, &client_value, srv_port, client_port);
    (pair, echo, http)
}

/// SOCKS5 CONNECT to a loopback target: the client reports success before the tunnel exists
/// (COR-11) and the server refuses the private destination (SEC-05).
#[test]
fn socks5_tcp_to_loopback_denied_by_private_guard() {
    let (pair, echo, _http) = pair("e2e_socks5_tcp");

    let (mut stream, reply) = socks5_connect(pair.client_addr, echo.addr, Duration::from_secs(5)).expect("connect");
    // Current behaviour: the SOCKS5 reply is sent before the server confirms the session (COR-11).
    assert!(socks5_reply_succeeded(&reply), "expected a success reply, got {reply:x?}");

    // The tunnel is refused, so the payload never reaches the loopback echo server.
    let _ = stream.write_all(b"PING-TCP-TUNNEL");
    let echoed = read_until_eof(&mut stream, Duration::from_secs(2));
    assert!(!echoed.windows(15).any(|w| w == b"PING-TCP-TUNNEL"), "unexpected echo: {echoed:?}");
    assert_eq!(echo.connections.load(Ordering::SeqCst), 0, "loopback target must not be reached");

    assert!(
        poll_until(Duration::from_secs(5), || pair
            .server
            .logs()
            .contains("destination address is private, skipping")),
        "server log must report the refused private destination:\n{}",
        pair.server.logs()
    );
}

/// SOCKS5 UDP ASSOCIATE: the reply advertises `advertise_ip` and the tunnel relays both ways.
#[test]
fn socks5_udp_round_trip() {
    let (pair, _echo, _http) = pair("e2e_socks5_udp");
    let udp_echo = udp_echo_server();

    let (_control, relay) = udp_associate(pair.client_addr).expect("udp associate");
    assert_eq!(
        relay.ip().to_string(),
        "127.0.0.1",
        "UDP relay must advertise the configured advertise_ip"
    );

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    let payload = vec![0x5au8; 512];
    udp_send(&socket, relay, udp_echo.addr, &payload).expect("send udp");
    // Note: the reply header carries the caller's own relay-facing address, not the echo address
    // (the client re-headers every relayed datagram); only the payload identity is asserted here.
    let (from, echoed) = udp_recv(&socket, Duration::from_secs(5)).expect("udp reply");
    assert_eq!(
        from.ip().to_string(),
        "127.0.0.1",
        "reply header must stay on the advertised address"
    );
    assert_eq!(echoed, payload, "UDP payload must survive the tunnel");

    // A second datagram on the same association must still be relayed.
    udp_send(&socket, relay, udp_echo.addr, b"SECOND-DATAGRAM").expect("send udp");
    let (_, second) = udp_recv(&socket, Duration::from_secs(5)).expect("second udp reply");
    assert_eq!(second, b"SECOND-DATAGRAM");
    assert!(udp_echo.datagrams.load(Ordering::SeqCst) >= 2);
}

/// SOCKS4 traffic is detected and dropped with a warning.
#[test]
fn unsupported_socks4_first_byte_is_rejected() {
    let (pair, _echo, _http) = pair("e2e_socks5_socks4");

    let mut stream = TcpStream::connect(pair.client_addr).expect("connect client");
    stream.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    stream.write_all(&[0x04, 0x01, 0x00]).expect("write socks4 header");
    let mut buf = [0u8; 16];
    // The client only peeks at the first byte and then shuts the connection down while the 3 bytes
    // are still unread. Linux/macOS kernels answer that with a RST, so `read` may fail with
    // `ConnectionReset` instead of returning 0; `Err` = the peer aborted the close, which is
    // equivalent to "closed without any answer".
    let read = stream.read(&mut buf).unwrap_or(0);
    assert_eq!(read, 0, "no SOCKS4 reply is expected");
    // Note: future 0x00/unknown-first-byte cases need the same `Err => 0` treatment.
    assert!(
        poll_until(Duration::from_secs(5), || pair.client.logs().contains("socks4 client detected")),
        "client log must report the SOCKS4 first byte:\n{}",
        pair.client.logs()
    );
}

/// HTTP proxy mode, CONNECT: the proxy answers 200 before the tunnel is confirmed, then goes
/// silent, because the loopback destination is refused by the server (SEC-05).
#[test]
fn http_proxy_connect_loopback_is_refused() {
    let (pair, echo, _http) = pair("e2e_socks5_http_connect");

    let mut stream = TcpStream::connect(pair.client_addr).expect("connect client");
    stream.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", echo.addr, echo.addr);
    stream.write_all(request.as_bytes()).expect("write CONNECT");
    let mut response = Vec::new();
    let mut chunk = [0u8; 512];
    while !response.windows(4).any(|w| w == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).expect("read CONNECT reply");
        assert!(read > 0, "expected a CONNECT reply, got {response:?}");
        response.extend_from_slice(&chunk[..read]);
    }
    let head = String::from_utf8_lossy(&response).to_string();
    assert!(head.starts_with("HTTP/1.1 200"), "expected 200 from the HTTP proxy, got: {head}");

    // The tunnel is refused, so the payload is dropped instead of echoed back.
    let _ = stream.write_all(b"PING-HTTP-TUNNEL");
    let echoed = read_until_eof(&mut stream, Duration::from_secs(2));
    assert!(!echoed.windows(16).any(|w| w == b"PING-HTTP-TUNNEL"), "unexpected echo: {echoed:?}");
    assert_eq!(echo.connections.load(Ordering::SeqCst), 0, "loopback target must not be reached");
}

/// HTTP proxy mode, absolute-form GET: the client derives the tunnel destination from the absolute
/// URI (the server logs the refusal for exactly that address), but the loopback destination is
/// refused, so no HTTP response ever reaches the caller.
#[test]
fn http_proxy_absolute_form_get_is_refused_for_loopback() {
    let (pair, _echo, http) = pair("e2e_socks5_http_absolute");

    let mut stream = TcpStream::connect(pair.client_addr).expect("connect client");
    stream.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let request = format!(
        "GET http://{}/ HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        http.addr, http.addr
    );
    stream.write_all(request.as_bytes()).expect("write absolute-form GET");
    let response = read_until_eof(&mut stream, Duration::from_secs(3));
    assert!(
        !response.windows(16).any(|w| w == b"HTTP-TARGET-BODY"),
        "the forwarded body must not be reachable, got: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        http.requests.lock().expect("http lock").is_empty(),
        "the target must not be contacted directly"
    );

    // Evidence that the absolute URI was turned into a tunnel request for the same destination.
    let expected = format!("<> {} destination address is private, skipping", http.addr);
    assert!(
        poll_until(Duration::from_secs(5), || pair.server.logs().contains(&expected)),
        "server log must report the refused destination {expected}:\n{}",
        pair.server.logs()
    );
}

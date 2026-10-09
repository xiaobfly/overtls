//! Regression tests for the UDP relay surface.
//!
//! Findings: SEC-04 (the UDP tunnel has no destination filter at all, so a plain unauthenticated
//! WebSocket session can reach loopback/RFC1918 - unlike the TCP side), SEC-13 (a single malformed
//! binary frame kills the whole UDP tunnel, on the server *and* on the client's UDP loop), COR-04
//! (a fragmented SOCKS5 UDP datagram terminates the whole association and payloads above ~1238
//! bytes are silently dropped), COR-05 (a malformed DNS payload to port 53 kills the client's UDP
//! loop in either direction), COR-06 (trailing bytes are treated as payload, an oversized datagram
//! terminates the tunnel).
//!
//! Every assertion describes the *current* behavior and must be flipped when the finding is fixed.

mod common;

use common::{
    DEFAULT_WAIT, Pair, UdpEcho, client_config, free_port, poll_until, server_config, socks5_addr_v4, spawn_role, tcp_echo_server,
    udp_associate, udp_echo_server, udp_recv, udp_send, udp_send_frag, wait_tcp, work_dir, write_json, ws, ws_accept_key,
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Build the server-side UDP framing: `Address(dst) + Address(src) + payload`.
fn udp_frame(dst: SocketAddr, src: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut frame = socks5_addr_v4(dst);
    frame.extend_from_slice(&socks5_addr_v4(src));
    frame.extend_from_slice(payload);
    frame
}

/// Split a UDP frame into `(dst, src, payload)`.
fn parse_udp_frame(frame: &[u8]) -> (SocketAddr, SocketAddr, Vec<u8>) {
    fn take(frame: &[u8]) -> (SocketAddr, usize) {
        assert!(frame.len() >= 7, "short address in frame: {frame:x?}");
        assert_eq!(frame[0], 0x01, "only IPv4 framing is used by these cases");
        let ip = Ipv4Addr::new(frame[1], frame[2], frame[3], frame[4]);
        (SocketAddr::new(IpAddr::V4(ip), u16::from_be_bytes([frame[5], frame[6]])), 7)
    }
    let (dst, dlen) = take(frame);
    let (src, slen) = take(&frame[dlen..]);
    (dst, src, frame[dlen + slen..].to_vec())
}

/// Last few lines of captured output, for assertion messages.
fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

fn start_server(name: &str) -> (common::Proc, SocketAddr, PathBuf) {
    let port = free_port();
    let value = server_config(port, None, json!({}), json!({}));
    let dir = work_dir(name);
    let cfg = write_json(&dir, "server.json", &value);
    let proc = spawn_role("server", &cfg, &["-v", "trace"], &dir);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(wait_tcp(addr, DEFAULT_WAIT), "server did not start: {}", proc.logs());
    (proc, addr, cfg)
}

fn udp_client_pair(name: &str) -> (Pair, UdpEcho) {
    let echo = udp_echo_server();
    let port = free_port();
    let client_port = free_port();
    let server_value = server_config(port, None, json!({}), json!({}));
    let client_value = client_config(port, client_port, json!({}), json!({}));
    let pair = common::start_pair(name, &server_value, &client_value, port, client_port);
    (pair, echo)
}

/// SEC-04: a WebSocket session with only the tunnel path (no credentials, no client id) can send
/// UDP datagrams to loopback - the TCP tunnel refuses the very same destination.
#[test]
fn udp_loopback_ssrf_without_credentials() {
    let (proc, addr, _cfg) = start_server("audit_udp_ssrf");
    let echo = udp_echo_server();

    let mut handshake = ws::Handshake::new("/t/", "127.0.0.1");
    handshake.udp_tunnel = true;
    let (mut socket, header) = ws::Ws::connect(addr, &handshake).expect("ws handshake");
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");

    let src = SocketAddr::from(([127, 0, 0, 1], common::free_udp_port()));
    socket
        .send_binary(&udp_frame(echo.addr, src, b"SSRF-LOOPBACK"))
        .expect("send datagram");
    let (opcode, frame) = socket.recv_frame(Duration::from_secs(5)).expect("udp reply frame");
    assert_eq!(opcode, ws::OPCODE_BINARY, "UDP replies must be binary frames");
    let (reply_dst, reply_src, payload) = parse_udp_frame(&frame);
    assert_eq!(payload, b"SSRF-LOOPBACK", "the loopback datagram must be relayed back");
    assert_eq!(reply_dst, src, "the reply must be addressed to the claimed source");
    assert_eq!(reply_src, echo.addr, "the reply must come from the loopback destination");
    assert!(proc.logs().contains("[UDP]"), "the UDP tunnel must be active:\n{}", proc.logs());
}

/// COR-06: an oversized payload in a *well-formed* frame terminates the tunnel.
#[test]
fn udp_oversized_ws_frame_terminates_tunnel() {
    let (proc, addr, _cfg) = start_server("audit_udp_oversized");
    let echo = udp_echo_server();

    let mut handshake = ws::Handshake::new("/t/", "127.0.0.1");
    handshake.udp_tunnel = true;
    let (mut socket, header) = ws::Ws::connect(addr, &handshake).expect("ws handshake");
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");

    let src = SocketAddr::from(([127, 0, 0, 1], common::free_udp_port()));
    let payload = vec![0x61u8; 65536];
    socket.send_binary(&udp_frame(echo.addr, src, &payload)).expect("send datagram");

    // Current behavior: the send error is propagated with `?` and the whole tunnel dies.
    let closed = poll_until(Duration::from_secs(3), || {
        let _ = socket.recv_frame(Duration::from_millis(200));
        socket.is_closed()
    });
    assert!(
        closed,
        "the UDP tunnel must be terminated by the oversized datagram:\n{}",
        proc.logs()
    );
    let _ = socket.send_binary(&udp_frame(echo.addr, src, b"AFTER"));
    assert!(
        socket.read_until_eof(Duration::from_secs(1)).is_empty(),
        "no further datagram may be relayed"
    );
    assert!(
        poll_until(Duration::from_secs(3), || proc.logs().contains("[UDP] 127.0.0.1")
            && proc.logs().contains("closed with error")),
        "the tunnel error must be logged:\n{}",
        tail(&proc.logs(), 10)
    );
}

/// SEC-13: a truncated address in a binary frame terminates the tunnel just the same.
#[test]
fn udp_truncated_frame_terminates_tunnel() {
    let (proc, addr, _cfg) = start_server("audit_udp_truncated");

    let mut handshake = ws::Handshake::new("/t/", "127.0.0.1");
    handshake.udp_tunnel = true;
    let (mut socket, header) = ws::Ws::connect(addr, &handshake).expect("ws handshake");
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");

    socket.send_binary(&[0x01, 0x7f]).expect("send truncated frame");
    let closed = poll_until(Duration::from_secs(3), || {
        let _ = socket.recv_frame(Duration::from_millis(200));
        socket.is_closed()
    });
    assert!(closed, "a malformed frame must terminate the tunnel:\n{}", tail(&proc.logs(), 10));
    assert!(
        poll_until(Duration::from_secs(3), || proc.logs().contains("closed with error")),
        "the parse failure must be logged:\n{}",
        tail(&proc.logs(), 10)
    );
}

/// COR-04: a SOCKS5 UDP datagram with the FRAG bit set tears down the whole association.
#[test]
fn udp_fragment_kills_association() {
    let (pair, echo) = udp_client_pair("audit_udp_fragment");

    let (mut control, relay) = udp_associate(pair.client_addr).expect("udp associate");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    udp_send(&socket, relay, echo.addr, b"BEFORE-FRAGMENT").expect("send udp");
    assert!(
        udp_recv(&socket, Duration::from_secs(5)).is_some(),
        "the association must work first"
    );

    // Current behavior: FRAG != 0 breaks out of the relay loop and closes the association for all
    // applications instead of dropping the single datagram.
    udp_send_frag(&socket, relay, echo.addr, 1, b"FRAGMENTED").expect("send fragmented udp");
    let mut buf = [0u8; 16];
    let closed = poll_until(Duration::from_secs(5), || {
        use std::io::Read;
        control.set_nonblocking(true).expect("nonblocking");
        matches!(control.read(&mut buf), Ok(0))
    });
    assert!(
        closed,
        "the control connection must be closed by the relay:\n{}",
        pair.client.logs()
    );
    assert!(
        pair.client.logs().contains("packet fragment is not supported"),
        "the fragment must be reported:\n{}",
        pair.client.logs()
    );
    udp_send(&socket, relay, echo.addr, b"AFTER-FRAGMENT").expect("send udp");
    assert!(udp_recv(&socket, Duration::from_secs(2)).is_none(), "the association must be gone");
}

/// COR-04: SOCKS5 UDP payloads above the internal 1238 byte buffer are never relayed intact.
///
/// Platform note (measured on Windows, derived from the vendored code for unix): with a 1238 byte
/// receive buffer a 1400 byte request cannot be satisfied - Windows fails the `recv` with
/// `WSAEMSGSIZE` (os error 10040) which tears the whole association down, while unix sockets
/// truncate silently and the packet is discarded after the header parse. The cross-platform
/// invariant that is asserted here is that the oversized datagram never comes back intact.
#[test]
fn udp_payload_above_buffer_limit_never_relayed_intact() {
    let (pair, echo) = udp_client_pair("audit_udp_oversized_payload");

    let (_control, relay) = udp_associate(pair.client_addr).expect("udp associate");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp client");

    let oversized = vec![0x42u8; 1400];
    let mut reply = None;
    let intact = poll_until(Duration::from_secs(3), || {
        udp_send(&socket, relay, echo.addr, &oversized).expect("send udp");
        reply = udp_recv(&socket, Duration::from_millis(500));
        matches!(&reply, Some((_, payload)) if payload.len() >= oversized.len())
    });
    assert!(
        !intact,
        "the oversized datagram must not be echoed intact: {:?}\n{}",
        reply.as_ref().map(|(_, payload)| payload.len()),
        tail(&pair.client.logs(), 12)
    );

    #[cfg(windows)]
    {
        // Measured on Windows: the receive error tears the association down (session ends with
        // "os error 10040"), so no further datagram of this association is relayed.
        assert!(
            poll_until(Duration::from_secs(3), || pair.client.logs().contains("os error 10040")),
            "the oversized datagram must surface as a socket error:\n{}",
            tail(&pair.client.logs(), 12)
        );
    }
}

/// COR-05: one malformed payload aimed at port 53 kills the client's UDP loop; the watchdog brings
/// it back about a second later.
#[test]
fn malformed_dns_payload_kills_client_udp_loop() {
    let (pair, echo) = udp_client_pair("audit_udp_dns");

    let (_control, relay) = udp_associate(pair.client_addr).expect("udp associate");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    assert!(
        poll_until(Duration::from_secs(5), || {
            udp_send(&socket, relay, echo.addr, b"WARMUP").expect("send udp");
            matches!(udp_recv(&socket, Duration::from_millis(500)), Some((_, payload)) if payload == b"WARMUP")
        }),
        "the tunnel must work before the malformed datagram:\n{}",
        pair.client.logs()
    );

    // A non-DNS payload to port 53 fails `parse_data_to_dns_message` inside the client's UDP loop.
    let dns_port = SocketAddr::from(([127, 0, 0, 1], 53));
    udp_send(&socket, relay, dns_port, b"NOT-A-DNS-MESSAGE").expect("send udp");

    // Current behavior: the whole loop dies, so the next datagram is not relayed for a while.
    std::thread::sleep(Duration::from_millis(200));
    udp_send(&socket, relay, echo.addr, b"RIGHT-AFTER").expect("send udp");
    let immediate = udp_recv(&socket, Duration::from_millis(500));
    assert!(
        immediate.is_none(),
        "the UDP loop must be interrupted by the malformed DNS payload, got {immediate:?}\n{}",
        pair.client.logs()
    );

    // The watchdog restarts the loop (fixed one second delay, no backoff) and service resumes.
    let recovered = poll_until(Duration::from_secs(10), || {
        udp_send(&socket, relay, echo.addr, b"RECOVERED").expect("send udp");
        matches!(udp_recv(&socket, Duration::from_millis(500)), Some((_, payload)) if payload == b"RECOVERED")
    });
    assert!(recovered, "the watchdog must restart the UDP loop:\n{}", pair.client.logs());
}

/// The legacy TCP tunnel refuses the loopback destination used by the UDP cases above, which is the
/// A/B counterpart of SEC-04.
#[test]
fn tcp_tunnel_refuses_the_same_loopback_destination() {
    let (pair, _echo) = udp_client_pair("audit_udp_tcp_ab");
    let tcp_target = tcp_echo_server();

    let (_stream, reply) = common::socks5_connect(pair.client_addr, tcp_target.addr, Duration::from_secs(5)).expect("connect");
    assert!(common::socks5_reply_succeeded(&reply), "reply: {reply:x?}");
    assert!(
        poll_until(Duration::from_secs(5), || pair
            .server
            .logs()
            .contains("destination address is private, skipping")),
        "the TCP side must refuse the same destination:\n{}",
        pair.server.logs()
    );
    assert_eq!(
        tcp_target.connections.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the loopback TCP target must not be reached"
    );
}

// ---------------------------------------------------------------------------------------------
// client lane: malformed frames arriving *from* the server
// ---------------------------------------------------------------------------------------------

/// One upgrade request the fake server received.
struct Upgrade {
    at: Instant,
    udp_tunnel: bool,
    request_line: String,
}

/// A loopback listener that plays the server side of the client's WebSocket upgrade by hand.
///
/// Every accepted connection is answered with `101`; the client's startup `check_correctness`
/// probe connects and closes without writing, and its UDP relay connection announces
/// `UDP-Tunnel: true`. On the *first* UDP-tunnel handshake the listener pushes `frame` 300ms after
/// the response: the delay keeps the frame out of the read carrying the `101`, because the client
/// discards bytes that share that read (SEC-12, `create_ws_stream` does a single `read_buf`). The
/// connection is then held open until the client closes it, so any further handshake can only come
/// from the client's own UDP relay loop dying and its watchdog reconnecting it.
///
/// Current behavior (SEC-13 client lane / COR-05 inbound): `_run_udp_loop` propagates the parse
/// failure with `?`, so one malformed frame ends the whole loop, and `udp_handler_watchdog`
/// restarts it after a fixed one-second sleep without any backoff. Post-fix expectation: the
/// malformed frame is dropped (and counted), the loop survives and no second handshake appears.
struct FakeUpgradeServer {
    addr: SocketAddr,
    upgrades: Arc<Mutex<Vec<Upgrade>>>,
}

impl FakeUpgradeServer {
    /// Start the listener; `frame` is pushed at the first `UDP-Tunnel: true` handshake.
    fn start(frame: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake upgrade server");
        let addr = listener.local_addr().expect("fake upgrade server addr");
        let upgrades: Arc<Mutex<Vec<Upgrade>>> = Arc::new(Mutex::new(Vec::new()));
        let accepted = upgrades.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let upgrades = accepted.clone();
                let frame = frame.clone();
                std::thread::spawn(move || handle_upgrade(stream, frame, upgrades));
            }
        });
        Self { addr, upgrades }
    }

    /// `(arrival instant, request line)` of every `UDP-Tunnel: true` handshake, in arrival order.
    fn udp_upgrades(&self) -> Vec<(Instant, String)> {
        self.upgrades
            .lock()
            .expect("upgrade lock")
            .iter()
            .filter(|upgrade| upgrade.udp_tunnel)
            .map(|upgrade| (upgrade.at, upgrade.request_line.clone()))
            .collect()
    }
}

/// Answer one upgrade request with `101`, then hold the connection open; the first UDP-tunnel
/// handshake additionally receives `frame` 300ms later.
fn handle_upgrade(mut stream: TcpStream, frame: Vec<u8>, upgrades: Arc<Mutex<Vec<Upgrade>>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("fake server read timeout");
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            // The startup `check_correctness` probe connects and closes without writing.
            Ok(0) | Err(_) => return,
            Ok(read) => request.extend_from_slice(&chunk[..read]),
        }
        if request.len() > 64 * 1024 {
            return;
        }
    }

    let head = String::from_utf8_lossy(&request).to_string();
    let udp_tunnel = head.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(name, value)| name.eq_ignore_ascii_case("udp-tunnel") && value.trim().eq_ignore_ascii_case("true"))
    });
    let Some(key) = head.lines().find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-key"))
            .map(|(_, value)| value.trim().to_string())
    }) else {
        return;
    };

    let request_line = head.lines().next().unwrap_or_default().to_string();
    let first_udp = {
        let mut guard = upgrades.lock().expect("upgrade lock");
        let first = udp_tunnel && !guard.iter().any(|upgrade| upgrade.udp_tunnel);
        guard.push(Upgrade {
            at: Instant::now(),
            udp_tunnel,
            request_line,
        });
        first
    };

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        ws_accept_key(&key)
    );
    if stream.write_all(response.as_bytes()).is_err() {
        return;
    }

    if first_udp {
        // SEC-12: bytes sharing the read with the handshake response are dropped, so the malformed
        // frame has to arrive in a later read.
        std::thread::sleep(Duration::from_millis(300));
        if stream.write_all(&frame).is_err() {
            return;
        }
    }

    // Hold the connection open and drain whatever the client sends (it pings every 30s); a read
    // timeout is not a disconnect.
    let mut sink = [0u8; 1024];
    loop {
        match stream.read(&mut sink) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if is_timeout(&error) => {}
            Err(_) => break,
        }
    }
}

/// A socket read timeout surfaces as `WouldBlock` or `TimedOut` depending on the platform.
fn is_timeout(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// An unmasked server-to-client Binary frame (the payload must fit the 7-bit length form).
fn server_binary_frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126, "the test frame must fit the 7-bit length form");
    let mut frame = vec![0x82, payload.len() as u8];
    frame.extend_from_slice(payload);
    frame
}

/// Spawn the real client against a fake WebSocket server that pushes `frame` at the first UDP
/// tunnel handshake.
fn client_with_malformed_server_frame(name: &str, frame: Vec<u8>) -> (FakeUpgradeServer, common::Proc) {
    let fake = FakeUpgradeServer::start(frame);
    let client_port = free_port();
    let dir = work_dir(name);
    let config = client_config(fake.addr.port(), client_port, json!({}), json!({}));
    let cfg = write_json(&dir, "client.json", &config);
    let client = spawn_role("client", &cfg, &["-v", "trace"], &dir);
    let client_addr = SocketAddr::from(([127, 0, 0, 1], client_port));
    assert!(wait_tcp(client_addr, DEFAULT_WAIT), "client did not start: {}", client.logs());
    (fake, client)
}

/// Wait for the watchdog's replacement handshake and return the interval between both handshakes.
///
/// The watchdog reconnects forever, so the assertion is "a second handshake arrives within 5s"
/// (never "no further handshake"); the one-second sleep it inserts bounds the interval from below.
fn assert_udp_loop_restarted(fake: &FakeUpgradeServer, client: &common::Proc) -> Duration {
    let restarted = poll_until(Duration::from_secs(5), || fake.udp_upgrades().len() >= 2);
    let upgrades = fake.udp_upgrades();
    assert!(
        restarted,
        "a malformed server frame must end the client's UDP loop so the watchdog reconnects it within 5s; UDP handshakes seen: {}\nclient log:\n{}",
        upgrades.len(),
        tail(&client.logs(), 20)
    );
    let interval = upgrades[1].0.saturating_duration_since(upgrades[0].0);
    assert!(
        interval >= Duration::from_secs(1),
        "the watchdog restart must wait for its fixed one-second sleep; handshake interval {interval:?} for {:?}\nclient log:\n{}",
        upgrades.iter().map(|upgrade| &upgrade.1).collect::<Vec<_>>(),
        tail(&client.logs(), 20)
    );
    interval
}

/// SEC-13 (client lane): a single truncated address in a Binary frame from the server kills the
/// client's whole UDP relay loop; only the fixed one-second watchdog restart brings it back.
///
/// Post-fix expectation: the frame is dropped (and counted), the loop survives and the fake server
/// sees exactly one UDP handshake.
#[test]
fn client_udp_loop_dies_on_truncated_server_frame() {
    // `0x01` is the IPv4 ATYP without any address bytes: `decode_udp_packet` fails on it.
    let (fake, client) = client_with_malformed_server_frame("audit_udp_client_truncated", server_binary_frame(&[0x01]));
    let interval = assert_udp_loop_restarted(&fake, &client);
    println!(
        "truncated frame: {} UDP handshake(s), watchdog restart interval {interval:?}",
        fake.udp_upgrades().len()
    );
}

/// COR-05 (server -> client direction): a well-formed frame whose `remote_addr` is port 53 with a
/// non-DNS payload kills the client's UDP loop exactly like the outbound datagram does.
///
/// Post-fix expectation: the payload is only parsed as DNS when the tunnel actually waits for that
/// answer (or the parse failure is contained); the loop survives and no second handshake appears.
#[test]
fn client_udp_loop_dies_on_malformed_dns_server_frame() {
    let incoming = SocketAddr::from(([127, 0, 0, 1], common::free_udp_port()));
    let remote_dns = SocketAddr::from(([127, 0, 0, 1], 53));
    // Server -> client framing: `Address(incoming) + Address(remote) + payload`; the port-53 check
    // is on the second address.
    let frame = server_binary_frame(&udp_frame(incoming, remote_dns, b"NOT-A-DNS-MESSAGE"));
    let (fake, client) = client_with_malformed_server_frame("audit_udp_client_dns", frame);
    let interval = assert_udp_loop_restarted(&fake, &client);
    println!(
        "malformed dns frame: {} UDP handshake(s), watchdog restart interval {interval:?}",
        fake.udp_upgrades().len()
    );
}

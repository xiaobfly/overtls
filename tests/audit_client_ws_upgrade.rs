//! SEC-10 / SEC-12 client-side regression tests against a hand-written WebSocket upgrade server.
//!
//! 回归：审计发现 SEC-10（客户端升级请求头与真实浏览器显著不同，`src/weirduri.rs:62-87`）与
//! SEC-12（客户端只比对 `Sec-WebSocket-Accept`，不校验状态码/`Upgrade`/`Connection`，且与握手
//! 响应同一批到达的字节被单次 `read_buf` 静默丢弃，`src/client.rs:563-575`）。断言描述的是
//! **当前行为**；发现修复后必须翻转断言（每条断言前都给出了修复后的期望值）。
//!
//! Each case spawns the real `overtls-bin` client against a plain TCP listener that plays the
//! server side of the WebSocket upgrade by hand (mode `Reject` / `FrameInSameRead` / `FrameLater`).
//! A local SOCKS5 CONNECT makes the client acquire a pooled WebSocket connection and start a
//! session; the SOCKS5 reply itself is never asserted. The client also opens a UDP relay WebSocket
//! connection at startup (its request carries `UDP-Tunnel: true`); that connection is answered with
//! a plain `101` in every mode.

mod common;

use common::ws::{OPCODE_PING, OPCODE_TEXT};
use common::{
    DEFAULT_WAIT, Proc, client_config, free_port, poll_until, read_until_eof, socks5_connect, spawn_role, wait_tcp, work_dir, write_json,
    ws_accept_key,
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};

/// Payload of the server Binary frame the fake upgrade server pushes after the handshake.
const FRAME_PAYLOAD: &[u8] = b"SEPARATE-FRAME";

/// Response mode of the fake upgrade server.
#[derive(Clone, Copy)]
enum Mode {
    /// `200 OK` and a correct `Sec-WebSocket-Accept`, but neither `Upgrade` nor `Connection`.
    Reject,
    /// `101` response and the server Binary frame in one single `write_all`.
    FrameInSameRead,
    /// `101` response, then the same server Binary frame 300ms later.
    FrameLater,
}

/// Everything recorded for one accepted connection.
struct Capture {
    /// Raw upgrade request bytes.
    request: Vec<u8>,
    /// Whether the request carried `UDP-Tunnel: true` (the client's relay connection does).
    udp_tunnel: bool,
    /// Frames the client sent, in arrival order.
    frames: Mutex<Vec<(u8, Vec<u8>)>>,
}

/// A loopback listener that plays the server side of the WebSocket upgrade by hand.
struct FakeUpgrade {
    addr: SocketAddr,
    captures: Arc<Mutex<Vec<Arc<Capture>>>>,
}

impl FakeUpgrade {
    /// Start the fake server in `mode`; every accepted connection gets its own thread.
    fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake upgrade server");
        let addr = listener.local_addr().expect("fake upgrade server addr");
        let captures: Arc<Mutex<Vec<Arc<Capture>>>> = Arc::new(Mutex::new(Vec::new()));
        let accepted = captures.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let captures = accepted.clone();
                std::thread::spawn(move || handle_connection(stream, mode, captures));
            }
        });
        Self { addr, captures }
    }

    /// Snapshot of all captures so far.
    fn captures(&self) -> Vec<Arc<Capture>> {
        self.captures.lock().expect("captures lock").clone()
    }

    /// Raw upgrade request of the first connection that did not carry `UDP-Tunnel: true`.
    fn session_request(&self) -> Option<Vec<u8>> {
        self.captures()
            .iter()
            .find(|capture| !capture.udp_tunnel)
            .map(|capture| capture.request.clone())
    }

    /// First frame the client sent on a non-UDP connection.
    fn first_session_frame(&self) -> Option<(u8, Vec<u8>)> {
        self.captures()
            .iter()
            .filter(|capture| !capture.udp_tunnel)
            .find_map(|capture| capture.frames.lock().expect("frames lock").first().cloned())
    }

    /// Text dump of every capture so far, for assertion messages.
    fn dump(&self) -> String {
        let mut lines = Vec::new();
        for (index, capture) in self.captures().iter().enumerate() {
            let udp = capture.udp_tunnel;
            let request = String::from_utf8_lossy(&capture.request);
            let frames = capture.frames.lock().expect("frames lock").clone();
            lines.push(format!(
                "connection #{index} udp_tunnel={udp} request={request:?} frames={frames:?}"
            ));
        }
        lines.join("\n")
    }
}

/// Answer one upgrade request according to `mode`, then keep recording the client's frames.
fn handle_connection(mut stream: TcpStream, mode: Mode, captures: Arc<Mutex<Vec<Arc<Capture>>>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("fake server read timeout");
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            // The client's startup `check_correctness` probe connects and closes without writing.
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

    let capture = Arc::new(Capture {
        request,
        udp_tunnel,
        frames: Mutex::new(Vec::new()),
    });
    captures.lock().expect("captures lock").push(capture.clone());

    if udp_tunnel {
        // The client's UDP relay connection: a plain `101` in every mode keeps it established.
        let _ = stream.write_all(upgrade_response(&key).as_bytes());
    } else {
        match mode {
            // SEC-12: `200 OK`, no `Upgrade`/`Connection`, but a correct accept key.
            Mode::Reject => {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nSec-WebSocket-Accept: {}\r\nContent-Length: 0\r\n\r\n",
                    ws_accept_key(&key)
                );
                let _ = stream.write_all(response.as_bytes());
            }
            // SEC-12: the response and a server frame share one TCP read on the client side.
            Mode::FrameInSameRead => {
                let mut bytes = upgrade_response(&key).into_bytes();
                bytes.extend_from_slice(&server_binary_frame(FRAME_PAYLOAD));
                let _ = stream.write_all(&bytes);
            }
            Mode::FrameLater => {
                let _ = stream.write_all(upgrade_response(&key).as_bytes());
                std::thread::sleep(Duration::from_millis(300));
                let _ = stream.write_all(&server_binary_frame(FRAME_PAYLOAD));
            }
        }
    }

    record_frames(stream, capture);
}

/// The plain `101 Switching Protocols` response used by the frame modes.
fn upgrade_response(key: &str) -> String {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        ws_accept_key(key)
    )
}

/// Read frames until the peer closes; answers WebSocket Pings with Pongs and keeps the socket open
/// across read timeouts.
fn record_frames(mut stream: TcpStream, capture: Arc<Capture>) {
    loop {
        match read_client_frame(&mut stream, Duration::from_secs(2)) {
            Ok(Some((opcode, payload))) => {
                let ping = opcode == OPCODE_PING;
                capture.frames.lock().expect("frames lock").push((opcode, payload));
                if ping {
                    let _ = stream.write_all(&[0x8a, 0x00]);
                }
            }
            Ok(None) => {} // read timeout, keep waiting for the client
            Err(_) => break,
        }
    }
}

/// Parse one (masked) client frame; `Ok(None)` on read timeout, `Err` once the peer is gone.
fn read_client_frame(stream: &mut TcpStream, timeout: Duration) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    stream.set_read_timeout(Some(timeout))?;
    let mut head = [0u8; 2];
    match stream.read_exact(&mut head) {
        Ok(()) => {}
        Err(error) if is_timeout(&error) => return Ok(None),
        Err(error) => return Err(error),
    }
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    let length = match head[1] & 0x7f {
        126 => {
            let mut extended = [0u8; 2];
            stream.read_exact(&mut extended)?;
            u16::from_be_bytes(extended) as usize
        }
        127 => {
            let mut extended = [0u8; 8];
            stream.read_exact(&mut extended)?;
            u64::from_be_bytes(extended) as usize
        }
        short => short as usize,
    };
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask)?;
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok(Some((opcode, payload)))
}

/// A socket read timeout surfaces as `WouldBlock` or `TimedOut` depending on the platform.
fn is_timeout(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// An unmasked server-to-client Binary frame (the payload fits the 7-bit length form).
fn server_binary_frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126, "the test frame must fit the 7-bit length form");
    let mut frame = vec![0x82, payload.len() as u8];
    frame.extend_from_slice(payload);
    frame
}

/// Spawn a client pointed at the fake server and drive one local SOCKS5 CONNECT.
///
/// The CONNECT target is a closed loopback port; the reply is not asserted (the client answers
/// Succeeded before any confirmation). The request only exists to make the client acquire a pooled
/// WebSocket connection and send `Start session` on it.
fn start_session(mode: Mode, name: &str) -> (TcpStream, FakeUpgrade, Proc) {
    let fake = FakeUpgrade::start(mode);
    let client_port = free_port();
    let client_addr: SocketAddr = format!("127.0.0.1:{client_port}").parse().expect("client addr");
    let dir = work_dir(name);
    let config = client_config(fake.addr.port(), client_port, json!({}), json!({}));
    let config_path = write_json(&dir, "client.json", &config);
    let client = spawn_role("client", &config_path, &["-v", "debug"], &dir);
    assert!(
        wait_tcp(client_addr, DEFAULT_WAIT),
        "client must listen on {client_addr}:\n{}",
        client.logs()
    );

    let target: SocketAddr = "127.0.0.1:9".parse().expect("closed target addr");
    let (local, _reply) = socks5_connect(client_addr, target, Duration::from_secs(5)).expect("local SOCKS5 CONNECT");
    (local, fake, client)
}

/// SEC-12: the client accepts `200 OK` without `Upgrade`/`Connection` and starts a session on it.
#[test]
fn ignores_status_and_upgrade_headers() {
    let (_local, fake, client) = start_session(Mode::Reject, "audit_client_ws_upgrade_reject");

    let started = poll_until(Duration::from_secs(2), || {
        fake.first_session_frame()
            .is_some_and(|(opcode, payload)| opcode == OPCODE_TEXT && payload.starts_with(b"Start session:"))
    });
    // Post-fix expectation: the upgrade is rejected (no `Start session:` frame is ever sent and the
    // local SOCKS5 session fails) because status 101 / `Upgrade` / `Connection` are validated.
    assert!(
        started,
        "expected `Start session:` on the connection answered with `200 OK` (SEC-12);\ncaptures:\n{}\nclient log:\n{}",
        fake.dump(),
        client.logs()
    );
}

/// SEC-10: the upgrade request carries only the minimal header set, no browser markers.
#[test]
fn handshake_headers_lack_browser_markers() {
    let (_local, fake, client) = start_session(Mode::Reject, "audit_client_ws_upgrade_headers");

    let request = fake.session_request().unwrap_or_else(|| {
        panic!(
            "no non-UDP upgrade request captured:\n{}\nclient log:\n{}",
            fake.dump(),
            client.logs()
        )
    });
    let head = String::from_utf8_lossy(&request).to_string();
    assert!(head.starts_with("GET /t/ HTTP/1.1\r\n"), "unexpected request line:\n{head}");

    // Current behaviour (SEC-10): exactly these five headers, fixed order, `Host` without a port.
    // Post-fix expectation: the fixed client mimics a real browser handshake (header set + order).
    for line in [
        "Host: 127.0.0.1",
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
    ] {
        assert!(head.lines().any(|candidate| candidate == line), "missing `{line}` in:\n{head}");
    }
    assert!(
        head.lines().any(|candidate| candidate.starts_with("Sec-WebSocket-Key: ")),
        "missing key header in:\n{head}"
    );

    let lower = head.to_ascii_lowercase();
    // Current behaviour (SEC-10): none of these browser markers is sent.
    // Post-fix expectation: at least `User-Agent` and `Origin` must appear in the fixed handshake.
    for marker in ["user-agent:", "origin:", "sec-websocket-extensions:", "accept-language:"] {
        assert!(!lower.contains(marker), "unexpected browser marker `{marker}` in:\n{head}");
    }
}

/// SEC-12: a server frame sharing the read with the `101` response is discarded; a frame arriving
/// in a later read is delivered (the control case).
#[test]
fn trailing_bytes_dropped_single_read() {
    // Pass A: response + frame written by the fake server in one buffer.
    let (mut local_same, fake_same, client_same) = start_session(Mode::FrameInSameRead, "audit_client_ws_upgrade_same_read");
    let early = read_until_eof(&mut local_same, Duration::from_secs(1));
    // Post-fix expectation: the trailing bytes must survive the handshake read, so this read
    // receives `SEPARATE-FRAME` instead of nothing.
    assert!(
        early.is_empty(),
        "expected the frame sharing the handshake read to be dropped (SEC-12), got {:?};\ncaptures:\n{}\nclient log:\n{}",
        String::from_utf8_lossy(&early),
        fake_same.dump(),
        client_same.logs()
    );

    // Control: the session really was established on this connection (the client sent its
    // `Start session:` frame), so the empty read above means the frame was dropped, not that no
    // session existed.
    let started = poll_until(Duration::from_secs(2), || {
        fake_same
            .first_session_frame()
            .is_some_and(|(opcode, payload)| opcode == OPCODE_TEXT && payload.starts_with(b"Start session:"))
    });
    assert!(
        started,
        "expected the client to start a session on the connection that shared the read (SEC-12);\ncaptures:\n{}\nclient log:\n{}",
        fake_same.dump(),
        client_same.logs()
    );

    // Pass B: the same frame in a later read (fresh fake server and client).
    let (mut local_later, fake_later, client_later) = start_session(Mode::FrameLater, "audit_client_ws_upgrade_later_frame");
    let late = read_until_eof(&mut local_later, Duration::from_secs(2));
    // Current behaviour is correct here; this is the control showing the frame does reach the
    // session when it does not share the read with the response.
    assert_eq!(
        late.as_slice(),
        FRAME_PAYLOAD,
        "expected {:?} on the local connection when the frame arrives in a later read, got {:?};\ncaptures:\n{}\nclient log:\n{}",
        String::from_utf8_lossy(FRAME_PAYLOAD),
        String::from_utf8_lossy(&late),
        fake_later.dump(),
        client_later.logs()
    );
}

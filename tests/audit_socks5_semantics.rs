//! Regression test for COR-11: the client answers the local SOCKS5 CONNECT with `Succeeded`
//! *before* the server confirms the session (`src/client.rs` `handle_socks5_cmd_connection` replies
//! first, `client_traffic_loop` sends `Start session:` afterwards and gates reads on the
//! confirmation).
//!
//! A fake peer is used instead of a real server: it completes the WebSocket upgrade, then waits
//! before it reads anything, and it never sends a confirmation. The test observes that the local
//! SOCKS5 reply is already there while no session request can have been answered, and that local
//! payload stays unforwarded without the confirmation.
//!
//! The assertions describe the *current* behavior; a fix (reply only after the confirmation, or a
//! failure reply when the tunnel fails) must flip them.

mod common;

use common::{client_config, free_port, poll_until, spawn_role, wait_tcp, work_dir, write_json, ws};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Received WebSocket frames, in arrival order.
type Frames = Arc<Mutex<Vec<(u8, Vec<u8>)>>>;

/// A plain TCP peer that answers the WebSocket upgrade and then stays silent for a while.
struct FakePeer {
    addr: SocketAddr,
    /// When the `Start session:` text frame was read (delayed, see `READ_DELAY`).
    start_session_at: Arc<Mutex<Option<Instant>>>,
    /// Every WebSocket frame received, in arrival order.
    frames: Frames,
}

const READ_DELAY: Duration = Duration::from_millis(500);

impl FakePeer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake peer");
        let addr = listener.local_addr().expect("fake peer addr");
        let start_session_at = Arc::new(Mutex::new(None));
        let frames = Arc::new(Mutex::new(Vec::new()));
        let session = start_session_at.clone();
        let received = frames.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let session = session.clone();
                let frames = received.clone();
                std::thread::spawn(move || serve_peer(stream, session, frames));
            }
        });
        Self {
            addr,
            start_session_at,
            frames,
        }
    }

    fn start_session_at(&self) -> Option<Instant> {
        *self.start_session_at.lock().expect("session lock")
    }

    fn binary_frames(&self) -> Vec<Vec<u8>> {
        self.frames
            .lock()
            .expect("frame lock")
            .iter()
            .filter(|(opcode, _)| *opcode == ws::OPCODE_BINARY)
            .map(|(_, payload)| payload.clone())
            .collect()
    }

    fn frames(&self) -> Vec<(u8, Vec<u8>)> {
        self.frames.lock().expect("frame lock").clone()
    }
}

fn serve_peer(mut stream: TcpStream, session: Arc<Mutex<Option<Instant>>>, frames: Frames) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    // Everything after the handshake is frame data - it must not be parsed as a request again.
    buf.drain(..head_end);
    let key = head
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
        .unwrap_or_default()
        .trim()
        .to_string();
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        common::ws_accept_key(&key)
    );
    if stream.write_all(response.as_bytes()).is_err() {
        return;
    }

    // The fake peer is deliberately slow: everything the client sends is only observed later.
    std::thread::sleep(READ_DELAY);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        if let Some((opcode, payload)) = read_frame(&mut stream, &mut buf) {
            if opcode == ws::OPCODE_TEXT && payload.starts_with(b"Start session") {
                let mut guard = session.lock().expect("session lock");
                if guard.is_none() {
                    *guard = Some(Instant::now());
                }
            }
            frames.lock().expect("frame lock").push((opcode, payload));
        }
    }
}

/// Read one masked frame from the peer, `None` on timeout/EOF.
fn read_frame(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<(u8, Vec<u8>)> {
    loop {
        if let Some(frame) = take_frame(buf) {
            return Some(frame);
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn take_frame(buf: &mut Vec<u8>) -> Option<(u8, Vec<u8>)> {
    if buf.len() < 2 {
        return None;
    }
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let mut offset = 2;
    let len = match buf[1] & 0x7f {
        126 => {
            if buf.len() < 4 {
                return None;
            }
            let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            offset = 4;
            len
        }
        127 => {
            if buf.len() < 10 {
                return None;
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&buf[2..10]);
            offset = 10;
            u64::from_be_bytes(raw) as usize
        }
        len => len as usize,
    };
    let mut mask = [0u8; 4];
    if masked {
        if buf.len() < offset + 4 {
            return None;
        }
        mask.copy_from_slice(&buf[offset..offset + 4]);
        offset += 4;
    }
    if buf.len() < offset + len {
        return None;
    }
    let mut payload = buf[offset..offset + len].to_vec();
    if masked {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
    }
    buf.drain(..offset + len);
    Some((opcode, payload))
}

/// COR-11: the SOCKS5 reply is sent before the session request, and local data stays unforwarded
/// until the (never arriving) confirmation.
#[test]
fn connect_replies_succeeded_before_confirmation() {
    let peer = FakePeer::start();
    let client_port = free_port();
    let dir = work_dir("audit_socks5_semantics");
    let value = client_config(peer.addr.port(), client_port, json!({}), json!({}));
    let cfg = write_json(&dir, "client.json", &value);
    let _client = spawn_role("client", &cfg, &["-v", "debug"], &dir);
    let client_addr = SocketAddr::from(([127, 0, 0, 1], client_port));
    assert!(wait_tcp(client_addr, common::DEFAULT_WAIT), "client did not start");

    let (mut stream, reply) =
        common::socks5_connect(client_addr, "127.0.0.1:9".parse().expect("target"), Duration::from_secs(5)).expect("socks5 connect");
    let reply_at = Instant::now();
    // Current behavior: `Succeeded` although nothing confirmed a tunnel (the peer is not even an
    // overtls server); a fix must reply after the session is confirmed.
    assert!(common::socks5_reply_succeeded(&reply), "expected a success reply, got {reply:x?}");

    assert!(
        poll_until(Duration::from_secs(5), || peer.start_session_at().is_some()),
        "the client must request the session after replying, frames seen: {:?}",
        peer.frames()
            .iter()
            .map(|(opcode, payload)| (*opcode, String::from_utf8_lossy(payload).to_string()))
            .collect::<Vec<_>>()
    );
    let start_session_at = peer.start_session_at().expect("session time");
    assert!(
        reply_at + Duration::from_millis(300) < start_session_at,
        "the SOCKS5 reply must precede the session request: reply at {reply_at:?}, request read at {start_session_at:?}"
    );

    // Without the confirmation the client does not read the local connection, so nothing is sent.
    let _ = stream.write_all(b"LOCAL-PAYLOAD");
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        peer.binary_frames().is_empty(),
        "no payload may be forwarded before the confirmation, got {:?}",
        peer.binary_frames()
    );
}

//! Shared helpers for the overtls integration tests.
//!
//! Everything here is process-external: the tests spawn the real `overtls-bin` binary, real
//! loopback TCP/UDP peers, a fake SSPanel endpoint and a raw WebSocket client. All filesystem
//! writes stay inside `target/test-tmp/`, no test needs the network.
#![allow(dead_code)]

use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub mod ws;

pub const DEFAULT_WAIT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------------------------
// paths and process handling
// ---------------------------------------------------------------------------------------------

/// Path of the `overtls-bin` executable (cargo injects it for integration tests).
pub fn bin() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_overtls-bin") {
        return PathBuf::from(path);
    }
    let exe = if cfg!(windows) { "overtls-bin.exe" } else { "overtls-bin" };
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target");
    for profile in ["release", "debug"] {
        let candidate = target.join(profile).join(exe);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("overtls-bin not found under {target:?}, build it first (`cargo build`)");
}

/// An unused loopback port.
pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// A scratch directory below `target/test-tmp/`, created on demand.
pub fn work_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("test-tmp").join(name);
    std::fs::create_dir_all(&dir).expect("create work dir");
    dir
}

/// Write `value` as pretty JSON into `dir/name`, returning the file path.
pub fn write_json(dir: &Path, name: &str, value: &Value) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(value).expect("serialize config")).expect("write config");
    path
}

/// A spawned `overtls-bin` process whose output is captured for assertions.
pub struct Proc {
    name: String,
    child: Option<Child>,
    output: Arc<Mutex<String>>,
}

impl Proc {
    /// Everything the process wrote to stdout/stderr so far.
    pub fn logs(&self) -> String {
        self.output.lock().expect("proc log lock").clone()
    }

    /// Whether the process already exited.
    pub fn exited(&mut self) -> bool {
        self.status().is_some()
    }

    /// `Some(status)` once the process exited.
    pub fn status(&mut self) -> Option<ExitStatus> {
        let child = self.child.as_mut()?;
        match child.try_wait() {
            Ok(Some(status)) => Some(status),
            _ => None,
        }
    }

    /// Wait at most `d` for the process to exit.
    pub fn wait_timeout(&mut self, d: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + d;
        loop {
            if let Some(status) = self.status() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Stop the process and collect its output.
    pub fn stop(&mut self) -> String {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        std::thread::sleep(Duration::from_millis(100));
        self.logs()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_process(mut command: Command, name: &str, log_filter: Option<String>) -> Proc {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Remove any inherited filter first; `spawn_role` re-adds an explicit one right afterwards.
        .env_remove("RUST_LOG")
        .env_remove("RUST_BACKTRACE");
    if let Some(filter) = log_filter {
        command.env("RUST_LOG", filter);
    }
    let mut child = command.spawn().unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    let output = Arc::new(Mutex::new(String::new()));
    for reader in [
        child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
        child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let sink = output.clone();
        std::thread::spawn(move || {
            let mut reader = reader;
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut guard) = sink.lock() {
                            guard.push_str(&String::from_utf8_lossy(&buf[..n]));
                        }
                    }
                }
            }
        });
    }
    Proc {
        name: name.to_string(),
        child: Some(child),
        output,
    }
}

/// The verbosity level passed to the spawned binary, parsed from `extra` (`-v <level>`,
/// `--verbosity=<level>`); defaults to `debug` (every current caller passes `-v`).
fn verbosity_level<'a>(extra: &'a [&'a str]) -> &'a str {
    for (index, arg) in extra.iter().enumerate() {
        if (*arg == "-v" || *arg == "--verbosity")
            && let Some(level) = extra.get(index + 1)
        {
            return level;
        }
        if let Some(level) = arg.strip_prefix("--verbosity=").or_else(|| arg.strip_prefix("-v=")) {
            return level;
        }
    }
    "debug"
}

/// Spawn `overtls-bin -r <role> -c <cfg> <extra...>` with `dir` as working directory.
///
/// The working directory matters: `dotenvy` walks up from the CWD and a repository root `.env`
/// (the readme tells developers to create one holding `RUST_LOG`) would otherwise change the log
/// filter. `spawn_role` therefore sets the filter *explicitly* to the level asked for with `-v`
/// instead of just deleting `RUST_LOG`: `dotenvy::dotenv` never overwrites variables that already
/// exist, so an inherited or `.env`-provided `RUST_LOG` can no longer silently suppress `-v trace`.
pub fn spawn_role(role: &str, cfg: &Path, extra: &[&str], dir: &Path) -> Proc {
    let mut command = Command::new(bin());
    command.arg("-r").arg(role).arg("-c").arg(cfg).args(extra).current_dir(dir);
    let level = verbosity_level(extra);
    let filter = format!("overtls={level},connection_pool={level}");
    spawn_process(command, &format!("{role} ({})", cfg.display()), Some(filter))
}

/// Spawn `overtls-bin` with raw arguments (used by the CLI tests).
pub fn spawn_bin(args: &[&str], dir: &Path) -> Proc {
    let mut command = Command::new(bin());
    command.args(args).current_dir(dir);
    spawn_process(command, &format!("overtls-bin {args:?}"), None)
}

/// Run `overtls-bin` with raw arguments to completion, returning `(status, output)`.
pub fn run_bin(args: &[&str], dir: &Path) -> (ExitStatus, String) {
    let mut proc = spawn_bin(args, dir);
    let status = proc.wait_timeout(Duration::from_secs(30)).expect("process did not exit");
    (status, proc.logs())
}

// ---------------------------------------------------------------------------------------------
// waiting helpers
// ---------------------------------------------------------------------------------------------

/// Poll `f` until it returns true or `d` elapsed.
pub fn poll_until(d: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + d;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait until `addr` accepts a TCP connection.
pub fn wait_tcp(addr: SocketAddr, d: Duration) -> bool {
    poll_until(d, || TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok())
}

/// Wait until `addr` refuses TCP connections (used to observe a listener that went away).
pub fn wait_tcp_closed(addr: SocketAddr, d: Duration) -> bool {
    poll_until(d, || TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_err())
}

/// Read a whole TCP stream until EOF or timeout, returning what arrived.
pub fn read_until_eof(stream: &mut TcpStream, d: Duration) -> Vec<u8> {
    let _ = stream.set_read_timeout(Some(d));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 1 << 20 {
                    break;
                }
            }
        }
    }
    buf
}

/// Send a request and read whatever the peer answers within `d`.
pub fn exchange(addr: SocketAddr, request: &[u8], d: Duration) -> Vec<u8> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
    stream.write_all(request).expect("send request");
    read_until_eof(&mut stream, d)
}

// ---------------------------------------------------------------------------------------------
// loopback peers
// ---------------------------------------------------------------------------------------------

/// A loopback TCP echo server.
pub struct TcpEcho {
    pub addr: SocketAddr,
    pub connections: Arc<AtomicUsize>,
}

/// Start a TCP echo server that echoes everything back until EOF.
pub fn tcp_echo_server() -> TcpEcho {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = stream.shutdown(Shutdown::Both);
            });
        }
    });
    TcpEcho { addr, connections }
}

/// A loopback UDP echo server.
pub struct UdpEcho {
    pub addr: SocketAddr,
    pub datagrams: Arc<AtomicUsize>,
}

/// Start a UDP echo server.
pub fn udp_echo_server() -> UdpEcho {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp echo");
    let addr = socket.local_addr().expect("udp echo addr");
    let datagrams = Arc::new(AtomicUsize::new(0));
    let counter = datagrams.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = socket.send_to(&buf[..n], peer);
        }
    });
    UdpEcho { addr, datagrams }
}

/// A loopback HTTP/1.1 target that answers 200 with a fixed body.
pub struct HttpTarget {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// Start an HTTP target answering every request with `body` and `Connection: close`.
pub fn http_target(body: &'static str) -> HttpTarget {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind http target");
    let addr = listener.local_addr().expect("http target addr");
    let requests: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let recorded = recorded.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                recorded.lock().expect("http target lock").push(request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown(Shutdown::Both);
            });
        }
    });
    HttpTarget { addr, requests }
}

// ---------------------------------------------------------------------------------------------
// fake SSPanel (`mod_mu`) endpoint
// ---------------------------------------------------------------------------------------------

/// Response mode of the fake panel.
#[derive(Clone, Debug)]
pub enum PanelMode {
    /// `{"ret":1,"data":[{"client_id":..,"enable":..}]}`
    Ok(Vec<(Uuid, bool)>),
    /// `{"ret":0}` - the contract requires a non-zero `ret`, so this must be treated as a failure.
    Ret0,
    /// HTTP 500.
    Http500,
    /// Accept the connection and never answer.
    Silent,
}

/// A minimal `mod_mu` panel.
pub struct Panel {
    pub addr: SocketAddr,
    pub mode: Arc<Mutex<PanelMode>>,
    /// Bodies of the received `POST /mod_mu/users/traffic` requests.
    pub reports: Arc<Mutex<Vec<Value>>>,
    /// Request lines of every received request.
    pub requests: Arc<Mutex<Vec<String>>>,
}

impl Panel {
    /// Switch the response mode.
    pub fn set(&self, mode: PanelMode) {
        *self.mode.lock().expect("panel mode lock") = mode;
    }

    /// Number of received requests.
    pub fn request_count(&self) -> usize {
        self.requests.lock().expect("panel request lock").len()
    }

    /// Received traffic report bodies.
    pub fn report_bodies(&self) -> Vec<Value> {
        self.reports.lock().expect("panel report lock").clone()
    }
}

/// Start a fake panel serving `GET /mod_mu/users` and `POST /mod_mu/users/traffic`.
pub fn fake_panel(initial: PanelMode) -> Panel {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind panel");
    let addr = listener.local_addr().expect("panel addr");
    let mode = Arc::new(Mutex::new(initial));
    let reports: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let handler_mode = mode.clone();
    let handler_reports = reports.clone();
    let handler_requests = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mode = handler_mode.clone();
            let reports = handler_reports.clone();
            let requests = handler_requests.clone();
            std::thread::spawn(move || handle_panel_request(stream, mode, reports, requests));
        }
    });
    Panel {
        addr,
        mode,
        reports,
        requests,
    }
}

fn handle_panel_request(
    mut stream: TcpStream,
    mode: Arc<Mutex<PanelMode>>,
    reports: Arc<Mutex<Vec<Value>>>,
    requests: Arc<Mutex<Vec<String>>>,
) {
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
    let request_line = head.lines().next().unwrap_or_default().to_string();
    let path = request_line.split_whitespace().nth(1).unwrap_or_default().to_string();
    requests.lock().expect("panel request lock").push(request_line.clone());

    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }

    if path.starts_with("/mod_mu/users/traffic") {
        if let Ok(value) = serde_json::from_slice::<Value>(&body[..content_length.min(body.len())]) {
            reports.lock().expect("panel report lock").push(value);
        }
        let payload = br#"{"ret":1,"data":{}}"#.to_vec();
        let _ = stream.write_all(response_bytes(200, &payload).as_slice());
        return;
    }

    let mode = mode.lock().expect("panel mode lock").clone();
    match mode {
        PanelMode::Ok(users) => {
            let data: Vec<Value> = users
                .iter()
                .map(|(client_id, enable)| json!({ "client_id": client_id, "enable": enable }))
                .collect();
            let payload = serde_json::to_vec(&json!({ "ret": 1, "data": data })).expect("panel payload");
            let _ = stream.write_all(response_bytes(200, &payload).as_slice());
        }
        PanelMode::Ret0 => {
            let _ = stream.write_all(response_bytes(200, br#"{"ret":0,"data":[]}"#).as_slice());
        }
        PanelMode::Http500 => {
            let _ = stream.write_all(response_bytes(500, b"internal error").as_slice());
        }
        PanelMode::Silent => {
            std::thread::sleep(Duration::from_secs(30));
        }
    }
}

fn response_bytes(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------------------------
// SOCKS5 client side
// ---------------------------------------------------------------------------------------------

/// Send the SOCKS5 greeting and return the raw 2-byte method-selection reply.
pub fn socks5_greeting_raw(stream: &mut TcpStream) -> std::io::Result<[u8; 2]> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    Ok(reply)
}

/// Send the SOCKS5 greeting and require the no-auth selection.
pub fn socks5_greeting(stream: &mut TcpStream) -> std::io::Result<()> {
    let reply = socks5_greeting_raw(stream)?;
    assert_eq!(reply, [0x05, 0x00], "unexpected SOCKS5 method selection");
    Ok(())
}

/// Connect to `proxy` and request CONNECT to `target`; returns the stream and the raw reply.
///
/// The reply is returned instead of asserted so callers can check both the success reply of the
/// implementation and the "connection closed before any reply" failure modes.
pub fn socks5_connect(proxy: SocketAddr, target: SocketAddr, timeout: Duration) -> std::io::Result<(TcpStream, Vec<u8>)> {
    let mut stream = TcpStream::connect_timeout(&proxy, timeout)?;
    socks5_greeting(&mut stream)?;
    stream.write_all(&[0x05, 0x01, 0x00, 0x01])?;
    let ip = match target {
        SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
        SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
    };
    stream.write_all(&ip)?;
    stream.write_all(&target.port().to_be_bytes())?;
    let reply = read_socks5_reply(&mut stream, timeout)?;
    Ok((stream, reply))
}

/// Read one SOCKS5 reply (VER, REP, RSV, ATYP, BND.ADDR, BND.PORT).
pub fn read_socks5_reply(stream: &mut TcpStream, timeout: Duration) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(timeout))?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    let mut reply = head.to_vec();
    let rest = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            reply.push(len[0]);
            len[0] as usize + 2
        }
        other => panic!("unexpected SOCKS5 address type {other:#x}"),
    };
    let mut tail = vec![0u8; rest];
    stream.read_exact(&mut tail)?;
    reply.extend_from_slice(&tail);
    Ok(reply)
}

/// True when the SOCKS5 reply reports success (REP == 0).
pub fn socks5_reply_succeeded(reply: &[u8]) -> bool {
    reply.len() >= 2 && reply[0] == 0x05 && reply[1] == 0x00
}

/// Wrap a socket address as a SOCKS5 address (ATYP + address + port).
pub fn socks5_addr_v4(addr: SocketAddr) -> Vec<u8> {
    let mut out = vec![0x01];
    match addr {
        SocketAddr::V4(v4) => out.extend_from_slice(&v4.ip().octets()),
        SocketAddr::V6(v6) => {
            out[0] = 0x04;
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

/// Perform a SOCKS5 UDP ASSOCIATE; returns the control connection and the relay address.
pub fn udp_associate(proxy: SocketAddr) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut stream = TcpStream::connect_timeout(&proxy, Duration::from_secs(5))?;
    socks5_greeting(&mut stream)?;
    stream.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    let reply = read_socks5_reply(&mut stream, Duration::from_secs(5))?;
    assert!(socks5_reply_succeeded(&reply), "UDP ASSOCIATE failed: {reply:x?}");
    let relay = match reply[3] {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
            SocketAddr::from((ip, u16::from_be_bytes([reply[8], reply[9]])))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&reply[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            SocketAddr::from((ip, u16::from_be_bytes([reply[20], reply[21]])))
        }
        other => panic!("unexpected BND.ATYP {other:#x}"),
    };
    Ok((stream, relay))
}

/// Send one SOCKS5 UDP datagram (no fragmentation) to `relay` for `dst`.
pub fn udp_send(socket: &UdpSocket, relay: SocketAddr, dst: SocketAddr, payload: &[u8]) -> std::io::Result<()> {
    let mut packet = vec![0x00, 0x00, 0x00];
    packet.extend_from_slice(&socks5_addr_v4(dst));
    packet.extend_from_slice(payload);
    socket.send_to(&packet, relay)?;
    Ok(())
}

/// Send one SOCKS5 UDP datagram with an explicit FRAG byte.
pub fn udp_send_frag(socket: &UdpSocket, relay: SocketAddr, dst: SocketAddr, frag: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut packet = vec![0x00, 0x00, frag];
    packet.extend_from_slice(&socks5_addr_v4(dst));
    packet.extend_from_slice(payload);
    socket.send_to(&packet, relay)?;
    Ok(())
}

/// Receive one SOCKS5 UDP datagram and return `(dst_address, payload)`.
pub fn udp_recv(socket: &UdpSocket, timeout: Duration) -> Option<(SocketAddr, Vec<u8>)> {
    socket.set_read_timeout(Some(timeout)).ok()?;
    let mut buf = [0u8; 65535];
    let n = socket.recv(&mut buf).ok()?;
    let packet = &buf[..n];
    if packet.len() < 4 {
        return None;
    }
    let (addr, offset) = match packet[3] {
        0x01 if packet.len() >= 10 => (
            SocketAddr::from((
                std::net::Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]),
                u16::from_be_bytes([packet[8], packet[9]]),
            )),
            10,
        ),
        0x04 if packet.len() >= 22 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[4..20]);
            (
                SocketAddr::from((std::net::Ipv6Addr::from(octets), u16::from_be_bytes([packet[20], packet[21]]))),
                22,
            )
        }
        _ => return None,
    };
    Some((addr, packet[offset..].to_vec()))
}

/// A free UDP port (bound and released).
pub fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind udp")
        .local_addr()
        .expect("udp addr")
        .port()
}

// ---------------------------------------------------------------------------------------------
// configuration templates
// ---------------------------------------------------------------------------------------------

/// Shallow-merge object `extra` into object `base` (nested objects are merged one level deep).
pub fn merge(base: &mut Value, extra: Value) {
    match (base, extra) {
        (Value::Object(base), Value::Object(extra)) => {
            for (key, value) in extra {
                match base.get_mut(&key) {
                    Some(existing @ Value::Object(_)) if value.is_object() => merge(existing, value),
                    _ => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, extra) => *base = extra,
    }
}

/// A server config with plaintext listening; `top`/`settings` are merged into the template.
pub fn server_config(listen_port: u16, forward_addr: Option<&str>, top: Value, settings: Value) -> Value {
    let mut value = json!({
        "tunnel_path": "/t/",
        "test_timeout_secs": 10,
        "server_settings": {
            "disable_tls": true,
            "listen_host": "127.0.0.1",
            "listen_port": listen_port,
            "forward_addr": forward_addr.unwrap_or("http://127.0.0.1:9"),
        },
    });
    merge(&mut value, top);
    let settings = serde_json::to_value(settings).expect("settings");
    if let Some(server_settings) = value.get_mut("server_settings") {
        merge(server_settings, settings);
    }
    value
}

/// A client config with plaintext tunneling; `top`/`settings` are merged into the template.
pub fn client_config(server_port: u16, listen_port: u16, top: Value, settings: Value) -> Value {
    let mut value = json!({
        "tunnel_path": "/t/",
        "test_timeout_secs": 10,
        "client_settings": {
            "disable_tls": true,
            "server_host": "127.0.0.1",
            "server_port": server_port,
            "listen": format!("mixed://127.0.0.1:{listen_port}"),
            "advertise_ip": "127.0.0.1",
            "pool_max_size": 8,
        },
    });
    merge(&mut value, top);
    let settings = serde_json::to_value(settings).expect("settings");
    if let Some(client_settings) = value.get_mut("client_settings") {
        merge(client_settings, settings);
    }
    value
}

/// Read the listen port of a client config created by [`client_config`].
pub fn client_listen_port(config: &Value) -> u16 {
    let listen = config["client_settings"]["listen"].as_str().expect("client listen");
    listen.rsplit(':').next().expect("listen port").parse().expect("listen port")
}

/// A running server + client pair.
pub struct Pair {
    pub dir: PathBuf,
    pub server_addr: SocketAddr,
    pub client_addr: SocketAddr,
    pub server: Proc,
    pub client: Proc,
}

impl Pair {
    /// Stop both processes and return their logs.
    pub fn logs(&mut self) -> (String, String) {
        (self.server.stop(), self.client.stop())
    }
}

/// Spawn a server and a client from already-built config values and wait until both listen.
pub fn start_pair(name: &str, server_value: &Value, client_value: &Value, srv_port: u16, client_port: u16) -> Pair {
    start_pair_verbosity(name, server_value, client_value, srv_port, client_port, "debug")
}

/// Spawn only the server role (used by the cases that talk to the server directly).
pub fn start_server(name: &str, value: &Value, srv_port: u16, verbosity: &str) -> (PathBuf, Proc) {
    let dir = work_dir(name);
    let cfg = write_json(&dir, "server.json", value);
    let proc = spawn_role("server", &cfg, &["-v", verbosity], &dir);
    assert!(
        wait_tcp(SocketAddr::from(([127, 0, 0, 1], srv_port)), DEFAULT_WAIT),
        "server did not start listening on 127.0.0.1:{srv_port}: {}",
        proc.logs()
    );
    (dir, proc)
}

/// Same as [`start_pair`] with an explicit verbosity level.
pub fn start_pair_verbosity(
    name: &str,
    server_value: &Value,
    client_value: &Value,
    srv_port: u16,
    client_port: u16,
    verbosity: &str,
) -> Pair {
    let dir = work_dir(name);
    let server_cfg = write_json(&dir, "server.json", server_value);
    let client_cfg = write_json(&dir, "client.json", client_value);
    let server_addr = SocketAddr::from(([127, 0, 0, 1], srv_port));
    let client_addr = SocketAddr::from(([127, 0, 0, 1], client_port));

    let server = spawn_role("server", &server_cfg, &["-v", verbosity], &dir);
    assert!(
        wait_tcp(server_addr, DEFAULT_WAIT),
        "server did not start listening on {server_addr}: {}",
        server.logs()
    );
    let client = spawn_role("client", &client_cfg, &["-v", verbosity], &dir);
    assert!(
        wait_tcp(client_addr, DEFAULT_WAIT),
        "client did not start listening on {client_addr}: {}",
        client.logs()
    );
    Pair {
        dir,
        server_addr,
        client_addr,
        server,
        client,
    }
}

// ---------------------------------------------------------------------------------------------
// TLS fixtures
// ---------------------------------------------------------------------------------------------

/// Directory holding the test certificates.
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures")
}

/// Paths of the committed leaf certificate and key of `ca`.
pub fn ca_files(ca: &str) -> (PathBuf, PathBuf) {
    let dir = fixtures_dir().join(ca);
    (dir.join("server.crt"), dir.join("server.key"))
}

/// Path of the committed CA certificate of `ca` (used as the client `cafile`).
pub fn ca_root(ca: &str) -> PathBuf {
    fixtures_dir().join(ca).join("root.crt")
}

/// Copy the leaf certificate and key of `ca` into `dir`, returning the absolute paths.
pub fn copy_ca(dir: &Path, ca: &str) -> (PathBuf, PathBuf) {
    let (cert, key) = ca_files(ca);
    let target_cert = dir.join(format!("{ca}-server.crt"));
    let target_key = dir.join(format!("{ca}-server.key"));
    std::fs::copy(&cert, &target_cert).expect("copy certificate");
    std::fs::copy(&key, &target_key).expect("copy key");
    (
        std::fs::canonicalize(&target_cert).expect("canonical certificate"),
        std::fs::canonicalize(&target_key).expect("canonical key"),
    )
}

/// Absolute path of the given path (needed for config values consumed from another directory).
pub fn absolute(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).expect("canonicalize")
}

// ---------------------------------------------------------------------------------------------
// small primitives
// ---------------------------------------------------------------------------------------------

/// Standard base64 encoding (padding included).
pub fn b64(data: &[u8]) -> String {
    base64easy::encode(data, base64easy::EngineKind::Standard)
}

/// Minimal SHA-1 (used for the WebSocket accept key).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// The WebSocket accept key for `key` (RFC 6455).
pub fn ws_accept_key(key: &str) -> String {
    b64(&sha1(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()))
}

/// A `JoinHandle` that is intentionally left detached in tests.
pub type Detached = JoinHandle<()>;

pub fn keep_detached(_handle: Detached) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_known_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn ws_accept_key_matches_rfc_example() {
        assert_eq!(ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    fn hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

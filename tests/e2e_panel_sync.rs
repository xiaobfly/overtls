//! Link 7: SSPanel `mod_mu` synchronisation - enable/disable gating, fail-closed behaviour,
//! traffic reporting (COR-03), the mandatory `Client-Id` gating (COR-10) and token leakage in the
//! server log (SEC-16).
//!
//! The panel contract (`src/panel_sync.rs`): `GET {webapi_url}/mod_mu/users?key=..&node_id=..` must
//! answer `{"ret":<non-zero>,"data":[{"client_id":..,"enable":..}]}` and
//! `POST .../mod_mu/users/traffic` receives `{reporter_id,sequence,data:[{client_id,u,d}]}`.
//! The sync interval is `api_update_time.max(10)` seconds and the first tick fires immediately.

mod common;

use common::{
    DEFAULT_WAIT, Panel, PanelMode, Proc, client_config, fake_panel, free_port, poll_until, server_config, spawn_role, udp_associate,
    udp_echo_server, udp_recv, udp_send, wait_tcp, work_dir, write_json, ws,
};
use serde_json::json;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use uuid::Uuid;

fn panel_settings(panel: &Panel, token: &str) -> serde_json::Value {
    json!({
        "enabled": true,
        "webapi_url": format!("http://{}/", panel.addr),
        "webapi_token": token,
        "node_id": 1,
        "api_update_time": 10,
    })
}

/// Start a server whose panel is served by `panel`; the first sync tick is awaited.
fn panel_server(name: &str, panel: &Panel, token: &str) -> (Proc, SocketAddr, serde_json::Value) {
    let port = free_port();
    let value = server_config(port, None, json!({}), json!({ "panel_sync": panel_settings(panel, token) }));
    let dir = work_dir(name);
    let cfg = write_json(&dir, "server.json", &value);
    let proc = spawn_role("server", &cfg, &["-v", "debug"], &dir);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(wait_tcp(addr, DEFAULT_WAIT), "server did not start: {}", proc.logs());
    assert!(
        poll_until(DEFAULT_WAIT, || panel.request_count() >= 1),
        "the server must sync with the panel right after startup:\n{}",
        proc.logs()
    );
    (proc, addr, value)
}

fn raw_ws(addr: SocketAddr, client_id: Option<Uuid>, udp_tunnel: bool) -> (ws::Ws, String) {
    let mut handshake = ws::Handshake::new("/t/", "127.0.0.1");
    handshake.client_id = client_id;
    handshake.udp_tunnel = udp_tunnel;
    ws::Ws::connect(addr, &handshake).expect("ws handshake")
}

/// Wait until the connection is closed by the server, returning everything that was read.
fn wait_for_close(socket: &mut ws::Ws, deadline: Duration) -> Vec<u8> {
    let end = Instant::now() + deadline;
    let mut seen = Vec::new();
    while Instant::now() < end {
        if let Some((_opcode, payload)) = socket.recv_frame(Duration::from_millis(300)) {
            seen.extend_from_slice(&payload);
        }
        if socket.is_closed() {
            break;
        }
    }
    seen
}

/// A client registered with `enable: true` keeps its tunnel across the one-second enable check.
#[test]
fn panel_enable_true_keeps_tunnel_alive() {
    let client_id = Uuid::new_v4();
    let panel = fake_panel(PanelMode::Ok(vec![(client_id, true)]));
    let (proc, addr, _cfg) = panel_server("e2e_panel_enabled", &panel, "tok-secret-enabled");

    let (mut socket, header) = raw_ws(addr, Some(client_id), false);
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");

    // Cross two enable-check ticks and verify the tunnel is still serving.
    for _ in 0..2 {
        std::thread::sleep(Duration::from_millis(1200));
        socket.send_ping(b"keepalive").expect("ping");
        let frame = socket.recv_frame(Duration::from_secs(2));
        assert!(
            matches!(&frame, Some((opcode, _)) if *opcode == ws::OPCODE_PONG),
            "an enabled client must stay connected, got {frame:?}\nserver log:\n{}",
            proc.logs()
        );
    }
    assert!(
        !proc.logs().contains("disabled by panel sync"),
        "no disable may be applied:\n{}",
        proc.logs()
    );
}

/// Disabling a client in the panel tears down its established tunnel after the next sync.
#[test]
fn panel_disable_kills_established_tunnel() {
    let client_id = Uuid::new_v4();
    let panel = fake_panel(PanelMode::Ok(vec![(client_id, true)]));
    let (proc, addr, _cfg) = panel_server("e2e_panel_disabled", &panel, "tok-secret-disabled");

    let (mut socket, header) = raw_ws(addr, Some(client_id), false);
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");
    socket.send_ping(b"alive").expect("ping");
    assert!(
        matches!(socket.recv_frame(Duration::from_secs(2)), Some((opcode, _)) if opcode == ws::OPCODE_PONG),
        "the tunnel must be alive before the panel flips"
    );

    let flips = panel.request_count();
    panel.set(PanelMode::Ok(vec![(client_id, false)]));

    // The tunnel dies after the next sync (<= 10 s) plus the one-second enable check.
    let mut seen = Vec::new();
    let closed = poll_until(Duration::from_secs(25), || {
        let _ = socket.send_ping(b"probe");
        match socket.recv_frame(Duration::from_millis(500)) {
            Some((_, payload)) => {
                seen.extend_from_slice(&payload);
                payload.windows(11).any(|w| w == b"End session")
            }
            None => socket.is_closed(),
        }
    });
    assert!(
        closed,
        "the tunnel must be torn down after the next sync ({flips} syncs so far)\nserver log:\n{}",
        proc.logs()
    );
    assert!(
        poll_until(Duration::from_secs(5), || proc.logs().contains("disabled by panel sync")),
        "the server must report the panel-driven teardown:\n{}",
        proc.logs()
    );
    assert!(panel.request_count() > flips, "a second sync must have happened:\n{}", proc.logs());
}

/// An unreachable panel fails closed: the client id is never enabled, so the tunnel is refused.
#[test]
fn panel_unreachable_fails_closed() {
    let client_id = Uuid::new_v4();
    let dead_port = free_port();
    let mut settings = panel_settings(&fake_panel(PanelMode::Ok(vec![])), "tok-secret-unreachable");
    settings["webapi_url"] = json!(format!("http://127.0.0.1:{dead_port}/"));
    let port = free_port();
    let value = server_config(port, None, json!({}), json!({ "panel_sync": settings }));
    let dir = work_dir("e2e_panel_unreachable");
    let cfg = write_json(&dir, "server.json", &value);
    let proc = spawn_role("server", &cfg, &["-v", "debug"], &dir);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(wait_tcp(addr, DEFAULT_WAIT), "server did not start: {}", proc.logs());

    let (mut socket, header) = raw_ws(addr, Some(client_id), false);
    assert!(
        ws::Ws::status_line(&header).contains("101"),
        "the upgrade itself is answered: {header:?}"
    );
    let _ = wait_for_close(&mut socket, Duration::from_secs(3));
    assert!(socket.is_closed(), "an unsynchronised client id must be rejected:\n{}", proc.logs());
    assert!(
        poll_until(Duration::from_secs(5), || proc.logs().contains("is disabled")),
        "the server must report the rejected client id:\n{}",
        proc.logs()
    );
}

/// The panel contract requires a non-zero `ret`; `ret: 0` counts as a failed sync (fail closed).
#[test]
fn panel_ret_zero_fails_sync() {
    let client_id = Uuid::new_v4();
    let panel = fake_panel(PanelMode::Ret0);
    let (proc, addr, _cfg) = panel_server("e2e_panel_ret0", &panel, "tok-secret-ret0");

    let (mut socket, header) = raw_ws(addr, Some(client_id), false);
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");
    let _ = wait_for_close(&mut socket, Duration::from_secs(3));
    assert!(socket.is_closed(), "ret:0 must not enable the client:\n{}", proc.logs());
    assert!(
        poll_until(Duration::from_secs(5), || proc.logs().contains("panel sync failed")),
        "the failed sync must be reported:\n{}",
        proc.logs()
    );
}

/// Traffic of a registered client is reported as a delta with the documented body shape (COR-03).
#[test]
fn traffic_report_delta_accounting() {
    let client_id = Uuid::new_v4();
    let panel = fake_panel(PanelMode::Ok(vec![(client_id, true)]));
    let (_server, server_addr, _value) = panel_server("e2e_panel_traffic", &panel, "tok-secret-traffic");
    let udp_echo = udp_echo_server();

    // A real client must use the same client id as the panel registration.
    let client_port = free_port();
    let client_value = client_config(
        server_addr.port(),
        client_port,
        json!({}),
        json!({ "client_id": client_id.to_string() }),
    );
    let dir = work_dir("e2e_panel_traffic");
    let client_cfg = write_json(&dir, "client.json", &client_value);
    let _client = spawn_role("client", &client_cfg, &["-v", "debug"], &dir);
    assert!(
        wait_tcp(SocketAddr::from(([127, 0, 0, 1], client_port)), DEFAULT_WAIT),
        "client did not start"
    );

    let payload = b"PANEL-DELTA-PING";
    let (_control, relay) = udp_associate(SocketAddr::from(([127, 0, 0, 1], client_port))).expect("udp associate");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    let replied = poll_until(Duration::from_secs(10), || {
        udp_send(&socket, relay, udp_echo.addr, payload).expect("send udp");
        matches!(udp_recv(&socket, Duration::from_millis(500)), Some((_, data)) if data == payload)
    });
    assert!(replied, "the tunneled datagram must be answered");

    let report = poll_until(Duration::from_secs(25), || {
        !panel.reports.lock().expect("panel report lock").is_empty()
    });
    assert!(report, "a traffic report must be posted within one sync interval");
    let reports = panel.report_bodies();
    let body = reports
        .iter()
        .find(|body| {
            body["data"]
                .as_array()
                .is_some_and(|entries| entries.iter().any(|entry| entry["client_id"] == json!(client_id)))
        })
        .unwrap_or_else(|| panic!("no report for client {client_id}: {reports:#?}"));

    assert!(body["reporter_id"].is_string(), "reporter_id missing: {body}");
    assert!(body["sequence"].as_u64().is_some_and(|s| s >= 1), "sequence missing: {body}");
    let entry = body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .find(|entry| entry["client_id"] == json!(client_id))
        .expect("entry for our client");
    let upstream = entry["u"].as_u64().expect("u");
    let downstream = entry["d"].as_u64().expect("d");
    // Accounting (src/server.rs): every message counts `payload + WS_MSG_HEADER_LEN(14)`; the
    // handshake is charged as `2 * handshake_length` on the upstream side, and the UDP framing of
    // the client adds 10 address bytes per datagram.
    let sent = (payload.len() + 10) as u64;
    assert!(
        upstream >= sent + 14,
        "upstream delta must at least cover the WS header of one message: u={upstream} sent={sent}"
    );
    assert!(
        upstream - sent <= 2076,
        "upstream delta must not exceed 2*128 + handshake constant: u={upstream} sent={sent}"
    );
    assert!(
        downstream >= payload.len() as u64,
        "downstream delta must cover the reply: d={downstream}"
    );
    assert!(
        downstream - payload.len() as u64 <= 2076,
        "downstream delta out of range: d={downstream}"
    );
}

/// A failing panel sync leaks the webapi token into the server log (SEC-16).
#[test]
fn panel_error_logs_token() {
    let dead_port = free_port();
    let mut settings = panel_settings(&fake_panel(PanelMode::Ok(vec![])), "tok-secret-leak");
    settings["webapi_url"] = json!(format!("http://127.0.0.1:{dead_port}/"));
    let port = free_port();
    let value = server_config(port, None, json!({}), json!({ "panel_sync": settings }));
    let dir = work_dir("e2e_panel_token");
    let cfg = write_json(&dir, "server.json", &value);
    let proc = spawn_role("server", &cfg, &["-v", "debug"], &dir);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(wait_tcp(addr, DEFAULT_WAIT), "server did not start: {}", proc.logs());

    assert!(
        poll_until(DEFAULT_WAIT, || proc.logs().contains("panel sync failed")),
        "the failed sync must be logged:\n{}",
        proc.logs()
    );
    assert!(
        proc.logs().contains("tok-secret-leak"),
        "the webapi token must not be part of the log output (SEC-16):\n{}",
        proc.logs()
    );
}

/// A client id is gated even without a panel: unregistered ids are kicked after the one-second
/// check, while connections without a client id keep running (COR-10).
#[test]
fn client_id_without_panel_killed_within_1s() {
    let port = free_port();
    let value = server_config(port, None, json!({}), json!({}));
    let dir = work_dir("e2e_panel_no_panel");
    let cfg = write_json(&dir, "server.json", &value);
    let proc = spawn_role("server", &cfg, &["-v", "debug"], &dir);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(wait_tcp(addr, DEFAULT_WAIT), "server did not start: {}", proc.logs());

    let (mut gated, header) = raw_ws(addr, Some(Uuid::new_v4()), false);
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");
    let mut seen = Vec::new();
    let closed = poll_until(Duration::from_secs(5), || {
        if let Some((_, payload)) = gated.recv_frame(Duration::from_millis(300)) {
            seen.extend_from_slice(&payload);
        }
        gated.is_closed()
    });
    assert!(closed, "a client id without panel registration must be kicked:\n{}", proc.logs());
    assert!(
        seen.windows(11).any(|w| w == b"End session"),
        "the kick must be announced with 'End session', got: {:?}\n{}",
        String::from_utf8_lossy(&seen),
        proc.logs()
    );

    // Control: without the Client-Id header the same server keeps the tunnel open.
    let (mut open, header) = raw_ws(addr, None, false);
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");
    std::thread::sleep(Duration::from_millis(2500));
    open.send_ping(b"control").expect("ping");
    assert!(
        matches!(open.recv_frame(Duration::from_secs(2)), Some((opcode, _)) if opcode == ws::OPCODE_PONG),
        "a tunnel without client id must survive:\n{}",
        proc.logs()
    );
}

/// COR-10 (UDP lane): the same one-second check that kicks an unregistered TCP tunnel also tears
/// down a UDP tunnel whose `Client-Id` was never registered by a panel.
///
/// Difference from the TCP lane above: `svr_udp_tunnel` leaves the loop without sending anything,
/// so there is no `End session` text frame - only the socket going away. The check itself is the
/// first tick of `tokio::time::interval(1s)`, which completes immediately, hence the 2s bound is
/// only an upper bound (measured in the printout).
///
/// Post-fix expectation (COR-10): a client id the panel never announced must not be kicked, so this
/// tunnel stays open and the assertions flip to "still alive".
#[test]
fn client_id_udp_tunnel_kicked_without_panel() {
    let port = free_port();
    let value = server_config(port, None, json!({}), json!({}));
    let dir = work_dir("e2e_panel_udp_no_panel");
    let cfg = write_json(&dir, "server.json", &value);
    let proc = spawn_role("server", &cfg, &["-v", "debug"], &dir);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(wait_tcp(addr, DEFAULT_WAIT), "server did not start: {}", proc.logs());

    let started = Instant::now();
    let (mut gated, header) = raw_ws(addr, Some(Uuid::new_v4()), true);
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");

    // Read once to observe the EOF/RST before checking `is_closed()`.
    let mut seen = Vec::new();
    let closed = poll_until(Duration::from_secs(2), || {
        if let Some((_, payload)) = gated.recv_frame(Duration::from_millis(200)) {
            seen.extend_from_slice(&payload);
        }
        gated.is_closed()
    });
    let elapsed = started.elapsed();
    println!(
        "udp tunnel with an unregistered client id closed after {elapsed:?}, {} frame bytes read",
        seen.len()
    );
    assert!(
        closed,
        "a UDP tunnel with an unregistered client id must be kicked (COR-10), still open after {elapsed:?}:\n{}",
        proc.logs()
    );
    assert!(elapsed <= Duration::from_secs(2), "the UDP kick took {elapsed:?}");
    // Only the TCP lane announces the kick (`END_SESSION`); the UDP lane just drops the socket.
    assert!(
        !seen.windows(11).any(|window| window == b"End session"),
        "the UDP kick must not send `End session`, got {:?}\n{}",
        String::from_utf8_lossy(&seen),
        proc.logs()
    );
    assert!(
        poll_until(Duration::from_secs(5), || proc
            .logs()
            .contains("[UDP] tunnel disabled by panel sync")),
        "the server must log the panel-driven UDP teardown:\n{}",
        proc.logs()
    );

    // Control: the same server keeps a UDP tunnel *without* a Client-Id alive - the per-second
    // check only exists for connections that announced one - and it still relays datagrams.
    let echo = udp_echo_server();
    let (mut open, header) = raw_ws(addr, None, true);
    assert!(ws::Ws::status_line(&header).contains("101"), "handshake failed: {header:?}");
    std::thread::sleep(Duration::from_millis(1500));
    let src = SocketAddr::from(([127, 0, 0, 1], common::free_udp_port()));
    let mut frame = common::socks5_addr_v4(echo.addr);
    frame.extend_from_slice(&common::socks5_addr_v4(src));
    frame.extend_from_slice(b"UDP-CONTROL");
    open.send_binary(&frame).expect("send udp frame");
    let reply = open.recv_frame(Duration::from_secs(5));
    assert!(
        matches!(&reply, Some((opcode, payload)) if *opcode == ws::OPCODE_BINARY && payload.ends_with(b"UDP-CONTROL")),
        "a UDP tunnel without client id must stay alive and relay, got {reply:?}\n{}",
        proc.logs()
    );
}

//! Link 6: certificate hot reload - `notify` watches the *parent directory* of `certfile`/`keyfile`
//! and swaps the acceptor for new connections after a 250 ms debounce; a failed reload keeps the
//! running certificate (SEC-20).

mod common;

use common::{
    Pair, ca_files, ca_root, client_config, copy_ca, free_port, poll_until, server_config, start_pair, udp_associate, udp_echo_server,
    udp_recv, udp_send, work_dir,
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    time::Duration,
};

/// Server with the `ca-a` leaf, client trusting only `ca-b`: every TLS attempt must fail until the
/// server switches to the `ca-b` leaf.
fn reload_pair(name: &str) -> (Pair, PathBuf, PathBuf, PathBuf) {
    let dir = work_dir(name);
    let (cert, key) = copy_ca(&dir, "ca-a");
    let srv_port = free_port();
    let client_port = free_port();
    let server_value = server_config(
        srv_port,
        None,
        json!({}),
        json!({ "disable_tls": false, "certfile": cert, "keyfile": key }),
    );
    let client_value = client_config(
        srv_port,
        client_port,
        json!({}),
        json!({ "disable_tls": false, "server_domain": "example.com", "cafile": ca_root("ca-b") }),
    );
    let pair = start_pair(name, &server_value, &client_value, srv_port, client_port);
    assert!(
        pair.server.logs().contains("using TLS"),
        "server must run with TLS:\n{}",
        pair.server.logs()
    );
    (pair, dir, cert, key)
}

/// Ask the local SOCKS5 endpoint for the method selection reply; `None` when the tunnel is refused.
fn greeting_reply(addr: SocketAddr) -> Option<[u8; 2]> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream.write_all(&[0x05, 0x01, 0x00]).ok()?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).ok()?;
    Some(reply)
}

/// Write a file through an existing symlink (or at the path itself) without replacing the symlink.
fn overwrite(path: &PathBuf, source: &PathBuf) {
    std::fs::copy(source, path).expect("overwrite file");
}

/// Replacing the configured certificate files in place is picked up for new connections.
#[test]
fn reload_after_cert_file_replacement() {
    let (pair, _dir, cert, key) = reload_pair("e2e_tls_reload");

    assert_eq!(
        greeting_reply(pair.client_addr),
        None,
        "ca-b must not be accepted yet:\n{}",
        pair.client.logs()
    );

    let (ca_b_cert, ca_b_key) = ca_files("ca-b");
    overwrite(&cert, &ca_b_cert);
    overwrite(&key, &ca_b_key);

    assert!(
        poll_until(Duration::from_secs(20), || pair
            .server
            .logs()
            .contains("reloaded server TLS certificate")),
        "the server must reload the replaced certificate:\n{}",
        pair.server.logs()
    );
    assert!(
        poll_until(Duration::from_secs(20), || greeting_reply(pair.client_addr) == Some([0x05, 0x00])),
        "the ca-b client must be accepted after the reload:\n{}",
        pair.client.logs()
    );

    // Traffic actually flows through the freshly loaded certificate. The UDP tunnel of the client
    // reconnects on its own schedule (1 s backoff after a failed attempt), so retry the datagram.
    let udp_echo = udp_echo_server();
    let (_control, relay) = udp_associate(pair.client_addr).expect("udp associate");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    let mut received = None;
    let replied = poll_until(Duration::from_secs(15), || {
        udp_send(&socket, relay, udp_echo.addr, b"RELOADED-CERT").expect("send udp");
        received = udp_recv(&socket, Duration::from_millis(500));
        matches!(&received, Some((_, payload)) if payload == b"RELOADED-CERT")
    });
    assert!(
        replied,
        "UDP traffic must flow through the reloaded certificate, last reply: {received:?}\nclient log:\n{}\nserver log:\n{}",
        pair.client.logs(),
        pair.server.logs()
    );
}

/// A certificate path that is a symlink into an archive directory is not reloaded when only the
/// archive target is replaced: the watcher only watches the configured file's parent directory
/// (SEC-20).
#[cfg(unix)]
#[test]
fn symlinked_cert_archive_write_not_reloaded() {
    let dir = work_dir("e2e_tls_reload_symlink");
    let archive_dir = dir.join("archive");
    std::fs::create_dir_all(&archive_dir).expect("create archive dir");
    let (ca_a_cert, ca_a_key) = ca_files("ca-a");
    let archive_cert = archive_dir.join("server.crt");
    let archive_key = archive_dir.join("server.key");
    std::fs::copy(&ca_a_cert, &archive_cert).expect("stage archive certificate");
    std::fs::copy(&ca_a_key, &archive_key).expect("stage archive key");
    let live_dir = dir.join("live");
    std::fs::create_dir_all(&live_dir).expect("create live dir");
    let live_cert = live_dir.join("server.crt");
    let live_key = live_dir.join("server.key");
    for (link, target) in [(&live_cert, &archive_cert), (&live_key, &archive_key)] {
        std::fs::remove_file(link).ok();
        std::os::unix::fs::symlink(target, link).expect("symlink certificate");
    }

    let srv_port = free_port();
    let client_port = free_port();
    let server_value = server_config(
        srv_port,
        None,
        json!({}),
        json!({ "disable_tls": false, "certfile": live_cert, "keyfile": live_key }),
    );
    let client_value = client_config(
        srv_port,
        client_port,
        json!({}),
        json!({ "disable_tls": false, "server_domain": "example.com", "cafile": ca_root("ca-b") }),
    );
    let pair = start_pair("e2e_tls_reload_symlink", &server_value, &client_value, srv_port, client_port);
    assert!(
        pair.server.logs().contains("using TLS"),
        "server must run with TLS:\n{}",
        pair.server.logs()
    );
    assert_eq!(
        greeting_reply(pair.client_addr),
        None,
        "ca-b must not be accepted yet:\n{}",
        pair.client.logs()
    );

    let (ca_b_cert, ca_b_key) = ca_files("ca-b");
    overwrite(&archive_cert, &ca_b_cert);
    overwrite(&archive_key, &ca_b_key);

    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(
        greeting_reply(pair.client_addr),
        None,
        "a write to the symlink target must not be reloaded:\n{}",
        pair.server.logs()
    );
    assert!(
        !pair.server.logs().contains("reloaded server TLS certificate"),
        "no reload may be triggered by the archive path:\n{}",
        pair.server.logs()
    );
}

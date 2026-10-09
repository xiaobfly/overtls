//! Regression: audit finding SEC-19 (silent plaintext listener when the certificate cannot load).
//!
//! Current behaviour (`src/server.rs:56-78`): when `certfile`/`keyfile` are set but cannot be
//! loaded, the server only emits `warn!` lines and keeps serving *plaintext* WebSocket upgrades on
//! the configured port. The assertions below describe that current behaviour; the `// post-fix:`
//! comments name the expectation to flip to once SEC-19 makes startup fail instead of downgrading.

mod common;

use common::{free_port, poll_until, server_config, start_server, work_dir, ws};
use serde_json::json;
use std::{net::SocketAddr, time::Duration};

/// `certfile`/`keyfile` that cannot be read downgrade the server to a plaintext listener (SEC-19).
#[test]
fn missing_cert_falls_back_to_plaintext() {
    let port = free_port();
    let dir = work_dir("audit_plaintext_fallback");
    // `watch_server_tls_files` only watches the *parent directories* of the two paths, so those have
    // to exist at startup - the files themselves are deliberately missing.
    let tls_dir = dir.join("tls");
    std::fs::create_dir_all(&tls_dir).expect("create tls dir");
    let value = server_config(
        port,
        None,
        json!({}),
        json!({
            // The helper template is a plaintext test setup; SEC-19 needs the TLS-enabled branch.
            "disable_tls": false,
            "certfile": tls_dir.join("missing.crt"),
            "keyfile": tls_dir.join("missing.key"),
        }),
    );

    // `start_server` waits for the port to accept connections: the server is up despite the failure.
    let (_dir, mut server) = start_server("audit_plaintext_fallback", &value, port, "debug");
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    // Current behaviour: the broken TLS configuration yields a *plaintext* listener that completes
    // an ordinary WebSocket upgrade.
    // post-fix: the server must refuse to start (or at least not answer a plaintext handshake), so
    // this must flip to "no 101 / no listener" (SEC-19: startup failure instead of a downgrade).
    let (_ws, header) = ws::Ws::connect(addr, &ws::Handshake::new("/t/", "127.0.0.1")).expect("ws handshake");
    assert!(
        ws::Ws::status_line(&header).contains("101"),
        "current behaviour: a missing certificate falls back to plaintext, got: {header:?}\nserver log:\n{}",
        server.logs()
    );

    // post-fix: the plaintext fallback must be gone, so this log line must disappear with it.
    assert!(
        poll_until(Duration::from_secs(5), || server
            .logs()
            .contains("no certificate and key file, using plain TCP")),
        "the downgrade must be logged:\n{}",
        server.logs()
    );
    // post-fix: the load error itself stays (the files are still missing); the flip is that startup
    // aborts instead of only warning.
    assert!(
        poll_until(Duration::from_secs(5), || server
            .logs()
            .contains("failed to load server certificate or key")),
        "the load failure must be logged:\n{}",
        server.logs()
    );
    // post-fix: the branch logged here is the plaintext one; after the fix the server must either
    // exit or log `using TLS`, so this assertion flips to `assert!(... contains("using TLS"))` or is
    // removed together with the assertions above.
    assert!(
        !server.logs().contains("using TLS"),
        "the server must not claim TLS is active:\n{}",
        server.logs()
    );
    // post-fix: flips - a TLS-configured server with unloadable certificates must refuse to start
    // (`server.exited()` becomes true with a non-zero status) instead of serving plaintext.
    assert!(
        !server.exited(),
        "the server keeps running in plaintext (the SEC-19 downgrade):\n{}",
        server.logs()
    );
}

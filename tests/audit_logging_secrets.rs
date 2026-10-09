//! Regression: audit finding SEC-15 - the whole configuration (credentials included) is written
//! into the log at trace level, and the unix `-d` mode writes fixed name files under `/tmp`.
//!
//! Every assertion describes the *current* behavior of the shipped binary. The SEC-15 fix
//! (redacting `password`/`client_id`/`tunnel_path` from the trace dump, opening the daemon logs
//! with `O_EXCL|O_NOFOLLOW` under a per-run name) must flip each of them - the post-fix
//! expectation is noted at every assertion.

mod common;

use common::{client_config, client_listen_port, free_port, poll_until, spawn_role, tcp_echo_server, work_dir, write_json};
use serde_json::json;
use std::time::Duration;

/// Distinctive values so the assertions cannot be satisfied by unrelated log output.
const PASSWORD: &str = "PASSWORD-LEAK-7f3a1c";
const CLIENT_ID: &str = "0f7e4b1a-3c2d-4e5f-8a9b-1c2d3e4f5a6b";
const TUNNEL_PATH: &str = "/secret-trace-path/";

/// A work directory whose name is unique per test process, so two concurrent `cargo test` runs on
/// the same machine cannot truncate each other's logs (or `pkill` each other's daemon).
fn unique_dir(name: &str) -> std::path::PathBuf {
    work_dir(&format!("{name}-{}", std::process::id()))
}

/// Serializes the two `/tmp/overtls.out`/`/tmp/overtls.err` tests below: both use the same fixed
/// paths, and the test harness runs test functions in parallel threads of one process.
#[cfg(unix)]
static DAEMON_TMP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `-v trace` dumps the complete client configuration verbatim, credentials included (SEC-15).
#[test]
fn trace_log_contains_full_config() {
    // The client role validates its configuration by dialing `server_host:server_port`
    // (`Config::check_correctness`), so a plain loopback listener is enough to get it started; no
    // overtls server is involved in this test.
    let endpoint = tcp_echo_server();
    let listen_port = free_port();
    let value = client_config(
        endpoint.addr.port(),
        listen_port,
        json!({
            "tunnel_path": TUNNEL_PATH,
            "password": PASSWORD,
            "test_timeout_secs": 10,
        }),
        json!({ "client_id": CLIENT_ID }),
    );
    assert_eq!(
        client_listen_port(&value),
        listen_port,
        "test config must listen on the chosen port"
    );

    let dir = unique_dir("audit_logging_secrets_trace");
    let cfg = write_json(&dir, "client.json", &value);
    let proc = spawn_role("client", &cfg, &["-v", "trace"], &dir);

    assert!(
        poll_until(Duration::from_secs(10), || proc.logs().contains("with following settings")),
        "the client must dump its settings at trace level, client output:\n{}",
        proc.logs()
    );

    let logs = proc.logs();
    let dump_from = logs.find("with following settings").expect("dump marker");
    let dump = &logs[dump_from..];

    // Current behavior: `serde_json::to_string_pretty(config)` prints the whole configuration from
    // the marker onward, credentials included.
    // Post-fix expectation: none of these needles may appear any more (password/token redacted and
    // client_id/tunnel_path hashed or removed).
    for (needle, what) in [
        ("\"client_settings\"", "the client settings section"),
        ("\"client_id\"", "the client_id key"),
        (CLIENT_ID, "the exact client_id value"),
        ("\"password\"", "the password key"),
        (PASSWORD, "the exact password value"),
        (TUNNEL_PATH, "the tunnel path"),
        ("\"test_timeout_secs\"", "the test timeout"),
    ] {
        assert!(
            dump.contains(needle),
            "the trace dump must contain {what} ({needle:?}), client output:\n{logs}"
        );
    }
}

/// `-d` (unix only) creates the fixed name logs `/tmp/overtls.out` and `/tmp/overtls.err` before
/// dropping privileges, and the detached daemon keeps serving (SEC-15).
#[cfg(unix)]
#[test]
fn daemonize_writes_fixed_tmp_path() {
    use common::{server_config, start_server, wait_tcp, wait_tcp_closed};

    // Fixed names taken from `src/bin/main.rs`; `File::create` follows symlinks (SEC-15).
    const DAEMON_OUT: &str = "/tmp/overtls.out";
    const DAEMON_ERR: &str = "/tmp/overtls.err";

    // Both daemon tests use the same fixed names; run them one at a time.
    let _daemon_guard = DAEMON_TMP_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    // A stale file from an earlier run must not satisfy the existence check on its own.
    let _ = std::fs::remove_file(DAEMON_OUT);
    let _ = std::fs::remove_file(DAEMON_ERR);

    let srv_port = free_port();
    let server_value = server_config(srv_port, Some("http://127.0.0.1:9"), json!({}), json!({}));
    let (dir, _server) = start_server(
        &format!("audit_logging_secrets_daemon-{}", std::process::id()),
        &server_value,
        srv_port,
        "debug",
    );

    let listen_port = free_port();
    let value = client_config(srv_port, listen_port, json!({}), json!({}));
    let cfg = write_json(&dir, "client.json", &value);
    let client_addr = std::net::SocketAddr::from(([127, 0, 0, 1], listen_port));

    // daemonize forks: the parent exits, the detached child keeps running.
    let mut parent = spawn_role("client", &cfg, &["-v", "debug", "-d"], &dir);
    let parent_exited = parent.wait_timeout(Duration::from_secs(15)).is_some();

    let out_exists = poll_until(Duration::from_secs(15), || std::path::Path::new(DAEMON_OUT).exists());
    let listens = wait_tcp(client_addr, Duration::from_secs(5));
    // The daemon's log lands in the second fixed file (env_logger writes to stderr, redirected there
    // before the fork); poll briefly so a slow write cannot make the assertion flaky.
    let daemon_logged = poll_until(Duration::from_secs(5), || {
        std::fs::read_to_string(DAEMON_ERR).is_ok_and(|text| text.contains("starting overtls"))
    });
    let daemon_log = std::fs::read_to_string(DAEMON_ERR).unwrap_or_default();

    // Cleanup before any assertion so a failure cannot leak the detached daemon or its fixed files.
    let _ = std::process::Command::new("pkill")
        .args(["-f", cfg.to_str().expect("config path")])
        .status();
    let daemon_gone = wait_tcp_closed(client_addr, Duration::from_secs(5));
    let _ = std::fs::remove_file(DAEMON_OUT);
    let _ = std::fs::remove_file(DAEMON_ERR);

    assert!(
        parent_exited,
        "the `-d` parent must exit after forking the daemon, parent output:\n{}",
        parent.logs()
    );
    // Post-fix expectation: a per-run name (PID/random suffix) opened O_EXCL|O_NOFOLLOW with 0600.
    assert!(
        out_exists,
        "`-d` must create the fixed name {DAEMON_OUT} (SEC-15), daemon stderr:\n{daemon_log}"
    );
    assert!(
        listens,
        "the daemonized client must serve on {client_addr}, daemon stderr:\n{daemon_log}"
    );
    // Post-fix expectation: the daemon logs to syslog/journald or a per-run file instead.
    assert!(
        daemon_logged,
        "the daemon must log into the fixed name {DAEMON_ERR}, daemon stderr:\n{daemon_log}"
    );
    // `pkill -f <config path>` must really have taken the daemon down, otherwise this test leaks a
    // listener (and, with `-d`, a detached process) into later runs on the same machine.
    assert!(
        daemon_gone,
        "the daemon on {client_addr} is still reachable after `pkill -f {}`",
        cfg.display()
    );
}

/// Pre-creating the fixed `/tmp/overtls.out` as a symlink is followed by `File::create`, so `-d`
/// truncates whatever the link points at instead of refusing (SEC-15, CWE-59).
///
/// Post-fix expectation: the log file is opened with `O_EXCL|O_NOFOLLOW` under a per-run name, so
/// the victim stays byte-for-byte intact and `victim_overwritten` must become false.
#[cfg(unix)]
#[test]
fn daemonize_follows_symlink_in_tmp() {
    use common::{server_config, start_server, wait_tcp_closed};

    const DAEMON_OUT: &str = "/tmp/overtls.out";
    const DAEMON_ERR: &str = "/tmp/overtls.err";
    const SENTINEL: &str = "SYMLINK-VICTIM-SENTINEL-1f4d9c";

    // Both daemon tests use the same fixed names; run them one at a time.
    let _daemon_guard = DAEMON_TMP_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let srv_port = free_port();
    let server_value = server_config(srv_port, Some("http://127.0.0.1:9"), json!({}), json!({}));
    let (dir, _server) = start_server(
        &format!("audit_logging_secrets_symlink-{}", std::process::id()),
        &server_value,
        srv_port,
        "debug",
    );

    // A victim file outside /tmp that the daemon must never touch.
    let victim = dir.join("victim.txt");
    std::fs::write(&victim, SENTINEL).expect("write victim");
    // Pre-create the fixed path as a symlink to the victim (a stale file is removed first).
    let _ = std::fs::remove_file(DAEMON_OUT);
    std::os::unix::fs::symlink(&victim, DAEMON_OUT).expect("create symlink");

    let listen_port = free_port();
    let value = client_config(srv_port, listen_port, json!({}), json!({}));
    let cfg = write_json(&dir, "client.json", &value);
    let client_addr = std::net::SocketAddr::from(([127, 0, 0, 1], listen_port));

    let mut parent = spawn_role("client", &cfg, &["-v", "debug", "-d"], &dir);
    let parent_exited = parent.wait_timeout(Duration::from_secs(15)).is_some();

    // Current behavior: `File::create` follows the symlink and truncates the victim (its content is
    // gone, length 0); post-fix: the sentinel survives untouched.
    let victim_overwritten = poll_until(Duration::from_secs(15), || {
        let len = std::fs::metadata(&victim).map_or(0, |meta| meta.len());
        let text = std::fs::read_to_string(&victim).unwrap_or_default();
        len == 0 || !text.contains(SENTINEL)
    });

    // Cleanup before the assertions so a failure cannot leak the symlink or the detached daemon.
    let _ = std::process::Command::new("pkill")
        .args(["-f", cfg.to_str().expect("config path")])
        .status();
    let daemon_gone = wait_tcp_closed(client_addr, Duration::from_secs(5));
    let _ = std::fs::remove_file(DAEMON_OUT);
    let _ = std::fs::remove_file(DAEMON_ERR);
    let _ = std::fs::remove_file(&victim);

    assert!(
        parent_exited,
        "the `-d` parent must exit after forking the daemon, parent output:\n{}",
        parent.logs()
    );
    assert!(
        victim_overwritten,
        "a pre-created {DAEMON_OUT} symlink must be followed by the daemon log creation (SEC-15)",
    );
    assert!(
        daemon_gone,
        "the daemon on {client_addr} is still reachable after `pkill -f {}`",
        cfg.display()
    );
}

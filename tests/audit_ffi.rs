//! Regression tests for the C API (`src/api.rs`, `src/traffic_status.rs`).
//!
//! Findings: FFI-01 (`over_tls_client_run_with_ssr_url` has no null check for the URL - the process
//! dies inside `CStr::from_ptr`), FFI-04 (the traffic-status callback is invoked while the callback
//! mutex is held, so re-entering the API deadlocks), FFI-06 (the `overtls_generate_url` buffer
//! contract: required size includes the NUL, nothing is written when the buffer is too small),
//! FFI-07 (`EXITING_FLAG` is set before `run_client` starts and is only cleared by
//! `over_tls_client_stop`; a client whose `run_client` returns *on its own* - e.g. because the
//! listen port could not be bound - leaves the flag set, so every later `over_tls_client_run`
//! fails immediately with "tun2proxy already started").
//!
//! Tests that must crash, deadlock or restart a client run in a *child process* of this test binary
//! (`E2E_FFI_CASE` selects the case, `--exact` keeps the child to that single test), so the parent
//! test only observes exit codes and output. Every assertion describes the *current* behavior.
#![allow(unsafe_op_in_unsafe_fn)]

mod common;

use common::{client_config, free_port, poll_until, server_config, work_dir, write_json};
use serde_json::json;
use std::{
    ffi::CString,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::raw::{c_char, c_int, c_void},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI32, Ordering},
    },
    time::{Duration, Instant},
};

const CASE_ENV: &str = "E2E_FFI_CASE";

fn child_case() -> Option<String> {
    std::env::var(CASE_ENV).ok()
}

/// A child process of this test binary running exactly one test.
struct ChildRun {
    child: Option<Child>,
    output: Arc<Mutex<String>>,
}

impl ChildRun {
    /// Spawn `current_exe <test> --exact --nocapture` with `E2E_FFI_CASE=case`.
    fn spawn(case: &str, test: &str) -> Self {
        let mut command = Command::new(std::env::current_exe().expect("test binary path"));
        command
            .arg(test)
            .arg("--exact")
            .arg("--nocapture")
            .env(CASE_ENV, case)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn child test process");
        let output = Arc::new(Mutex::new(String::new()));
        for reader in [
            child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
            child.stderr.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let sink = output.clone();
            std::thread::spawn(move || {
                use std::io::Read;
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
        Self {
            child: Some(child),
            output,
        }
    }

    fn output(&self) -> String {
        self.output.lock().expect("child output lock").clone()
    }

    fn status(&mut self) -> Option<ExitStatus> {
        self.child.as_mut()?.try_wait().ok().flatten()
    }

    fn wait(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.status() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wait until `marker` shows up in the child output.
    fn wait_for_marker(&mut self, marker: &str, timeout: Duration) -> bool {
        poll_until(timeout, || self.output().contains(marker))
    }

    fn alive(&mut self) -> bool {
        self.status().is_none()
    }
}

impl Drop for ChildRun {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn json_string(value: &serde_json::Value) -> String {
    serde_json::to_string(value).expect("config json")
}

/// A plain TCP listener that only accepts connections, used as the "server" for `check_correctness`.
fn silent_listener() -> (SocketAddr, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    (addr, listener)
}

// ---------------------------------------------------------------------------------------------
// FFI-01
// ---------------------------------------------------------------------------------------------

/// FFI-01: a null `url` is dereferenced instead of being rejected, so the process dies.
#[test]
fn null_url_terminates_process() {
    if child_case().as_deref() == Some("null_url") {
        // Child: perform the dangerous call. A working null check would return -1 here.
        let rc = unsafe {
            overtls::over_tls_client_run_with_ssr_url(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                overtls::LogLevel::Info,
                None,
                std::ptr::null_mut(),
            )
        };
        println!("FFI-NULL-RETURNED rc={rc}");
        std::process::exit(0);
    }

    let mut child = ChildRun::spawn("null_url", "null_url_terminates_process");
    let status = child.wait(Duration::from_secs(60)).expect("the child must terminate");
    let output = child.output();
    assert!(
        !output.contains("FFI-NULL-RETURNED"),
        "the call returned instead of dereferencing the null pointer (FFI-01 fixed?): {output}"
    );
    // Current behavior: a crash (segmentation fault / access violation), never a normal exit.
    assert!(
        !status.success(),
        "a null url must not be accepted silently, status {status:?}: {output}"
    );
}

// ---------------------------------------------------------------------------------------------
// FFI-04
// ---------------------------------------------------------------------------------------------

unsafe extern "C" fn reentrant_traffic_callback(_status: *const overtls::TrafficStatus, _ctx: *mut c_void) {
    // Re-entering the API from inside the callback deadlocks: the callback mutex is held by the
    // caller (`send_traffic_stat`).
    eprintln!("FFI04-CALLBACK-FIRED");
    unsafe {
        overtls::overtls_set_traffic_status_callback(1, Some(reentrant_traffic_callback), std::ptr::null_mut());
    }
    eprintln!("FFI04-CALLBACK-RETURNED");
}

/// FFI-04: the traffic-status callback is called with the mutex held; re-entering the API hangs.
#[test]
fn reentrant_callback_deadlocks() {
    if child_case().as_deref() == Some("ffi04") {
        run_deadlock_child();
    }

    let mut child = ChildRun::spawn("ffi04", "reentrant_callback_deadlocks");
    let fired = child.wait_for_marker("FFI04-CALLBACK-FIRED", Duration::from_secs(90));
    let output = child.output();
    assert!(
        fired,
        "the traffic callback must be triggered by tunneled sessions (if this fails, the case is \
         inconclusive - see the header of this file):\n{output}"
    );
    std::thread::sleep(Duration::from_secs(3));
    let output = child.output();
    assert!(
        !output.contains("FFI04-CALLBACK-RETURNED"),
        "the re-entrant call must not return:\n{output}"
    );
    assert!(
        child.alive(),
        "re-entering the traffic-status API from the callback must deadlock the process:\n{output}"
    );
}

/// Child process for FFI-04: in-process server + FFI client + two tunnel sessions.
fn run_deadlock_child() -> ! {
    let srv_port = free_port();
    let client_port = free_port();
    let dir = work_dir("audit_ffi04_child");
    let server_value = server_config(srv_port, None, json!({}), json!({}));
    let client_value = client_config(srv_port, client_port, json!({}), json!({}));

    let mut server_config = overtls::Config::from_json_str(&json_string(&server_value)).expect("server config");
    server_config.check_correctness(true).expect("server config check");
    let token = overtls::CancellationToken::new();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
        let _ = runtime.block_on(overtls::run_server(&server_config, token));
    });
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, srv_port));
    assert!(
        common::wait_tcp(server_addr, Duration::from_secs(8)),
        "in-process server did not start"
    );

    unsafe {
        overtls::overtls_set_traffic_status_callback(1, Some(reentrant_traffic_callback), std::ptr::null_mut());
    }

    let cfg = write_json(&dir, "client.json", &client_value);
    let path = CString::new(cfg.to_string_lossy().as_bytes()).expect("config path");
    std::thread::spawn(move || unsafe {
        overtls::over_tls_client_run(
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            overtls::LogLevel::Debug,
            None,
            std::ptr::null_mut(),
        )
    });
    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, client_port));
    assert!(common::wait_tcp(client_addr, Duration::from_secs(8)), "ffi client did not start");

    // Each session receives an `End session` frame (the loopback target is refused), which updates
    // the traffic counters; the second update, more than one second later, reports them.
    for _ in 0..4 {
        let _ = common::socks5_connect(client_addr, SocketAddr::from((Ipv4Addr::LOCALHOST, 9)), Duration::from_secs(3));
        std::thread::sleep(Duration::from_millis(700));
    }
    std::thread::sleep(Duration::from_secs(2));
    eprintln!("FFI04-NO-DEADLOCK");
    std::process::exit(0);
}

// ---------------------------------------------------------------------------------------------
// FFI-06
// ---------------------------------------------------------------------------------------------

/// FFI-06: buffer contract of `overtls_generate_url`.
#[test]
fn generate_url_contract() {
    let dir = work_dir("audit_ffi06");
    let value = client_config(
        free_port(),
        free_port(),
        json!({ "remarks": "ffi06", "method": "none", "password": "ffi06-password" }),
        json!({}),
    );
    let path = write_json(&dir, "client.json", &value);
    let c_path = CString::new(path.to_string_lossy().as_bytes()).expect("config path");

    // (1) query the required size without a buffer.
    let required = unsafe { overtls::overtls_generate_url(c_path.as_ptr(), std::ptr::null_mut(), 0) };
    assert!(required > 1, "the required size must include the NUL terminator, got {required}");

    // (2) one byte too small: nothing is written and the required size is returned.
    let mut too_small = vec![0xAAu8; required - 1];
    let returned = unsafe { overtls::overtls_generate_url(c_path.as_ptr(), too_small.as_mut_ptr() as *mut c_char, too_small.len()) };
    assert_eq!(
        returned, required,
        "the required size must be returned when the buffer is too small"
    );
    assert!(
        too_small.iter().all(|byte| *byte == 0xAA),
        "no data may be written into a too small buffer"
    );

    // (3) exact size: the URL is written and NUL terminated.
    let mut buffer = vec![0u8; required];
    let returned = unsafe { overtls::overtls_generate_url(c_path.as_ptr(), buffer.as_mut_ptr() as *mut c_char, buffer.len()) };
    assert_eq!(returned, required);
    assert_eq!(buffer[required - 1], 0, "the URL must be NUL terminated");
    let url = String::from_utf8(buffer[..required - 1].to_vec()).expect("utf8 url");
    assert!(url.starts_with("ssr://"), "unexpected url: {url}");

    // (4) an oversized buffer produces the same bytes.
    let mut oversized = vec![0u8; required + 16];
    let returned = unsafe { overtls::overtls_generate_url(c_path.as_ptr(), oversized.as_mut_ptr() as *mut c_char, oversized.len()) };
    assert_eq!(returned, required);
    assert_eq!(
        &oversized[..required],
        &buffer[..required],
        "the URL must not depend on the buffer size"
    );

    // (5) a null config path is reported as failure (0), not as a required size.
    let mut scratch = vec![0u8; required];
    let returned = unsafe { overtls::overtls_generate_url(std::ptr::null(), scratch.as_mut_ptr() as *mut c_char, scratch.len()) };
    assert_eq!(returned, 0, "a null config path must fail");
}

// ---------------------------------------------------------------------------------------------
// FFI-07
// ---------------------------------------------------------------------------------------------

static CALLBACK_PORT: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn port_callback(port: c_int, _ctx: *mut c_void) {
    CALLBACK_PORT.store(port, Ordering::SeqCst);
}

/// FFI-07: a client whose first `run` returns *on its own* (its listen port is already bound, so
/// `run_client` fails while binding) leaves `EXITING_FLAG` set forever, because only
/// `over_tls_client_stop` clears it. A second `over_tls_client_run` with a different, free listen
/// port therefore reports -1 immediately instead of serving. This is the defect the audit
/// describes; the earlier version of this case called `stop()` between the two runs, which clears
/// the flag itself and could never observe it.
///
/// Post-fix expectation: the flag is cleared when `run` returns on its own, so the second run
/// listens - `FFI07-SECOND-RUN-SERVING` becomes true and `FFI07-SECOND-RC` becomes 0/running;
/// flip both assertions then.
#[test]
fn second_run_after_natural_failure_is_rejected() {
    if child_case().as_deref() == Some("ffi07") {
        run_restart_child();
    }

    let mut child = ChildRun::spawn("ffi07", "second_run_after_natural_failure_is_rejected");
    let status = child.wait(Duration::from_secs(90)).expect("the child must terminate");
    let output = child.output();
    assert!(status.success(), "the child scenario failed: {output}");
    assert!(
        output.contains("FFI07-FIRST-RC=-1"),
        "the first run must fail on its own (listen port is already bound): {output}"
    );
    assert!(
        output.contains("FFI07-SECOND-RUN-SERVING=false"),
        "the second run must not serve: the flag is still set after the natural failure \
         (flip this when the flag is cleared on return): {output}"
    );
    assert!(
        output.contains("FFI07-SECOND-RC=-1"),
        "the second run must be rejected immediately with -1: {output}"
    );
}

/// Child process for FFI-07.
///
/// 1. a listener stays bound on port A, so `configA` (listening on A) makes `run_client` fail
///    while binding - a *natural* return with no `over_tls_client_stop` involved;
/// 2. a `run` with a free port B is attempted afterwards; the child reports what is observable
///    from the outside (return code of the second run and whether it ever served).
///
/// `tun2proxy already started` (the message from `_over_tls_client_run`) is only visible to a log
/// callback - the DumpLogger drops records without one - so it is deliberately not asserted here.
fn run_restart_child() -> ! {
    let (server_addr, _server_listener) = silent_listener();
    // Port A: bound for the whole child lifetime, so the first run cannot listen on it.
    let taken_listener = TcpListener::bind("127.0.0.1:0").expect("bind taken port");
    let taken_port = taken_listener.local_addr().expect("taken addr").port();
    let second_port = free_port();

    let dir = work_dir("audit_ffi07_child");
    let value_a = client_config(server_addr.port(), taken_port, json!({}), json!({}));
    let cfg_a = write_json(&dir, "client-a.json", &value_a);
    let path_a = CString::new(cfg_a.to_string_lossy().as_bytes()).expect("config path");

    // (1) natural failure: bind(A) fails inside `run_client`, `stop()` is intentionally not called.
    let first_rc = std::thread::spawn(move || unsafe {
        overtls::over_tls_client_run(
            path_a.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            overtls::LogLevel::Info,
            Some(port_callback),
            std::ptr::null_mut(),
        )
    })
    .join()
    .expect("first run thread");

    // (2) second run on a free port; the child waits for either a return or a listening socket.
    let value_b = client_config(server_addr.port(), second_port, json!({}), json!({}));
    let cfg_b = write_json(&dir, "client-b.json", &value_b);
    let path_b = CString::new(cfg_b.to_string_lossy().as_bytes()).expect("config path");
    let second_rc_slot = Arc::new(AtomicI32::new(i32::MIN));
    let slot = second_rc_slot.clone();
    let second = std::thread::spawn(move || unsafe {
        let rc = overtls::over_tls_client_run(
            path_b.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            overtls::LogLevel::Info,
            Some(port_callback),
            std::ptr::null_mut(),
        );
        slot.store(rc, Ordering::SeqCst);
    });
    let second_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, second_port));
    let mut serving = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !second.is_finished() && Instant::now() < deadline {
        if TcpStream::connect_timeout(&second_addr, Duration::from_millis(200)).is_ok() {
            serving = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let second_rc = if serving {
        // Post-fix path (flag cleared on natural return): the run serves; stop it cleanly.
        unsafe { overtls::over_tls_client_stop() };
        "running".to_string()
    } else if second.is_finished() {
        second_rc_slot.load(Ordering::SeqCst).to_string()
    } else {
        unsafe { overtls::over_tls_client_stop() };
        "running".to_string()
    };

    println!("FFI07-FIRST-RC={first_rc}");
    println!("FFI07-SECOND-RC={second_rc}");
    println!("FFI07-SECOND-RUN-SERVING={serving}");
    std::process::exit(0);
}

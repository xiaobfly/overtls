//! CLI surface: version output and non-zero exits for invalid flag combinations.
//!
//! Both cases are process-level contracts of `src/cmdopt.rs` (`CmdOpt::parse_cmd` / `version_info`).

mod common;

use common::{run_bin, work_dir};

/// `-V` prints the crate name, version and the embedded git hash/build time and exits 0.
#[test]
fn version_output_contract() {
    let dir = work_dir("e2e_cli_version");
    let (status, output) = run_bin(&["-V"], &dir);
    assert!(status.success(), "-V must exit 0, got {status:?}: {output}");
    assert!(
        output.contains("overtls 0.3.15 ("),
        "-V output must contain the crate name, version and build metadata, got: {output}"
    );
}

/// `-u/--url-of-node` requires `-l/--listen-addr`; clap must reject the combination.
#[test]
fn url_without_listen_addr_exits_nonzero() {
    let dir = work_dir("e2e_cli_url_without_listen");
    let url = format!("ssr://127.0.0.1:443:origin:none:plain:{}/?", common::b64(b"password"));
    let (status, output) = run_bin(&["-u", &url], &dir);
    assert!(!status.success(), "-u without -l must fail, got {status:?}: {output}");
}

/// Without a config file and without a node URL the client cannot be started.
#[test]
fn missing_config_exits_nonzero() {
    let dir = work_dir("e2e_cli_missing_config");
    let (status, output) = run_bin(&["-r", "client"], &dir);
    assert!(!status.success(), "missing config must fail, got {status:?}: {output}");
    assert!(
        output.contains("Config file or node URL is required"),
        "expected the explicit CLI error, got: {output}"
    );
}

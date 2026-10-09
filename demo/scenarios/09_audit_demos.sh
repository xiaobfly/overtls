#!/usr/bin/env bash
# Scenario 09 - run the audit regression tests.
#
# `cargo test --test 'audit_*'` cannot glob, so every file is invoked by name. Each file's tests pin
# the *current* behavior of one audit finding; a fix must flip the assertions instead of deleting
# the tests. See audit-report.md for the finding texts.
. "$(dirname "$0")/../lib.sh"

scenario_begin "09 audit regression tests (cargo test per file)"

cd "$ROOT" || fail "cannot enter $ROOT"
export RUST_BACKTRACE=1
CARGO_TIMEOUT_SECS=900   # a wedged cargo must not stall the whole demo suite

for name in \
    audit_server_input \
    audit_socks5_semantics \
    audit_udp_relay \
    audit_ws_close \
    audit_client_ws_upgrade \
    audit_tls_fingerprint \
    audit_plaintext_fallback \
    audit_logging_secrets \
    audit_ffi; do
    log="$LOGS/$name.log"
    printf '\n--- cargo test --test %s (timeout %ss)\n' "$name" "$CARGO_TIMEOUT_SECS"
    if run_with_timeout "$CARGO_TIMEOUT_SECS" cargo test --test "$name" >"$log" 2>&1; then
        pass "$name"
    elif grep -q '^!! timed out after' "$log"; then
        fail "$name (timed out after ${CARGO_TIMEOUT_SECS}s, see $log)"
    else
        fail "$name (see $log)"
    fi
    grep -E '^test result:' "$log" | tail -n 1 | sed 's/^/        /'
done

printf '\n    log files: %s\n' "$LOGS"

scenario_end

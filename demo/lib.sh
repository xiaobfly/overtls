#!/usr/bin/env bash
# Shared helpers for the overtls demo scenarios.
#
# POSIX shell compatible on purpose: the scenarios are invoked by demo/run_all.sh through either
# bash or sh (Git Bash on Windows, the system shell elsewhere).
#
# Everything this suite writes lives in demo/.run/<scenario>/ (git-ignored).

set -u

# Note: every path is normalized to forward slashes. On Windows shells `pwd` may answer with
# `D:\dir` which neither `cd` nor the child processes handle reliably when concatenated.
DEMO_DIR=$(cd "$(dirname "$0")" && pwd | tr '\\' '/')
[ -f "$DEMO_DIR/lib.sh" ] || DEMO_DIR=$(cd "$DEMO_DIR/.." && pwd | tr '\\' '/')
ROOT=$(cd "$DEMO_DIR/.." && pwd | tr '\\' '/')
# Per-scenario run directory. The scenarios use fixed file names (server.json, client.log,
# panel.state, ...), so every scenario owns `demo/.run/<scenario>/` - that keeps them apart and
# allows two scenarios to run at the same time. The name is the invoking script's, not lib.sh's.
RUN_NAME=$(printf '%s' "$0" | tr '\\' '/' | sed 's|.*/||; s|\.sh$||')
[ -n "$RUN_NAME" ] || RUN_NAME=scenario
RUN="$DEMO_DIR/.run/$RUN_NAME"
LOGS="$RUN/logs"
PYTHON_DIR="$DEMO_DIR/python"
FIXTURES="$ROOT/tests/fixtures"
mkdir -p "$LOGS"

PIDS=""
PASS=0
FAIL=0
SCENARIO=""

# MSYS converts environment values that look like POSIX paths when it spawns native programs
# (`/t/` reaches python as `T://`). The tunnel path must arrive verbatim, so its variable is
# excluded from that conversion; the exclusion is a no-op on Linux and macOS.
MSYS2_ENV_CONV_EXCL="TUNNEL_ROUTE;${MSYS2_ENV_CONV_EXCL:-}"
export MSYS2_ENV_CONV_EXCL

# ---------------------------------------------------------------------------------------------
# environment
# ---------------------------------------------------------------------------------------------

py() {
    # A candidate counts only when it really runs code: on Windows `python3` on PATH is frequently
    # the Microsoft Store execution alias, which opens the Store instead of executing a script.
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'pass' >/dev/null 2>&1; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    echo "!! python3/python not found on PATH (or only the Microsoft Store alias)" >&2
    return 1
}

PY=$(py) || exit 1

overtls_bin() {
    for candidate in \
        "$ROOT/target/release/overtls-bin.exe" \
        "$ROOT/target/release/overtls-bin" \
        "$ROOT/target/debug/overtls-bin.exe" \
        "$ROOT/target/debug/overtls-bin"; do
        if [ -f "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    cat >&2 <<'EOF'
!! overtls-bin not found.
   Build it first:  cargo build --release     (or: cargo build)
EOF
    return 1
}

BIN=$(overtls_bin) || exit 1

# ---------------------------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------------------------

banner() {
    printf '\n=== %s\n' "$*"
}

step() {
    printf '\n--- %s\n' "$*"
}

note() {
    printf '    %s\n' "$*"
}

# expect <text>: print the expectation for the following observation.
expect() {
    printf '    预期: %s\n' "$*"
}

# actual <text>: print what was observed.
actual() {
    printf '    实际: %s\n' "$*"
}

check() {
    # check <description> <command...>: pass when the command succeeds.
    description=$1
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$description"
    else
        fail "$description"
    fi
}

pass() {
    PASS=$((PASS + 1))
    printf '    [PASS] %s\n' "$*"
}

fail() {
    FAIL=$((FAIL + 1))
    printf '    [FAIL] %s\n' "$*"
}

scenario_begin() {
    SCENARIO="$1"
    printf '\n################################################################\n'
    printf '# %s\n' "$SCENARIO"
    printf '################################################################\n'
    printf '    binary: %s\n' "$BIN"
}

scenario_end() {
    printf '\n    scenario result: %s (%s passed, %s failed)\n' \
        "$([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)" "$PASS" "$FAIL"
    [ "$FAIL" -eq 0 ] || return 1
    return 0
}

# ---------------------------------------------------------------------------------------------
# ports and processes
# ---------------------------------------------------------------------------------------------

free_port() {
    "$PY" -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

wait_port() {
    # wait_port HOST PORT [TIMEOUT]
    "$PY" - "$1" "$2" "${3:-10}" <<'PYEOF'
import socket, sys, time
host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
deadline = time.time() + timeout
while time.time() < deadline:
    try:
        socket.create_connection((host, port), 0.3).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)
PYEOF
}

port_closed() {
    ! wait_port "$1" "$2" 1
}

# run_with_timeout [--log FILE] SECONDS COMMAND...: run COMMAND with a hard deadline through
# demo/python/run_with_timeout.py; a deadline hit prints `!! timed out after <s>s` and returns 124.
# stdout/stderr are copied live (and into FILE with `--log`). Used around cargo in scenario 09;
# run_all.sh calls the same helper (it does not source this file).
run_with_timeout() {
    "$PY" "$PYTHON_DIR/run_with_timeout.py" "$@"
}

# start <logname> <command...>: start a background process, remember its pid.
start() {
    logname=$1
    shift
    "$@" >"$LOGS/$logname.log" 2>&1 &
    pid=$!
    PIDS="$PIDS $pid"
    sleep 0.3
    kill -0 "$pid" 2>/dev/null || {
        printf '    !! %s exited immediately, see %s\n' "$logname" "$LOGS/$logname.log"
        return 1
    }
    printf '    started %s (pid %s, log %s)\n' "$logname" "$pid" "$LOGS/$logname.log"
}

stop_pid() {
    pid=$1
    [ -n "$pid" ] || return 0
    # `kill` takes the MSYS pid that `$!` reports; `taskkill //PID` would need the native pid and
    # could hit an unrelated process that happens to reuse that id, so it is not used here.
    kill "$pid" >/dev/null 2>&1 || true
    sleep 0.2
    if kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1 || true
    fi
}

cleanup() {
    for pid in $PIDS; do
        stop_pid "$pid"
    done
    PIDS=""
}

trap cleanup EXIT
# Signal traps must exit: a handler that only cleans up returns into the scenario, which would then
# print a summary (and possibly a "PASS") for an interrupted run.
trap 'cleanup; exit 130' INT TERM

# ---------------------------------------------------------------------------------------------
# configuration templates
# ---------------------------------------------------------------------------------------------

# gen_server_cfg <out> <listen_port> <forward_addr>
#
# Environment knobs (all optional):
#   TUNNEL_ROUTE     tunnel path (JSON value is emitted verbatim, default "/t/").
#                    Note: the name deliberately avoids "PATH" - MSYS converts env vars whose name
#                    looks like a path list, which would rewrite "/t/" into "T:/".
#   DISABLE_TLS      true|false (default true)
#   CERTFILE KEYFILE server certificate paths (TLS mode)
#   PANEL_URL PANEL_TOKEN PANEL_NODE_ID PANEL_INTERVAL PANEL_ENABLED  panel sync settings
gen_server_cfg() {
    SERVER_CFG_OUT=$1 SERVER_CFG_PORT=$2 SERVER_CFG_FORWARD=$3 "$PY" - <<'PYEOF'
import json, os
path = os.environ["SERVER_CFG_OUT"]
raw_tunnel_path = os.environ.get("TUNNEL_ROUTE", "/t/")
try:
    tunnel_path = json.loads(raw_tunnel_path)
except ValueError:
    tunnel_path = raw_tunnel_path
top = {
    "tunnel_path": tunnel_path,
    "test_timeout_secs": int(os.environ.get("TEST_TIMEOUT_SECS", "10")),
}
settings = {
    "disable_tls": os.environ.get("DISABLE_TLS", "true") == "true",
    "listen_host": "127.0.0.1",
    "listen_port": int(os.environ["SERVER_CFG_PORT"]),
    "forward_addr": os.environ["SERVER_CFG_FORWARD"],
}
if os.environ.get("CERTFILE"):
    settings["certfile"] = os.environ["CERTFILE"]
if os.environ.get("KEYFILE"):
    settings["keyfile"] = os.environ["KEYFILE"]
if os.environ.get("PANEL_URL"):
    panel = {
        "enabled": os.environ.get("PANEL_ENABLED", "true") == "true",
        "webapi_url": os.environ["PANEL_URL"],
        "webapi_token": os.environ.get("PANEL_TOKEN", "demo-token"),
        "node_id": int(os.environ.get("PANEL_NODE_ID", "1")),
        "api_update_time": int(os.environ.get("PANEL_INTERVAL", "10")),
    }
    settings["panel_sync"] = panel
doc = dict(top)
doc["server_settings"] = settings
with open(path, "w") as handle:
    json.dump(doc, handle, indent=4)
PYEOF
}

# gen_client_cfg <out> <server_port> <listen_port>
#
# Environment knobs (all optional):
#   TUNNEL_ROUTE     tunnel path (default "/t/")
#   DISABLE_TLS      true|false (default true)
#   SERVER_HOST      default 127.0.0.1
#   CAFILE SERVER_DOMAIN DANGEROUS_MODE  TLS verification settings
#   CLIENT_ID ADVERTISE_IP POOL_MAX_SIZE
gen_client_cfg() {
    CLIENT_CFG_OUT=$1 CLIENT_CFG_SERVER_PORT=$2 CLIENT_CFG_LISTEN_PORT=$3 "$PY" - <<'PYEOF'
import json, os
path = os.environ["CLIENT_CFG_OUT"]
raw_tunnel_path = os.environ.get("TUNNEL_ROUTE", "/t/")
try:
    tunnel_path = json.loads(raw_tunnel_path)
except ValueError:
    tunnel_path = raw_tunnel_path
top = {
    "tunnel_path": tunnel_path,
    "test_timeout_secs": int(os.environ.get("TEST_TIMEOUT_SECS", "10")),
}
settings = {
    "disable_tls": os.environ.get("DISABLE_TLS", "true") == "true",
    "server_host": os.environ.get("SERVER_HOST", "127.0.0.1"),
    "server_port": int(os.environ["CLIENT_CFG_SERVER_PORT"]),
    "listen": "mixed://127.0.0.1:%s" % os.environ["CLIENT_CFG_LISTEN_PORT"],
    "advertise_ip": os.environ.get("ADVERTISE_IP", "127.0.0.1"),
    "pool_max_size": int(os.environ.get("POOL_MAX_SIZE", "8")),
}
if os.environ.get("CAFILE"):
    settings["cafile"] = os.environ["CAFILE"]
if os.environ.get("SERVER_DOMAIN"):
    settings["server_domain"] = os.environ["SERVER_DOMAIN"]
if os.environ.get("DANGEROUS_MODE"):
    settings["dangerous_mode"] = os.environ["DANGEROUS_MODE"] == "true"
if os.environ.get("CLIENT_ID"):
    settings["client_id"] = os.environ["CLIENT_ID"]
doc = dict(top)
doc["client_settings"] = settings
with open(path, "w") as handle:
    json.dump(doc, handle, indent=4)
PYEOF
}

start_server() {
    # start_server <config> [tag]
    tag=${2:-}
    start "server${tag:+-$tag}" "$BIN" -r server -c "$1" -v "${VERBOSITY:-debug}"
}

start_client() {
    # start_client <config> [tag]
    # The client validates the server endpoint once at startup (`check_correctness`) and exits when
    # that connection fails, so a slow server bind is retried a few times before giving up.
    cfg=$1
    tag=${2:-}
    attempt=1
    while [ "$attempt" -le 3 ]; do
        if start "client${tag:+-$tag}" "$BIN" -r client -c "$cfg" -v "${VERBOSITY:-debug}"; then
            return 0
        fi
        attempt=$((attempt + 1))
        [ "$attempt" -le 3 ] && sleep 1
    done
    return 1
}

have() {
    command -v "$1" >/dev/null 2>&1
}

# socks5_greeting HOST PORT -> prints "REPLY <hex>" (method selection) or "FAILED <reason>".
#
# The overtls client acquires its WebSocket connection *before* answering the local SOCKS5 client,
# so a failed TLS handshake shows up as "no reply at all".
socks5_greeting() {
    "$PY" - "$1" "$2" <<'PYEOF'
import socket, sys
try:
    sock = socket.create_connection((sys.argv[1], int(sys.argv[2])), 3)
    sock.sendall(b"\x05\x01\x00")
    sock.settimeout(5)
    data = sock.recv(2)
    print("REPLY %s" % data.hex() if data else "FAILED closed without reply")
except Exception as error:
    print("FAILED %s" % error)
PYEOF
}

# wait_log NAME PATTERN [TIMEOUT] -> true once the log contains PATTERN.
wait_log() {
    "$PY" - "$LOGS/$1.log" "$2" "${3:-10}" <<'PYEOF'
import sys, time
path, pattern, timeout = sys.argv[1], sys.argv[2], float(sys.argv[3])
deadline = time.time() + timeout
while time.time() < deadline:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            if pattern in handle.read():
                sys.exit(0)
    except OSError:
        pass
    time.sleep(0.2)
sys.exit(1)
PYEOF
}

# probe <description> <expected-substring> <probe args...>
#
# Runs demo/python/http_probe.py, prints its output and fails unless the output contains the
# expected substring (pass '-' to only require a successful exit status).
probe() {
    description=$1
    expected=$2
    shift 2
    output=$("$PY" "$PYTHON_DIR/http_probe.py" "$@" 2>&1)
    printf '%s\n' "$output" | sed 's/^/        /'
    if [ "$expected" = "-" ]; then
        case "$output" in
            FAILED* | "EOF"*) fail "$description ($output)"; return 1 ;;
            *) pass "$description" ;;
        esac
        return 0
    fi
    case "$output" in
        *"$expected"*) pass "$description" ;;
        *) fail "$description (expected \"$expected\", got \"$output\")" ;;
    esac
}

show_log() {
    # show_log <name> [lines]
    name=$1
    lines=${2:-8}
    printf '    --- %s (last %s lines) ---\n' "$name" "$lines"
    tail -n "$lines" "$LOGS/$name.log" 2>/dev/null | sed 's/^/    /'
}

log_contains() {
    grep -q -- "$2" "$LOGS/$1.log" 2>/dev/null
}

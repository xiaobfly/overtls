#!/usr/bin/env bash
# Scenario 08 - `tunnel_path` handling (COR-01).
#
# A `tunnel_path` array is normalized by `Config::check_correctness`; entries that only contain
# slashes or whitespace are dropped, and an array that loses every entry (`[""]`, `["/"]`) never
# matches anything - the server then forwards *every* request, including complete WebSocket
# handshakes, to `forward_addr`.
. "$(dirname "$0")/../lib.sh"

scenario_begin "08 tunnel_path: multiple entries and the degenerated array"

SRV_PORT=$(free_port)
DEGEN_PORT=$(free_port)
HTTP_PORT=$(free_port)

step "start the forward target on 127.0.0.1:$HTTP_PORT"
start target "$PY" "$PYTHON_DIR/http_target.py" --port "$HTTP_PORT"
wait_port 127.0.0.1 "$HTTP_PORT" 10 || fail "http target did not start"

printf 'GET /a/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n' >"$RUN/req-a.txt"
printf 'GET /b/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n' >"$RUN/req-b.txt"
printf 'GET /t/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n' >"$RUN/req-t.txt"

step "server A with tunnel_path = [\"/a/\", \"/b/\"]"
export DISABLE_TLS=true
export TUNNEL_ROUTE='["/a/","/b/"]'
gen_server_cfg "$RUN/server-a.json" "$SRV_PORT" "http://127.0.0.1:$HTTP_PORT"
start_server "$RUN/server-a.json"
wait_port 127.0.0.1 "$SRV_PORT" 15 || fail "server A did not listen"
probe "/a/ performs the handshake" "101" --raw "$RUN/req-a.txt" --host "127.0.0.1:$SRV_PORT" --timeout 2
probe "/b/ performs the handshake" "101" --raw "$RUN/req-b.txt" --host "127.0.0.1:$SRV_PORT" --timeout 2
probe "/t/ is not configured and gets forwarded" "HTTP-TARGET-BODY" --raw "$RUN/req-t.txt" --host "127.0.0.1:$SRV_PORT"

step "server B with tunnel_path = [\"\"] (every element degenerates to empty)"
expect "the tunnel path never matches, so even a valid handshake is forwarded to the target"
export TUNNEL_ROUTE='[""]'
gen_server_cfg "$RUN/server-degen.json" "$DEGEN_PORT" "http://127.0.0.1:$HTTP_PORT"
start_server "$RUN/server-degen.json" degen
wait_port 127.0.0.1 "$DEGEN_PORT" 15 || fail "server B did not listen"
probe "/t/ is forwarded instead of upgraded" "HTTP-TARGET-BODY" --raw "$RUN/req-t.txt" --host "127.0.0.1:$DEGEN_PORT"
show_log server-degen 3
if log_contains server-degen "not match path"; then
    pass "the degenerated config reports a path mismatch for a request that should have matched"
else
    fail "no 'not match path' line in the degenerated server log"
fi

scenario_end

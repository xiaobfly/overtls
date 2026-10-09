#!/usr/bin/env bash
# Scenario 04 - the camouflage fallback: what a scanner, browser or reverse proxy sees.
#
# A request whose path does not match `tunnel_path` is forwarded verbatim to `forward_addr`; a
# request that matches the tunnel path without a WebSocket upgrade is closed without any response
# (no 400, no 404 - nothing to fingerprint); a matching request with the upgrade headers performs
# the handshake.
. "$(dirname "$0")/../lib.sh"

scenario_begin "04 forward fallback and tunnel path handling"

SRV_PORT=$(free_port)
HTTP_PORT=$(free_port)

step "start the forward target on 127.0.0.1:$HTTP_PORT"
start target "$PY" "$PYTHON_DIR/http_target.py" --port "$HTTP_PORT"
wait_port 127.0.0.1 "$HTTP_PORT" 10 || fail "http target did not start"

step "start the overtls server on $SRV_PORT (no client needed for this scenario)"
export DISABLE_TLS=true TUNNEL_ROUTE=/t/
gen_server_cfg "$RUN/server.json" "$SRV_PORT" "http://127.0.0.1:$HTTP_PORT"
start_server "$RUN/server.json"
wait_port 127.0.0.1 "$SRV_PORT" 15 || fail "server did not listen"

step "unmatched path -> forwarded verbatim"
expect "200 OK with the target body, and the exact request line at the target"
probe "GET /anything is forwarded" "HTTP-TARGET-BODY" --url "http://127.0.0.1:$SRV_PORT/anything"
show_log target 3

step "tunnel path without a WebSocket upgrade"
expect "the connection is closed with zero bytes (no status line, no error page)"
printf 'GET /t/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' >"$RUN/req-no-upgrade.txt"
probe "no response for /t/ without upgrade headers" "EOF" --raw "$RUN/req-no-upgrade.txt" --host "127.0.0.1:$SRV_PORT"
show_log server 4

step "tunnel path with the WebSocket upgrade"
expect "HTTP/1.1 101 Switching Protocols"
printf 'GET /t/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n' >"$RUN/req-upgrade.txt"
probe "101 for /t/ with upgrade headers" "101" --raw "$RUN/req-upgrade.txt" --host "127.0.0.1:$SRV_PORT" --timeout 2
show_log server 4

scenario_end

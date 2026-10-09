#!/usr/bin/env bash
# Scenario 02 - SOCKS5 UDP ASSOCIATE: the tunnel that actually carries payload in this sandbox.
#
# Unlike TCP destinations, the UDP relay has no private-range filter (`src/server.rs` only rewrites
# DNS-to-private destinations to 8.8.8.8), so a loopback UDP echo server is reachable through the
# WebSocket tunnel. The reply advertises `advertise_ip` (127.0.0.1 here).
. "$(dirname "$0")/../lib.sh"

scenario_begin "02 SOCKS5 UDP: associate, advertise_ip, round trip"

SRV_PORT=$(free_port)
CLIENT_PORT=$(free_port)
UDP_PORT=$(free_port)

step "start the UDP echo target on 127.0.0.1:$UDP_PORT"
start udp-echo "$PY" "$PYTHON_DIR/udp_echo.py" --port "$UDP_PORT" --count 50
sleep 0.5

step "start overtls server ($SRV_PORT, plaintext) and client ($CLIENT_PORT)"
export DISABLE_TLS=true TUNNEL_ROUTE=/t/ ADVERTISE_IP=127.0.0.1
gen_server_cfg "$RUN/server.json" "$SRV_PORT" "http://127.0.0.1:9"
gen_client_cfg "$RUN/client.json" "$SRV_PORT" "$CLIENT_PORT"
start_server "$RUN/server.json"
# The client validates the server endpoint once at startup, so the server must listen first.
wait_port 127.0.0.1 "$SRV_PORT" 15 || fail "server did not listen"
start_client "$RUN/client.json"
wait_port 127.0.0.1 "$CLIENT_PORT" 15 || fail "client did not listen"

step "UDP ASSOCIATE + two datagrams through the client"
expect "the associate reply advertises 127.0.0.1, both datagrams come back unchanged"
output=$("$PY" "$PYTHON_DIR/socks5_udp.py" --proxy "127.0.0.1:$CLIENT_PORT" --target "127.0.0.1:$UDP_PORT" \
    --payload DEMO-UDP --count 2 --timeout 5 2>&1)
printf '%s\n' "$output" | sed 's/^/        /'
case "$output" in
    *OK*) pass "UDP round trip through the tunnel" ;;
    *) fail "UDP round trip failed" ;;
esac
show_log server 6

scenario_end

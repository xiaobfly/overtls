#!/usr/bin/env bash
# Scenario 07 - SSPanel `mod_mu` synchronisation.
#
# Contract (`src/panel_sync.rs`): `GET {webapi_url}/mod_mu/users?key=..&node_id=..` must answer
# `{"ret":<non-zero>,"data":[{"client_id":..,"enable":..}]}`; `POST .../mod_mu/users/traffic` gets
# `{reporter_id,sequence,data:[{client_id,u,d}]}`. The sync interval is `api_update_time.max(10)`
# seconds, the first tick fires immediately, and `enable: false` tears a running tunnel down within
# about a second.
. "$(dirname "$0")/../lib.sh"

scenario_begin "07 panel sync: enable / disable / traffic report"

SRV_PORT=$(free_port)
CLIENT_PORT=$(free_port)
PANEL_PORT=$(free_port)
UDP_PORT=$(free_port)
CLIENT_ID=33959370-71e0-401d-9746-cda471fc5926
STATE="$RUN/panel.state"

step "start a fake panel (demo/python/http_target.py --panel) and the UDP echo target"
echo true >"$STATE"
start panel "$PY" "$PYTHON_DIR/http_target.py" --panel --state "$STATE" --port "$PANEL_PORT" --client-id "$CLIENT_ID"
start udp-echo "$PY" "$PYTHON_DIR/udp_echo.py" --port "$UDP_PORT" --count 50
wait_port 127.0.0.1 "$PANEL_PORT" 10 || fail "panel did not start"
sleep 0.5

step "start server (panel enabled) and a client with that client id"
export DISABLE_TLS=true TUNNEL_ROUTE=/t/ ADVERTISE_IP=127.0.0.1
export PANEL_URL="http://127.0.0.1:$PANEL_PORT/" PANEL_TOKEN=demo-token PANEL_NODE_ID=1 PANEL_INTERVAL=10 PANEL_ENABLED=true
export CLIENT_ID
gen_server_cfg "$RUN/server.json" "$SRV_PORT" "http://127.0.0.1:9"
gen_client_cfg "$RUN/client.json" "$SRV_PORT" "$CLIENT_PORT"
start_server "$RUN/server.json"
# The client validates the server endpoint once at startup, so the server must listen first.
wait_port 127.0.0.1 "$SRV_PORT" 15 || fail "server did not listen"
start_client "$RUN/client.json"
wait_port 127.0.0.1 "$CLIENT_PORT" 15 || fail "client did not listen"

step "enable = true: the panel is polled and the tunnel works"
if wait_log panel "GET /mod_mu/users" 10; then
    pass "the server synchronised with the panel"
else
    fail "no /mod_mu/users request arrived at the panel"
fi
output=$("$PY" "$PYTHON_DIR/socks5_udp.py" --proxy "127.0.0.1:$CLIENT_PORT" --target "127.0.0.1:$UDP_PORT" \
    --payload PANEL-ENABLED --timeout 5 2>&1)
case "$output" in
    *OK*) pass "an enabled client id may use the tunnel" ;;
    *) fail "an enabled client id could not use the tunnel: $output" ;;
esac

step "wait for one reporting interval: the traffic report is posted"
expect "a TRAFFIC line with reporter_id/sequence/data[client_id,u,d]"
if wait_log panel "TRAFFIC" 20; then
    pass "the server reported traffic to the panel"
else
    fail "no traffic report within 20s"
fi
grep -- "TRAFFIC" "$LOGS/panel.log" | tail -n 2 | sed 's/^/        /'

step "flip the panel to enable = false"
echo false >"$STATE"
if wait_log server "disabled by panel sync" 25; then
    pass "the server disabled the client id after the next sync"
else
    fail "the client id was not disabled within 25s"
fi
show_log server 4

step "a disabled client id can no longer use the tunnel"
sleep 2
output=$("$PY" "$PYTHON_DIR/socks5_udp.py" --proxy "127.0.0.1:$CLIENT_PORT" --target "127.0.0.1:$UDP_PORT" \
    --payload PANEL-DISABLED --timeout 3 2>&1)
actual "$(printf '%s' "$output" | tr '\n' ' ')"
case "$output" in
    *OK*) fail "a disabled client id still tunnels traffic" ;;
    *) pass "traffic is refused for the disabled client id" ;;
esac

scenario_end

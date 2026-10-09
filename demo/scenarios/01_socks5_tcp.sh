#!/usr/bin/env bash
# Scenario 01 - SOCKS5 mode: TCP destinations through the tunnel and the camouflage fallback.
#
# Observation target: the server refuses TCP destinations inside private ranges
# (`src/server.rs::tcp_stream_from_s5_address`), so a loopback target is never reached even though
# the client answers the SOCKS5 request with "Succeeded" first. The positive TCP path in this setup
# is the fallback to `forward_addr` (scenario 04).
. "$(dirname "$0")/../lib.sh"

scenario_begin "01 SOCKS5 TCP: private destinations refused, fallback serves HTTP"

SRV_PORT=$(free_port)
CLIENT_PORT=$(free_port)
HTTP_PORT=$(free_port)

step "start the forward target on 127.0.0.1:$HTTP_PORT"
start target "$PY" "$PYTHON_DIR/http_target.py" --port "$HTTP_PORT"
wait_port 127.0.0.1 "$HTTP_PORT" 10 || fail "http target did not start"

step "start overtls server ($SRV_PORT, plaintext) and client ($CLIENT_PORT)"
export DISABLE_TLS=true TUNNEL_ROUTE=/t/
gen_server_cfg "$RUN/server.json" "$SRV_PORT" "http://127.0.0.1:$HTTP_PORT"
gen_client_cfg "$RUN/client.json" "$SRV_PORT" "$CLIENT_PORT"
start_server "$RUN/server.json"
# The client validates the server endpoint once at startup (`check_correctness`), so the server has
# to be listening before the first client is started.
wait_port 127.0.0.1 "$SRV_PORT" 15 || fail "server did not listen"
start_client "$RUN/client.json"
wait_port 127.0.0.1 "$CLIENT_PORT" 15 || fail "client did not listen"

step "SOCKS5 CONNECT to 127.0.0.1:$HTTP_PORT through the client"
expect "the SOCKS5 request is answered, then nothing: the server refuses the private destination"
if have curl; then
    note "equivalent: curl -sv -x socks5h://127.0.0.1:$CLIENT_PORT http://127.0.0.1:$HTTP_PORT/"
    curl -s -S -o /dev/null -x "socks5h://127.0.0.1:$CLIENT_PORT" --max-time 5 "http://127.0.0.1:$HTTP_PORT/" >"$RUN/curl-01.log" 2>&1
    actual "curl exit code $? (see $RUN/curl-01.log; no body expected)"
else
    note "curl not found - using demo/python/http_probe.py with the SOCKS5 mode skipped"
fi

sleep 0.5
if log_contains server "destination address is private, skipping"; then
    pass "server refused the loopback destination (log: destination address is private, skipping)"
else
    fail "the refusal is missing in the server log"
fi
show_log server 6

step "positive TCP path: the camouflage fallback carries a normal HTTP request"
expect "200 OK with the body of the forward target, and the request is logged by the target"
probe "fallback answers 200 + target body" "HTTP-TARGET-BODY" --url "http://127.0.0.1:$SRV_PORT/anything"
show_log target 3

scenario_end

#!/usr/bin/env bash
# Scenario 03 - HTTP proxy mode of the client (`mixed://` listener).
#
# The client sniffs the first bytes: `0x05` -> SOCKS5, an ASCII HTTP verb -> HTTP proxy mode via
# `socks-hub`. Both HTTP shapes end up in the same tunnel to the request target and inherit the
# server's private-destination guard: an absolute-form GET gets no response at all, a CONNECT to a
# loopback target is answered `HTTP/1.1 200` first and then stays silent (see scenario 04 for the
# HTTP path that does work).
. "$(dirname "$0")/../lib.sh"

scenario_begin "03 HTTP proxy mode: absolute-form GET and CONNECT"

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
# The client validates the server endpoint once at startup, so the server must listen first.
wait_port 127.0.0.1 "$SRV_PORT" 15 || fail "server did not listen"
start_client "$RUN/client.json"
wait_port 127.0.0.1 "$CLIENT_PORT" 15 || fail "client did not listen"

step "absolute-form GET through the HTTP proxy"
expect "no HTTP response at all: the client tunnels to the URI authority, which the server refuses"
note "equivalent: curl -x http://127.0.0.1:$CLIENT_PORT http://127.0.0.1:$HTTP_PORT/"
output=$("$PY" "$PYTHON_DIR/http_probe.py" --proxy "127.0.0.1:$CLIENT_PORT" --url "http://127.0.0.1:$HTTP_PORT/" --timeout 3 2>&1)
printf '%s\n' "$output" | sed 's/^/        /'
case "$output" in
    *STATUS*) fail "the proxy answered a request it must have refused: $output" ;;
    # The client keeps the local connection open while the tunnel is refused, so the probe usually
    # reports its own timeout; on a platform where the client closes instead, it reports EOF.
    EOF*|FAILED*) pass "the absolute-form request receives no HTTP response ($output)" ;;
    *) fail "unexpected probe output: $output" ;;
esac
if wait_log server "destination address is private, skipping" 5; then
    pass "server refused the destination derived from the absolute URI"
else
    fail "the refusal is missing in the server log"
fi

step "CONNECT through the HTTP proxy"
expect "the proxy answers HTTP/1.1 200, then stays silent (the tunnel is refused)"
note "equivalent: curl -p -x http://127.0.0.1:$CLIENT_PORT http://127.0.0.1:$HTTP_PORT/"
output=$("$PY" "$PYTHON_DIR/http_probe.py" --connect-proxy "127.0.0.1:$CLIENT_PORT" --url "http://127.0.0.1:$HTTP_PORT/" --timeout 3 2>&1)
printf '%s\n' "$output" | sed 's/^/        /'
case "$output" in
    "CONNECT-STATUS HTTP/1.1 200"*) pass "CONNECT is answered HTTP/1.1 200 before the tunnel goes silent" ;;
    *) fail "expected a 200 CONNECT reply, got: $output" ;;
esac
if wait_log server "destination address is private, skipping" 5; then
    pass "the CONNECT tunnel was refused as well"
else
    fail "the refusal is missing in the server log"
fi
show_log server 6

step "conclusion"
note "the client's HTTP proxy is only usable with public destinations in this build;"
note "a working HTTP flow against a local disguise endpoint is the server's forward fallback (04)."

scenario_end

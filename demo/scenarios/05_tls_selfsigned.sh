#!/usr/bin/env bash
# Scenario 05 - TLS with the committed test CAs (`tests/fixtures/ca-*`).
#
# The server loads `certfile`/`keyfile`; the client verifies against `cafile` (a path or inline PEM,
# unioned with the webpki roots) plus `server_domain` as the SNI/verification name. The positive
# observation is a UDP round trip through the encrypted tunnel, because TCP destinations inside
# private ranges are refused (scenario 01).
. "$(dirname "$0")/../lib.sh"

scenario_begin "05 TLS: cafile, server_domain and dangerous_mode"

SRV_PORT=$(free_port)
CLIENT_A_PORT=$(free_port)
CLIENT_B_PORT=$(free_port)
CLIENT_C_PORT=$(free_port)
UDP_PORT=$(free_port)

step "start the UDP echo target on 127.0.0.1:$UDP_PORT"
start udp-echo "$PY" "$PYTHON_DIR/udp_echo.py" --port "$UDP_PORT" --count 50
sleep 0.5

step "start the TLS server with tests/fixtures/ca-a/server.crt"
export DISABLE_TLS=false TUNNEL_ROUTE=/t/ ADVERTISE_IP=127.0.0.1
export CERTFILE="$FIXTURES/ca-a/server.crt" KEYFILE="$FIXTURES/ca-a/server.key"
gen_server_cfg "$RUN/server.json" "$SRV_PORT" "http://127.0.0.1:9"
start_server "$RUN/server.json"
wait_port 127.0.0.1 "$SRV_PORT" 15 || fail "server did not listen"
if log_contains server "using TLS"; then pass "server is using TLS"; else fail "server is not using TLS"; fi

step "client A: cafile = ca-a root, server_domain = example.com"
expect "the handshake completes (SOCKS5 method reply 05 00) and UDP traffic flows"
export CAFILE="$FIXTURES/ca-a/root.crt" SERVER_DOMAIN=example.com
gen_client_cfg "$RUN/client-a.json" "$SRV_PORT" "$CLIENT_A_PORT"
start_client "$RUN/client-a.json" a
wait_port 127.0.0.1 "$CLIENT_A_PORT" 15 || fail "client A did not listen"
greeting=$(socks5_greeting 127.0.0.1 "$CLIENT_A_PORT")
actual "SOCKS5 method reply: $greeting"
case "$greeting" in
    "REPLY 0500") pass "client A completed the TLS handshake" ;;
    *) fail "client A could not use the trusted certificate" ;;
esac
output=$("$PY" "$PYTHON_DIR/socks5_udp.py" --proxy "127.0.0.1:$CLIENT_A_PORT" --target "127.0.0.1:$UDP_PORT" \
    --payload TLS-DEMO --timeout 5 2>&1)
printf '%s\n' "$output" | sed 's/^/        /'
case "$output" in
    *OK*) pass "UDP round trip through the TLS tunnel" ;;
    *) fail "UDP round trip through the TLS tunnel failed" ;;
esac

step "client B: cafile = ca-b root (a different CA)"
expect "the client closes the local connection without any SOCKS5 reply"
export CAFILE="$FIXTURES/ca-b/root.crt"
gen_client_cfg "$RUN/client-b.json" "$SRV_PORT" "$CLIENT_B_PORT"
start_client "$RUN/client-b.json" b
wait_port 127.0.0.1 "$CLIENT_B_PORT" 15 || fail "client B did not listen"
greeting=$(socks5_greeting 127.0.0.1 "$CLIENT_B_PORT")
actual "SOCKS5 method reply: $greeting"
case "$greeting" in
    "REPLY 0500") fail "a foreign CA must not be accepted" ;;
    *) pass "the handshake failed as expected ($greeting)" ;;
esac

step "client C: cafile = ca-b root but dangerous_mode = true"
expect "TLS verification is skipped, so the very same certificate is accepted"
export CAFILE="$FIXTURES/ca-b/root.crt" DANGEROUS_MODE=true
gen_client_cfg "$RUN/client-c.json" "$SRV_PORT" "$CLIENT_C_PORT"
start_client "$RUN/client-c.json" c
wait_port 127.0.0.1 "$CLIENT_C_PORT" 15 || fail "client C did not listen"
greeting=$(socks5_greeting 127.0.0.1 "$CLIENT_C_PORT")
actual "SOCKS5 method reply: $greeting"
case "$greeting" in
    "REPLY 0500") pass "dangerous_mode bypasses certificate verification" ;;
    *) fail "dangerous_mode did not bypass verification" ;;
esac
if log_contains client-c "Dangerous mode enabled"; then
    pass "the client warns about dangerous mode in its log"
else
    fail "no dangerous-mode warning in the client log"
fi

scenario_end

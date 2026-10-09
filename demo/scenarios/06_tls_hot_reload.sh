#!/usr/bin/env bash
# Scenario 06 - certificate hot reload.
#
# `notify` watches the *parent directory* of `certfile`/`keyfile` (250 ms debounce) and swaps the
# TLS acceptor for new connections; existing connections keep the old certificate. Replacing the
# files at their configured paths is picked up, writing to a symlink target elsewhere is not.
. "$(dirname "$0")/../lib.sh"

scenario_begin "06 TLS hot reload: replacing the configured certificate files"

SRV_PORT=$(free_port)
CLIENT_PORT=$(free_port)
UDP_PORT=$(free_port)
CERT_DIR="$RUN/certs"

step "stage the ca-a certificate in $CERT_DIR"
mkdir -p "$CERT_DIR"
cp "$FIXTURES/ca-a/server.crt" "$CERT_DIR/server.crt"
cp "$FIXTURES/ca-a/server.key" "$CERT_DIR/server.key"
ls -l "$CERT_DIR" | sed 's/^/        /'

step "start the UDP echo target and the TLS server on the staged files"
start udp-echo "$PY" "$PYTHON_DIR/udp_echo.py" --port "$UDP_PORT" --count 50
sleep 0.5
export DISABLE_TLS=false TUNNEL_ROUTE=/t/ ADVERTISE_IP=127.0.0.1
export CERTFILE="$CERT_DIR/server.crt" KEYFILE="$CERT_DIR/server.key"
export CAFILE="$FIXTURES/ca-b/root.crt" SERVER_DOMAIN=example.com
gen_server_cfg "$RUN/server.json" "$SRV_PORT" "http://127.0.0.1:9"
gen_client_cfg "$RUN/client.json" "$SRV_PORT" "$CLIENT_PORT"
start_server "$RUN/server.json"
# The client validates the server endpoint once at startup, so the server must listen first.
wait_port 127.0.0.1 "$SRV_PORT" 15 || fail "server did not listen"
start_client "$RUN/client.json"
wait_port 127.0.0.1 "$CLIENT_PORT" 15 || fail "client did not listen"

step "before the swap: the ca-b client must not be able to use the ca-a certificate"
greeting=$(socks5_greeting 127.0.0.1 "$CLIENT_PORT")
actual "SOCKS5 method reply: $greeting"
case "$greeting" in
    "REPLY 0500") fail "the ca-b client must not be accepted yet" ;;
    *) pass "the ca-b client is rejected before the swap ($greeting)" ;;
esac

step "replace $CERT_DIR/server.crt and server.key with the ca-b certificate"
cp "$FIXTURES/ca-b/server.crt" "$CERT_DIR/server.crt"
cp "$FIXTURES/ca-b/server.key" "$CERT_DIR/server.key"
if wait_log server "reloaded server TLS certificate" 20; then
    pass "the server reloaded the certificate"
else
    fail "no reload within 20s"
fi
show_log server 4

step "after the swap: the same client must now succeed"
case "$(socks5_greeting 127.0.0.1 "$CLIENT_PORT")" in
    "REPLY 0500") pass "the reloaded certificate is used for new connections" ;;
    *) fail "the client still fails after the reload" ;;
esac
# The client's UDP tunnel reconnects on its own schedule (one second backoff after a failed
# attempt), so retry the datagram instead of requiring the first one to be relayed.
output=""
attempt=1
while [ "$attempt" -le 6 ]; do
    output=$("$PY" "$PYTHON_DIR/socks5_udp.py" --proxy "127.0.0.1:$CLIENT_PORT" --target "127.0.0.1:$UDP_PORT" \
        --payload AFTER-RELOAD --timeout 3 2>&1)
    case "$output" in
        *OK*) break ;;
    esac
    attempt=$((attempt + 1))
    sleep 1
done
printf '%s\n' "$output" | sed 's/^/        /'
case "$output" in
    *OK*) pass "traffic flows through the reloaded certificate (attempt $attempt)" ;;
    *) fail "traffic does not flow after the reload" ;;
esac

scenario_end

# TLS test fixtures

**Test-only material. Never use these keys or certificates outside the test suite.**

Two independent, self-signed certificate authorities (`ca-a`, `ca-b`) used to exercise the
server certificate loading, the client `cafile` / `server_domain` / `dangerous_mode` logic and the
certificate hot-reload path. Both leaf certificates carry the *same* subject alternative names
(`DNS:example.com`, `IP Address:127.0.0.1`), so a client reachable as `server_host = 127.0.0.1`
can verify the leaf either by `server_domain = "example.com"` (DNS SAN) or by the IP SAN.

`ca-c` is a third, independent CA whose leaf carries **only** `DNS:example.com` (no IP SAN). It is
used to pin down SEC-09: the certificate verification is bound to `server_domain` only, never to
`server_host`, so a client configured with `server_host = 127.0.0.1` (an IP literal) and
`server_domain = "example.com"` still completes the handshake against a leaf without any IP SAN.

| file | content |
|---|---|
| `ca-{a,b}/root.crt` | CA certificate (used as the client `cafile`) |
| `ca-{a,b}/root.key` | CA private key (kept so the leaf can be re-signed later) |
| `ca-{a,b}/server.crt` | leaf certificate (`CN=server-a` / `CN=server-b`), SAN: `DNS:example.com` + `IP Address:127.0.0.1` |
| `ca-{a,b}/server.key` | leaf private key |
| `ca-c/root.crt` | CA certificate (used as the client `cafile`) |
| `ca-c/root.key` | CA private key (kept so the leaf can be re-signed later) |
| `ca-c/server.crt` | leaf certificate (`CN=server-c`), SAN: `DNS:example.com` only |
| `ca-c/server.key` | leaf private key |

Validity: 3650 days from generation (2026-10-09), i.e. until 2036.

## Regeneration

Generated with the repository's own `install/selfsign.sh` (9 arguments), one CA per directory:

```sh
rm -rf tests/fixtures/ca-a tests/fixtures/ca-b tests/fixtures/ca-c
mkdir -p tests/fixtures/ca-a tests/fixtures/ca-b tests/fixtures/ca-c
(cd tests/fixtures/ca-a && sh ../../../install/selfsign.sh \
    CN JS CZ TestFixture TestCA-A server-a test@example.com example.com 127.0.0.1)
(cd tests/fixtures/ca-b && sh ../../../install/selfsign.sh \
    CN JS CZ TestFixture TestCA-B server-b test@example.com example.com 127.0.0.1)
(cd tests/fixtures/ca-c && sh ../../../install/selfsign.sh \
    CN JS CZ TestFixture TestCA-C server-c test@example.com example.com 127.0.0.1)
rm -f tests/fixtures/ca-*/server.csr tests/fixtures/ca-*/serverca.txt
```

`ca-c` needs one extra step: `selfsign.sh` always writes the `IP.1` SAN, so the leaf is re-signed
from the same CSR with a DNS-only extension file (the CA stays untouched, keeping `ca-c`
independent of `ca-a`/`ca-b`):

```sh
cat > tests/fixtures/ca-c/san-dns-only.cnf <<'EOF'
subjectAltName = @alt
extendedKeyUsage = serverAuth

[alt]
DNS.1 = example.com
EOF
openssl x509 -req -CA tests/fixtures/ca-c/root.crt -CAkey tests/fixtures/ca-c/root.key \
    -in tests/fixtures/ca-c/server.csr -out tests/fixtures/ca-c/server.crt \
    -extfile tests/fixtures/ca-c/san-dns-only.cnf -sha256 -set_serial 0x2222 -days 3650
rm -f tests/fixtures/ca-c/server.csr tests/fixtures/ca-c/san-dns-only.cnf
```

## Verification

```sh
openssl x509 -noout -subject -ext subjectAltName -in tests/fixtures/ca-a/server.crt
# subject=C=CN, ST=JS, L=CZ, O=TestFixture, OU=TestFixture, CN=server-a, emailAddress=test@example.com
# X509v3 Subject Alternative Name: DNS:example.com, IP Address:127.0.0.1

openssl x509 -noout -subject -ext subjectAltName -in tests/fixtures/ca-c/server.crt
# subject=C=CN, ST=JS, L=CZ, O=TestFixture, OU=TestFixture, CN=server-c, emailAddress=test@example.com
# X509v3 Subject Alternative Name: DNS:example.com
```

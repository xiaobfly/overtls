# overtls demo suite

Manual, human-readable walkthrough of the overtls behaviour: every scenario starts real processes
(target services, the server, one or more clients), drives traffic with `curl`-equivalent probes and
prints **预期** (expectation) next to **实际** (observation) for each step, followed by a
`scenario result: PASS|FAIL` line.

The machine-checked counterpart lives in `../tests/` (run by CI); this directory is for reading the
behaviour off the wire without a Rust debugging session.

## Prerequisites

| what | why |
|---|---|
| `cargo build --release` | the scenarios drive `target/release/overtls-bin` (falls back to `target/debug`) |
| python 3.8+ as `python3` or `python` | targets (`http_target.py`, `udp_echo.py`), probes (`http_probe.py`, `socks5_udp.py`) |
| `curl` (optional) | scenario 01 really runs a `curl -x socks5h://...` request against the client (its exit code is printed, not asserted) and prints the equivalent command; scenario 03 prints the equivalent commands only - the python probes do the asserted work |
| Git Bash on Windows | `demo/run_all.sh` runs under `sh`/`bash`; `run_all.ps1` locates Git Bash for you |

## Running

```sh
cargo build --release
sh demo/run_all.sh            # or: bash demo/run_all.sh    (Linux, macOS, Git Bash)
sh demo/scenarios/02_socks5_udp.sh   # a single scenario
```

```powershell
powershell -ExecutionPolicy Bypass -File demo\run_all.ps1
```

`run_all.ps1` runs `run_all.sh` through Git Bash *and* one native PowerShell scenario (no bash and no
python involved): it starts the release binary plus an `HttpListener` target, checks the camouflage
fallback with `Invoke-WebRequest` and probes the client's SOCKS5 greeting and HTTP proxy mode over
raw sockets (`.NET`'s `WebProxy` silently bypasses loopback proxies, so the byte-exact probe is the
honest one). It waits for the target to announce itself in `ps-target.log`; when the HTTP prefix
cannot be registered it reports the background job's own error and points at an elevated shell or
`netsh http add urlacl url=http://127.0.0.1:<port>/ user=%USERNAME%`.

Everything the scenarios write goes to `demo/.run/` (git-ignored), in a directory per scenario:
`demo/.run/<scenario>/logs/*.log` per process, `demo/.run/<scenario>/<config>.json` per role. Ports
are picked dynamically and the fixed file names live inside that per-scenario directory, so
scenarios can run **in parallel**. Each scenario kills the processes it started on exit (`EXIT`, and
`INT`/`TERM` with `exit 130`, so an interrupted run cannot print a stale `PASS`).

`run_all.sh` copies each scenario's output live to the terminal *and* into
`demo/.run/logs/run-<scenario>.log`, and wraps every scenario in a 900 s deadline
(`run_with_timeout`; a deadline hit returns 124 and is reported as `!! timed out after 900s`,
override with the `SCENARIO_TIMEOUT_SECS` environment variable). A scenario counts as passed only
when it exited zero *and* its log ends with the `scenario result: PASS` line, so neither a lost exit
status nor a killed run can show up as a false PASS. `run_all.ps1` keeps its own artifacts in
`demo/.run/logs/`.

## Scenarios

| scenario | what it shows |
|---|---|
| `01_socks5_tcp.sh` | SOCKS5 TCP destinations: the server refuses private ranges; the camouflage fallback serves HTTP |
| `02_socks5_udp.sh` | SOCKS5 UDP ASSOCIATE: `advertise_ip` in the reply, datagrams relayed by the tunnel |
| `03_http_proxy.sh` | the `mixed://` listener in HTTP proxy mode: absolute-form `GET` and `CONNECT` |
| `04_forward_fallback.sh` | `forward_addr` fallback, tunnel path without upgrade (silence), handshake with upgrade |
| `05_tls_selfsigned.sh` | TLS with the committed test CAs: `cafile`, `server_domain`, `dangerous_mode` |
| `06_tls_hot_reload.sh` | certificate hot reload after replacing the configured files |
| `07_panel_sync.sh` | fake SSPanel: `enable` gating in both directions and the traffic report body |
| `08_tunnel_path.sh` | `tunnel_path` array entries and the degenerated `[""]` array |
| `09_audit_demos.sh` | runs every `tests/audit_*.rs` file (the regression suite for `audit-report.md`) |

## Behaviour the demos pin down

These are observations, not recommendations; `audit-report.md` lists the same facts as findings and
`tests/audit_*.rs` asserts them.

1. **TCP destinations in private ranges are refused by the server** (`tcp_stream_from_s5_address`
   skips them). A loopback target is therefore unreachable through the tunnel even on one machine,
   while the *client* still answers the SOCKS5 request with `Succeeded` (COR-11). The positive TCP
   data path in this sandbox is the server's `forward_addr` fallback (scenario 04).
2. **UDP has no destination filter at all** (SEC-04): the same loopback target is reachable over the
   UDP tunnel, which is what makes scenarios 02/05/06/07 possible. Only DNS lookups aimed at private
   addresses are rewritten (IPv4 to `8.8.8.8:53`, IPv6 to `[2001:4860:4860::8888]:53`).
3. **The HTTP proxy of the client** (absolute-form `GET` and `CONNECT`) implements both shapes by
   building a tunnel to the request target, so both inherit the private-range refusal: an
   absolute-form `GET` gets no response at all, a `CONNECT` is answered `200 OK` and then goes
   silent.
4. **TLS**: `cafile` is a path *or* inline PEM and is unioned with the built-in webpki roots;
   `server_domain` is used for SNI *and* verification; a missing `cafile` falls back to those roots;
   `dangerous_mode: true` skips verification entirely (and warns). The certificate is reloaded when
   the file at the configured path changes (`notify`, 250 ms debounce); a write to a symlink target
   elsewhere is not observed.
5. **Panel (`mod_mu`)**: a successful sync requires `ret` to be non-zero (`{"ret":1,...}`), the
   interval is at least 10 s with the first tick immediately, `enable: false` and unregistered
   client ids tear down tunnels within about a second, and reports carry
   `{reporter_id,sequence,data:[{client_id,u,d}]}` with `u`/`d` counted as
   `payload + 14` per message; the `2 * handshake_length` constant is counted **upstream only** and
   only when the client identifies itself with a `Client-Id`.
6. **Fingerprints**: the client's upgrade request has no `User-Agent`, `Origin`,
   `Sec-WebSocket-Extensions` or ALPN and advertises a fixed 5-suite cipher list; the `Host` header
   carries no port even for a non-standard listen port.

## Layout

```
demo/
  lib.sh                  shared helpers (paths, ports, process handling, config generation)
  run_all.sh              runs scenarios/*.sh, prints a summary, non-zero exit on failure
  run_all.ps1             Git Bash entry point + one native PowerShell scenario
  scenarios/*.sh          the scenarios, each self-contained and exit-code honest
  python/http_target.py   HTTP target; --panel serves a fake mod_mu endpoint
  python/udp_echo.py      UDP echo target
  python/socks5_udp.py    SOCKS5 UDP ASSOCIATE client (round-trip check)
  python/http_probe.py    byte-exact HTTP probe (raw request, HTTP proxy, CONNECT)
  python/run_with_timeout.py  deadline wrapper (live + logged output, kills the whole process tree)
                          used by lib.sh and run_all.sh
  .run/                   created at runtime: demo/.run/<scenario>/{logs,configs,...} plus
                          demo/.run/logs/run-*.log from run_all.sh (git-ignored)
```

### Environment knobs of the config generators

`gen_server_cfg <out> <port> <forward_addr>` / `gen_client_cfg <out> <server_port> <listen_port>`
inside `lib.sh` read these variables: `TUNNEL_ROUTE`, `DISABLE_TLS`, `CERTFILE`, `KEYFILE`,
`PANEL_URL`, `PANEL_TOKEN`, `PANEL_NODE_ID`, `PANEL_INTERVAL`, `PANEL_ENABLED`, `SERVER_HOST`,
`CAFILE`, `SERVER_DOMAIN`, `DANGEROUS_MODE`, `CLIENT_ID`, `ADVERTISE_IP`, `POOL_MAX_SIZE`.

Note for Windows shells: MSYS rewrites environment values that look like POSIX paths when it spawns
native programs (`/t/` arrives as `T://`), so `TUNNEL_ROUTE` is listed in `MSYS2_ENV_CONV_EXCL`.
Paths that really are filesystem paths (`CERTFILE`, `CAFILE`, ...) *should* be converted, which is
what the shell does by itself.

Certificates used by scenarios 05/06 come from `tests/fixtures/` (see the README there); they are
test-only material.

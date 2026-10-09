# overtls 代码审计报告（安全 · 有效性 · 性能）

**本报告只给结论与修复建议，未修改任何仓库代码。**

---

## 1. 审计修订与范围

|项|值|
|---|---|
|仓库|`D:/OpenSources/network/overtls`|
|审计修订|`24b4edf80571f2bb3f4f8c5f6b2c4e6b948d520e`（`git rev-parse HEAD`，分支 `master`）|
|工作树|仅未跟踪文件：`AGENTS.md`、`openspec/`（审计前已存在，未改动）|
|构建|`cargo build --release` → `Finished \`release\` profile [optimized] target(s) in 48.24s`|
|版本串|`./target/release/overtls-bin.exe -V` → `overtls 0.3.15 (24b4edf 2026-10-09 06:42:39)`（P7 的 `cargo clean` + 重建后**同一路径**变为 `06:55:47`；同 commit、同尺寸，仅 52 字节时间戳差异，见 PRF-07）|
|离线测试|`cargo test tls_reload_event_tests -- --nocapture` → `2 passed; 0 failed; 2 filtered out`|
|release 体积|`target/release/overtls-bin.exe` = **13,817,856** 字节|
|本次审计新增的未跟踪文件|仅新增 `tmp/audit/`（`.gitignore:19` 忽略）与生成的 `Cargo.lock`（`.gitignore:22` 忽略）；`audit-report.md` 为本报告|

范围：`src/` 下全部 20 个 `.rs`（4474 行），加上 `Cargo.toml`、`build.rs`、`cbindgen.toml`、`config.json`、`.github/workflows/*`、`docker*/`、`install/*`；第三方行为只在“被本仓库调用点可达”时纳入，并就地读取 vendored 源码（`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`）确认默认值。

威胁模型四条：① 被动 DPI / 主动探测 ② 恶意服务器 / MITM ③ 恶意客户端 / 未授权滥用 ④ 本地宿主进程 / FFI。

**已知限制**
- `src/config.rs::test_config`（`src/config.rs:543`）会向 `www.gov.cn:443` 建立真实连接，本机联网条件下可通过；离线必然失败且未标 `#[ignore]` → 记为 `COR-09`。
- Android（`src/android.rs`）与 iOS 代码在 Windows 上被 `#![cfg(target_os = "android")]` 排除，本机无法编译或动态验证 → 该 lane 结论均为静态推导。
- 本机无 `socat`/`nc`，所有 PoC 用 Python 3.12 标准库实现；无 `valgrind`/`ASan`/`Miri`，FFI 内存错误只能靠“构造即 UB”与实跑退出码佐证。

---

## 2. 摘要表

|严重级|① DPI/探测|② 恶意服务器|③ 未授权/滥用|④ FFI/JNI|正确性|性能|依赖/构建|合计|
|---|---|---|---|---|---|---|---|---|
|Critical|0|0|**1**|0|0|0|0|**1**|
|High|0|1|**5**|**2**|**1**|0|0|**9**|
|Medium|3|5|2|3|2|2|4|**21**|
|Low|3|1|0|3|8|6|5|**26**|
|Info|—|—|—|—|—|—|—|见附录 C|

**Critical / High 一览**

|Id|标题|lane|
|---|---|---|
|`SEC-01`|未认证连接无并发上限、首读无超时；`accept()` 错误经 `?` 终止 `run_server` 且进程以 exit code 0 退出（全局 DoS）|③|
|`SEC-02`|`tunnel_path` 是唯一凭证，而出厂 `config.json` / Docker / release zip 内置的默认值就是公开常量 `/secret-tunnel-path/`|①③|
|`SEC-03`|`TrafficAudit::add_client` 无上限、无过期；未认证请求即可永久增长全局 HashMap|③|
|`SEC-04`|UDP 隧道目标无过滤：任意回环 / RFC1918 / `169.254.169.254` / CGNAT 可达（SSRF）|③|
|`SEC-05`|TCP 私网过滤覆盖不全，`::ffff:127.0.0.1` 等 IPv4-mapped 形态直接绕过|③|
|`SEC-06`|在 async 上下文中执行阻塞 `ToSocketAddrs`（每个 UDP 包一次）与阻塞 connect（最长 `test_timeout_secs`）→ 单个客户端可耗尽全部 worker 线程|③|
|`SEC-07`|`dangerous_mode=true` 无条件关闭证书校验，且可经 `ssr://` URL 注入（配置型 MITM 面）|②|
|`FFI-01`|`over_tls_client_run_with_ssr_url` 对 `url` 无空指针检查即 `CStr::from_ptr` → 构造即 UB|④|
|`FFI-03`|全部 C 导出与 JNI 入口无 `catch_unwind`；panic 穿越 `extern "C"` → 宿主进程 abort|④|
|`COR-10`|携带 `Client-Id` 的客户端在 1 秒内被无条件断开（出厂 `config.json` 即该组合），而不带该头者不受门控|③|

---

## 3. 发现明细

### 3.1 Critical

#### SEC-01 · 未认证可致服务进程退出（全局 DoS） · Critical · lane ③

位置：`src/server.rs:128`、`src/server.rs:279-283`、`src/lib.rs:135-139`

证据（`src/server.rs:127-128`）：
```rust
            ret = listener.accept() => {
                let (stream, peer_addr) = ret?;
```
证据（`src/server.rs:279-283`）：
```rust
    let mut buf = BytesMut::with_capacity(2048);
    let size = stream.read_buf(&mut buf).await?;
    if size == 0 {
        return Err(Error::from("empty request"));
    }
```
证据（`src/lib.rs:135-139`）：
```rust
    if let Err(e) = main_body.await {
        log::error!("{} -- main_body error: \"{e}\"", method_name_unstable!());
    }
    Ok(())
```

影响与前提：
1. 接受循环对每个连接 `tokio::spawn`，**没有任何并发上限、没有半开连接读超时**：连接建立后不发送任何字节即可让一个任务持有 TCP 连接（TLS 模式下还持有一条 rustls 会话）直到对端断开。
2. 一旦 fd/句柄被耗尽，`accept()` 返回 `EMFILE`/`WSAEMFILE`，`ret?` 使 `run_server` 返回 `Err`，经 `lib.rs::async_main` **只记日志并返回 `Ok(())`**，`main` 随之以 **exit code 0** 结束。
3. 安装脚本生成的 unit 是 `Restart=on-failure`（`install/overtls-install-2026.sh:317`），而 exit 0 **不会**触发重启 → 服务永久停止。`LimitNOFILE=1000000`（同文件 `:319`）只是把这个门槛抬高，不改变路径。
4. 前提：无需任何凭证（连接建立早于 `tunnel_path` 判定）。TLS 模式下 TLS 握手失败的错误路径（`acceptor.accept(stream).await?`）不影响第 1 点（连接本身仍被持有）。

复现：静态推导，未复现（无法在本机把 fd 上限压到可触发的量级而不影响宿主）。判定链条的每一环都有上述 `file:line` 支撑；**“吞错 + exit code 0”已旁证观测到**：并行 PoC 期间一个客户端因端口占用而绑定失败时，日志只有
`ERROR overtls] async_main -- main_body error: "IO error: 通常每个套接字地址…(os error 10048)"`
（`tmp/audit/logs/overtls_client.log`），进程随即以 0 退出、无任何非零返回码——即运行期致命错误不会让 supervisor 判定为失败。

修复建议：
- `accept()` 的错误分而治之：`Err(e) if e.kind() == WouldBlock || matches!(e.raw_os_error(), EMFILE|ENFILE|WSAEMFILE)` → 记录 + `tokio::time::sleep(50ms)` 继续，其余才致命。
- 给首个 `read_buf` 加超时（例如 `tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, ...)`），并用 `Semaphore`（如 4096）限制同时存活会话数，超限时直接关闭新连接。
- `async_main` 不再吞错：把 `main_body` 的错误向上传播，让进程以非 0 退出码结束（配合 `Restart=on-failure`）。

置信度：高（机制逐环可读；触发条件为静态推导）。

---

### 3.2 High

#### SEC-02 · `tunnel_path` 是唯一凭证，默认值公开 · High · lane ①③

位置：`config.json:6`、`docker/Dockerfile:3`、`docker_overtls_caddy/Dockerfile:4`、`src/config.rs:69`、`src/server.rs:419-433`

证据（`config.json:6`，随每个 release zip 一起分发，见 `.github/workflows/freebsd.yml:48`）：
```json
    "tunnel_path": "/secret-tunnel-path/",
```
证据（`docker/Dockerfile:3` 与 `docker_overtls_caddy/Dockerfile:4`）：
```dockerfile
ENV TUNNEL_PATH=/secret-tunnel-path/
```
证据（`src/server.rs:419-433`，`panel_sync.enabled` 默认 `false` 时不参与判定）：
```rust
    let mut panel_sync_enabled = true;
    let panel_sync_config = config.get_panel_sync_config();
    if let Some(panel_sync_config) = panel_sync_config
        && panel_sync_config.enabled.unwrap_or(false)
    {
        panel_sync_enabled = false;
```

影响与前提：默认配置下，能否建立隧道**只取决于 `path == tunnel_path`**（`src/server.rs:315-325`）。`config.json`、两个 Docker 镜像与所有 release zip 都携带同一个常量 `/secret-tunnel-path/`，README 还以它作为示例（`docker/README.md:3`）。任何未修改该值的部署（含“照文档跑起来”的绝大多数部署）等于公开的未授权隧道入口；与之配套的 `panel_sync` 默认关闭，所以连 Client-Id 都不需要。
反面证据（值得肯定）：安装脚本会生成 20 字符随机路径（`install/overtls-install.sh:96` 等 6 处 `reverse_proxy_location=$(random_string_gen 20)`）——问题只在“样例/Docker/默认值”这条路径上。

复现：`P6`（对默认路径与随机路径的响应差异）**+** `P1-A`（见附录 B：在 `panel_sync.enabled=false` 下，一条仅带 `GET /t/` 与 `UDP-Tunnel: true` 的裸 WebSocket 握手——**不含 `Client-Id`、不含 method/password 任何凭证**——即拿到 `101` 并完成 UDP 往返；反之如实携带 `Client-Id` 的客户端会被 `COR-10` 的 1 秒 tick 杀掉），加上配置本身即证据。

修复建议：把样例 `config.json` 与两个 Dockerfile 的默认值改成**运行时生成**（例如 Docker entrypoint 在 `TUNNEL_PATH` 未显式设置时生成随机值，并在日志中提示），样例配置改为占位符 `<REPLACE-WITH-RANDOM-PATH>`；`check_correctness` 对已知常量黑名单（`/secret-tunnel-path/`、`/tunnel/`、`/path/`）直接报错拒绝启动。

置信度：高。

#### SEC-03 · 审计表按 Client-Id 无上限增长 · High · lane ③

位置：`src/server.rs:415-417`、`src/traffic_audit.rs:73-75`、`src/panel_sync.rs:99-104`

证据（`src/server.rs:415-417`，在 `panel_sync` 判定**之前**执行）：
```rust
    if let Some(client_id) = &client_id {
        traffic_audit.lock().await.add_client(client_id);
    }
```
证据（`src/traffic_audit.rs:73-75`）：
```rust
    pub fn add_client(&mut self, client_id: &Uuid) {
        self.client_map.entry(*client_id).or_default();
    }
```
`remove_client` 在全仓库只有一处调用者：`src/panel_sync.rs:101`（同步循环里剔除面板已删除的用户）。

影响与前提：`Client-Id` 头完全由连接方提供（`src/server.rs:370-388` 仅要求可解析为 UUID），且**不需要**通过任何鉴权。默认配置下 `panel_sync.enabled=false`，因此没有任何代码会清理这张表：攻击者每次连接换一个随机 UUID 即可永久占用一个 `HashMap` 槽（`Uuid` 16B + `ClientNode` 24B + 表开销 ≈ 64–96B），百万级连接即上百 MB 常驻内存；该增长是单调的（进程重启才回收）。
前提：持有一条可建立隧道的连接（见 `SEC-02`：默认路径公开时等同于无需凭证）。

复现：静态推导，未复现（不改仓库代码的前提下，可用 100 万次握手证明内存增长，代价高、收益低）。

修复建议：`add_client` 加容量上限（LRU / 只保留最近 N 个），或在无 `panel_sync` 时直接不为未知 id 建表（仅在 `panel_sync_enabled` 为真时才记录）；连接关闭时回收本连接引入的 id。

置信度：高。

#### SEC-04 · UDP 隧道无目标地址过滤（SSRF） · High · lane ③

位置：`src/server.rs:705-747`

证据（`src/server.rs:736-747`）：
```rust
    if dst_addr.port() == 53 && addr_is_private(&dst_addr) {
        match dst_addr {
            SocketAddr::V4(_) => dst_addr = "8.8.8.8:53".parse::<SocketAddr>()?,
            SocketAddr::V6(_) => dst_addr = "[2001:4860:4860::8888]:53".parse::<SocketAddr>()?,
        }
    }

    if dst_addr.is_ipv4() {
        udp_socket.send_to(&pkt, &dst_addr).await?;
```

影响与前提：`addr_is_private` 只在“目标端口恰为 53”时被调用；其余 65535 个端口上的任何目标（`127.0.0.1`、RFC1918、`169.254.169.254` 云元数据、`100.64.0.0/10` CGNAT）都直接 `send_to`。与 TCP 方向不同（`SEC-05` 至少还有一次 `addr_is_private` 检查），UDP 方向**完全没有**私网/回环过滤，构成可用作内网探测与打内网无认证 UDP 服务（DNS、SNMP、memcached、CLDAP 等）的 SSRF 原语。
前提：一条 `UDP-Tunnel: true` 的 WebSocket 会话（即需 `tunnel_path`）。

复现：`P1`（见附录 B，**复现成功**，含零凭证裸 WS 与真实客户端两条路径：`127.0.0.1:19999` 与 RFC1918 `10.255.216.78:19999` 均完成完整 UDP 往返；同一回环目标的 TCP 方向被 `addr_is_private` 拒绝，形成 A/B 对照）。

修复建议：对 UDP 目标一律套用与 TCP 同源的地址策略白名单（默认拒绝私网/回环/链路本地/保留段），把“53 端口重写 8.8.8.8”这类特例改为显式的 `allow_dns_rewrite` 配置项；补充 `0.0.0.0/8`、`100.64.0.0/10`、`192.0.0.0/24`、`240.0.0.0/4`、`::`、`::ffff:0:0/96`、`2001:db8::/32` 等段落。

置信度：高。

#### SEC-05 · TCP 私网过滤不完整 + IPv4-mapped 绕过 · High · lane ③

位置：`src/server.rs:752-766`（判定）、`src/server.rs:796-807`（唯一 TCP 调用点）、`src/server.rs:799-804`

证据（`src/server.rs:752-766`）：
```rust
    match addr {
        SocketAddr::V4(addr) => addr_v4_is_private(addr.ip()),
        SocketAddr::V6(addr) => addr_v6_is_private(addr.ip()),
    }
}
```
其中 `addr_v6_is_private` 只覆盖 `is_loopback()`、`(segments()[0] & 0xffc0) == 0xfe80`、`(segments()[0] & 0xfe00) == 0xfc00`。

影响与前提：
- 未覆盖：`0.0.0.0/8`、`100.64.0.0/10`、`192.0.0.0/24`、`240.0.0.0/4`、`::`、`2001:db8::/32`，以及**全部 IPv4-mapped IPv6（`::ffff:a.b.c.d`）**——mapped 形态走 V6 分支而三个条件都不成立。
- 绕过路径：SOCKS5 请求用 ATYP=4（IPv6 字面量）给出 `::ffff:127.0.0.1`，`b64str_to_address` → `Address::SocketAddress(V6)` → `to_socket_addrs()` 不做归一化（`socks5-impl-0.9.8/src/protocol/address.rs:234-239` 对 `SocketAddress` 原样返回）→ `addr_is_private` 判 false → `std_create` 连上回环。
- 另一处削弱：`tcp_stream_from_s5_address` 对私网地址是 `continue`（跳过该候选地址）而非整体拒绝，多地址域名仍会连到非私网候选——这是正确设计，但意味着“只有私网候选”才会最终失败，错误信息不区分“被过滤”与“连不上”。

复现：`P2`（见附录 B，**过滤绕过复现成功／端到端在 Windows 上受平台限制未打通**）：`::ffff:127.0.0.1:34598` 与 `0.0.0.0:34598`、`100.64.0.1:34598` 都未被判为私网（服务端日志出现只可能来自 `addr_is_private == false` 分支的 `destination address is unreachable: … (os error 10049/10061)`，且**没有** `destination address is private, skipping`）；其中 mapped 形态的 TCP 连接在 Windows 上被 OS 拒绝（`socket2 0.6.5` 的 `set_common_flags` 不设 `IPV6_V6ONLY=0`，Windows 对 AF_INET6 默认 `V6ONLY=1` → `WSAEADDRNOTAVAIL`）。同机 OS 级隔离实验证明：同一个 IF_INET6 socket 在 `IPV6_V6ONLY=0`（Linux 默认）时 **可以** 连上 `::ffff:127.0.0.1` 并读到回环 HTTP 服务的响应 —— 因此这是真实的分类器缺口，可利用性随平台/双栈设置而定，Linux 上可打通为 [INFERENCE]。

修复建议：统一为一份 `is_disallowed_destination()`，先做 `Ipv6Addr::to_ipv4_mapped()` 归一化再判段；补全保留段；用 `IpAddr::is_global()` 的稳定替代（对 1.89 可用 `is_global()` 已稳定——若仍不稳定则手工实现同一语义，并加单测覆盖 mapped/broadcast/CGNAT/benchmarking）。

置信度：高。

#### SEC-06 · async 上下文内阻塞 DNS/connect → worker 线程耗尽 · High · lane ③

位置：`src/server.rs:722-726`（每包一次 DNS）、`src/server.rs:799-804`（阻塞 connect）、`src/server.rs:453`/`536`（超时来源）

证据（`src/server.rs:722-726`）：
```rust
    for addr in dst_addr.to_socket_addrs()? {
        match addr {
            SocketAddr::V4(_) if ipv4_addr.is_none() => {
                ipv4_addr = Some(addr);
            }
```
证据（`src/server.rs:799-804`）：
```rust
    for dst_addr in s5_addr.to_socket_addrs()? {
        if addr_is_private(&dst_addr) {
            log::warn!("{mn} -- {peer} <> {dst_addr} destination address is private, skipping");
            continue;
        }
        match crate::tcp_stream::std_create(dst_addr, Some(time_out)) {
```
证据（`src/tcp_stream.rs:22-41`）：`std_create` 用 `socket2` 的 `connect_timeout(&SockAddr::from(addr), timeout)` —— **同步阻塞**调用。

影响与前提：
- `svr_send_udp_packet_to_dst` 在 async 函数内对**每一个** UDP 包调用 `Address::to_socket_addrs()`（域名目标才真的查询 DNS，但调用点无条件执行）。DNS 查询走 `getaddrinfo` 的系统解析器：阻塞当前 tokio worker 线程直到完成（默认超时在 Windows 上可达数秒）。
- `tcp_stream_from_s5_address` 的 `std_create(..., connect_timeout)` 同样在 async 上下文内阻塞，上限是 `config.test_timeout_secs`（默认 10，`src/config.rs:14`），逐候选地址累加。
- 攻击方式（需持有一条隧道）：对**不可解析域名**发 UDP 包（一个包一次阻塞），或反复发 `Start session` 指向黑洞地址（`198.51.100.0/24`、`203.0.113.0/24` 均不在过滤名单内）。运行时是 `new_multi_thread()`，worker 数 = CPU 核数（`src/bin/main.rs:143-144`、`src/api.rs:158-159`），因此 ~N_cpu 个并发此类请求即可让整个进程停止响应（包含 accept 循环所在线程）。
- 与 `SEC-01` 的区别：SEC-01 靠 fd/内存耗尽并导致进程退出，本项是**线程级饥饿**，不需要触碰 fd 上限，触发更快。

复现：静态推导，未复现（用一个不解析的域名即可构造，但需要起 server+client 全程观察 worker 饱和；成本高于收益，未纳入本次实跑）。

修复建议：所有 `to_socket_addrs` 移出 async 上下文并缓存（`tokio::task::spawn_blocking` + 结果 TTL 缓存）；`std_create` 换成 `tokio::net::TcpStream::connect` + `tokio::time::timeout`（TOCTOU 与 `set_nonblocking` 也一并消失）；对 UDP 目标禁止域名（只允许字面量地址）或对每包解析做严格节流。

置信度：高（阻塞 API 与调用点确定）。

#### SEC-07 · `dangerous_mode` 无条件关闭证书校验，且可被 `ssr://` URL 注入 · High · lane ②

位置：`src/config.rs:468`（URL 注入）、`src/tls.rs:107-127`（验证器）、`src/client.rs:513-520`（生效点）

证据（`src/config.rs:468`）：
```rust
        let dangerous_mode = map.get("dangerous_mode").and_then(|r| r.parse::<bool>().ok());
```
证据（`src/tls.rs:107-127`）：
```rust
    // this completely disables cert-verification
    let verifier = Arc::new(NoCertificateVerification::default());
    config.dangerous().set_certificate_verifier(verifier);
```
`NoCertificateVerification` 的 `verify_server_cert` / `verify_tls12_signature` / `verify_tls13_signature` 全部返回 `::assertion()`（`src/tls.rs:130-166`），即对**任何**证书与签名一律通过；`create_dangerous_tls_client_stream` 还以空 `RootCertStore` 构建。

影响与前提：`dangerous_mode=true` 时不存在任何残余校验（无 pinning、无 CN/SAN 检查、无有效期检查），TLS 退化为“可被任何中间人明读并改写”的信道，而客户端只打印一条 `log::warn!`（`src/client.rs:516-517`）。更关键的是它**是 `ssr://` URL 的一个可选项**：任何导入别人给的节点 URL（`-u ssr://...`、`over_tls_client_run_with_ssr_url`、扫码）都会连带导入该标志，用户全程无感。这与“客户端唯一使命是抗中间人”直接冲突。
前提：用户导入/粘贴了一个带 `dangerous_mode=1` 的 URL，或在自己配置里打开。

复现：`P5`（见附录 B，**复现成功**）：同一份“错误 CA”客户端配置（`cafile=certs-b/root.crt`，与服务器证书的 CA-A 不匹配）在 `dangerous_mode=false` 时以 `invalid peer certificate: UnknownIssuer` 失败，而把 `dangerous_mode=true` 打开后**同一连接立刻成功**（`curl` 经隧道取到 `HTTP/1.1 301 Moved Permanently`，exit 0），日志仅有那一条 `WARN` —— 即开关一开即无任何残余校验。

修复建议：`from_ssr_url` 拒绝导入 `dangerous_mode=true`（或至少要求显式 CLI 覆盖 `--allow-dangerous-mode` 才生效）；把生效点从 `log::warn!` 提升为启动横幅 + 每次连接一条 `error!`；在 README 与 `cbindgen` 文档里标注该选项的后果。

置信度：高。

#### FFI-01 · `over_tls_client_run_with_ssr_url` 缺空指针检查 · High · lane ④

位置：`src/api.rs:115`（对照 `src/api.rs:58`）

证据（`src/api.rs:114-116`）：
```rust
    let result = || {
        let url = unsafe { std::ffi::CStr::from_ptr(url).to_str()? };
        let listen_addr = if listen_addr.is_null() {
```
证据（`src/api.rs:58-61`，同文件内 `over_tls_client_run` 的对照写法）：
```rust
        if config_path.is_null() {
            return Err("config_path is null".into());
        }
        let config_path = unsafe { std::ffi::CStr::from_ptr(config_path).to_str()? };
```

影响与前提：`CStr::from_ptr(NULL)` 立即构造出无效的 `&CStr`，属 UB（不保证崩溃，可能读到任意内存并把后续解析结果当作 URL）。同文件内 `over_tls_client_run`（`config_path`）与 `overtls_generate_url`（`cfg_path`）都做了 `is_null()` 检查，说明这是遗漏而非有意契约。前提：C/Android/宿主调用方传入 NULL 或未初始化指针——这是 C 互操作里最常见的错误之一。

**实跑结果（P4，独立 crate `tmp/audit/ffi-null/`）**：不是理论 UB，而是**确定性崩溃**，release 与 debug 完全一致：
```
ssr-null        exit=3221225477 (0xC0000005) STATUS_ACCESS_VIOLATION   <- 缺陷路径
ssr-null-catch  exit=3221225477 (0xC0000005)                          <- 外层 catch_unwind 也无济于事
config-null     exit=0  RET=-1     <- 对照：api.rs:58 判空成功
genurl-null     exit=0  RET=0      <- 对照：overtls_generate_url 判空成功
ssr-garbage     exit=0  RET=-1     <- 对照：非空非法 URL 走正常错误返回
```
调试器定位（cdb）：
```
(55dc.b394): Access violation - code c0000005 (first chance)
rip=00007ff8da3ed921 rax=0000000000000000
ucrtbase!strlen+0x31:  00007ff8`da3ed921 488b10  mov rdx,qword ptr [rax]
  ... : ucrtbase!strlen+0x31
  ... : overtls_ffi_null!over_tls_client_run_with_ssr_url+0x18b
```
即 `CStr::from_ptr` 展开的 `strlen(NULL)` 直接解引用地址 0。因此该缺陷**不可被宿主拦截**（无 panic 可展开、`catch_unwind` 无效、函数无法返回 `-1`），只会终止宿主进程。注意平台边界：本平台（Windows x64 MSVC / ucrtbase）是确定性 AV；其它 CRT 可能返回垃圾长度后继续，把任意内存当 URL 解析——无论如何都是 UB。
导出函数空指针检查现状（逐一）：`over_tls_client_run` `config_path/listen_addr/advertise_ip` 均检查；`over_tls_client_run_with_ssr_url` 仅 `listen_addr/advertise_ip` 检查，**`url` 未检查**；`overtls_generate_url` `cfg_path` 与 `buf` 均检查；`over_tls_client_stop` 无指针参数；`overtls_set_log_callback` / `overtls_set_traffic_status_callback` 的 `callback` 为 `Option<fn>`（可空）而 `ctx` 为透传（无需检查）；JNI 入口参数由 `jni` 类型系统约束。

复现：`P4`（见附录 B）。

修复建议：与其他参数一致地加 `if url.is_null() { return -1; }`（或返回专门错误码）；把这一检查抽成 `unsafe fn cstr_arg(ptr) -> Result<&CStr>` 统一使用，避免再次遗漏。

置信度：高。

#### FFI-03 · 无 `catch_unwind`，panic 穿越 `extern "C"` → 宿主 abort · High · lane ④

位置：`src/api.rs:47`、`src/api.rs:97`、`src/api.rs:120`、`src/api.rs:156`、`src/api.rs:186`、`src/android.rs:20`、`src/android.rs:142`

证据（`src/api.rs:156-165`）：
```rust
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        crate::client::run_client(&config, shutdown_token, Some(cb)).await?;
        Ok::<(), Error>(())
    })?;
```
证据（`src/android.rs:153-155`，panic hook 只记日志，不提供隔离）：
```rust
fn set_panic_handler() {
    std::panic::set_hook(Box::new(|panic_info| {
        log::error!("{} -- *** PANIC [{:?}]", method_name::method_name_unstable!(), panic_info);
```

影响与前提：所有导出边界都是 `#[unsafe(no_mangle)] pub unsafe extern "C"`，内部既无 `catch_unwind` 也无 `AssertUnwindSafe`。Rust 1.71+ 会在 `extern "C"` 边界插入 abort 保护，因此**任何**未捕获 panic 都会直接终止宿主进程（Android app、FFI 宿主），而不是把错误交回调用方。可达性：客户端数据面在主循环中有多处可 panic 的算术/索引/`unwrap` 风格调用（例如 `src/client.rs:440` 附近的 `buf.clear()` 组合、`src/udprelay.rs` 内的 `split_to`、`Address::try_from` 之后的下标运算），且这些路径由服务端/对端数据驱动；`Cargo.toml` 未设 `panic = "abort"`，所以 FFI 构建下是 unwind → abort。
前提：宿主使用 C ABI 启动客户端；对端（服务器）能触发 panic 路径（构造条件见 `COR-*` 与 `SEC-13`）。

复现：静态推导，未复现（需要一个能确定触发 panic 的输入；见下方修复建议里的“先加 fuzz 再断言”）。

修复建议：在六个导出入口包裹 `std::panic::catch_unwind(AssertUnwindSafe(...))` 并映射为 `-1` 返回码；把 `EXITING_FLAG` 的清理放进 `catch_unwind` 的恢复路径（否则 panic 后无法重启，见 `FFI-07`）；补 `panic = "abort"` 的显式决策文档（若选择 abort，则必须在 README 声明“宿主进程会被终止”）。

置信度：高（边界与后果确定）／中（具体 panic 触发点的可达性未实跑验证）。

#### COR-10 · 携带 `Client-Id` 的客户端在 1 秒内被无条件断开（出厂配置即命中） · High · lane ③

位置：`src/server.rs:486-494`（TCP）、`src/server.rs:649-660`（UDP）、`src/traffic_audit.rs:116-123`、`src/server.rs:419-433`（对照：握手期门控）

证据（`src/server.rs:486-494`，TCP 会话循环内的 1s tick）：
```rust
            _ = enable_check.tick() => {
                if let Some(client_id) = client_id
                    && !traffic_audit.lock().await.get_enable_of(client_id)
                {
                    log::debug!("{mn} -- {peer} <> {dst_addr:?} client id {client_id:?} disabled by panel sync");
                    let _ = ws_stream.send(Message::Text(END_SESSION.into())).await;
                    break;
                }
            }
```
证据（`src/server.rs:653-660`，UDP 隧道内的同型检查，命中即 `break`）：
```rust
            _ = enable_check.tick() => {
                if let Some(client_id) = client_id
                    && !traffic_audit.lock().await.get_enable_of(client_id)
                {
                    log::debug!("{mn} -- [UDP] tunnel disabled by panel sync for client {client_id:?}");
                    break;
```
证据（`src/traffic_audit.rs:116-123` —— `enable=true` 只有 `panel_sync` 会写入，`add_client` 插入的是 `ClientNode::default()`（`enable=false`））：
```rust
    pub fn set_enable_of(&mut self, client_id: &Uuid, enable: bool) {
        self.client_map.entry(*client_id).or_default().set_enable(enable);
    }

    pub fn get_enable_of(&self, client_id: &Uuid) -> bool {
        let f = |client_node: &ClientNode| client_node.get_enable();
        self.client_map.get(client_id).map(f).unwrap_or(false)
    }
```

影响与前提：**握手期的 `panel_sync` 门控**（`src/server.rs:419-433`）只在 `panel_sync.enabled == true` 时生效，所以默认（`enabled=false`）任何 id 都能建立会话；但**隧道循环内的 1s tick 完全没有这层 gate**——只要请求带了 `Client-Id`，`get_enable_of()` 在 `panel_sync` 未运行时恒为 `false`（没有任何代码把 `enable` 置真，`set_enable_of` 的调用者只有 `src/panel_sync.rs:96`），于是**第一个 tick（≤1s）就断开会话**：TCP 发一条 `End session` 再 break，UDP 直接 break。结果是：
- 默认配置（`panel_sync.enabled=false`）+ 客户端配置里带 `client_id`（**出厂 `config.json:23` 就是这种组合**，客户端每次建连都会带 `Client-Id` 头：`src/client.rs:534` → `src/weirduri.rs:74-77`）→ 每个 TCP/UDP 隧道存活 ≤1 秒；短请求可能侥幸成功，长连接/长传输必然中断，症状表现为“随机断流”。
- 反过来，**不带 `Client-Id` 的客户端不受任何门控**（两个 tick 都因 `if let Some(client_id)` 不成立而跳过），隧道可长期存活。即“如实上报身份”反被惩罚，而省略身份即绕过——门控语义与实际效果相反。

**实跑证据**（P1-F / P2-F）：
```
# 带 Client-Id：包先被正常转发，紧接着在首个 tick 被杀
server: svr_send_udp_packet_to_dst -- [UDP] 127.0.0.1:12345 -> 127.0.0.1:19999 length 19
server: svr_udp_tunnel -- [UDP] tunnel disabled by panel sync for client 33959370-71e0-401d-9746-cda471fc5926
client: after hold: tunnel gone (eof)
# 同一载荷不带 Client-Id：隧道活过整个 4s 观察窗
client: after hold: tunnel gone (timed out)          ← 服务器未关闭
# 真实 client（不带 client_id）的 UDP 隧道持续存活，30s 周期 ping 正常
server: svr_udp_tunnel -- [UDP] received ping message, ignoring   （06:49:48 / 06:50:08 / 06:50:18 / 06:51:18）
# TCP 方向同型（P2 控制组，20 秒内 23 次会话全部被同一行日志终结）
server: svr_normal_tunnel -- 127.0.0.1:33708 <> None client id 33959370-71e0-401d-9746-cda471fc5926 disabled by panel sync
```
前提：客户端配置含 `client_id`（出厂样例即如此）。

复现：`P1`(/P1-F)、`P2`(/F)（见附录 B，**复现成功**）。

修复建议：把两个 tick 都加 `panel_sync.enabled` 条件（与 `src/server.rs:419-433` 同源判断），或改判据为“仅当 id 在面板名单中且被显式禁用才断开”（`contain_client(id) && !get_enable_of(id)`）；`ClientNode` 增加 `known: bool` 以区分“面板未同步”与“面板已禁用”。同时把出厂 `config.json` 的 `client_id` 去掉或注释说明其与 `panel_sync` 的耦合。

置信度：高（代码 + 双向实跑对照）。

---

### 3.3 Medium

#### SEC-08 · cafile 是“追加信任”而非 pinning；配置错误静默退化 · Medium · lane ②

位置：`src/tls.rs:13-28`、`src/config.rs:176-186`

证据（`src/tls.rs:24-28`）：
```rust
        }
    }
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(root_cert_store)
```
证据（`src/config.rs:176-186`，路径存在但内容不合法时返回 `None`，无任何告警）：
```rust
    fn _certificate_content(cert: &str) -> Option<String> {
        const BEGIN_CERT: &str = "-----BEGIN CERTIFICATE-----";
        let checker = |s: &str| !s.is_empty() && s.starts_with(BEGIN_CERT) && s.len() > 100;
        if PathBuf::from(cert).exists() {
            std::fs::read_to_string(cert).ok().filter(|s| checker(s))
```
影响与前提：即使配置了 `cafile`，`webpki_roots` 也**始终**在信任集合里，因此 cafile 只能“多信任”而不能“只信任”；用户无法用 cafile 固定服务端证书。cafile 的三条“失效但无声”路径（P5 全部实跑确认）：
|配置形态|实际行为（原始输出）|
|---|---|
|路径不存在|**完全没有** ERROR/WARN，也没有任何提到 cafile 的日志；故障只在下一次建连时表现为 `invalid peer certificate: UnknownIssuer`|
|`cafile=""`（出厂 `config.json:28` 的值）|同上，无配置层报错|
|文件存在但内容不满足判定（无 `-----BEGIN CERTIFICATE-----` 前缀或 ≤100 字节）|`_certificate_content` 返回 `None` → 静默忽略|
|内容通过判定但 PEM 体非法|`ERROR overtls::tls] retrieve_root_cert_store_for_client -- Error parsing certificate: Custom { kind: InvalidData, error: "InvalidCharacter(33)" }` 后**继续**，仍退化为 webpki 根|

“退化为只信任 webpki 根”的**反证**（P5 case 7）：把 cafile 指向不存在的路径、同时把 `server_host` 指向公网 `1.1.1.1:443`、`server_domain=cloudflare-dns.com` —— TLS 握手**成功**（客户端拿到对方 301 响应，仅 WebSocket 升级因路径不匹配失败），证明此时信任集合就是 webpki 内置根。
另注：`retrieve_root_cert_store_for_client(&None)?` 亦被服务端转发路径使用（`src/server.rs:343-350`），语义相同。真正**致命**的只有 `add()` 失败（P5 case 6：PEM 可解但 DER 非法 → `BadEncoding` → 该次建连失败、进程存活），即“解析失败静默降级、校验失败才报错”——恰好把最该报警的配置错误藏起来。
前提：用户依赖 cafile 做自签部署（本仓库的 selfsign 安装脚本正是这种用法）。

复现：`P5`（见附录 B，**复现成功**：正例通过、异 CA 反例失败、三条静默路径与 webpki 回退反证均已实跑）。

修复建议：新增 `cafile_mode: "additive" | "pinned"`（默认 additive 以保持兼容，pinned 时不 extend `webpki_roots`）；cafile 内容解析失败必须 `warn!` 并明确写出“将以公共根继续”，且提供 `--strict-cafile` 让其成为启动错误；对“路径存在但内容非法”单独报错。

置信度：高。

#### SEC-09 · SNI/Host 与连接目标分离，且解析结果只取一次 · Medium · lane ②

位置：`src/client.rs:513-526`、`src/config.rs:345-357`、`src/config.rs:368-384`

证据（`src/client.rs:522-526`）：
```rust
    let cert_content = client.certificate_content();
    let cert_store = retrieve_root_cert_store_for_client(&cert_content)?;
    let domain = client.server_domain.as_ref().unwrap_or(&client.server_host);
    let stream = create_tls_client_stream(cert_store, svr_addr, domain).await?;
```
证据（`src/config.rs:368-373`）：
```rust
                let mut addr = (server_host, client.server_port).to_socket_addrs()?;
                let addr = addr.next().ok_or("address not available")?;
                {
                    let timeout = std::time::Duration::from_secs(self.test_timeout_secs.unwrap_or(TEST_TIMEOUT_SECS));
                    crate::tcp_stream::std_create(addr, Some(timeout))?;
                }
```
影响与前提：证书校验只约束 `server_domain`，不约束真正连过去的 `server_host`（IP 或另一域名）。这本身是有意设计（域名+IP 分离部署），但它意味着：能让 `server_host` 的 DNS 被劫持/替换的一方（本地 DNS、运营商、同级网络）可以把连接导向自己的服务器，只要它持有 `server_domain` 的**任意**公共受信证书即可通过校验。进一步：`server_ip_addr` 在 `check_correctness` 中解析一次并缓存在配置里（`src/config.rs:384`），运行期**永不重解析**——DNS 记录变更不会生效，同时把“解析时刻的劫持”固化为整进程生命周期的会话目标。
前提：DNS 侧被劫持或初始解析被投毒；`server_domain` 使用公共可信域名（默认行为）。

复现：`P5`（见附录 B，**复现成功，两个方向都实跑**）：(a) 把 `server_domain` 改成 `wrong.example.com` → 立即失败并打印 `certificate not valid for name "wrong.example.com"; certificate is only valid for DnsName("example.com") or IpAddress(127.0.0.1)` → 域名确实被校验；(b) 换用一张**不含 `127.0.0.1` SAN** 的服务器证书（certs-c：`SAN DNS:example.com, IP:192.0.2.1`）并以 `server_host=127.0.0.1` 连接 → **连接成功**（`curl` 经隧道取到 301，exit 0）→ 证书校验只绑定 `server_domain`，与真正连接的目标地址无关。

修复建议：在 README/配置注释中明确“`server_domain` 必须是你自己控制的域名，且 `server_host` 的解析结果应视为不可信”；提供 `server_ip_hint` 与定期重解析（TTL 跟随）；可选的对 IP 白名单校验（`pin_ip`）。

置信度：中（机制确定，危害依赖外部条件）。

#### SEC-10 · WebSocket 握手头与真实浏览器显著不同 · Medium · lane ①

位置：`src/weirduri.rs:62-87`

证据（`src/weirduri.rs:62-70`）：
```rust
        let mut builder = Request::builder()
            .method("GET")
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", value.sec_websocket_key);
```
影响与前提：客户端发出的升级请求只含 `Host`、`Connection`、`Upgrade`、`Sec-WebSocket-Version`、`Sec-WebSocket-Key`（外加可选的 `Target-Address`、`UDP-Tunnel`、`Client-Id`）。缺失真实 Chrome 在 `wss://` 握手时同时发送的 `User-Agent`、`Origin`、`Accept-Encoding`、`Accept-Language`、`Pragma`/`Cache-Control`、`Sec-WebSocket-Extensions`；且头部由 `Request::builder` 按**固定插入顺序**序列化（不存在浏览器式的顺序变化），`Client-Id`/`Target-Address` 更是绝无仅有的私有头。任何能看到 TLS 明文的中间设备（或能解密的观察者）都可以按“缺 UA/Origin/Extensions + 出现私有头”的规则高置信度指纹化。
注意 `Target-Address`/`UDP-Tunnel` 只在旧客户端路径出现（`src/client.rs:88-92` 仅在连接池创建时带 `UDP-Tunnel: true`；正常会话走 `Start session` 文本帧），但 `Client-Id` 每次都带。
前提：观察者能观测到握手明文（TLS 内层由服务端解密，但明文模式 `disable_tls=true`、TLS 终止型中间盒、或服务端自身可观测）。

复现：`P6` 记录了服务端可见的原始请求头（见附录 B）。

修复建议：在 `WeirdUri` 中补齐一套与目标浏览器一致的头部集合（UA、Origin、Accept-*、Extensions 与顺序），并支持从配置模板加载；把 `Client-Id` 等私有信息移到 URL 路径段或 `Sec-WebSocket-Protocol` 中（两者的存在感远低于自定义头）。

置信度：高（头集合与顺序由代码确定）／中（对“真实浏览器”头部集合的对比依据为公开常识，未在本机用浏览器实测，标 [INFERENCE]）。

#### SEC-11 · 主动探测可单次区分“路径正确/错误” · Medium · lane ①

位置：`src/server.rs:285-287`（转发分支）、`src/server.rs:393-397`（握手失败分支）

证据（`src/server.rs:285-287`）：
```rust
    if !check_uri_path(&buf, &config.tunnel_path.extract())? {
        return forward_traffic_wrapper(stream, &buf, &config).await;
    }
```
证据（`src/server.rs:393-397`）：
```rust
    if !handshake.is_empty() {
        if let Some((_, req)) = Request::try_parse(handshake)? {
            retrieve_values(&req);

            let res = create_response(&req)?;
```
`create_response`（`tungstenite-0.30.0/src/handshake/server.rs:28-75`）会校验 `GET`、`HTTP/1.1+`、`Connection: Upgrade`、`Upgrade: websocket`、`Sec-WebSocket-Version: 13`、`Sec-WebSocket-Key`（长度 24 且 base64 解码为 16 字节），任一不满足即 `Err` → 经 `?` 直接结束会话、**不回任何 HTTP 响应**。

影响与前提：错误路径的请求被原样转给 `forward_addr`（观测点得到 nginx/Caddy 的正常 HTTP 响应）；正确路径 + 非 WS 请求则**连接被静默关闭（无响应字节）**；正确路径 + 完整 WS 头返回 `101`。一次普通 HTTP 请求即可区分两种情形，因此“随机路径探测”能直接定位 `tunnel_path` 是否正确，配合 `SEC-02` 的公开默认值即可拿下隧道。
前提：探测者能建立 TCP 连接（无需凭证）。

复现：`P6`（见附录 B，**复现成功** 4 用例 × 3 次一致：A `GET /random` → 反代 `200 OK`；B `GET /t/` → 0 字节 + FIN，`curl exit 52 Empty reply from server`；C `GET /t/` + WS 头 → `101 Switching Protocols`；D `GET /random` + WS 头 → 与 A 相同的 `200 OK`）。

修复建议：让“路径正确但非 WS 握手”的响应与“路径错误”不可区分——最小改动是在 `create_response` 失败时也把缓冲数据转发给 `forward_addr`（伪装成普通 GET），或返回与前置反代一致的 404/400 页面；同时给这两种情况加同速率的连接节流，避免探测者用关闭时序区分。

置信度：高。

#### SEC-12 · 客户端 WS 升级响应校验不足 + 单次 `read_buf` 脆弱 · Medium · lane ②

位置：`src/client.rs:563-575`

证据（`src/client.rs:563-575`）：
```rust
    let mut buf = BytesMut::with_capacity(2048);
    stream.read_buf(&mut buf).await?;

    let response = Response::try_parse(&buf)?.ok_or("response parse failed")?.1;
    let remote_key = response.headers().get("Sec-WebSocket-Accept").ok_or(format!("{response:?}"))?;

    let accept_key = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());

    if accept_key.as_str() != remote_key.to_str().map_err(|e| e.to_string())? {
        return Err(Error::from("accept key error"));
    }
```
影响与前提：
1. 只比对 `Sec-WebSocket-Accept`，**不检查状态码为 101**，也不检查 `Upgrade: websocket` / `Connection: Upgrade`（tungstenite 官方 `client_async` 会校验这些）。恶意/被劫持的服务器返回 `200 OK` + 正确的 `Sec-WebSocket-Accept` 也会被接受（旧的 `client_async` 调用已被注释掉：`src/client.rs:576`）。
2. `read_buf` 只调用一次且不循环：响应头跨 TCP 段到达（或服务器先发头再紧接一帧）时，`Response::try_parse` 可能返回 `Partial`（→ `None` → `"response parse failed"`），或头之后的字节被丢进 `stream` 之外。`try_parse` 返回的已消费长度 `usize` 被解构丢弃（`?;` 忽略第一元组项），即**任何与握手同批到达的字节都被静默丢弃**，而 `from_raw_socket` 之后由 tungstenite 从流上重新读取——服务端若在 101 之后立刻推送数据帧，这些字节会丢失（协议层表现为消息丢失）。
3. 客户端的 `Start session` 文本帧在 `client_traffic_loop` 中才发送（`src/client.rs:427-429`），真实服务器也不会在 101 后主动推送，所以第 2 点在本实现与官方服务端组合下不触发；但“协议允许的字节被丢弃”仍是不健壮点。
前提：连接的是恶意/异常服务器（或 TLS 被 `SEC-07` 关闭时的中间人）。

复现：`P5` 的握手日志（未直接构造 200+正确 accept key 的服务器，见附录 B 说明）。

修复建议：改用 `tokio_tungstenite::client_async`（或复刻其校验：状态 101、`Upgrade`/`Connection` 头），并把 `try_parse` 返回的消费长度用于构造 `read_buf` 的剩余部分（可用 `tungstenite::handshake::machine::TryParse` 的官方封装或自行 `BytesMut::split_to`）。

置信度：高（代码确定）／中（真实服务端组合下是否可观测到丢帧未复现）。

#### SEC-13 · UDP 帧无校验：一条畸形帧即终止隧道 · Medium · lane ②③

位置：`src/server.rs:676-681`、`src/udprelay.rs:249-256`、`src/udprelay.rs:351-356`

证据（`src/server.rs:677-681`）：
```rust
                    Message::Binary(data) => {
                        let buf = BytesMut::from(&data[..]);
                        svr_send_udp_packet_to_dst(buf, &dst_src_pairs, &udp_socket, &udp_socket_v6).await?;
                    }
```
证据（`src/udprelay.rs:351-356`）：
```rust
pub(crate) fn decode_udp_packet(buf: &mut BytesMut) -> Result<(Address, Address, Vec<u8>)> {
    let dst_addr = Address::try_from(&buf[..])?;
    let _ = buf.split_to(dst_addr.len());
    let src_addr = Address::try_from(&buf[..])?;
```
影响与前提：`decode_udp_packet` 的失败（长度不足、地址类型非法）、`Address::to_socket_addrs()` 失败（域名不存在）、`send_to` 失败（报文 >65507 或地址族不匹配）都通过 `?` 逃出 `select!` 分支并直接结束整个 UDP 隧道循环。
- 服务端侧（lane ③）：一个恶意客户端可以自伤（后果有限），但**正常用户**只要往一个无法解析的域名发一个 UDP 包，也会把自己整条 UDP 隧道打断（恢复依赖客户端看门狗 ≥1s）。
- 客户端侧（lane ②）：`_run_udp_loop` 中服务端返回的二进制帧同样 `decode_udp_packet(&mut BytesMut::from(buf))?`（`src/udprelay.rs:249-256`）→ 恶意服务器只要持续发送 1 字节的二进制帧，就能让客户端的 UDP 服务在“1 秒重启、立即再被打断”的循环里永久瘫痪；`udp_handler_watchdog`（`src/udprelay.rs:300-336`）固定 `sleep(1s)`，没有退避与熔断。
前提：服务端/客户端持有一条 UDP 隧道。

复现：`P1`/P1-E（见附录 B，**复现成功**）：目标为 `0.0.0.0:19999`、`169.254.169.254:80`、`[::ffff:127.0.0.1]:19999` 时，`send_to` 返回 OS 错误后整条隧道立即以 `closed with error "IO error: … (os error 10049/10051)"` 结束 —— 未授权客户端可用“任意非法/不可达目标”作为单会话 DoS 原语，且客户端看门狗 1 秒后就重连，可无限重复。

修复建议：把 UDP 帧解析错误从“终止会话”降级为“丢弃该帧 + `warn!` + 计数”（用 `match`/`continue` 替代 `?`），对连续错误计数超阈值才断开；客户端看门狗加指数退避与“最近 N 次失败则停用 UDP”的保护。

置信度：高。

#### SEC-14 · UDP 映射表无上限、出口 socket 未绑定来源 · Medium · lane ③

位置：`src/server.rs:638-646`、`src/server.rs:717`、`src/server.rs:777-786`

证据（`src/server.rs:717`）：
```rust
    dst_src_pairs.lock().await.insert(dst_addr.clone(), src_addr.clone());
```
证据（`src/server.rs:777-786`）：
```rust
    let dst_addr = Address::from(addr);
    let src_addr = dst_src_pairs.lock().await.get(&dst_addr).cloned();
    if let Some(src_addr) = src_addr {
        // Note: here dst_addr and src_addr are swapped
        let buf = crate::udprelay::build_udp_packet(&src_addr, &dst_addr, pkt);
```
影响与前提：`dst_src_pairs` 每个新目标插入一条且**从不淘汰**、无数量上限（一条隧道内可由攻击者用海量不同目标地址撑大，每条至少一个 `Address` ≈ 24–280B）；同时出口 socket 是 `UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))`（`src/server.rs:638-639`），**未 connect、未做来源校验**：回包只按“发送方地址 == 表中 key”匹配（等价于“任意主机先向该临时端口发包”即可被转发回客户端）。同机/同网段的第三方进程若猜到或扫到该临时端口，就能借隧道把任意数据送进客户端。
前提：一条 UDP 隧道；要利用回传需要猜测临时端口（16 位，可扫）。

复现：未复现（需要第三条进程构造注入包）。

修复建议：映射表加容量上限 + LRU/空闲超时；出口 socket 分片化（每个 5 元组一条 `connect`ed socket）或用 `recv_from` 时校验来源必须是表中最近请求过的地址；临时端口改为从配置的范围内分配以减少可预测性。

置信度：高。

#### SEC-15 · 敏感配置进日志（trace 级）与 `/tmp` 固定名日志 · Medium · lane ①④

位置：`src/client.rs:45-49`、`src/server.rs:49-50`、`src/bin/main.rs:124-130`

证据（`src/server.rs:48-50`）：
```rust
    log::trace!("with following settings:");
    log::trace!("{}", serde_json::to_string_pretty(config)?);
```
证据（`src/bin/main.rs:124-130`）：
```rust
    #[cfg(unix)]
    if opt.daemonize {
        let stdout = std::fs::File::create("/tmp/overtls.out")?;
        let stderr = std::fs::File::create("/tmp/overtls.err")?;
        let daemonize = daemonize::Daemonize::new()
            .working_directory("/tmp")
            .umask(0o777)
```
影响与前提：
1. `Config` 的序列化包含 `panel_sync.webapi_token`、`password`、`tunnel_path`、`client_id`、`cafile`（内联 PEM 全文）与证书/密钥**路径**。`-v trace`（或 `RUST_LOG=overtls=trace`）会把这些整体写入日志；日志在 `-d` 模式下落到 `/tmp/overtls.out`（世界可写目录、固定文件名、`File::create` 会跟随符号链接并截断）。`umask(0o777)` 使**此后**进程新建文件的权限位全被清除，但这两个文件是在 `umask` 生效之前由调用者权限创建的，权限取决于当时的 umask（通常 0022 → 0644）。
2. 符号链接后果：以 root 运行 `-d` 时，本地用户预先创建 `/tmp/overtls.out -> /etc/ssh/sshd_config` 之类的链接，root 进程会在启动时截断并覆写目标文件（CWE-59/CWE-377）。
前提：第 1 点需要 trace 级别或 `-d`；第 2 点需要本地非特权用户 + 管理员以 `-d` 启动。

复现：静态推导，未复现（Windows 上无 `#[cfg(unix)]` 分支；且本机不重装服务）。

修复建议：日志中的配置改为白名单字段（只打 `remarks`、`listen`、`server_host`、`tunnel_path` 的哈希），token/password/cafile 一律脱敏；`-d` 的日志改为 `O_EXCL|O_NOFOLLOW` 打开 + 0600 权限 + 与 PID/随机后缀同名的文件（或改用 syslog/journald，让 `systemd` 管理文件与权限）。

置信度：高。

#### SEC-16 · panel `webapi_token` 经 reqwest 错误进入日志 · Medium · lane ③④

位置：`src/panel_sync.rs:195-217`、`src/panel_sync.rs:60-70`、`src/panel_sync.rs:204-209`

证据（`src/panel_sync.rs:174-175`，token 拼进查询串）：
```rust
        let url = self.build_url("users", &[("node_id", node_id.to_string())])?;
        let response = self.client.get(url).send().await?;
```
证据（`src/panel_sync.rs:68-71`，错误只做 `Display`）：
```rust
                    if let Err(e) = self.sync_once(&traffic_audit).await {
                        log::warn!("{mn} -- panel sync failed: {e}");
                    }
```
影响与前提：`reqwest::Error` 的 `Display` 会带上请求 URL——这一点在其自身源码里有明确实现与警告（`reqwest-0.13.5/src/error.rs:300-302` `write!(f, " for url ({url})")?`；同文件 `:18-19` 的文档直接写 “contains sensitive information (e.g. an API key as a query parameter), be sure to remove it ([without_url])”）。因此任何连接/超时/TLS 错误都会把面板 API token 写进 `warn` 级日志（默认级别下也会输出，例如 `error sending request for url (https://panel/mod_mu/users?key=<TOKEN>&node_id=1)`）；本项目**没有**调用 `without_url()`。同理 `parse_payload` 的错误含响应体（`Wrong data: {value:?}`）。
另：`reqwest::Client::new()`（`src/panel_sync.rs:46`）未设置总超时与连接超时，面板不可达时该任务会长时间挂在请求里（`run` 的 `interval.tick()` 分支被阻塞，`quit.cancelled()` 也要等它返回才被观察）。
前提：`panel_sync.enabled=true` 且至少一次请求失败——即正常运维中不可避免。

复现：静态推导，未复现（需要真实面板端点；错误文案由 reqwest 决定，可在本机对任意不可达域名观察到同型输出）。

修复建议：日志只记 `e.is_timeout()`/`e.status()`/`e.url()` 的**脱敏**形式（把 `key` 值替换为 `***`）或干脆记 `e.without_url()`；`Client::builder().timeout(10s).connect_timeout(5s)`。

置信度：高。

#### COR-01 · `tunnel_path` 数组退化后所有请求都被转发 · Medium · lane ③

位置：`src/config.rs:326-330`、`src/config.rs:81-99`、`src/server.rs:315-325`

证据（`src/config.rs:81-99`）：
```rust
            TunnelPath::Multiple(v) => {
                v.iter_mut().for_each(|s| {
                    *s = s.trim().trim_matches('/').to_string();
                    if !s.is_empty() {
                        *s = format!("/{s}/");
                    }
                });
                v.retain(|s| !s.is_empty());
            }
```
证据（`src/config.rs:326-330`）：
```rust
        if self.tunnel_path.is_empty() {
            self.tunnel_path = TunnelPath::default();
        } else {
            self.tunnel_path.standardize();
        }
```
影响与前提：`Multiple(["/"])`（或 `[""]`、`["/","/"]`）在 `is_empty()` 时判为**非空**（`Vec` 长度 1），因此进入 `standardize()` 把元素清成空串并 `retain` 掉 —— 结果 `extract()` 返回**空数组**。`check_uri_path` 对空数组恒返回 `false`（`src/server.rs:319-324` 的 `for path in path` 不执行），于是每个请求都被 `forward_traffic_wrapper` 转到 `forward_addr`：隧道彻底失效，同时把“任意未认证请求都可命中的常量转发端点”暴露成对外行为（伪装面变成唯一的对外功能）。客户端侧同样取值失败并报 `"tunnel path not exist"`（`src/client.rs:544-545`）——即服务端静默降级、客户端直接失败，故障定位方向被误导。
前提：运维把 `tunnel_path` 写成单元素数组且只含 `/`（把“根路径”当成合法配置是很自然的误解）。

**实跑确认（P3，4 组取值）**：
|配置值|归一化结果|行为|
|---|---|---|
|`["/"]` / `[""]` / `["/",""]` / `["//"]`|`Multiple([])`（启动 trace 回显 `"tunnel_path": []`）|**永不匹配 → 所有请求被转发**，隧道失效|
|`[]`（空数组）/ `""`（单字符串）|回退默认 `/tunnel/`|正常（安全）|
|`"/"`（单字符串）|`"//"`（启动 trace 回显 `"tunnel_path": "//"`）|只匹配字面 `//`；`/`、`/anything`、`/tunnel/` 全被转发（同上后果）|

转发分支的原始日志为 `forward_traffic_wrapper -- not match path "", forward traffic directly...`。**附带影响（实测）**：真实客户端的握手元数据（`client-id: 33959370-71e0-401d-9746-cda471fc5926`、`udp-tunnel: true`、旧版 `Target-Address`）随首包被原样转交给 `forward_addr` 的后端服务，构成客户端身份信元外泄。

复现：`P3`（见附录 B，复现成功）。

修复建议：`standardize()` 后若结果为空视同非法配置，直接 `Err("tunnel_path is invalid")`；或在 `check_correctness` 里对“标准化后为空”显式报错，而不是留给运行期。

置信度：高。

#### COR-02 · 首包读取只有一次 2048B，且 `Status::Partial` 被当作“路径不匹配” · Medium · lane ③

位置：`src/server.rs:279-283`、`src/server.rs:315-325`

证据（`src/server.rs:315-325`）：
```rust
fn check_uri_path(buf: &[u8], path: &[&str]) -> Result<bool> {
    let mut headers = [httparse::EMPTY_HEADER; 512];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(buf)?;

    if let Some(p) = req.path {
```
影响与前提：
1. `BytesMut::with_capacity(2048)` + 单次 `read_buf`：请求行+头部超过 2048 字节的握手请求必然被截断（`read_buf` 不会扩容），`httparse` 返回 `Partial`。此时 `req.path` 可能已被填好，于是**路径匹配成功**进入 WS 分支，而 `Request::try_parse`（tungstenite，限 124 头）在截断输入上返回 `None` 或 `TooManyHeaders`，会话以 `"invalid handshake"` 结束——对端看到的是“连接被关闭”，而非 400。
2. 若 `req.path` 尚未解析出来，则 `check_uri_path` 返回 `false` → 被当作“路径不匹配”**原样转发**给 `forward_addr`（把半截请求交给上游反代）。
3. 头数上限不一致：`check_uri_path` 用 512 槽（`src/server.rs:316`），tungstenite 内部用 `MAX_HEADERS = 124`（`tungstenite-0.30.0/src/handshake/headers.rs:10`）→ 125..=512 个头的请求能通过路径检查却在握手阶段失败，形成一个稳定可复现的探测特征（与 `SEC-11` 叠加）。
前提：请求头总量 >2048 字节或头数 >124（正常浏览器带大量 Cookie 时并不罕见）。

复现：`P6` 的 C 组（完整 WS 头、单次请求）未覆盖 >2048B 情形；本项为静态推导，未复现。

修复建议：把首包读取改为“循环读取直到 `httparse` 返回 `Complete` 或达到上限（例如 16KB）”，并把 `Partial` 明确区分处理（等待更多数据，而不是当作不匹配）；两侧头数上限统一为一套常量。

置信度：高（代码路径确定）／中（触发所需的请求形态未实跑）。

#### FFI-02 · `#[repr(C)] enum` 越界值即 UB · Medium · lane ④

位置：`src/dump_logger.rs:9-16`、`src/api.rs:47`、`src/api.rs:99`

证据（`src/api.rs:47` 的参数类型 + `src/api.rs:51` 的转换）：
```rust
    log_level: crate::LogLevel,
```
```rust
    log::set_max_level(log_level.into());
```
影响与前提：`LogLevel` 被 `#[repr(C)]` 导出（cbindgen 生成同名 C enum，`cbindgen.toml:8-17`），Rust 侧对 `log_level.into()` 直接做 `match`。C 调用方传任意整数（例如从 JSON/配置读来的 `3` 以外的值、或 `-1`）不会经过任何校验就被当成合法 `LogLevel`，`match` 未覆盖的分支是 **UB**（不是返回 `Off`）。这在 cbindgen 生成的 C 头中是类型安全的，但对任何 FFI 桥（Python ctypes、JNA/JNI、Go cgo、以及本项目自己的 Android JNI 包装——后者已经自己做了 `match verbosity` 映射，见 `src/android.rs:33-41`）都是可绕过的。
前提：宿主用非 cbindgen 头调用，或整数来自外部输入。

复现：未复现（构造需另一个进程；见 `P4` 的对照工程可复用同一调用方式）。

修复建议：把 `log_level` 参数改为 `c_int`，内部 `match` 到 `LevelFilter`（未知值 → `Off` 或 `Info`）；若必须保留 enum，则在 cbindgen 头注释中明确“仅接受 0..=5”，并在 Rust 侧用 `#[repr(transparent)] struct LogLevel(u8)` + `TryFrom`。

置信度：高。

#### FFI-04 · 回调在持有互斥锁时被调用 → 重入即死锁 · Medium · lane ④

位置：`src/dump_logger.rs:129-141`、`src/traffic_status.rs:82-88`

证据（`src/dump_logger.rs:132-141`）：
```rust
        let c_msg = std::ffi::CString::new(msg)?;
        let ptr = c_msg.as_ptr();
        if let Ok(cb) = DUMP_CALLBACK.lock()
            && let Some(cb) = cb.clone()
        {
            unsafe { cb.call(record.level().to_level_filter().into(), ptr) };
        }
```
证据（`src/traffic_status.rs:82-88`）：
```rust
fn send_traffic_stat(traffic_status: &TrafficStatus) -> Result<()> {
    if let Ok(cb) = TRAFFIC_STATUS_CALLBACK.lock()
        && let Some(cb) = cb.clone()
    {
        unsafe { cb.call(traffic_status) };
```
影响与前提：两个回调都在**持有 `std::sync::Mutex` 的情况下**调用宿主代码。宿主回调里若再次 `log::info!`（`DumpLogger::log` → `do_dump_log` → `DUMP_CALLBACK.lock()`）或调用 `traffic_status_update`/`overtls_set_traffic_status_callback`，就会在同线程重复加锁 → **永久死锁**（std Mutex 不可重入）。文档只写了回调“should be thread-safe”（`src/api.rs:31-38`、`src/api.rs:74-79`），**没有**写“回调内禁止记录日志/调用本库 API”。
附加后果：回调 panic 会毒化该 Mutex，此后 `is_none_or_error` 判真（`src/traffic_status.rs:57-64`）导致流量上报**永久静默失效**。
前提：宿主回调里触发重入（对 JNI/Java 侧错误处理最自然的写法就是记一条日志）。

复现：静态推导，未复现（需宿主侧回调；可用 `P4` 的同一工程加一个回调复现）。

修复建议：把 `cb` 克隆出来、释放锁后再调用（`let cb = { let g = LOCK.lock()?; g.clone() }; if let Some(cb) = cb { cb.call(..) }`）；在头文件注释里明确“回调不得在本回调中调用本库任何 API”。

置信度：高。

#### FFI-07 · `EXITING_FLAG` 不复位 → FFI 客户端无法重启 · Medium · lane ④

位置：`src/api.rs:25`、`src/api.rs:144-152`、`src/api.rs:169-178`

证据（`src/api.rs:144-152`）：
```rust
    let shutdown_token = crate::CancellationToken::new();
    if let Ok(mut lock) = EXITING_FLAG.lock() {
        if lock.is_some() {
            return Err("tun2proxy already started".into());
        }
        *lock = Some(shutdown_token.clone());
    }
```
证据（`src/api.rs:169-178`）：
```rust
pub unsafe extern "C" fn over_tls_client_stop() -> c_int {
    if let Ok(mut token) = EXITING_FLAG.lock()
        && let Some(token) = token.take()
    {
        token.cancel();
    }
```
影响与前提：只有 `over_tls_client_stop()` 会把 `EXITING_FLAG` 置回 `None`。`run_client` 自然返回（服务端关闭连接池、监听出错、内部错误）时 `_over_tls_client_run` 直接返回，标志仍为 `Some` —— 宿主此后任何一次 `over_tls_client_run*` 都会立刻失败并返回 `-1`，除非它知道要先调用 `stop()`（而 `stop()` 在客户端已退出时也不会被调用）。对移动端/桌面端宿主而言，“连接断了想重连”是最常见路径。
另：错误文案 `"tun2proxy already started"` 是从 tun2proxy 项目复制来的（与实际产品名不符），一旦用户看到会误导排查方向（`src/api.rs:147`）。
前提：宿主使用 C API 且需要重启客户端。

复现：静态推导，未复现（可用 `P4` 工程连调两次复现）。

修复建议：把清理放到 `_over_tls_client_run` 的退出路径（含错误与 panic 恢复）；`stop()` 保持幂等；顺手改掉错误文案。

置信度：高。

#### COR-05 · `parse_data_to_dns_message` 失败会打断整个 UDP 服务 · Medium · lane ②③

位置：`src/udprelay.rs:200-215`、`src/udprelay.rs:243-256`、`src/dns.rs:9-24`

证据（`src/udprelay.rs:206-215`）：
```rust
                    if dst_addr.port() == 53 {
                        let msg = dns::parse_data_to_dns_message(&pkt, false)?;
                        let domain = dns::extract_domain_from_dns_message(&msg)?;
                        if let (true, Some(cached_message)) = (cache_dns, dns::dns_cache_get_message(&cache, &msg).await) {
```
影响与前提：客户端只要向 UDP 53 端口发出一段**不是合法 DNS 报文**的数据（本地任意应用的安全扫描、探测、错配的客户端），`parse_data_to_dns_message` 就返回 `Err`，`?` 直接从 `select!` 分支返回 → `_run_udp_loop` 结束 → 该次 UDP 隧道销毁（含所有别的应用的 UDP 会话），1 秒后看门狗重建。服务端返回的 DNS 响应同理（`extract_domain_from_dns_message` 要求 `queries` 非空，`QDCOUNT=0` 的响应即命中）。这既是可用性缺陷，也是本地任意进程可触发的“打断整条 UDP 通路”的原语。
前提：`--cache-dns` 不是必要条件（解析在任何情况下都执行）。

复现：静态推导，未复现。

修复建议：DNS 解析失败改为“跳过缓存逻辑、按普通 UDP 包转发”并 `warn!` 一次（限频）；只有真正的 IO 错误才结束循环。

置信度：高。

#### PRF-01 · 客户端每个数据消息一次 32KB/96KB 分配 + 重复复制 · Medium · lane 性能

位置：`src/client.rs:413-433`、`src/client.rs:200`、`src/client.rs:391-397`

证据（`src/client.rs:414-417`，位于 `loop {` 内）：
```rust
    loop {
        let mn = method_name_unstable!();
        let mut buf = BytesMut::with_capacity(crate::STREAM_BUFFER_SIZE);
        tokio::select! {
```
证据（`src/client.rs:433`）：
```rust
                ws_stream.send(Message::binary(buf.to_vec())).await?;
```
影响与前提：`STREAM_BUFFER_SIZE` 在 Windows 是 32KB、其他平台 96KB（`src/lib.rs:34-37`）。**每处理一个消息**都会：`BytesMut::with_capacity` 分配整个缓冲（即使消息只有 20 字节）→ 读入 → `buf.to_vec()` 再复制一次 → `Message::binary` 包一层。反向路径 `poll_write` 同样对每片数据 `buf.to_vec()`（`src/client.rs:200`）。因此每个 TCP 段/消息固定至少 2 次分配 + 2 次全量拷贝，成本与缓冲尺寸（32/96KB）而非消息尺寸挂钩。以 64KB/s、每消息 1KB 计：65536 次/秒 ×（32KB 分配 + 2KB 拷贝）≈ 2.1 GB/s 的无谓内存带宽。
前提：任何 TCP 会话（热路径，无需异常条件）。

依据来源：代码推导 + 常量定义；未做 heap profiling（未装 valgrind/dhat）。

修复建议：把 `BytesMut` 提到循环外并在每次使用后 `clear()`（`clear()` 只把长度置 0、保留容量），或用 `BytesMut::with_capacity(4096)` 起步让 `read_buf` 按需增长；发送侧用 `Message::Binary(buf.split().freeze())`（`Bytes` 零拷贝移交）替代 `to_vec()`。

置信度：高（代码级确定）。

#### PRF-02 · 每消息一次 flush + 未设 `TCP_NODELAY` · Medium · lane 性能

位置：`src/server.rs:632`、`src/server.rs:791`、`src/client.rs:433`、`src/udprelay.rs:222`、`src/tcp_stream.rs:13-49`

证据（`src/server.rs:593-597`）：
```rust
                    Ok(n) => {
                        let msg = Message::binary(buffer[..n].to_vec());
                        let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
                        log::trace!("{mn} -- {peer} <- {dst_addr:?} length {len}");
                        svr_send_ws_message(&mut ws_stream, msg, &traffic_audit, client_id).await?;
```
（`svr_send_ws_message` 内部 `ws_stream.send(msg)`，`SinkExt::send` = `feed` + `flush`，`src/server.rs:622-632`）
影响与前提：四条数据路径都用 `send()`，即每个消息一次 flush（一次 `write` syscall）。更关键的是所有 socket 都由 `tokio::net::TcpStream::connect`（`src/tcp_stream.rs:19`）或 `socket2::Socket::new`（同文件 `:22-27`）创建，**从未设置 `TCP_NODELAY`** → Nagle 算法默认开启：小的 WS 文本/二进制帧（例如 14B 的 `Start session`、20-50B 的 DNS 查询）会等待 ACK 或被合并，叠加 40ms 量级的延迟抖动。这与“UDP 低延迟”的场景直接冲突。
前提：任何会话。

依据来源：代码推导；未做 `tcpdump` 级验证（本机无 tcpdump；`P8` 的 p50/p95 可作为间接证据，见第 4 节）。

修复建议：所有主动连接与监听接受的 socket 都设 `set_nodelay(true)`；服务端在 `handle_incoming` 拿到 `TcpStream` 后立即设置（TLS 分支要在 `TlsAcceptor::accept` 之前对底层 `TcpStream` 设置）；若要保持 `socket2` 的 `connect_timeout`，在没有超时需求后改用 `tokio::net::TcpStream::connect`（其默认仍是 Nagle 开启，需显式设置）。

置信度：高。

#### SUP-01 · 无 lockfile 与 advisory 门禁 · Medium · lane 依赖

位置：`.gitignore:22`（`Cargo.lock`）、`.github/workflows/check.yml:94-104`

证据（`.github/workflows/check.yml:95-97`）：
```yaml
          else
            cargo build --verbose --target ${{ matrix.target }}
          fi
```
影响与前提：`Cargo.lock` 未提交，CI 也从不传 `--locked`，因此**每次构建都解析当时最新的 semver 兼容版本**：同一 commit 在不同日期会产出不同二进制（不可复现构建），也无法为已发布的二进制做依赖级追溯。实测 `cargo generate-lockfile` 锁到 **275** 个包（`tmp/audit/audit.json` 中一并记录）。同时仓库无 `cargo-deny`/`cargo-vet`，`cargo audit` 只在审计时临时执行（见第 5 节：0 漏洞、2 个 unmaintained 警告）。
前提：无（现状即如此）。

依据来源：`cargo generate-lockfile` + `cargo audit` 实跑（`tmp/audit/audit.json`）。

修复建议：提交 `Cargo.lock`（同时移除 `.gitignore:22`），CI 增加 `cargo build --locked` 与 `cargo audit`/`cargo-deny` 步骤；给 dependabot 也加 advisory 告警。

置信度：高。

#### SUP-03 · `pull_request_target` + 仓库管理员 PAT + 未固定 SHA 的第三方 action · Medium · lane 依赖

位置：`.github/workflows/auto-merge.yml:1-20`

证据：
```yaml
on:
  pull_request_target:
    types: [labeled]
jobs:
  auto:
    if: github.actor == 'dependabot[bot]'
```
```yaml
      - name: Auto approve pull request, then squash and merge
        uses: ahmadnassri/action-dependabot-auto-merge@v2
        with:
          github-token: ${{ secrets.PAT_REPO_ADMIN }}
```
影响与前提：`pull_request_target` 会在**基仓库上下文**中运行并携带 secrets；这里的 `actions/checkout` 未指定 `ref`（默认基分支）因此没有直接执行不可信代码，`github.actor` 限制也把触发面收窄到 dependabot——但 `PAT_REPO_ADMIN`（仓库管理员权限）被交给了一个**未固定 commit SHA** 的第三方 action（`:v2` 浮动标签）。该标签被移动或其上游账号被接管时，攻击者即可拿到管理员 PAT，进而绕过分支保护直接改写仓库/发布物。对一个“供应链即生命线”的代理工具而言这是高杠杆风险。
前提：上游 action 被投毒/标签被移动（无需本仓库任何人操作）。

复现：静态推导，未复现。

修复建议：把 action 固定到 commit SHA 并开启 Dependabot 的 actions 更新；用内置 `gh pr merge --auto --squash`（`GITHUB_TOKEN` + `pull_request` 触发）替代需要管理员 PAT 的第三方 action；至少把 PAT 换成最小权限（只给 `contents: write` + `pull_requests: write` 的细粒度 token）。

置信度：高。

#### SUP-05 · Docker 镜像供应链与完整性 · Medium · lane 依赖

位置：`docker/Dockerfile:1-35`、`docker_overtls_caddy/Dockerfile:1-31`

证据（`docker/Dockerfile:1-26` 节选）：
```dockerfile
FROM alpine:3.17
...
    apk add --update --allow-untrusted --no-cache bash unzip wget fontconfig nginx nginx-mod-stream nginx-mod-http-headers-more nginx-mod-http-lua vim && \
```
```dockerfile
    wget -O overtls.zip https://github.com/shadowsocksr-live/overtls/releases/latest/download/overtls-x86_64-unknown-linux-musl.zip && \
```
影响与前提：运行时下载 `releases/latest` 的 zip（**无版本、无 checksum、无签名校验**）并直接解压执行 → 上游 release 被替换/中间人被投毒即得到容器内的代码执行；`--allow-untrusted` 关闭 apk 签名校验；基础镜像是 EOL 的 `alpine:3.17`（`docker/Dockerfile:1`）；同时把 apk 源改为 aliyun 镜像（`docker/Dockerfile:26`）。镜像以 `USER root` 运行（`docker/Dockerfile:39`）。
前提：无（每次构建即发生）。

复现：静态推导，未复现。

修复建议：改为多阶段构建（用 `COPY --from=builder` 引入本仓库构建的二进制或固定版本 release + sha256 校验）；`apk add` 去掉 `--allow-untrusted`，升级基础镜像到受支持版本；不要替换官方源（或至少固定并校验）。

置信度：高。

#### SUP-09 · 两个关键依赖已标记 unmaintained · Medium · lane 依赖

位置：`Cargo.toml:47`（`rustls-pemfile = "2.2.0"`）、`Cargo.toml:64`（`daemonize = "0.5.0"`）；`src/tls.rs:16-23`、`170-187`；`src/bin/main.rs:119-125`

证据（`cargo audit` 原始输出）：
```
Crate:     daemonize
Version:   0.5.0
Warning:   unmaintained
Title:     `daemonize` is Unmaintained
Date:      2025-09-14
ID:        RUSTSEC-2025-0069
```
```
Crate:     rustls-pemfile
Version:   2.2.0
Warning:   unmaintained
Title:     rustls-pemfile is unmaintained
Date:      2025-11-28
ID:        RUSTSEC-2025-0134
```
影响与前提：两者都不在“已知漏洞”之列（本次扫描 0 漏洞，advisory-db 1295 条），但均已被 RustSec 标注为**无人维护**：`rustls-pemfile` 承担证书/私钥/cafile 的 PEM 解析（`src/tls.rs:16-23`、`170-187`）——这是 TLS 材料可信链的入口，长期停留在无维护的解析器上不可接受；`daemonize` 只服务于 `-d`（`src/bin/main.rs:119-125`，`#[cfg(unix)]`），与 `SEC-15` 的 `/tmp` 固定文件名问题在同一处。
前提：无（现状即如此）。

复现：`cargo audit`（本次临时安装 `cargo-audit 0.22.2`）；原始 JSON 见 `tmp/audit/audit.json`。

修复建议：`rustls-pemfile` → 迁移到 `rustls-pki-types` 的 PEM 解析（上游已把该能力合并回去）或 `rustls-pemfile` 的官方替代；`daemonize` → 改为由系统管理器托管（systemd unit 已存在，`-d` 可标记 deprecated），或用 `nix`/`libc` 自行 fork+setsid。
置信度：高。

#### SEC-17 · 头数上限不一致（512 vs 124） · Low · lane ①

位置：`src/server.rs:316`（512）对 `tungstenite-0.30.0/src/handshake/headers.rs:10`（`MAX_HEADERS = 124`）。
影响：125..=512 个头的请求“通过路径检查但握手失败”，且相比“头数正常 + 路径错误”情形响应完全不同（见 `SEC-11`），构成稳定指纹；两侧常量不一致本身也说明校验逻辑是拼接而非统一设计。
修复建议：抽出共享常量/统一解析器。
置信度：高。

#### SEC-18 · 客户端 TLS 指纹偏离浏览器 · Low · lane ①

位置：`src/tls.rs:31-38`（`CHROME_CIPHERS`）、`src/tls.rs:55-59`

证据（`src/tls.rs:31-36`）：
```rust
    // TLS 1.3 cipher suits
    rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    // TLS 1.2 cipher suits
    rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
```
影响：名称为 `CHROME_CIPHERS` 的列表只含 TLS1.3 全部 3 套 + TLS1.2 的 2 个 ECDHE-AES128 套件；**完全没有设置 ALPN**（全仓库无 `alpn` 出现），也没有 GREASE、没有 CA 列表裁剪、扩展顺序固定。ClientHello 里 TLS1.3 套件顺序为 AES256→AES128→CHACHA20。真实 Chrome 在上述每一项上都有可观测差异（顺序、ALPN `h2,http/1.1`、GREASE 值、TLS1.2 套件是 6 个而非 2 个）→ 被动 DPI 可用“无 ALPN + 套件集合/顺序 + 无 GREASE”的组合高置信度识别。[INFERENCE] 与真实浏览器的差异依据公开常识，未在本机抓包比对。
修复建议：真正对齐目标浏览器（补 ALPN、补 TLS1.2 CHACHA/AES256、加 GREASE、可用 `rustls` 的 `ClientConfig::alpn_protocols` 与 `extension_order` 类能力），或干脆不再使用 `CHROME_CIPHERS` 这一误导性命名。
置信度：高（代码事实）／中（“与 Chrome 不同”的具体项为外部知识）。

#### SEC-19 · 证书缺失/加载失败时静默明文监听 443 · Low · lane ①

位置：`src/server.rs:56-78`

证据（`src/server.rs:58-78`）：
```rust
    let acceptor = tls_paths.and_then(|(cert_path, key_path)| match server_tls_acceptor(cert_path, key_path) {
        Ok(acceptor) => Some(acceptor),
        Err(error) => {
            log::warn!("{mn} -- failed to load server certificate or key: {error}");
            None
        }
    });
    let (tls_acceptor_tx, tls_acceptor_rx) = watch::channel(acceptor);
    if tls_acceptor_rx.borrow().is_none() {
        log::warn!("{mn} -- no certificate and key file, using plain TCP");
```
影响：`config` 里既没写 `certfile/keyfile`、或文件读失败时，服务端在 `listen_port`（默认 443）上**明文**接受请求，只有 `warn!`。443 上跑明文是极强的指纹（也直接暴露所有隧道内容），而配置错误与正常运行在日志之外没有区别；`-v info` 下的唯一提示是这条 warn。
修复建议：默认拒绝启动（除非显式 `allow_plaintext: true` 或 `disable_tls: true`）；启动横幅打印 `TLS: on/off`。
置信度：高。

#### SEC-20 · 证书热重载在 symlink / 子目录布局下不触发 · Low · lane ②

位置：`src/server.rs:170-193`（watch 注册）、`src/server.rs:257-259`（事件过滤）

证据（`src/server.rs:186-192`）：
```rust
    let directories: HashSet<PathBuf> = [&cert_path, &key_path]
        .into_iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect();
    for directory in directories {
        watcher
            .watch(&directory, RecursiveMode::NonRecursive)
```
证据（`src/server.rs:257-259`）：
```rust
fn event_affects_tls_files(event: &Event, cert_path: &Path, key_path: &Path) -> bool {
    !event.kind.is_access() && event.paths.iter().any(|path| path == cert_path || path == key_path)
}
```

影响与前提：监听的是证书/私钥**父目录**且 `RecursiveMode::NonRecursive`，事件路径必须与配置里的字面路径**完全相等**（未做 `canonicalize`）。因此最常见的 Let's Encrypt/certbot 布局（`certfile = /etc/letsencrypt/live/<domain>/fullchain.pem` 是指向 `../../archive/<domain>/fullchainN.pem` 的**符号链接**）下：证书轮换改写的是 `archive/` 里的真实文件，而被监视目录是 `live/<domain>/` 且非递归 → **永远收不到事件**，服务端继续用旧证书直到人工重启（表现为轮换后客户端校验失败/服务中断，而日志里没有任何错误）。同理，符号链接本身被替换（`Modify(Name)` 只发生在 `live/` 目录，事件路径等于配置路径）能触发一次，但如果工具只改目标文件内容就完全不触发。另注：父目录不存在或无权限时 `watch()` 失败会让 `watch_server_tls_files` 返回 `Err` → `run_server` 启动失败（fail-loud，可接受）。
前提：证书以符号链接 + 目标目录布局部署（certbot/lego 的默认行为）；或证书/私钥位于子目录。

复现：静态推导，未复现（Windows 上无法复现 inotify+symlink 语义；`tls_reload_event_tests` 的 2 个单测只覆盖“同一路径被写”与“只读访问”两种事件）。

修复建议：`canonicalize` 配置路径后再注册监视并同时监视解析后的目标目录；对 certbot 场景至少监视 `archive/` 父目录；把 `RecursiveMode::Recursive` 作为可选项；在 reload 任务里加“启动时记录的证书指纹 vs 定期重读的指纹”巡检（例如每小时一次）作为兜底，并在指纹变化却未触发 reload 时给出 `warn!`。
置信度：中（代码与部署习惯可确定，具体平台事件语义未在本机实跑）。

#### COR-03 · 计费口径为近似值 · Low · lane 正确性

位置：`src/server.rs:42`、`src/server.rs:435-438`、`src/server.rs:500`、`src/server.rs:630`、`src/server.rs:786`

证据（`src/server.rs:42`）：
```rust
const WS_MSG_HEADER_LEN: usize = 14;
```
证据（`src/server.rs:435-438`）：
```rust
    if let Some(client_id) = &client_id {
        let len = WS_HANDSHAKE_LEN;
        let len = if !handshake.is_empty() { handshake.len() } else { len };
        let len = (len * 2) as u64;
```
影响：真实 WS 帧头是 2 字节（≤125B 载荷）到 4–14 字节（长载荷），客户端方向的帧还要 +4B 掩码；握手则按“实际首包长度的 2 倍”一次性记一笔（`handshake.len()` 最大 2048，故 4096B），与真实流量无对应关系。以 1500B UDP 包计误差约 +1%（14/1514）；以 20B DNS 查询计误差 70%。方向恒为**高估**（保守），因此不会放过超量用户，但会让限速/封禁阈值提前触发。
修复建议：按 `msg.len() + frame_header_len(msg.len()) + (client_to_server ? 4 : 0)` 精确计算（tungstenite 不暴露头部长度时可用同一公式），握手按实际字节计数。
置信度：高（公式确定）。

#### COR-04 · UDP 分片包终止整个关联；>1238B 载荷被静默丢弃 · Low · lane 正确性

位置：`src/udprelay.rs:119-123`、`src/udprelay.rs:61-62`、`socks5-impl-0.9.8/src/server/connection/associate.rs:216-225`

证据（`src/udprelay.rs:119-123`）：
```rust
        let (pkt, frag, dst_addr, src_addr) = listen_udp.recv_from().await?;
        if frag != 0 {
            log::warn!("{mn} -- [UDP] packet fragment is not supported");
            break;
        }
```
证据（`src/udprelay.rs:61-62`）：
```rust
            let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
```
影响：`UdpHeader::max_serialized_len() = 3 + Address::max_serialized_len() = 3 + 259 = 262`（`socks5-impl-0.9.8/src/protocol/udp.rs:27-29`、`socks5-impl-0.9.8/src/protocol/address.rs:121-123`），故接收缓冲为 **1238** 字节；超过该长度的 SOCKS5 UDP 报文会在 `recv()` 层被截断（`socks5-impl-0.9.8/src/server/connection/associate.rs:219-225` 用 `recv_from` + `truncate`），随后头部解析失败被静默跳过——即实际可用载荷上限约 1228B，而不是 `MAX_UDP_RELAY_PACKET_SIZE=1500` 所暗示的值。此外 `frag != 0` 时直接 `break` 退出 `socks5_to_relay`，**终止整个 UDP 关联**（所有应用的 UDP 一起断），而 RFC 1928 语义下只需丢弃该包。
修复建议：`frag != 0` 改为 `continue` + 限频告警；按“1500 - 10”分配缓冲（或让 `MAX_UDP_RELAY_PACKET_SIZE` 表示净载荷），并在文档中写明可用的 UDP 载荷上限。
置信度：高（算术与代码确定）／中（截断的具体丢包行为以 vendored 源码为据，未实跑大包）。

#### COR-06 · UDP 帧尾随字节被当作载荷，超长报文终止隧道 · Low · lane 正确性

位置：`src/udprelay.rs:351-356`、`src/server.rs:743-747`
影响：`decode_udp_packet` 只切走两个地址，剩余全部字节作为载荷（无长度上限校验）。对端（客户端或服务器）可以在**地址合法**的前提下附加任意长度数据，服务端随后 `send_to`（`src/server.rs:743-747`）对 >65507B 的报文必然失败 → `?` → 隧道终止（与 `SEC-13` 同源，但这条路径无需畸形帧，只需超长帧）。
修复建议：校验 `pkt.len() <= MAX_UDP_RELAY_PACKET_SIZE`，超出即丢弃该帧并告警；发送错误同样降级为丢帧。
置信度：高。

#### COR-07 · DNS 缓存无容量上限 · Low · lane 正确性

位置：`src/dns.rs:55-59`
证据：
```rust
pub(crate) fn create_dns_cache() -> Cache<Vec<Query>, Message> {
    Cache::builder()
        .time_to_live(Duration::from_secs(30 * 60))
        .time_to_idle(Duration::from_secs(5 * 60))
        .build()
}
```
影响：未设置 `max_capacity`。moka 0.12.16 在 `max_capacity = None` 时不做容量淘汰：`has_enough_capacity()` 为 `self.max_capacity.map_or(true, ...)`（`moka-0.12.16/src/future/base_cache.rs:1478-1482`），源码注释即“or the cache is unbounded”（同文件 `:1679-1680`）。因此只有 TTL/TTI 生效，本地应用可在 5 分钟内用海量不同域名（或不同查询组合）把内存推到无上限；缓存随 `_run_udp_loop` 重建（`src/udprelay.rs:193`），命中率也受 1 小时生命周期限制。
修复建议：`max_capacity(10_000)`（并按 `Query` 数量估算条目大小）。
置信度：高（含 vendored 源码证据）。

#### COR-08 · `test_config` 依赖外部网络 · Low · lane 正确性

位置：`src/config.rs:543-560`
影响：`test_config` 构造 `server_host: "www.gov.cn"` 并调用 `check_correctness(false)`，内部会做真实 DNS + TCP 连接（`src/config.rs:371-377`）。该测试既未 `#[ignore]` 也未做 mock：在离线环境（含企业 CI、容器内无出网）必然失败或挂满 10 秒超时；它同时把外网可达性变成测试套件的前置条件。
修复建议：改为 `127.0.0.1` + 本地临时监听（或直接拆成“纯函数”测试：只测 `generate_ssr_url`/`from_ssr_url` 往返，不再触发网络）。
置信度：高。

#### COR-09 · WS 关闭握手未完成（不回 Close 帧） · Low · lane 正确性

位置：`src/server.rs:503-506`、`src/client.rs:454-457`

证据（`src/server.rs:503-506`）：
```rust
                    Message::Close(_) => {
                        log::debug!("{mn} -- {peer} <> {dst_addr:?} incoming connection closed normally");
                        break;
                    }
```
影响与前提：收到对端的 Close 帧后直接 `break` 退出循环并丢弃流，**不回送 Close 帧**，RFC6455 §5.5.1 的关闭握手未完成；客户端侧同样（`src/client.rs:454-457` 只 `break`）。实跑（`P6` 补充用例 `p6_ws_close.py`，发送掩码 Close 帧 `88 82 aabbccdd a953`）确认服务端应答为 0 字节后 FIN。后果：严格实现“等待 Close 回执”的对端会一直等到自身超时（本实现的客户端不等待，所以自测不可见）；同时该行为对实现良好的 WS 客户端是一个指纹特征。
修复建议：`Message::Close(_)` 分支改为 `ws_stream.close(None).await?`（或 `send(Message::Close(None))` 后再 break）。
置信度：高（实跑 + 代码）。

#### COR-11 · SOCKS5 CONNECT 在服务端确认前就回 `Succeeded` · Low · lane 正确性

位置：`src/client.rs:389-390`（回复）对 `src/client.rs:406-409`、`420-424`、`464-466`（确认门控）

证据（`src/client.rs:389-390`）：
```rust
{
    let incoming = connect.reply(Reply::Succeeded, Address::unspecified()).await?;
```
证据（`src/client.rs:406-409`，确认请求在回复**之后**才发出）：
```rust
    // Send "Start session" command with target address
    let b64_addr = addess_to_b64str(&dst, false);
    let start_cmd = format!("{START_SESSION}:{b64_addr}");
    ws_stream.send(Message::Text(start_cmd.into())).await?;
```
影响与前提：本地应用在服务端尚未尝试连接目标（甚至尚未建立 WS 会话）时就收到 `Reply::Succeeded`（实跑观测：即使目标被服务端私网过滤拒绝，应用也先收到 `05 00 00 01 + 00 00 00 00 00 00`，随后才被 `WinError 10054` 重置，见 P2 用例 A/B）。后果：应用无法区分“目标不可达/被策略拒绝”与“连上后对端断开”，SOCKS5 语义被削弱（`Reply::ConnectionRefused`/`HostUnreachable` 永不出现）；对自动化流程会造成“连接成功但立即失败”的误导。数据本身不会错投（`session_confirmed` 门控保证未确认前不从本地读数据，`src/client.rs:418-424`）。
修复建议：把 `reply(Reply::Succeeded, …)` 移到收到服务端 `START_SESSION` 确认之后（失败时按服务端返回的原因回 `ConnectionRefused`/`HostUnreachable`），或至少在收到 `END_SESSION` 时回一个明确的关闭原因。
置信度：高（代码 + P2 实跑观测）。

#### COR-12 · 广播通道 `Lagged` 会终止整个 UDP 关联 · Low · lane 正确性

位置：`src/udprelay.rs:158`、`src/udprelay.rs:196-206`、`src/udprelay.rs:144-146`

证据（`src/udprelay.rs:156-160`，容量 10）：
```rust
pub(crate) fn create_udp_tunnel() -> (UdpRequestSender, UdpRequestReceiver, SocketAddrHashSet) {
    let incomings: SocketAddrHashSet = Arc::new(Mutex::new(HashSet::<SocketAddr>::new()));
    let (tx, rx) = tokio::sync::broadcast::channel::<(Bytes, Address, Address)>(10);
```
证据（`src/udprelay.rs:144-146`，慢消费者会拿到 `Err(Lagged)`）：
```rust
    while let Ok((pkt, addr, _from_addr)) = udp_rx.recv().await {
        let to_addr = SocketAddr::try_from(addr.clone())?;
        if *incoming_addr.lock().await == to_addr {
```
影响与前提：`relay_to_socks5` 用 `while let Ok(...)` 消费广播——一旦该接收者落后超过 10 条（本地 `AssociatedUdpSocket::send_to` 慢、或进程被调度延迟），`recv()` 返回 `Err(Lagged(n))` 而不是 `Ok`，循环**正常返回**（`Ok(())`）→ `handle_s5_upd_associate` 的 `select!` 以该分支结束 → 整个 SOCKS5 UDP 关联被关闭（不只是丢那 10 个包）。即：突发流量或短暂调度抖动会让本地应用的 UDP 关联直接消失，需要应用重建 ASSOCIATE。另外每个关联各自 `subscribe()`（`src/udprelay.rs:81`），所有关联都会收到每一份广播（`Some(pkt)` 的克隆成本 × 关联数）。
前提：本地 UDP 负载出现突发/背压（例如一次性大量小包或有慢速对端）。

复现：静态推导，未复现（需构造精确的背压时序；P8 的 1ms 节流未触发）。

修复建议：`recv()` 的错误分支显式处理——`Err(RecvError::Lagged(n))` 记 `warn!` 并 `continue`（丢帧不丢关联）；把容量提到足以覆盖一次突发（如 1024）或改用每关联独立通道 + `mpsc`；对“本地发送失败”单独计数并在阈值内不拆关联。
置信度：高（API 语义与调用形态确定）／中（触发时序未实跑）。

#### FFI-05 · 内存序不一致 · Low · lane ④

位置：`src/dump_logger.rs:48`（`SeqCst` 读）对 `src/dump_logger.rs:60-61`（`Relaxed` 写）
影响：`check_logger()` 用 `SeqCst` 读，写入端用 `Relaxed`。在 `overtls_set_log_callback` 与 `over_tls_client_run` 竞态时可能读到旧的 `false`，从而重复调用 `log::set_boxed_logger`（第二次返回 `Err` 并只打 warn）。后果轻微，但两者的顺序语义应当一致。
修复建议：统一为 `Acquire/Release`（或都用 `SeqCst`）。
置信度：高。

#### FFI-06 · `overtls_generate_url` 契约细节 · Low · lane ④

位置：`src/api.rs:186-208`
证据（`src/api.rs:203-207`）：
```rust
    let required_size = url.as_bytes_with_nul().len();
    if buf.is_null() || size < required_size {
        return required_size;
    }
    unsafe { std::ptr::copy_nonoverlapping(url.as_ptr(), buf, required_size) };
```
影响：返回值为**含 NUL 的长度**，与 `cbindgen.toml:11` 的注释（“Returns the required buffer size, including the null terminator”）一致；`buf.is_null()` 时返回所需长度而不写（正确、可两段式调用）；`copy_nonoverlapping` 不检测重叠与越界（由调用方保证 `size >= required_size`，符合 C 惯例）。未发现缺陷，仅两点可改进：返回 0 同时表示“失败”和“URL 为空”两种语义无法区分；未提供 `errno` 式的失败原因。
修复建议：文档中明确“0 表示失败”，或在头文件提供 `overtls_last_error()`。
置信度：高。

#### FFI-08 · `unsafe impl Send/Sync` 的前置条件未文档化 · Low · lane ④

位置：`src/api.rs:24-25`、`src/dump_logger.rs:65-66`、`src/traffic_status.rs:41-42`
影响：`CCallback`/`DumpCallback`/`TrafficStatusCallback` 都手工 `unsafe impl Send + Sync`，其正确性依赖“宿主提供的 `ctx` 指针本身可跨线程使用”。文档只要求“回调 should be thread-safe”（`src/api.rs:33、76-78`），没有说明 `ctx` 会从**多个**线程被访问（客户端有 per-session 会话来宾线程、tokio worker 与 UDP 看门狗），也没有说明 `*const c_char` 只在回调期间有效（`src/dump_logger.rs:129-141` 在回调返回后即释放 `CString`）。
修复建议：在 `cbindgen.toml` 导出的注释里补三句：ctx 需线程安全；日志指针仅在回调期间有效，不得保存；回调内不得再调用本库 API（见 `FFI-04`）。
置信度：高。

#### PRF-03 · 服务端每消息 `Vec` 复制 · Low · lane 性能

位置：`src/server.rs:594`、`src/server.rs:692-696`、`src/server.rs:783`、`src/udprelay.rs:220`、`src/udprelay.rs:232`、`src/udprelay.rs:343-349`
影响：`buffer[..n].to_vec()`（每读一次分配一次）、`Message::binary(buf.to_vec())`、`buf.freeze().to_vec()`（先转 `Bytes` 再复制回 `Vec`）、`build_udp_packet` 用 `BytesMut::new()`（零容量，多次扩容 + 最终 `to_vec()`）。每条消息 1–3 次额外分配/拷贝；`BytesMut::new()` 起步容量为 0，写地址+载荷时至少 2 次 realloc。
修复建议：统一改用 `Bytes`/`BytesMut` 的零拷贝移交（`freeze()` 后直接 `Message::Binary(bytes)`），`build_udp_packet` 用 `BytesMut::with_capacity(pkt.len() + 32)`。
置信度：高。

#### PRF-04 · UDP 每包分配与每包加锁 · Low · lane 性能

位置：`src/server.rs:643-646`、`src/server.rs:717`、`src/udprelay.rs:126`、`src/udprelay.rs:199`、`socks5-impl-0.9.8/src/server/connection/associate.rs:216-225`
影响：服务端每条 UDP 隧道预分配 2 × `STREAM_BUFFER_SIZE`（Windows 32KB、Linux 96KB）而实际报文上限 1500B（`src/server.rs:643-646`）；每个入站包都要 `dst_src_pairs.lock()` + `Address::clone()` + `insert`（`src/server.rs:717`）；`socks5-impl` 的 `recv_from` 每次调用 `vec![0; 1238]`（vendored 源码 `:218-221`）；客户端 `incomings.lock()` 每包一次（`src/udprelay.rs:199`）并在 `relay_to_socks5` 内每包再取 `incoming_addr.lock()`（`:210`）。
修复建议：缓冲区缩到 1600B 量级；`dst_src_pairs` 用 `HashMap<SocketAddr, Address>`（避免 `Address` 克隆）并考虑分片锁；`incoming_addr` 改 `AtomicU64`/`RwLock` 读写分离。
置信度：高。

#### PRF-05 · 全局审计锁在数据路径上 · Low · lane 性能

位置：`src/server.rs:482-494`、`src/server.rs:630`、`src/server.rs:649-660`、`src/server.rs:788`
影响：每条 TCP/UDP 隧道每秒 1 次 `enable_check.tick()` 取全局 `TrafficAudit` 的 `tokio::Mutex`，且**每个数据消息**再各取一次（上行、下行各一次）。所有会话共享同一把锁 → 隧道数 × 2 msg/s 的最小争用，加上数据面争用；`get_enable_of` 在未启用面板时永远返回 `false`（`src/traffic_audit.rs:120-123`），却仍要加锁（`src/server.rs:489`）。
修复建议：把 `client_id → enable` 抽成 `ArcSwap<HashMap>` 或 `RwLock`，把流量计数改为每会话本地累加、由 1s tick 批量提交。
置信度：高。

#### PRF-06 · 热点路径上的 `method_name_unstable!()` · Low · lane 性能

位置：`src/client.rs:415`（位于 `loop {` 内）
证据（`method_name-0.3.4/src/lib.rs:37-60`）：宏展开为 `core::any::type_name::<T>()` + 若干 `strip_suffix`/`strip_prefix`，trait 方法分支还会 `alloc::format!`（堆分配）。`core::any::type_name` 本身是编译期常量，字符串扫描是常数级开销（无分配）——因此这是**微小但非零**的每消息成本；真正需要注意的是若将来在 trait 方法内调用该宏，会引入每次调用的堆分配。
修复建议：把 `let mn = ...` 提到循环外（与 `src/udprelay.rs:112`、`src/server.rs:483` 的写法一致）。
置信度：高。

#### PRF-07 · 未配置 `[profile.release]` · Low · lane 性能

位置：`Cargo.toml`（无 `[profile.release]`）；实测数据见第 4 节 `P7`。
影响（**已用实测纠正两处常见误判**）：
1. 默认 release 的 exe**不含调试信息，也没有 COFF 符号表**——`objdump -h` 只有 5 个节、`objdump -x` 的 `SYMBOL TABLE:` 后是 `no symbols`，对基线副本执行 GNU `strip(1)` 字节数零变化；调试负载在**独立 PDB**（`target/release/overtls_bin.pdb` = 5,402,624 B）。因此 `strip=true` 对 exe 体积的贡献是 **0 B**，其价值是发布包少一个 5.4 MB 的 PDB。
2. 真正的体积收益来自 `lto` + `panic="abort"` + `codegen-units=1`：`thin`+`cgu=1` → 11,866,624 B（-14.12%）；再叠加 `panic="abort"` → 8,267,264 B（-40.17%）；`fat` LTO → 7,510,528 B（-45.65%）。
3. 顺带证据：默认构建**不可复现**——同输入重建尺寸一致但仍有 52 字节/19 段不同（PE `TimeDateStamp` @offset 264 与 `.rdata` 里 `build.rs` 的 `BUILD_TIME` 字符串），与 `SUP-01` 互相印证。
修复建议：加 `[profile.release] lto="thin", codegen-units=1, panic="abort"`（`panic="abort"` 必须先按 `FFI-03` 明确 FFI 边界的崩溃语义）；`strip=true` 可加，但理由应写成“发布包不含 PDB”，不要指望它缩小 exe。
置信度：高（全部为本次实测）。

#### PRF-08 · 重复的 `webpki-roots` 与未使用的 tungstenite TLS 特性 · Low · lane 性能

位置：`Cargo.toml:55-57`（`tokio-tungstenite` 的 `rustls-tls-webpki-roots`）；`cargo tree -d` 实测。
影响：`cargo tree -d` 显示 `webpki-roots v0.26.11`（经 `tokio-tungstenite`）与 `webpki-roots v1.0.9`（直接依赖）**同时**存在，两套 Mozilla 根证书表都会进入产物；而本仓库并不使用 tokio-tungstenite 的 TLS 连接器（唯一引用被注释：`src/client.rs:576`；全仓库无 `connect_async`/`client_async` 调用），该特性拉入的 `rustls`/`webpki-roots` 依赖树属于无用负担。另有 `getrandom v0.4.3`、`windows-sys v0.60.2`/`v0.61.2` 等重复版本（共 6 处重复根，见 `cargo tree -d`）。
修复建议：`tokio-tungstenite` 改为 `default-features = false`（仅 `handshake`/`protocol` 能力）；评估 `reqwest`（仅面板同步使用）是否可换更小的客户端，或至少开启 `default-features = false` 已生效的配置下再剪掉 `rustls-platform-verifier`。
置信度：高。

#### SUP-02 · MSRV 从未验证 · Low · lane 依赖

位置：`Cargo.toml:9`（`rust-version = "1.89"`）、`.github/workflows/check.yml:21`
影响：CI 全部使用 `dtolnay/rust-toolchain@stable`（`.github/workflows/check.yml:21、29、38、75`，`.github/workflows/release.yml` 同），`rust-version` 没有任何 job 校验；“1.89 可编译”这一对外承诺未被自动化，无法防止后续依赖升级把 MSRV 顶上去（本例中 `Locking 274 packages to latest Rust 1.89 compatible versions` 说明 cargo 会按 MSRV 裁剪，但那只是解析期约束，不等于构建通过）。
修复建议：加一个 `1.89` 固定 toolchain 的 `cargo check` job。
置信度：高。

#### SUP-04 · GitHub Actions 未固定 SHA · Low · lane 依赖

位置：`.github/workflows/*.yml`
影响：`actions/checkout@v7`、`dtolnay/rust-toolchain@stable`、`vmactions/freebsd-vm@v1`、`softprops/action-gh-release@v3`、`ahmadnassri/action-dependabot-auto-merge@v2` 全部为浮动标签，标签被移动即执行新代码；其中发布流水线（`.github/workflows/release.yml`/`.github/workflows/freebsd.yml`/`.github/workflows/mips-unknown-linux-gnu.yml`）持有 `GITHUB_TOKEN` 与发布权限。
修复建议：全部固定到 commit SHA（配合 Dependabot 的 github-actions 更新）。
置信度：高。

#### SUP-06 · 缺少动态分析基建 · Low · lane 依赖

位置：全仓库。
影响：无 `fuzz/`（`cargo-fuzz`）、无 Miri、无 sanitizer job、无覆盖率门禁、无 `[dev-dependencies]`；而本项目有 4 处手写解析（HTTP 头、WS 握手、SOCKS5 地址、DNS 报文）与 6 个 `unsafe` FFI 导出——正是最需要 fuzz/Miri 的地方。审计中也因此只能对 `FFI-03` 的 panic 可达性给“中”置信度。
修复建议：为 `udprelay::decode_udp_packet`、`check_uri_path`、`b64str_to_address`、`dns::parse_data_to_dns_message` 建 4 个 `cargo-fuzz` target；为 FFI 加 Miri 可跑的 smoke test。
置信度：高。

#### SUP-07 · `build.rs` 依赖 git 且无 `rerun-if-changed` · Low · lane 依赖

位置：`build.rs:1-19`、`src/cmdopt.rs:111-113`
影响：`GIT_HASH` 仅在 `git rev-parse --short HEAD` 成功时才通过 `cargo:rustc-env` 注入，而 `src/cmdopt.rs:112` 用 `env!("GIT_HASH")` 断言其存在 → **在没有 `.git` 的环境（源码 tarball、部分打包系统）直接编译失败**；同时 `build.rs` 未输出任何 `rerun-if-changed`，`git commit --amend` 之类不改文件的 HEAD 变更不会触发重编 → 版本串可能陈旧（本次基线 `-V` 显示 `24b4edf` 与 HEAD 一致，属正常情形）。
修复建议：`get_git_hash` 失败时注入 `"unknown"` 而非跳过；补 `cargo:rerun-if-changed=.git/HEAD`。
置信度：高。

#### SUP-08 · 发布流水线不跑测试 · Low · lane 依赖

位置：`.github/workflows/freebsd.yml:41-43`、`.github/workflows/mips-unknown-linux-gnu.yml:32-37`、`.github/workflows/release.yml:74-90`
影响：三条发布流水线只做 `fmt`/`clippy`/`build`（FreeBSD）或直接 `build`（mips、release），没有任何 `cargo test`；测试只在 `.github/workflows/check.yml:104` 跑，且那是针对**宿主机目标**（无 `--target`）而非交叉目标。同时 FreeBSD/mips/release 的产物 zip 里包含 `./config.json`（`.github/workflows/freebsd.yml:48`、`.github/workflows/mips-unknown-linux-gnu.yml:37`），即把 `SEC-02` 里的公开默认路径一并分发。
另注：`.github/workflows/mips-unknown-linux-gnu.sh:28-31` 用 `cat > .cargo/config.toml` 覆写 `.cargo/config.toml`，本机执行会破坏 iOS 的链接参数（审计未运行该脚本）。
修复建议：发布前加最小冒烟（起 server/client 跑一次握手）；zip 内不放 `config.json`（或放 `config.json.example` 且路径为占位符）。
置信度：高。

---

## 4. 性能

### 4.1 成本表

|#|位置|单位成本|受影响路径|依据|
|---|---|---|---|---|
|1|`src/client.rs:416`|32KB（Windows）/96KB（其他）堆分配 + 清零，**每消息一次**|客户端每个 TCP 消息|代码；`STREAM_BUFFER_SIZE` 定义于 `src/lib.rs:34-37`|
|2|`src/client.rs:433`、`src/client.rs:200`|1 次全量 `to_vec()` 复制（读方向）／每片 1 次（写方向）|同上|代码|
|3|`src/client.rs:415`|`method_name_unstable!()` 展开的字符串扫描（无分配；trait 方法内会 `format!`）|每个消息|`method_name-0.3.4/src/lib.rs:37-60`|
|4|`src/server.rs:594,692,783`|`to_vec()` 每消息 1–2 次|服务端 TCP 隧道|代码|
|5|`src/udprelay.rs:343-349`|`BytesMut::new()`（零容量）+ 2 次 realloc + `to_vec()`|每个 UDP 包（双向）|代码|
|6|`src/server.rs:632,791`；`src/client.rs:433`；`src/udprelay.rs:222`|`SinkExt::send` = feed+flush ⇒ 每消息 1 次 `write` syscall|所有数据面|代码（`send` 语义）|
|7|`src/tcp_stream.rs:19-27`|未设 `TCP_NODELAY`/keepalive ⇒ Nagle 生效|所有 socket|代码（Rust 默认 Nagle 开启）|
|8|`src/server.rs:722-726`|**每 UDP 包一次**阻塞 `to_socket_addrs()`（域名时才真查 DNS），发生在 async 上下文|服务端 UDP|代码|
|9|`src/server.rs:799-804` + `src/tcp_stream.rs:22-41`|阻塞 `connect_timeout`，上限 `test_timeout_secs`（默认 10s，逐候选累加），发生在 async 上下文|服务端 `Start session`/`Target-Address`|代码|
|10|`src/server.rs:500/630/788`|每消息 1 次全局 `tokio::Mutex`（`TrafficAudit`）|服务端数据面|代码|
|11|`src/server.rs:482/649`|每隧道每 1s 取同一把锁|服务端全部隧道|代码|
|12|`src/udprelay.rs:126/199/210`|每包 1–2 次 `Mutex`（`incomings`、`incoming_addr`）|客户端 UDP|代码|
|13|`socks5-impl-0.9.8/src/server/connection/associate.rs:218-221`|每包 `vec![0; 1238]` 分配|客户端 UDP|vendored 源码|
|14|`src/server.rs:645-646`|每隧道 2 × `STREAM_BUFFER_SIZE`（Windows 64KB / Linux 192KB）常驻，对 1500B 报文|服务端每条 UDP 隧道|代码|
|15|`connection-pool-0.3.9/src/connection_pool.rs:292,328`|`Semaphore::acquire_owned` 准入 + `connection_timeout`（默认 10s）包裹 `create_connection`；permit 持有至会话结束|客户端并发会话数上限 = `pool_max_size`（默认 50）|vendored 源码|
|16|`src/client.rs:604-616`|连接复用时 3s 超时的 Ping/Pong 探活（每次 `get_connection`）|客户端会话建立|代码|
|17|`src/dns.rs:55-59`|无上限的 moka 缓存（TTL 30min / TTI 5min）|客户端 `--cache-dns`|`moka-0.12.16/src/future/base_cache.rs:1478-1482`|

### 4.2 实测

**P7 · release 产物体积（`cargo build --release` 各 profile 覆盖）**

方法：`{ time cargo build --release --config 'profile.release.<key>=<value>' …; }`（cargo 1.95.0 接受 `--config` 形式，未使用环境变量回退）；每个变体 `stat -c '%s'` 取精确字节数。构建耗时列是在 5 个 PoC 子代理并发跑 server/python 时取得的，仅作参考量。

|变体|exe 字节数|相对基线|构建耗时|
|---|---|---|---|
|默认（基线，及 `cargo clean` 后的恢复产物）|**13,817,856**|—|51.28s（全量）|
|`lto="thin"` + `strip=true` + `codegen-units=1`|11,866,624|−14.12%|2m41s|
|`lto="thin"` + `strip=true` + `codegen-units=1` + `panic="abort"`|8,267,264|−40.17%|1m29s|
|`lto="thin"` + `codegen-units=1` + `panic="abort"`（**不加 strip**）|8,267,264|−40.17%（与上一行同尺寸）|1m49s|
|`lto="fat"` + `strip=true` + `codegen-units=1` + `panic="abort"`|7,510,528|−45.65%|2m16s|

结论要点：
1. **默认 release 的 exe 不含调试信息，也没有 COFF 符号表**：`objdump -h` 只有 `.text/.rdata/.data/.pdata/.reloc` 五个节（无任何 `.debug_*`）；`objdump -x` 末尾 `SYMBOL TABLE:` 后紧跟 `no symbols`；对基线副本执行 GNU `strip(1)` 前后字节数**完全不变**（13,817,856 → 13,817,856）。调试负载在**独立 PDB**：`target/release/overtls_bin.pdb` = 5,402,624 B。`strip=true` 的构建不生成该 PDB → strip 的价值是发布包/磁盘体积（少 5.4 MB），**不是** exe 体积。
2. `strip=true` 与不 strip 的 exe 字节数完全相同（8,267,264 vs 8,267,264），两文件在 PE 层各节尺寸一致（`.text 6639467 / .rdata 1488680 / .data 3584 / .pdata 103560 / .reloc 30124`），差异仅是符号哈希/链接顺序导致的字节重排。[INFERENCE] 机制：cargo 把 `strip` 计入 unit hash → `-C metadata` 变化。各变体都能正常运行（`-V` 均输出 `overtls 0.3.15 (24b4edf …)`）。
3. `panic="abort"` 是单项收益最大者（−26 个百分点），但它把 panic 变成直接终止进程——必须与 `FFI-03` 的宿主进程边界一起决策，不能单独加。
4. 构建**不可复现**的旁证：同输入下默认产物重建后尺寸一致（13,817,856），但仍有 52 字节/19 段不同，其中 `offset 264` = PE `TimeDateStamp`，`offset 11523283` = `.rdata` 内 `build.rs` 写入的 `BUILD_TIME` 字符串（`06:46:28` vs `06:55:47`）→ 与 `SUP-01` 的“每次构建解析最新依赖”叠加，构成双重不可复现。
5. 恢复：`cargo clean`（移除 12817 个文件 / 6.0 GiB）+ 裸 `cargo build --release` 后 `target/release/overtls-bin.exe` 回到 13,817,856 B，`-V` → `overtls 0.3.15 (24b4edf 2026-10-09 06:55:47)`，`target/release` 产物集合与基线一致（`overtls.dll 6415360`、`overtls.lib 63899068`、`libovertls.rlib 16159582` 等）。
6. 未改动仓库：`git diff --stat` 为空（profile 覆盖只走命令行）。

**P8 · UDP 回环端到端延迟（直连 / 明文隧道 / TLS 隧道）**

方法：`"C:/Program Files/Git/bin/bash.exe" tmp/audit/p8_run.sh` 一条命令串起 3 轮；UDP echo 目标 `127.0.0.1:19999`；2000 包 × 512B 载荷、1ms 节拍、序号写在载荷前 4 字节（回包按序号匹配，避免乱序影响统计）；配置 `tmp/audit/p8-{server,client}-{plain,tls}.json`（明文 `disable_tls=true` @18680/11080；TLS 用 `certs-a`、`server_domain=example.com`+`cafile=certs-a/root.crt` @18681/11081；两侧**都不带** `client_id`，以避开 `COR-10` 的 1 秒踢除）。运行期间无其它负载（P7 构建已结束）。

|轮次|收到/发出|丢包率|min|p50|p95|p99|max|
|---|---|---|---|---|---|---|---|
|① 直连（不经 overtls）|2000/2000|0.00%|29.3|93.9|162.9|231.0|694.2|
|② 明文隧道（`disable_tls=true`）|2000/2000|0.00%|102.0|**236.9**|337.6|410.0|1023.2|
|③ TLS 隧道|2000/2000|0.00%|110.6|**249.0**|366.0|441.3|1024.2|

（单位 µs；三轮均用满 2.0s 的发送节拍预算，收包阶段 0.05s，轮次之间串行）

解读：
- 隧道往返净增量：p50 +143 µs（+152%）、p95 +175 µs —— 即“本地 SOCKS5 中继 → WS 封帧 → 服务端解帧 → UDP 转发 → 原路回程”的代价，与 `PRF-01`/`PRF-03`/`PRF-04` 的每包分配/每包加锁是同一批成本项在回环上的表现。
- TLS 相对明文的增量很小：p50 +12 µs（+5%）、p95 +28 µs。回环 + 512B 小包下每记录开销直接被本地 CPU 吸收，**不能用这组数字推断跨公网表现**（真实链路由 RTT 与拥塞控制主导）。
- 丢包率 0%：在 1228B 有效载荷上限内（`COR-04`）且无并发负载时，UDP 通路本身不丢包。
- **本组数据既不证实也不证伪 `PRF-02` 的 Nagle 问题**：1ms 节拍 + 回环下 ACK 即时返回，Nagle 不会积累延迟；该条仍属“代码推导，未实测”（需真实 WAN 与请求-响应型流量）。
- 未覆盖：>1228B 载荷、多会话并发、跨公网链路、`--cache-dns` 命中路径。
- 收尾核查：脚本退出后 `tasklist` 无 `overtls-bin.exe` 残留，18680/18681/11080/11081/19999 均无 LISTENING。

---

## 5. 依赖与构建强化

- `cargo generate-lockfile`：锁定 **275** 个包（`Locking 274 packages to latest Rust 1.89 compatible versions`，`Cargo.lock` 2704 行；未提交，见 `SUP-01`）。
- `cargo audit`（本次临时安装 `cargo-audit 0.22.2`，advisory-db 1295 条）：**0 个漏洞**；2 个 `unmaintained` 警告：
  - `RUSTSEC-2025-0069` `daemonize 0.5.0`（2025-09-14，unmaintained）→ 影响 `-d` 守护化路径（`src/bin/main.rs:119-125`），并与 `SEC-15` 的 `/tmp` 写法叠加。
  - `RUSTSEC-2025-0134` `rustls-pemfile 2.2.0`（2025-11-28，unmaintained）→ 影响服务端证书/私钥加载（`src/tls.rs:170-187`）与 cafile 解析（`src/tls.rs:16-23`），是本项目 TLS 材料解析的关键依赖，建议迁移到 `rustls-pki-types` 自带的 PEM 解析或维护中的替代品。
  - 原始 JSON：`tmp/audit/audit.json`。
- 重复依赖：`cargo tree -d` 报 6 个重复根 —— `webpki-roots v0.26.11` / `v1.0.9`、`windows-sys v0.60.2` / `v0.61.2`、`getrandom v0.4.3`（两处消费者）→ 见 `PRF-08`。
- CI 门禁现状（`.github/workflows/check.yml`）：`cargo check --all --all-targets --all-features --tests`、`cargo fmt --all -- --check`、`cargo clippy --all --all-targets --all-features -- -D warnings`、7 目标构建矩阵 + `cargo test --all-features`（宿主机目标）。无 advisory/deny/vet、无覆盖率、无 fuzz、无 `--locked`。
- 其他已核对事实：`Cargo.toml` 无 `[features]`/`[profile]`/`[dev-dependencies]`（`--all-features` 为空操作）；`crate-type = ["staticlib","cdylib","lib"]`（C ABI 由 cdylib 导出）；`aws-lc-rs` 因 rustls 的 `aws_lc_rs` 特性必然参与原生构建（本次 Windows MSVC 构建成功，48s）。

---

## 6. 附录

### 附录 A · 攻击者可控输入面（Step 1 复核结果）

|入口|锚点（复核后行号）|判定要点|
|---|---|---|
|服务端首读 ≤2048B，仅 `size==0` 被拒|`src/server.rs:279-283`|无超时、无上限重试；`Partial` 不区分（`COR-02`）|
|httparse 路径判定（512 槽，`Status` 被忽略）|`src/server.rs:315-325`|`Path` 对空数组恒 false（`COR-01`）|
|路径不匹配 → 原样转发 `forward_addr`|`src/server.rs:285-287`、`330-353`|仅接受 http/https；host 必须是 IP 字面量（`host.parse()`）；https 用 webpki 根|
|WS 握手头 `Target-Address`/`UDP-Tunnel`/`Client-Id`|`src/server.rs:370-388`|解析失败静默降级；`Client-Id` 触发无上限表增长（`SEC-03`）|
|WS 文本控制帧 `Start session`/`End session`|`src/server.rs:516-558`|未确认态的文本帧只 warn；`START_SESSION` 可反复重连（每次新建出站连接）|
|WS 二进制 → 目标 TCP（无缓冲直写）|`src/server.rs:507-511`|`write_all` 直接下发；无长度校验|
|UDP 隧道帧 `Address(dst)+Address(src)+payload`|`src/server.rs:679-681`、`715`；`src/udprelay.rs:343-356`|无长度上限、无来源校验（`COR-06`、`SEC-14`）|
|服务端 → 客户端文本帧（驱动本地 socket）|`src/client.rs:450-473`|`REMOTE_EOF` 1s 强关；未确认前不读本地 socket|
|WS 升级响应解析（只比对 `Sec-WebSocket-Accept`）|`src/client.rs:563-575`|不校验 101/Upgrade/Connection；单次 `read_buf`（`SEC-12`）|
|本地 SOCKS5/HTTP 分类（16B peek）|`src/client.rs:232-280`|`0x04` 拒绝；HTTP 方法白名单匹配；其余直接关闭|
|远端 TLS 证书链|`src/tls.rs:13-28`、`107-166`；`src/client.rs:513-526`|`dangerous_mode` 全放行（`SEC-07`）；cafile 追加而非 pin（`SEC-08`）|
|DNS 载荷解析（hickory，`?` 终止 UDP 循环）|`src/udprelay.rs:206-215`、`243-256`；`src/dns.rs:9-24`|非 DNS 报文 → 整条 UDP 中断（`COR-05`）|
|C ABI 入参（含裸指针）|`src/api.rs:47`、`99`、`171`、`186`|`url` 缺 null 检查（`FFI-01`）；enum 越界 UB（`FFI-02`）|
|JNI 入参|`src/android.rs:20`、`142`|`verbosity` 已做范围映射；config/stat 路径来自 Java 侧字符串|

### 附录 B · PoC 脚本与实跑输出

所有 PoC 均使用冻结副本 `tmp/audit/overtls-bin.exe`（13,817,856 字节，`-V` → `overtls 0.3.15 (24b4edf 2026-10-09 06:42:39)`，sha256 `120eb37475ce33074c5b3c4c883bbb6a125efa49c21494abe05eede3d0e41b5d`），以免与并行的重建任务相互影响。复核说明：该副本与 P7 重建后的 `target/release/overtls-bin.exe`（sha256 `492ce62b084c150a5302319bc262e3a26656cf26fdc4f8bafb984abbee4001de`）同为 13,817,856 字节、同一 commit，`cmp -l` 仅 **52** 字节不同——PE `TimeDateStamp`（offset 249/250）与 `.rdata` 内的 `BUILD_TIME` 字符串，即同一源码的两次构建，不含语义差异。端口冲突时按“+100 递增”规则改用 18380/18390 等。

#### P3 · `tunnel_path` 退化取值 → 隧道失效 + 全量转发 · **复现成功（4 组取值全部实测）**

命令：
```bash
python tmp/audit/target_http.py 18090                        # 靶子，回显原始请求行/头
./tmp/audit/overtls-bin.exe -r server -c tmp/audit/cfg-degen-slash.json -v trace      # tunnel_path=["/"]
curl -sS -D- http://127.0.0.1:18080/anything ; curl -sS -D- http://127.0.0.1:18080/tunnel/
./tmp/audit/overtls-bin.exe -r server -c tmp/audit/cfg-degen-empty.json -v trace      # tunnel_path=[""]
./tmp/audit/overtls-bin.exe -r server -c tmp/audit/cfg-empty-list.json -v trace       # tunnel_path=[]（对照）
./tmp/audit/overtls-bin.exe -r server -c tmp/audit/cfg-degen-single-slash.json -v trace  # tunnel_path="/"（对照）
```

原始输出关键行（`tmp/audit/logs/p3-findings.txt`、`p3-curl-results.txt` 等）：
```
[config A/B] 启动 trace 回显:  "tunnel_path": []            ← 归一化后为空数组，且未走 fallback
[config A/B] forward_traffic_wrapper -- not match path "", forward traffic directly...
[curl A/B]   HTTP/1.1 200 OK + X-Target-Port: 18090 + body TARGET-HTTP-18090: forwarded-path=/anything|/tunnel/|/
[config D]   启动 trace: "tunnel_path": "//"                ← Single("/") 被归一化成 "//"
[config D]   GET /  → not match path "//", forward traffic directly...
[config C]   启动 trace: "tunnel_path": "/tunnel/"          ← [] 安全回退到默认值
```

结论：`["/"]`、`[""]`、`["/",""]`、`["//"]` 一律归一化为空数组，`extract()` 返回空切片 → `check_uri_path` 的 `for` 循环 0 次、恒返回 `false`（`src/server.rs:319-324`）→ **所有**请求（含本该是隧道入口的 `/tunnel/`）经 `forward_traffic_wrapper` 原样转发到 `forward_addr`；隧道完全不可用，伪装面退化为“与路径无关、任何未认证连接均可命中的常量端点”。附带后果（本次实测）：真实客户端的握手元数据（`client-id: 33959370-71e0-401d-9746-cda471fc5926`、`udp-tunnel: true`、旧客户端 `Target-Address`）被原样转交给 `forward_addr` 的后端服务。
安全对照：`[]`（空数组）与 `""`（单字符串）都会命中 `is_empty()` → 回退默认 `/tunnel/`，**不会**退化；`Single("/")` 则是另一条漏网路径——归一化成 `"//"`，只匹配字面 `//`（`src/config.rs:73-78`），`/`、`/anything`、`/tunnel/` 全部被转发。
产物：`tmp/audit/cfg-degen-slash.json`、`cfg-degen-empty.json`、`cfg-empty-list.json`、`cfg-degen-single-slash.json`、`tmp/audit/logs/p3-*.log`、`p3-curl-results.txt`、`p3-findings.txt`。

#### P6 · 主动探测可单次区分路径命中 · **复现成功（4 用例 × 3 次重复，逐例响应一致）**

命令：
```bash
./tmp/audit/overtls-bin.exe -r server -c tmp/audit/p6-server.json -v trace   # 127.0.0.1:18380, tunnel_path=["/t/"], forward_addr=http://127.0.0.1:18390
python tmp/audit/target_http.py 18390
python tmp/audit/p6_curl.py      # 12 次 curl.exe -sv -D - 记录 -> logs/p6-<tag>.raw
python tmp/audit/p6_probe.py     # 原始 socket 逐字节探测，3 次/用例 -> logs/p6_python_probe.json
python tmp/audit/p6_ws_close.py  # 合法 WS 握手 + RFC6455 Close 帧
```

|用例|请求|原始响应|
|---|---|---|
|A|`GET /random`（普通）|`HTTP/1.1 200 OK` / `Server: p6-target-http/1.0` / `X-P6-Target: 127.0.0.1:18390` / `Content-Length: 27`，body `P6-TARGET-HTTP GET /random`；curl exit 0，ttfb 1.5–1.8ms|
|B|`GET /t/`（普通）|**0 字节后 FIN**：`http_code=000 size=0`，curl exit 52 `Empty reply from server`，total 0.7–1.2ms|
|C|`GET /t/` + 完整 WS 升级头|`HTTP/1.1 101 Switching Protocols` + `connection: Upgrade` / `upgrade: websocket` / `sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`（129 字节，ttfb 0.6–0.8ms），随后无数据；curl exit 28（`--max-time 3`）|
|D|`GET /random` + 完整 WS 升级头|与 A 完全相同的 `200 OK`（WS 头被原样透传给靶子，靶子日志可见 `Upgrade='websocket'`、`Key='dGhlIHNhbXBsZSBub25jZQ=='`）|

服务端原始日志：
```
A/D: forward_traffic_wrapper -- not match path "/t/", forward traffic directly...
B  : run_server -- 127.0.0.1:30443: tungstenite::error::Error WebSocket protocol error: No "Connection: upgrade" header
      （3 次均由不同 peer 端口触发，随后 session ended；服务端未向 socket 写任何字节）
C  : 无 "not match path" 行；正常关闭轮次见
     svr_normal_tunnel -- 127.0.0.1:50259 <> None incoming connection closed normally
```

结论（探测 oracle）：**无需任何凭证**，一条普通 HTTP 请求即可判定 `tunnel_path` 是否命中——不匹配得到反代/网站的真实完整响应，匹配则得到“0 字节 + FIN”。真实网站从不以 0 字节应答 HTTP 请求，因此“0 字节 FIN”本身就是“命中隧道路径”的阳性指示；TLS 开启时该差异只是被移动到 TLS 记录层之内，结论不变。附加信号：路径正确 + 合法 WS 头即拿到 `101`，服务端**不要求任何 `Client-Id`**（`panel_sync` 默认关闭）就把隧道交付。
旁证发现：收到合法的掩码 RFC6455 Close 帧（`88 82 aabbccdd a953`）后，服务端直接丢弃流、**不回 Close 帧**（`src/server.rs:503-506` 的 `Message::Close(_) => { log::debug!(); break; }`），未完成 RFC6455 §5.5.1 的关闭握手（客户端侧同样如此：`src/client.rs:454-457`）。
产物：`tmp/audit/p6-server.json`、`p6_curl.py`、`p6_probe.py`、`p6_repeat.py`、`p6_ws_close.py`、`tmp/audit/logs/p6-*.raw`（12 份 curl 全量输出）、`p6-summary.txt`、`p6-server.log`、`p6-target-http.log`。

#### P1 · UDP 隧道无目标过滤（SSRF） · **复现成功（零凭证裸 WS + 真实客户端两条路径）**

环境说明：计划端口 18080/1080 被并行 PoC 占用（首次启动时客户端因 `WSAEADDRINUSE` 立即退出），改用 server `127.0.0.1:18580`、client SOCKS5 `127.0.0.1:11080`；判据与端口无关。

命令：
```bash
python tmp/audit/udp_echo.py 127.0.0.1 19999
# 零凭证裸 WS（手写 WS 帧，无 Client-Id / 无 method / 无 password）
python tmp/audit/ws_raw_udp_poc.py 18580 t 127.0.0.1 19999 127.0.0.1 12345 PING-RAW-WS-OVERTLS
# 真实客户端经 SOCKS5 UDP ASSOCIATE
python tmp/audit/socks5_udp_poc.py 11080 127.0.0.1 19999 PING-VIA-REAL-CLIENT
# RFC1918 目标
python tmp/audit/udp_echo.py 10.255.216.78 19999 && python tmp/audit/ws_raw_udp_poc.py 18580 t 10.255.216.78 19999 127.0.0.1 12345 PING-RFC1918-DST
# 反向对照：同一目标的 TCP 方向
curl -s -m 10 --socks5 127.0.0.1:11080 http://127.0.0.1:19998/     # curl_rc=56
```

原始输出（`tmp/audit/logs/ws_raw_poc.log`、`poc_socks5_client.log`、`overtls_server3.log`、`udp_echo_lan.log`）：
```
P1-A  HTTP/1.1 101 Switching Protocols                                        ← 请求仅含 Host/Connection/Upgrade/Version/Key + UDP-Tunnel: true
P1-A  [raw-poc] binary frame payload hex=017f0000014e1f017f000001303950494e472d5241572d57532d4f564552544c53
P1-A  [raw-poc] reply frame opcode=0x02 len=33 hex=017f0000013039017f0000014e1f50494e472d5241572d57532d4f564552544c53
P1-A  udp-echo: #1 recv from 127.0.0.1:58897 len=19 hex=50494e472d5241572d57532d4f564552544c53 repr=b'PING-RAW-WS-OVERTLS'
      server: svr_send_udp_packet_to_dst -- [UDP] 127.0.0.1:12345 -> 127.0.0.1:19999 length 19
      server: svr_udp_write_ws_stream -- [UDP] 127.0.0.1:12345 <- 127.0.0.1:19999 length 19
P1-B  [poc] step 3: reply head hex=05000001  → relay endpoint = 127.0.0.1:52063
P1-B  [poc] step 5: reply from 127.0.0.1:52063 len=30 hex=000000017f000001cb6050494e472d5649412d5245414c2d434c49454e54
P1-B  [poc] SUCCESS: UDP payload round-tripped through the overtls UDP tunnel (exit 0)
P1-C  server: svr_send_udp_packet_to_dst -- [UDP] 127.0.0.1:12345 -> 10.255.216.78:19999 length 16
P1-C  udp-echo(lan): #1 recv from 10.255.216.78:52067 len=16 repr=b'PING-RFC1918-DST'
P1-D  [WARN overtls::server] tcp_stream_from_s5_address -- 127.0.0.1:50306 <> 127.0.0.1:19998 destination address is private, skipping
P1-D  [ERROR overtls::server] svr_normal_tunnel -- 127.0.0.1:50306 failed to create connection to address '127.0.0.1:19998': … All addresses failed to connect
```

补充用例（同批实跑）：
- **P1-E（单会话 DoS）**：`dst=0.0.0.0:19999` → `closed with error "IO error: … (os error 10049)"`；`dst=169.254.169.254:80` → `(os error 10051)`；`dst=[::ffff:127.0.0.1]:19999` → `(os error 10049)`。三者都让整条 UDP 隧道立即结束。
- **P1-F（`COR-10` 的双向对照）**：带 `Client-Id` → 包先被转发（`reply len=33, PING-WITH-CLIENT-ID`），随即 `svr_udp_tunnel -- [UDP] tunnel disabled by panel sync for client 33959370-…`，客户端观察 `after hold: tunnel gone (eof)`；不带 `Client-Id`（同载荷）→ `after hold: tunnel gone (timed out)`（服务端未关闭），且真实客户端的 UDP 隧道持续存活并每 30s 收到 `received ping message, ignoring`。
- **P1-G（唯一的过滤点）**：`dst=127.0.0.1:53` → 服务端 trace 打印的是**重写前**目标（`-> 127.0.0.1:53`），本机 `:53` 的 echo 只留下 `[udp-echo] listening on 127.0.0.1:53`、未收到任何包 → 证明 53 端口路径是**替换为 8.8.8.8**而非拦截。**测试副作用如实记录**：该用例向 `8.8.8.8:53` 真实外发了一个 11 字节 UDP 数据报。
- **P1-H（未复现项）**：`[::ffff:127.0.0.1]:19999` 与 `0.0.0.0:19999` 在 UDP 路径同样被 OS 拒绝（10049，与 P2 的 Windows 语义一致）；`100.64.0.1:53`（CGNAT，分类器未覆盖）与 `192.168.221.1:19999` 的 `send_to` **成功**（隧道未被拆，因无监听者而超时）→ 说明 UDP 侧根本不存在私网拒绝逻辑。

结论：未授权客户端（**零凭证**，只要 `tunnel_path` 命中）可让服务端向任意 UDP 目标（含回环与 RFC1918）转发并把回包送回；TCP 方向的同类目标被明确拒绝，A/B 对照成立。
产物：`tmp/audit/{udp_echo.py,socks5_udp_poc.py,ws_raw_udp_poc.py,p1_run_matrix.sh,server-udp.json,client-udp.json}`、`tmp/audit/logs/{ws_raw_poc.log,poc_socks5_client.log,overtls_server2.log,overtls_server3.log,udp_echo*.log}`。

#### P2 · `addr_is_private` 的 IPv4-mapped 绕过 · **过滤绕过复现成功；端到端回环读取在 Windows 上未打通（平台限制，机制已定位）**

命令：
```bash
python -m http.server 34598 --bind 127.0.0.1 --directory tmp/audit/p2/httproot   # 带 marker.txt
./tmp/audit/overtls-bin.exe -r server -c tmp/audit/p2/server.json -v trace > tmp/audit/logs/p2-srv-final.log 2>&1
./tmp/audit/overtls-bin.exe -r client -c tmp/audit/p2/client.json -v trace > tmp/audit/logs/p2-cli-final.log 2>&1
python tmp/audit/p2/socks5_connect_poc.py > tmp/audit/p2/poc-run-final.txt 2>&1   # server 34580 / proxy 34581
python tmp/audit/p2/mapped_connect_diag.py > tmp/audit/p2/diag-os-level.txt 2>&1
```

|用例|SOCKS5 目标|服务端原始日志|判定|
|---|---|---|---|
|A（反例）|`127.0.0.1:34598`|`WARN tcp_stream_from_s5_address -- … <> 127.0.0.1:34598 destination address is private, skipping` → `ERROR … failed to create connection … All addresses failed to connect`|过滤生效（`std_create` 从未被调用）|
|B|`::ffff:127.0.0.1:34598`（ATYP=4）|`DEBUG … <> [::ffff:127.0.0.1]:34598 destination address is unreachable: 在其上下文中，该请求的地址无效。 (os error 10049)`|**绕过生效**：该行只能由 `src/server.rs:807-809` 的 `Err` 分支产生，而该分支仅当 `addr_is_private()` 在第 800 行返回 `false` 时才可达|
|C|`0.0.0.0:34598`|`destination address is unreachable: … (os error 10049)`|同类绕过（`0.0.0.0/8` 未覆盖）|
|D|`100.64.0.1:34598`|`destination address is unreachable: 由于目标计算机积极拒绝 … (os error 10061)`|同类绕过（CGNAT 未覆盖，且已到达 OS 连接阶段）|

OS 级隔离实验（`tmp/audit/p2/diag-os-level.txt`）：
```
AF_INET6, V6ONLY unset (socket2 default), target ::ffff:127.0.0.1   -> FAIL errno=10049
AF_INET6, IPV6_V6ONLY=1,              target ::ffff:127.0.0.1        -> FAIL errno=10049
AF_INET6, IPV6_V6ONLY=0,              target ::ffff:127.0.0.1        -> CONNECT OK -> b'HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 Pytho'
AF_INET, target 127.0.0.1 (baseline, filter catches)                -> CONNECT OK -> b'HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 Pytho'
```
结论：mapped 地址在**双栈**（`IPV6_V6ONLY=0`，Linux 默认）时确实能连上回环服务并读取数据；Windows 默认 `V6ONLY=1` 且 `socket2 0.6.5` 从不清除该位（`socket2-0.6.5/src/socket.rs:773-800` 的 `set_common_flags` 在 Windows 上什么都不做），因此本机端到端被 OS 拒绝。这是**真实的分类器缺口**，可利用性由平台/双栈设置决定；Linux 上可打通为 [INFERENCE]（本机无 WSL/Linux 环境，未实跑）。
产物：`tmp/audit/p2/{server.json,client.json,client-withid.json,socks5_connect_poc.py,mapped_connect_diag.py,poc-run-final.txt,poc-withid.txt,poc-run1.txt,poc-run2.txt,diag-os-level.txt,key-lines.txt,netstat-1.txt,netstat-2.txt,netstat-final.txt,httproot/marker.txt}`、`tmp/audit/logs/p2-*.log`。

#### P5 · cafile 生效性 / webpki 回退 / 证书名校验边界 / `dangerous_mode` · **复现成功（11 个用例）**

证书材料（复用仓库 `install/selfsign.sh`；注意在 Git Bash 下需显式路径且 `MSYS_NO_PATHCONV=1`，否则 `-subj` 的 `/C=CN/...` 会被 MSYS 改写）：
```bash
(cd tmp/audit/certs-a && MSYS_NO_PATHCONV=1 "C:/Program Files/Git/bin/bash.exe" \
   D:/OpenSources/network/overtls/install/selfsign.sh CN JiangSu ChangZhou OvertlsOrgA CA-A \
   example.com test@example.com example.com 127.0.0.1)
openssl x509 -in certs-a/server.crt -noout -ext subjectAltName       # -> DNS:example.com, IP Address:127.0.0.1
openssl verify -CAfile certs-b/root.crt certs-a/server.crt          # -> error 20 … unable to get local issuer certificate
```
`certs-a`/`certs-b` 同 SAN 不同 CA；`certs-c` 的 SAN 为 `DNS:example.com, IP:192.0.2.1`（**不含** `127.0.0.1`）。

|用例|配置|原始输出|判定|
|---|---|---|---|
|正例|`cafile=certs-a/root.crt`，`server_domain=example.com`，`server_host=127.0.0.1:18180`|`< HTTP/1.1 301 Moved Permanently` / `< Server: cloudflare` / `curl exit=0`；服务端 `started new session; … length 85 / <- Some(1.1.1.1:80) length 400`|cafile 生效，SNI≠连接目标可正常工作|
|反例|同上但 `cafile=certs-b/root.crt`|curl `(97) Recv failure: Connection was reset`；客户端 `Connection creation failed: IO error: invalid peer certificate: UnknownIssuer`；服务端 `received fatal alert: UnknownCA`|cafile 确实参与校验|
|路径不存在|`cafile=<不存在路径>`|**启动与运行日志中无任何 ERROR/WARN，也没有任何提到 cafile 的行**；仅 `[UDP] IO error: invalid peer certificate: UnknownIssuer`|**静默回退**|
|空串|`cafile=""`（出厂 `config.json:28` 的值）|同上，无配置层报错|**静默回退**|
|PEM 体非法|`cafile=certs-bad/badbase64.crt`|`ERROR overtls::tls] retrieve_root_cert_store_for_client -- Error parsing certificate: Custom { kind: InvalidData, error: "InvalidCharacter(33)" }` 后继续 → `UnknownIssuer`|记录后静默降级|
|DER 非法|`cafile=certs-bad/badder.crt`|`tokio_rustls::rustls::Error invalid peer certificate: BadEncoding`（进程存活，仅该次建连失败）|`add()` 分支才致命|
|**webpki 回退反证**|`cafile=<不存在>` + `server_host=1.1.1.1:443` + `server_domain=cloudflare-dns.com`|`Connection creation failed: String error: Response { status: 301, version: HTTP/1.1, …, "server": "cloudflare", "location": "https://one.one.one.one/t/" }`|TLS 握手成功 → 此刻信任集合就是 webpki 根|
|`dangerous_mode=true`|+ `cafile=certs-b/root.crt`（错误 CA）|仅 `WARN create_tls_ws_stream -- Dangerous mode enabled, this will skip certificate verification…`，随后 `< HTTP/1.1 301` / `curl exit=0`|**无条件绕过**|
|域名校验|`server_domain=wrong.example.com`|`certificate not valid for name "wrong.example.com"; certificate is only valid for DnsName("example.com") or IpAddress(127.0.0.1)`|域名**被**校验|
|连接目标不校验|`server_host=127.0.0.1:18181` + `certs-c`（无 `127.0.0.1` SAN）|`[UDP] Websocket pong from remote` → `curl` 301 / `exit=0`|证书只绑定 `server_domain`|
|内联 PEM|`cafile` 字段 = `certs-a/root.crt` 全文（2142 字节）|`http_code=301` / `curl exit=0`|内联 PEM 生效|

产物：`tmp/audit/p5-{server-a,server-c}.json`、`tmp/audit/p5-client-*.json`（13 份）、`tmp/audit/certs-{a,b,c}/`、`certs-bad/`、`tmp/audit/curl-body-*.txt`、`tmp/audit/hdr-{ok,bad}.txt`、`tmp/audit/logs/p5-*.log`、汇总 `tmp/audit/p5-cafile-evidence.txt`。

#### P4 · FFI NULL `url` → 确定性访问违例 · **复现成功（release 与 debug 一致）**

工程：`tmp/audit/ffi-null/`（`Cargo.toml`：`overtls = { path = "../../.." }`，`.cargo/config.toml` 隔离 `target-dir`，`src/main.rs` 按 `argv[1]` 选择用例，`run_cases.py` 批量记录原始退出码与 stdout/stderr，`Cargo.lock` 复制自仓库根以固定版本）。

命令：
```bash
cargo build --release --manifest-path tmp/audit/ffi-null/Cargo.toml
cargo build         --manifest-path tmp/audit/ffi-null/Cargo.toml
python tmp/audit/ffi-null/run_cases.py tmp/audit/ffi-null/target/release/overtls-ffi-null.exe
python tmp/audit/ffi-null/run_cases.py tmp/audit/ffi-null/target/debug/overtls-ffi-null.exe
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe" -c "g; r rip, rax; u @rip L1; kb; g; q" \
    tmp/audit/ffi-null/target/release/overtls-ffi-null.exe ssr-null
```

原始结果（`tmp/audit/ffi-null/out/results.txt`、`results.json`）：
```
ssr-null          release exit=3221225477 (0xC0000005) STATUS_ACCESS_VIOLATION | debug 同
ssr-null-catch    release exit=3221225477 (0xC0000005)                      | debug 同
config-null       release exit=0 RET=-1        <- 对照（api.rs:58 判空）
genurl-null       release exit=0 RET=0         <- 对照（判空）
ssr-garbage       release exit=0 RET=-1        <- 对照（非空非法 URL）
stop              release exit=0 RET=0
$ cmd.exe /v:on /c "...\overtls-ffi-null.exe ssr-null & echo CMD exit=!ERRORLEVEL!"
CMD exit=-1073741819            # 无符号 0xC0000005
--- stderr (ssr-null, release) ---
[ssr-null] BEGIN
[ssr-null] calling over_tls_client_run_with_ssr_url(url = NULL, ...)
[2026-10-09T06:54:42Z WARN  overtls::api] over_tls_client_run_with_ssr_url -- failed to set logger, error=SetLoggerError(())
                                                                     <- 此后无任何输出，函数未返回
--- 调试器 ---
(55dc.b394): Access violation - code c0000005 (first chance)
rip=00007ff8da3ed921 rax=0000000000000000
ucrtbase!strlen+0x31: 00007ff8`da3ed921 488b10  mov rdx,qword ptr [rax]
  ... : ucrtbase!strlen+0x31
  ... : overtls_ffi_null!over_tls_client_run_with_ssr_url+0x18b
```
UB 性质（rustc 1.95.0 `core/src/ffi/c_str.rs:253-263`）：`from_ptr` 函数体 = `let len = strlen(ptr);` + `from_bytes_with_nul_unchecked(...)`，既无 `is_null()` 也无 `debug_assert!()` → 所以 debug 构建与 release 表现**完全相同**（排除了“debug 才会断言”的猜想）；`ssr-null-catch` 组合说明外层 `catch_unwind` 抓不到任何可展开的 unwind。触发的是 C 侧前置条件违例，表现由 CRT 决定：本平台 ucrtbase 的 `strlen` 立即解引用 NULL 而确定性崩溃，其它 CRT 可能返回垃圾长度后继续，把任意内存当 URL 解析（仍为 UB）。
产物：`tmp/audit/ffi-null/{Cargo.toml,Cargo.lock,src/main.rs,run_cases.py,out/results.txt,out/results.json,out/ssr-null.txt,out/ssr-null-catch.txt,out/config-null.txt,out/genurl-null.txt,out/ssr-garbage.txt,out/stop.txt}`。

#### P7 · release 体积/裁剪量化 · **完成**

原始测量与结论见第 4.2 节（表格 + 5 条要点）。产物：`tmp/audit/overtls-bin-thinlto-strip-cgu1.exe`（11,866,624）、`overtls-bin-thinlto-strip-cgu1-panicabort.exe`（8,267,264）、`overtls-bin-thinlto-cgu1-panicabort-NOSTRIP.exe`（8,267,264）、`overtls-bin-fatlto-strip-cgu1-panicabort.exe`（7,510,528）、`copy-default.exe`（基线副本）、`base-objdump-{h,x}.txt`、`base-nm-count.txt`、`base-size-A.txt`、`b2-size-A.txt`、`b3-size-A.txt`、`build{2,3,4,5,6}-*.log`。

#### P8 · UDP 端到端延迟 · **完成（3 轮，0% 丢包）**

原始三份 JSON 与解读见第 4.2 节。产物：`tmp/audit/p8_run.sh`、`tmp/audit/p8_bench.py`、`tmp/audit/p8-{server,client}-{plain,tls}.json`、`tmp/audit/p8-{direct,plain,tls}.json`、`tmp/audit/logs/p8-*.log`。

#### 收尾状态

所有 PoC 进程已终止并核验（`tasklist` 无 `overtls-bin.exe`；18680/18681/11080/11081/18080/18090/18580/19999 等端口均无 LISTENING）；仓库已跟踪文件未被修改（`git status --porcelain` 仅 `?? AGENTS.md`、`?? openspec/`，另有本报告 `audit-report.md` 与 `Cargo.lock` 为本审计新增的未跟踪文件）。**测试副作用如实记录**：P1-G 用例向 `8.8.8.8:53` 真实外发过 1 个 11 字节 UDP 数据报（验证 53 端口的“重写而非拦截”语义）。

### 附录 C · 已复核但未发现问题的审项

|审项|结论与理由|
|---|---|
|SOCKS5/HTTP 地址、长度字段的解析内存安全|`Address::try_from(&[u8])` 走 `Cursor` + `read_exact`（`socks5-impl-0.9.8/src/protocol/address.rs:298-301`），截断输入返回 `Err` 而非 panic；`decode_udp_packet` 的两次 `split_to` 依赖刚解析出的 `Address::len()`，不可能越界。未发现内存安全问题|
|WS 协议层校验（服务端）|`tungstenite` 的 `create_response` 校验 `GET`/`HTTP/1.1+`/`Connection: Upgrade`/`Upgrade: websocket`/`Sec-WebSocket-Version: 13`/key（24 字符 base64 → 16 字节）（`tungstenite-0.30.0/src/handshake/server.rs:28-90`）；`WebSocketConfig::default()` 提供 `max_message_size=64MiB`、`max_frame_size=16MiB`、`accept_unmasked_frames=false`、读/写缓冲各 128KiB（`tungstenite-0.30.0/src/protocol/mod.rs:95-105`）——虽然是隐式默认值，但对“恶意对端用超长帧撑爆内存”已有上限；`max_write_buffer_size = usize::MAX` 是唯一的例外（写失败才累积，未构成可复现放大面）。未发现需立即修复项|
|`WsWebSocketStreamAdapter` 的读写语义|`poll_read` 空消息继续、`Close`/`None` 返回 0 长度（EOF），`poll_write` 用 `start_send` + `poll_flush` 分开（`src/client.rs:150-230`）。未发现数据丢失或死锁|
|服务端 TCP 隧道状态机|`outgoing_can_be_read` 串行化（写成功后才允许读）避免了“读结果乱序/丢失”，`END_SESSION`/`REMOTE_EOF`/`Close` 三条终止路径都有确定终态，`is_old_client` 保留旧语义（`src/server.rs:468-634`）。数据面无丢失、无乱序|
|客户端会话门控|`session_confirmed` 前不读本地 socket（`src/client.rs:406-412`），`REMOTE_EOF` 触发 1s 强关并补发 `End session`（`src/client.rs:461-473`）。重复 `Start session` 时服务端先关旧连接再建新的（`src/server.rs:516-537`）。未发现竞态导致的数据错投|
|`panel_sync` 失效模式|属 **fail-closed**：`get_enable_of` 对未知 id 返回 `false`（`src/traffic_audit.rs:120-123`），未同步成功时所有隧道被拒（`src/server.rs:419-433`）——安全方向正确，代价是“面板不可达=服务不可用”，已在 `SEC-16` 记录超时缺失|
|`traffic_audit` 计数溢出|`ClientNode` 的累加用 `saturating_add`（`src/traffic_audit.rs:19-25`），无溢出 panic|
|`overtls_generate_url` 的缓冲契约|与 `cbindgen.toml:11` 注释一致（含 NUL 的所需长度；`buf.is_null()` 或空间不足时不写）——见 `FFI-06`|
|Android `JAVA_VM`/`VPN_SERVICE` 覆盖顺序|`JAVA_VM.replace()` 先于 `VPN_SERVICE.replace()`（`src/android.rs:62-66`），因此旧 `Global<JObject>` 被 drop 时新 VM 已就位，不会用已释放的 VM 调 `DeleteGlobalRef`。未发现缺陷|
|Windows 服务路径|`src/win_svc.rs` 走 `windows-service` crate 的标准 `service_dispatcher` 流程（`-d` 时由 `src/bin/main.rs:128-131` 调用）。未发现权限或生命周期问题|
|`--pool-max-size` 下界|CLI 对 client 强制 `>= 10`（`src/cmdopt.rs:106-111`，注意提示文案写成 “must be greater than 10” 而实际允许 10）；但**配置文件路径没有同等校验**：`pool_max_size: 0` 会经 `connection-pool` 的 `Semaphore::new(0)`（vendored 源码 `:266`）让每次 `acquire_owned()`（`:292`）永久阻塞 → 本地 SOCKS5 能接受连接但永不转发。属配置校验缺口（低），建议在 `check_correctness` 里补 `pool_max_size >= 1` 的检查|

### 附录 D · 复现用配置文件与脚本清单

见 `tmp/audit/`（不清理，作为证据留存）：`audit.json`、`audit.err`、各 PoC 脚本与日志；`<script>` 名称在附录 B 中逐条给出。另含本报告的自检工具与修订记录：`verify_citations.py`（66 个证据块逐行核对 `file:line`，最终 0 处不符）、`dump_citations.py`（251 条引证的边界检查，0 处越界）、`fix_citations.sed`、`audit-report.pre-fix.md`（修订前副本，可用于对比）。

# DNS 特性修复（GUI 配置往返 + 安卓数据面）

> 分支：`resolve-doh`（基于 `ZnqbuZ/feat/dns-policy`，PR#1862 可定制魔法 DNS）。
> 本文覆盖该分支上全部 3 个修复 commit。

---

## 一、GUI「编辑为文件」丢失 `[dns]` 配置（commit `940208b`）

### 问题

GUI「编辑网络 → 编辑为文件」输入的 `[dns]` / `[[dns.zone]]` 段，保存后再次打开丢失；
其它段（`[[peer]]`、`[network_identity]` 等）正常。命令行 `easytier-core -c config.toml` 不受影响。

### 根因

GUI 保存配置时经过 `NetworkConfig`（protobuf）做一次往返 `TOML → NetworkConfig → TOML`。
`NetworkConfig` 没有 dns 字段、`launcher.rs` 也不处理 dns，dns 在中间表示里被丢弃。

### 解决

给 `NetworkConfig` 加一个字符串字段 `dns_config_toml`（proto field 67），把 `[dns]` 段序列化为 TOML 文本存进去，
反向再解析写回；其它配置仍走原有结构化字段，不受影响。

改动（2 个文件）：
- `easytier/src/proto/api_manage.proto`：`message NetworkConfig` 新增 `optional string dns_config_toml = 67;`
- `easytier/src/launcher.rs`：
  - `new_from_config()`：把 `[dns]` 段序列化进 `dns_config_toml`
  - `gen_config()`：把 `dns_config_toml` 解析写回配置

dns 代码用 `#[cfg(feature = "magic-dns")]` 门控。`magic-dns` 是 easytier 的默认 feature，
GUI 构建自动带上，GUI 侧（`parse_network_config` / `generate_network_config`）无需改动。

---

## 二、安卓自定义 DNS 无效（commit `a9be870`）

### 问题

Windows GUI 上自定义 `[[dns.zone]]` 正常解析，安卓 App 上完全无效——DNS 查询仍走运营商 DNS。

### 根因

安卓 TUN 是只读 fd（`virtual_nic.rs` `config.raw_fd(tun_fd)`），Rust 侧既无法给 TUN 绑 IP
（`DummyIfConfiger` 空实现），普通 app 也无 `CAP_NET_BIND_SERVICE`（无法 bind 特权端口 53）。
于是 `DnsServer` 的 socket bind 路径在安卓彻底失效——`rebind()` 把失败的 binding `retain` 掉，静默空转。

DNS 查询包进入 TUN fd → NIC forward pipeline → `get_msg_dst_peer_ipv4(100.100.100.101)` 找不到 peer → 丢弃。

外加一个前端问题：`mobile_vpn.ts` 用废弃的 `enable_magic_dns` 字段判断是否给 VPN 设 DNS / 加路由，
新 `[dns]` 模块不再写这个字段，导致条件恒假 → 安卓系统 resolver 根本没指向 100.100.100.101。

### 解决

**数据面（`server.rs` + `node.rs`）**：给 `DnsServer` 实现 `NicPacketFilter`，在 NIC packet pipeline 内联应答 DNS/ICMP。

- DNS 查询（UDP:53）：解析请求 → 通过 catalog 解析 → 构建 IPv4/UDP 响应包（src/dst 交换）→ 回注 NIC channel。
- ICMP Echo Request：直接改写为 Echo Reply 回注。
- 响应字节通过 hickory 公开的 `ResponseHandle` + `BufDnsStreamHandle` 获取（`MessageResponse::encode` 是 `pub(crate)`，不能直接调）。

**filter 在桌面端休眠**：桌面（Windows/Linux/macOS）的 `IfConfiger` 真正把 `100.100.100.101` 绑到了 TUN，
DNS 查询由已 bind 的 socket 直接应答，包不进入 NIC forward pipeline → filter 不会触发 → 行为零变化。

**前端信号（`launcher.rs`）**：在 `new_from_config()` 中回填 `enable_magic_dns` 为派生只读信号
（`result.enable_magic_dns = Some(!dns_config.disabled)`），让安卓 VPN 前端重新设上 `addDnsServer` + `100.100.100.101/32` 路由。
`gen_config()` 不读此字段，不会泄漏进 TOML 往返。

改动（4 个文件）：
- `easytier/src/dns/server.rs`：新增 NicPacketFilter impl + DNS/ICMP 包处理 + 辅助函数（+271 行）
- `easytier/src/dns/node.rs`：DnsServer 选举胜出后注册 filter（+10 行）
- `easytier/src/launcher.rs`：回填 `enable_magic_dns`（+9 行）
- `easytier/src/peers/tests.rs`：测试辅助（+14 行）

---

## 三、NIC pipeline 非阻塞修复（commit `4aadb73`）

### 问题

初版 NicPacketFilter 在 `try_process_packet_from_nic` 里内联 `await catalog.handle_request`。
NIC 包处理流水线是串行的（逐包、逐 filter `await`），慢或不可达的 forwarder 会阻塞整个 NIC→peer 转发路径。
实测：安卓上一个挂起的 LAN forwarder 拖垮了所有 LAN 访问，直到重启网络才恢复。

### 解决

把 DNS 解析（含 forwarder）`tokio::spawn` 到独立 task，filter 立即返回；响应就绪后异步回注 NIC channel。
ICMP Echo Reply 无 I/O（纯改写），仍内联处理。

改动（1 个文件）：
- `easytier/src/dns/server.rs`：`handle_dns_query` → `spawn_dns_query`（不 await）+ 独立函数 `resolve_dns_and_inject`（+64/-38 行）

---

## 验证

- 单元测试 `launcher::tests::dns_config_roundtrip`：构造含 `[[dns.zone]]` 的配置走 `new_from_config → gen_config` 往返，断言 zone 不丢。通过。
- Windows GUI 实测：「编辑为文件」输入含 `[[dns.zone]]` 配置 → 保存 → 重开，`[dns]` 段完整保留。
- 安卓实测：配置含 `[[dns.zone]] origin="example.com" records=["nas IN A 1.2.3.4"]` → `nslookup nas.example.com 100.100.100.101` 解析到 1.2.3.4；`ping 100.100.100.101` 通。
- 桌面回归：Windows 仍走 bind 路径（filter 不触发），行为不变。

---

## 改动文件汇总

| 文件 | commit | 改动 |
|---|---|---|
| `easytier/src/proto/api_manage.proto` | `940208b` | +`dns_config_toml` field 67 |
| `easytier/src/launcher.rs` | `940208b` + `a9be870` | dns 往返 + `enable_magic_dns` 回填 |
| `easytier/src/dns/server.rs` | `a9be870` + `4aadb73` | NicPacketFilter 数据面 + 非阻塞 spawn |
| `easytier/src/dns/node.rs` | `a9be870` | filter 注册 |
| `easytier/src/peers/tests.rs` | `a9be870` | 测试辅助 |

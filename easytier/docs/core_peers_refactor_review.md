# easytier-core Peers 重构 Patch Review 报告

## 审查范围

- **分支:** `refactor_core`
- **审查提交范围:** `7521e0ab..81134bab`（共 78 个提交）
- **目标:** 把 `easytier/src/peers/` 整体迁移进 `easytier-core`，同时保持语义不变、不引入新 bug。
- **审查方法:**
  1. 按模块把 78 个提交分成 9 组。
  2. 为每组启动一个 Senior Rust Reviewer subagent，逐个 commit 做 `git show` 审查。
  3. 审查焦点：代码移动是否保留语义、是否有逻辑/类型/顺序/并发/错误处理变化、是否违反 core 的 wasm-safety 约束。
  4. 运行 `easytier/docs/core_peers_refactor.md` 中列出的全部验收命令，记录结果。

## 总体结论

**重构在功能层面基本完成了“peers 进 core”的目标，绝大多数 patch 是机械迁移，语义保持。**

**但发现若干需要关注的地方（按严重性）：**

1. **ACL 包解析器替换 `pnet` 后，对异常/截断包的解析行为与 `pnet` 不完全一致**（`c1f0524`/`b816983`/`ad6e332`）。正常包无差异；畸形包可能被接受并应用 ACL 规则，而旧代码会放行。安全组件建议补齐或显式声明。
2. **错误类型在 core ↔ runtime 之间往返映射时，部分变体会被双包成 `Error::Other(anyhow!(...))`**（`b14f7478`、`7194ece7`）。调用方若精确匹配旧变体，会观察到不同变体。
3. **`7521e0ab` 拆分 proto/core crates 时:**
   - `rpc_types::error::Error::TunnelError` 从结构化 `TunnelError` 变成 `String`，丢失了结构化负载（无当前调用方受影响，但是 API/序列化变化）。
   - 在 `easytier-core/src/transport.rs` 引入了计划文档明确要求删除的 `PacketTransport`/`SocketFactory` 遗留抽象（当前未使用，但与架构方向冲突）。
4. **PeerConn 迁移中的 `TunnelError` 变体调整**（`b4e8df85`）：mpsc/websocket 的 `TunnelError` 变体从 `Anyhow(...)` 改为 `Shutdown`/字符串化，对依赖精确变体的代码有行为差异。
5. **`7194ece7` 把 `check_remote_addr_not_from_virtual_network` 移入 core，该路径调用 `url::Url::socket_addrs`，可能触发 DNS 解析。** 这是旧逻辑，但位于 core 中，需要确认仍满足 wasm-safety 要求（实际 `cargo check` 通过）。
6. **OSPF 迁移量大**（`7fdbe9b8`，~6.5k 行），审查未发现明显语义问题，但无法逐行证明。
7. **Group 8 中 `6a27e36d` 一度误删 `core_conn_info_to_api` 辅助函数**，被同组后续 commit `4835e1b6` 修复；最终状态正确。

**wasm-safety 验收：** `cargo check -p easytier-proto --target wasm32-wasip1` 与 `cargo check -p easytier-core --target wasm32-wasip1 --no-default-features` 均通过，未发现 `tokio::net`、`socket2`、`nix`、`pnet`、`tun`、DNS、netns、socket mark、真实 tunnel impl、`GlobalCtx`、TOML/CLI/service manager 进入 core。

---

## 分组审查详情


### Group 1: Crates split and plan

**Commits:**
- `7521e0ab` refactor: split proto and core crates
- `a512dfbe` docs: record core peers refactor plan
- `642b62d8` docs: clarify peers refactor scope

**审查结果：**
- `7521e0ab` 是整个重构的基础，新增 `easytier-core` / `easytier-proto` 两个 crate，并把大量类型和 RPC runtime 迁出。
  - **Important:** `easytier-proto/src/rpc_types/error.rs:31` — `TunnelError` 从结构化 `#[from] crate::tunnel::TunnelError` 变成 `TunnelError(String)`。虽然 `easytier/src/proto/mod.rs` 加了 shim `From` 让 `?` 仍工作，但任何对 `Error::TunnelError(TunnelError::...)` 做模式匹配的调用方都会失效；序列化负载也变了。
  - **Important:** `easytier-core/src/transport.rs:1` — 引入了计划文档明确称为“前一轮错误重构遗留”的 `PacketTransport` / `TunnelIo` / `SocketFactory` 抽象。当前 commit 中该文件未被使用，运行无影响，但与计划方向冲突。
  - **Minor:** `easytier-proto/src/common.rs:9-20` — `IP_SCHEMES` 改为手写且 feature-gated；默认 `full` feature 下与旧行为一致，但非默认 feature 组合可能导致 URL normalize 行为变化。
  - **Minor:** `easytier/src/tunnel/packet_def.rs:9-11` — `.unwrap()` 改为 `.expect(...)`，panic 路径相同。
  - 其余改动为机械 import/路径调整。
- `a512dfbe`、`642b62d8` 为纯文档，无代码改动。

**Group verdict:** Issues found（主要是 `7521e0ab` 的 `TunnelError` 结构化和 `transport.rs` 遗留抽象）。

---

### Group 2: PeerConn and PeerMap foundations

**Commits:**
- `b4e8df85` refactor: move peer connection core into easytier-core
- `8ed69eb5` refactor: route runtime peer map through core
- `fbfece4b` refactor: expose public ipv6 route info from core
- `da41938a` refactor: use core route trait in runtime
- `2ac8d758` refactor: move route graph algorithm into core
- `1c4d289f` refactor: delegate peer map core logic
- `5b8136e0` refactor: consolidate migrated peer re-export
- `998cc051` refactor: consolidate migrated peers re-exports
- `612de6fd` refactor: track client urls in core peer map

**审查结果：**
- `b4e8df85` 是最大一次代码移动，把 `PeerConn`、握手、Noise、session、secure datagram、PeerMap 等核心逻辑移入 `easytier-core`。
  - **Important:** `easytier-core/src/tunnel/mpsc.rs:32` / `:141` — `MpscTunnelSender::send` 与内部 forward loop 把 closed channel 从 `TunnelError::Anyhow("send error")` 映射为 `TunnelError::Shutdown`；依赖精确变体的代码行为可能变化。
  - **Important:** `easytier-core/src/tunnel.rs:1147` — `TunnelError::WebSocketError` 从包装 `tokio_websockets::Error` 变为 `String`；wasm-safe 必要，但丢失具体错误类型。
  - **Minor:** `easytier-core/src/peers/secure_datagram.rs:17` — `atomic_shim::AtomicU64` 换为 `std::sync::atomic::AtomicU64`；64 位 native 目标等价，`wasm32-wasip1` 支持。
  - **Minor:** `easytier-core/src/peers/peer_conn_ping.rs:120` — 聚合流量指标替换为 `ArcPeerContext` + `network_name`；runtime adapter 仍把 `record_control_tx/rx` 路由到 `StatsManager`，语义保留。
  - **Minor:** `easytier-core/src/peers/route_trait.rs:111` — `get_local_public_ipv6_info` 临时返回 `()`，在 `fbfece4b` 修复。
  - **Minor:** `easytier-core/src/peers/route_trait.rs:160` — 使用 `std::time::Instant` 而 runtime 用 `quanta::Instant`，在 `8ed69eb5` 修复。
- `8ed69eb5` 把 core `route_trait` 的 `Instant` 统一为 `quanta::Instant`，解决与 runtime 的不一致。
- `fbfece4b` 修复 public IPv6 返回 `()` 的 stub，恢复响应形状。
- `da41938a` 中 `RoutePeerInfo -> core_peer::peer::Route` 转换在 `network_length == 0` 时硬编码为 `24`，需确认与旧 implicit default 一致。
- `2ac8d758`、`1c4d289f`、`5b8136e0`、`998cc051` 为纯移动/re-export/delegate，无语义变化。
- `612de6fd` 把 `alive_client_urls` 跟踪移回 core，用 `HashMap<Url, HashSet<PeerConnId>>` 替代 `multimap::MultiMap`，语义等价。

**Group verdict:** Safe。`TunnelError` 变体变化是唯一非机械性行为变更，为 wasm-safe 目标可接受。

---

### Group 3: OSPF route and core context

**Commits:**
- `18175ac6` refactor: move ospf route table into core
- `c8db136d` refactor: use core packet filter traits in runtime
- `0bb92953` refactor: reuse core encrypt primitives in runtime
- `75d15335` refactor: drop stale runtime rpc implementation
- `a1365cc3` refactor: move peer context adapter to global ctx
- `2eaca6fb` refactor: retire runtime peer rpc shim
- `9e9e71a2` refactor: move trusted key map into core context
- `46d45aaf` refactor: expose stun snapshot through core context
- `accd042e` refactor: expose acl groups through core context
- `a248b18b` refactor: move route info inputs into core context
- `f0c4c560` refactor: expose peer events through core context
- `e5950ffd` refactor: make ospf route use core context
- `aa9f4c18` refactor: pass ospf runtime dependencies explicitly
- `df1e8d84` refactor: source ospf placeholder version from context
- `7fdbe9b8` refactor: move ospf route into core
- `7c174ea2` test: restore core ospf interface cache coverage

**审查结果：**
- `18175ac6` 引入 route-table snapshot：`sync_suppressed_peer_ids` 从 snapshot `BTreeSet` 读取，`route_snapshot()` 在持有读锁时克隆整张表。得到的是一致时间点视图，比旧行为更强。
- `c8db136d` 把 blanket impl 替换为对两个具体类型的显式 impl；`auto_impl(Arc)` 覆盖原有 `Arc<PeerRoute>` 用法，语义不变。
- `0bb92953` 删除 runtime 重复 RPC 实现文件；runtime `rpc_impl/mod.rs` 已 re-export core，无变化。
- `a1365cc3` 把 `impl PeerContext for GlobalCtx` 从 `peer_conn.rs` 移到 `global_ctx.rs`，无逻辑变化。
- `2eaca6fb` 把 `StatsRpcMetrics`/`register_service` 移动到更自然位置；`peers::peer_rpc` 变为 inline re-export。
- `9e9e71a2` 把 `TrustedKeyMap` 等原样移入 core context。
- `46d45aaf` 暴露 `stun_info()`，默认返回 `StunInfo::default()`；`GlobalCtx` 委托给原 STUN 收集器。
- `accd042e` 暴露 `acl_group_declarations()`；`PeerGroupIdentity` 映射 proto `GroupIdentity` 字段。
- `a248b18b` 把 route info inputs 移入 `PeerContext`；`GlobalCtx` 各方法委托给原实现。
- `f0c4c560` 新增专用 `peer_event_bus`（容量 16，与原全局 bus 相同），OSPF 改订阅该通道；行为等价。
- `e5950ffd` / `aa9f4c18` / `df1e8d84` / `7fdbe9b8` 把 OSPF ~6.5k 行移入 core；所有 `global_ctx` 访问替换为 `PeerContext` 方法调用，`easytier_version()` 等通过 context seam 提供。
- `7c174ea2` 补充 core OSPF interface cache 单测，覆盖与 runtime 旧测试等价。

**Group verdict:** Safe。OSPF 移动量大，未发现语义问题；`PeerContext` seam 逐步增长，默认实现 harmless。

---

### Group 4: Credential, ACL, metrics, compressor

**Commits：**
- `5a5b30a6` refactor: move credential state into core
- `d83ec4c4` fix: preserve credential save ordering
- `9fbb45eb` refactor: move credential persistence adapter out of peers
- `95a14b17` refactor: move acl primitives into core
- `c1f0524f` refactor: move acl filter into core
- `b816983c` fix: preserve acl packet length parsing
- `ad6e332e` fix: preserve acl truncated header parsing
- `98437bb1` refactor: move traffic metrics into core
- `bcaf9dd2` refactor: move packet compressor into core

**审查结果：**
- `5a5b30a6` 把 credential 内存状态移入 core；`generate_credential_with_options` 在 `generated.changed == false` 时跳过 `save_to_disk`（序列化内容相同，无行为差异）。
- `d83ec4c4` 保持 core `Mutex` 跨越 JSON 序列化和阻塞 `std::fs::write`，与原来单 crate 锁粒度一致；保留了原 contention/latency 风险。
- `9fbb45eb` 纯 relocation + re-export shim。
- `95a14b17` ACL primitives 移入 core；`acl` module 改为 `core` feature 可见，Display impl 仍 `api` feature gated。
- **`c1f0524f` 关键：** 用手写 parser 替换 `pnet` IP/TCP/UDP 解析。正常包输出一致；畸形包行为可能不同。
- **`b816983c` 关键：** IPv4 `transport_payload` 钳制到 `total_length - header_len`，IPv6 钳制到 16-bit payload length，与 pnet 一致。
  - 但 IHL < 5 时仍按 20 字节 header 处理，而 pnet 使用 `header_length * 4`，对非法包行为不同。
- **`ad6e332e` 关键：** 当 buffer 短于 `IHL * 4` 时，parser 把 `payload_start` 设为 `payload.len()` 并返回空 `transport_payload`；pnet 会返回 `None`，旧 runtime 代码因此无条件放行。新代码会接受并分类该包，ACL 行为变化。
- `98437bb1` traffic metrics 直接移动；可见性从 `pub(crate)`  widening 到 `pub`，行为不变。
- `bcaf9dd2` compressor 直接移动，无逻辑变化。

**Group verdict:** Issues found。**ACL parser 对异常/截断 IPv4 包的行为与 pnet 仍有差异**，建议补齐测试或显式文档化。

---

### Group 5: RPC transports, relay, public IPv6

**Commits：**
- `40c10ded` refactor: move peer send routing into core
- `69b10267` refactor: move public ipv6 service into core
- `04ea1a3f` refactor: move relay peer map into core
- `b8e29a12` refactor: move peer rpc transport into core
- `cea15e05` refactor: move relay route transport into core
- `1994432a` refactor: move foreign network rpc transport into core
- `09690299` refactor: move peer admission checks into core

**审查结果：**
- `40c10ded` `send_msg_internal` 返回 core error，runtime 通过 `Error::from` 映射；覆盖所有路由路径可能产生的变体。
- `69b10267` public IPv6 service 移入 core，新增 `PublicIpv6Runtime` trait；`GlobalCtx` 实现复现原行为。
- `04ea1a3f` relay peer map 移入 core，引入 `RelayRouteTransport` seam；runtime shim 做 core↔runtime error 映射，因底层已 delegate 到 core，往返无损。
- `b8e29a12` peer RPC transport 移入 core；channel/peer-map 关闭时的 anyhow 提示文本变化，失败模式相同。
- `cea15e05` / `1994432a` relay/foreign network RPC transport 移入 core，verbatim 迁移。
- `09690299` peer admission checks 移入 core；`close_untrusted_credential_peers` 改为接收 `is_pubkey_trusted` callback，runtime 传 closure 调用 `global_ctx.is_pubkey_trusted`，保留两层信任查找。

**Group verdict:** Safe。error message 文本变化不影响行为。

---

### Group 6: Foreign network

**Commits：**
- `4c038a81` refactor: move peer task scheduler into core
- `3fafcd87` refactor: re-export core foreign network client
- `5605abee` refactor: move foreign network client into core
- `6f925624` refactor: move foreign network accessor into core
- `e2762251` fix: re-export foreign network accessor
- `d64568e6` refactor: move foreign network route interface into core
- `c021dcdf` refactor: make runtime peer map a core re-export
- `6f8837dd` refactor: move peer manager route interface into core
- `9356ea30` refactor: move foreign packet handling into core
- `551781d8` refactor: move recent traffic tracker into core
- `3db35b73` refactor: move foreign network packet router into core
- `9f727eff` refactor: move foreign network manager into core
- `52593ed7` refactor: move peer center map adapter into core
- `73fdc179` refactor: move peer center into core

**审查结果：**
- `4c038a81` peer task scheduler 直接移动，无语义变化。
- `3fafcd87` / `5605abee` foreign network client 变为 core re-export / 移入 core；client URL liveness 跟踪由 runtime wrapper 负责，通过 `close_notifier` 保持行为。
- `6f925624` / `e2762251` / `d64568e6` foreign network accessor/route interface 移入 core，verbatim。
- `c021dcdf` runtime `PeerMap` wrapper 移除，多个调用点增加 `.map_err(...)` / `.into_iter().map(Into::into).collect()` 适配 core 类型；均为机械转换。
- `6f8837dd` 引入 `ForeignNetworkRouteInfoProvider` trait；runtime `ForeignNetworkManager` 实现，字段映射一致。
- `9356ea30` foreign packet handling 移入 core，generic over `ForeignNetworkPacketHandler`；runtime 实现委托并 map error。
- `551781d8` recent traffic tracker 移入 core，用单个 wrapper 替换两个 `Arc` 字段，语义等价。
- `3db35b73` foreign network packet router 移入 core；新增 `PeerContext::disable_relay_data()`，默认读 `self.flags().disable_relay_data`，`GlobalCtx` 覆盖为 `self.flags_arc().disable_relay_data`，同一 flag。
- `9f727eff` foreign network manager 移入 core；
  - **Minor:** `wait_parent_feature_change` 在 `recv()` 出错时不再重新订阅父事件 bus；tokio broadcast lagged receiver 仍有效，行为大概率 benign，但与旧显式 resubscribe 不同。
- `52593ed7` / `73fdc179` peer center 移入 core，`network_name` 替代 `global_ctx`，`list_routes` 返回 core `Route`。

**Group verdict:** Safe。类型转换正确性依赖 `From`/`Into` impl 的无损性，是本次重构的系统性风险点，但未发现具体错误。

---

### Group 7: PeerManager routing and packet processors

**Commits：**
- `e5ed87af` refactor: move peer outbound routing into core
- `2343aa89` refactor: move peer packet router into core
- `cfd838a3` refactor: move proxy route policy into core
- `20056c91` refactor: move default peer packet processors into core
- `5a41b0f7` refactor: move peer route selection into core
- `d6ec9b0a` refactor: move peer route installation into core
- `f1dd2222` refactor: move peer maintenance tasks into core
- `b14f7478` refactor: move peer connection close routing into core
- `67baa84a` refactor: move client tunnel admission into core
- `7194ece7` refactor: move server tunnel admission into core

**审查结果：**
- `e5ed87af` IPv4 广播 peer 选择改用 core `Route` 类型，过滤条件相同；`exit_nodes` 改为 `Arc<RwLock<Vec<IpAddr>>>` 以共享给 core router。
- `2343aa89` / `cfd838a3` / `20056c91` / `5a41b0f7` / `d6ec9b0a` / `f1dd2222` 均为直接移动，pipeline 安装顺序、GC 间隔、清理逻辑保持不变。
- **`b14f7478` Important:** `ForeignPeerConnectionCloser` 把 runtime error 映射到窄 core error 集，未知变体包成 `Error::Other(anyhow!(err))` 后再经 `Error::from` 映射回 runtime；精确匹配旧变体的调用方会观察到不同变体。
- `67baa84a` client tunnel admission 直接移动。
- **`7194ece7` Important:** server tunnel admission 同样存在 error wrapping 问题；
  - **Minor:** `check_remote_addr_not_from_virtual_network` 进入 core 后调用 `url::Url::socket_addrs`，可能触发 DNS 解析；旧逻辑即如此，但现位于 core。

**Group verdict:** Issues found。主要是 error variant 双包问题，以及 DNS-capable 路径进入 core 的 wasm-safety 边界问题（实际编译通过）。

---

### Group 8: Final assembly and shim cleanup

**Commits：**
- `0e5e2410` refactor: move credential peer gc into core
- `39a64fce` refactor: move traffic metrics peer gc into core
- `653040cd` refactor: move peer manager startup into core
- `4936df21` refactor: move peer manager state into core
- `0d94f420` refactor: build peer manager components in core
- `4835e1b6` fix: preserve peer conn shim converter
- `6a27e36d` refactor: inline remaining peers shims
- `e6c536d8` refactor: collapse peers reexport shims
- `d9f075a2` test: move relay packet classification tests to core

**审查结果：**
- `0e5e2410` / `39a64fce` / `653040cd` / `4936df21` / `0d94f420` 把 credential/traffic GC、PeerManager 启动、状态、组件组装全部移入 core；`PeerManagerCore` 现在拥有完整生命周期，runtime `PeerManager` 仅作 adapter。
- `39a64fce` 中 `PeerContextEvent::PeerAdded/PeerRemoved` 增加 `PeerId` payload；事件源与所有 core match 分支同步更新，语义不变。
- `4835e1b6` 恢复 `core_conn_info_to_api` crate-visible 辅助函数。
- **`6a27e36d` Changed:** 在 `peer_conn.rs` 被删除并内联到 `mod.rs` 时，一度误删 `core_conn_info_to_api`；同组后续 `4835e1b6` 修复。最终状态正确，但中间 commit 有临时回归。
- `e6c536d8` 把剩余 shim 文件替换为 `mod.rs` 中的 `pub use`/`pub(crate) use`，无逻辑变化。
- `d9f075a2` 把 relay packet classification 测试移到 core，verbatim。

**Group verdict:** Safe（最终状态）。中间 `6a27e36d` 有临时回归，已被同组修复。

---

### Group 9: Final docs

**Commits：**
- `81134bab` docs: record core peers refactor completion

**审查结果：**
- 纯文档 commit，无代码改动。
- 文档中的事实声明（`PeerManagerCore` 存在、`easytier/src/peers/` 剩余文件列表、验收命令）与代码树一致。

**Group verdict:** Safe。

---

## 验收命令执行结果

| 命令 | 结果 | 说明 |
|------|------|------|
| `cargo check -p easytier-proto --target wasm32-wasip1` | ✅ 通过 | 5.93s |
| `cargo check -p easytier-core --target wasm32-wasip1 --no-default-features` | ✅ 通过 | 7.35s |
| `cargo test -p easytier-core` | ✅ 通过 | 90 个测试全部通过 |
| `cargo check -p easytier --no-default-features` | ✅ 通过 | 11.24s |
| `cargo check -p easytier` | ✅ 通过 | 14.49s |
| `cargo test -p easytier --no-run` | ✅ 通过 | 32.67s，编译成功 |
| `docker exec rust ... cargo test -p easytier foreign_network -- --nocapture` | ✅ 通过 | 34 个 foreign_network 相关测试全部通过 |

**已完成的验收结论：** 所有 wasm-safety 检查、`easytier-core` 单元测试、`easytier` 编译检查均已通过，未发现编译或测试失败。

---

## 需要关注/建议后续处理的问题

1. **ACL 异常包解析行为差异（最重要）**
   - 文件：`easytier-core/src/peers/acl_filter.rs:41-83`
   - 问题：手写 parser 对 IHL < 5 和截断 IPv4 选项/头部的处理与 `pnet` 不同，可能让本应被放行的畸形包进入 ACL 规则匹配。
   - 建议：增加与 `pnet` 行为对标的测试（特别是 `ihl < 5`、截断 header、total_length 小于 header_len 等场景），或显式文档化“对畸形包更严格/更宽松”的策略。

2. **core ↔ runtime error 变体双包**
   - 文件：`easytier/src/peers/foreign_network_manager.rs:581` / `:590`
   - 问题：`ForeignNetworkConnectionAdmission` / `ForeignPeerConnectionCloser` 把 runtime error 转成窄 core error 再转回 runtime，未知变体变成 `Error::Other(anyhow!(...))`。
   - 建议：audit 所有 `easytier` 中精确匹配这些 error variant 的调用方；若存在，应扩展 core error 变体或保留原始 error 透传。

3. **`TunnelError` 结构化丢失**
   - 文件：`easytier-proto/src/rpc_types/error.rs:31`
   - 问题：`Error::TunnelError` 从结构化枚举变成 `String`。
   - 建议：确认没有外部/序列化消费者依赖旧结构；若有，考虑保留一个可序列化的子枚举。

4. **`easytier-core/src/transport.rs` 遗留抽象**
   - 文件：`easytier-core/src/transport.rs:1`
   - 问题：与计划文档冲突的 `PacketTransport` / `SocketFactory` 仍存在（当前未使用）。
   - 建议：在后续重构中删除，避免与新上移的 `Tunnel` trait 并存。

5. **DNS-capable 路径进入 core**
   - 文件：`easytier-core/src/peers/peer_manager.rs:367`（server admission 中的 `url::Url::socket_addrs`）
   - 问题：旧逻辑进入 core，虽然 wasm check 通过，但位于 core wasm-safety 约束的边界。
   - 建议：评估是否应把该检查抽出到 runtime adapter，或在文档中明确允许 `url` 的 socket_addrs 解析。

6. **OSPF 大文件移动无法逐行证明**
   - 文件：`easytier-core/src/peers/peer_ospf_route.rs`（~6.5k 行）
   - 建议：如后续有 OSPF 相关 bug，优先怀疑移动过程中 import/trait-method 映射；当前单测通过是主要信心来源。

---

## 最终评估

- **是否所有 patch 都未引入语义变化或新 bug？** 否。
- **是否存在会直接影响生产运行的 bug？** 未发现明确的运行时崩溃或功能破坏；主要风险是 ACL 对畸形包的处理差异和 error variant 映射差异，具体影响取决于调用方行为。
- **是否建议合入 main？** 在修复或明确接受上述 ACL/error 差异后，可以合入。当前编译和 core 单测已全部通过。

---

*报告生成时间：2026-07-03*
*审查方式：9 个 reviewer subagent 分组逐个 patch 审查 + 本地验收命令*

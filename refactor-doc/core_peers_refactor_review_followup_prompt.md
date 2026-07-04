# 复核提示词：easytier-core peers 重构关键问题确认

请把以下提示词完整发给负责复核的 agent。

---

**角色：** Senior Rust 代码审查员

**任务：** 复核 `refactor_core` 分支上 easytier-core peers 重构中已标记的潜在语义变化问题，确认这些问题是否真实存在、影响范围多大、是否需要修复。

**上下文：**
- 工作目录：`/data/project/EasyTier`
- 分支：`refactor_core`
- 重构目标：把 `easytier/src/peers/` 整体迁移进 `easytier-core`
- 已有一份 patch review 报告在 `easytier/docs/core_peers_refactor_review.md`
- 已发现若干潜在问题，需要你逐个独立复核

**请逐个确认以下问题：**

## 1. ACL 包解析器替换 `pnet` 后的异常包行为差异

- **相关 commit：** `c1f0524f`、`b816983c`、`ad6e332e`
- **相关文件：** `easytier-core/src/peers/acl_filter.rs:41-83`
- **问题描述：** 手写 IPv4/IPv6 parser 替代 `pnet` 后，对畸形/截断包的处理可能与旧代码不一致：
  - IHL < 5 时仍按 20 字节 header 处理，而 `pnet` 使用 `header_length * 4`
  - buffer 短于 `IHL * 4` 时，新代码返回空 transport_payload 并继续分类；旧 `pnet` 返回 `None`，runtime 会无条件放行
- **需要确认：**
  - 这些差异是否真实存在？
  - 是否存在可被利用的 ACL 绕过或误拦截场景？
  - 是否应增加与 `pnet` 行为对标的测试？还是显式文档化新策略？
- **建议操作：** 对比旧 `easytier/src/peers/acl_filter.rs` 中 `extract_packet_info` 使用 `pnet` 的行为，构造 IHL < 5、截断 header、total_length < header_len 等异常包的测试用例。

## 2. core ↔ runtime error 变体双包问题

- **相关 commit：** `b14f7478`、`7194ece7`
- **相关文件：** `easytier/src/peers/foreign_network_manager.rs:581` 和 `:590`
- **问题描述：** `ForeignNetworkConnectionAdmission` / `ForeignPeerConnectionCloser` 把 runtime error 映射到窄 core error 集，未知变体被包成 `Error::Other(anyhow!(...))`，再经 `Error::from` 映射回 runtime，导致精确匹配旧变体的调用方看到不同变体。
- **需要确认：**
  - 当前 `easytier` 中是否有调用方精确匹配这些函数的 error variant？
  - 双包后的 variant 是否与原始 variant 在功能上等价？
  - 是否应扩展 core error 变体或保留原始 error 透传？
- **建议操作：** grep `easytier/src` 中 `close_peer_conn`、`add_tunnel_as_server`、foreign-network admission 的调用点，检查是否有 `if let Error::Xxx = err` 或 `match err`。

## 3. `TunnelError` 结构化丢失

- **相关 commit：** `7521e0ab`
- **相关文件：** `easytier-proto/src/rpc_types/error.rs:31`
- **问题描述：** `Error::TunnelError` 从结构化 `#[from] crate::tunnel::TunnelError` 变成 `TunnelError(String)`，丢失结构化负载。
- **需要确认：**
  - 当前代码库中是否有任何对 `Error::TunnelError(TunnelError::Xxx)` 的模式匹配？
  - 序列化/反序列化是否受到影响？
  - 是否有外部消费者（web、gui、ffi）依赖旧结构？
- **建议操作：** 搜索 `TunnelError(` 和 `Error::TunnelError` 的所有使用位置。

## 4. `easytier-core/src/transport.rs` 遗留抽象

- **相关 commit：** `7521e0ab`
- **相关文件：** `easytier-core/src/transport.rs:1`
- **问题描述：** 该文件引入了 `PacketTransport` / `TunnelIo` / `SocketFactory` 抽象，但重构计划文档 `easytier/docs/core_peers_refactor.md` 明确要求删除这套遗留抽象，以上移后的 `Tunnel` trait 作为唯一 seam。
- **需要确认：**
  - 该文件当前是否被任何代码使用？
  - 是否可以安全删除？
  - 删除是否会影响编译？

## 5. DNS-capable 路径进入 core

- **相关 commit：** `7194ece7`
- **相关文件：** `easytier-core/src/peers/peer_manager.rs:367`（`check_remote_addr_not_from_virtual_network` 中的 `url::Url::socket_addrs`）
- **问题描述：** 该函数可能触发系统 DNS 解析，现位于 `easytier-core`，而 core 的 wasm-safety 约束要求不依赖 DNS resolver。
- **需要确认：**
  - `url::Url::socket_addrs` 在当前使用场景下是否真的会触发 DNS？
  - 是否应把该检查抽到 runtime adapter？
  - `cargo check -p easytier-core --target wasm32-wasip1 --no-default-features` 通过是否足以说明无问题？

## 6. OSPF 大文件移动的语义等价性

- **相关 commit：** `7fdbe9b8`
- **相关文件：** `easytier-core/src/peers/peer_ospf_route.rs`（约 6.5k 行从 runtime 移入）
- **问题描述：** 移动量巨大，无法逐行证明语义等价。
- **需要确认：**
  - 旧 `easytier/src/peers/peer_ospf_route.rs` 与新 core 文件在关键函数（`sync_route_info`、`route_snapshot`、`build_next_hop_map`、`update_my_conn_info` 等）上是否逻辑一致？
  - `PeerContext` trait 替代 `GlobalCtx` 后，所有方法委托是否等价？
  - 是否有遗漏的 runtime 依赖被带入 core？

---

**输出格式：**

对每个问题给出：

```
### 问题 N: <标题>
- **是否确认存在:** 是 / 否 / 部分存在
- **影响范围:** 高 / 中 / 低
- **是否会导致生产 bug:** 是 / 否 / 不确定
- **证据:** 具体文件、行号、代码片段、测试结果
- **修复建议:** 如果需要修复，给出具体方案；如果不需要，说明理由
```

最后给出：

```
## 总体结论
- 最需要优先处理的问题
- 是否建议当前分支合入 main
```

**约束：**
- 不要修改任何代码
- 如果需要运行测试验证，使用 `cargo check` / `cargo test -p easytier-core` / `cargo test -p easytier`
- 对比旧代码时请使用 `git show <commit>^:path/to/file`
- 如果发现我报告中的某个问题不成立，请明确说明并给出证据

---

*提示词来源：easytier/docs/core_peers_refactor_review.md 中标记的关键问题*

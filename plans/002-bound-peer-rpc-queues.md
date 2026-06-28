# 计划 002：为 peer RPC/control packet 队列加入背压和过载行为

> **执行者说明**：按步骤执行本计划。每一步都必须运行验证命令，并确认结果符合预期后再继续。如果触发“STOP 条件”中的任一情况，立即停止并报告，不要自行发挥。完成后更新 `plans/README.md` 中本计划的状态行，除非 reviewer 明确说明由他们维护索引。
>
> **漂移检查（首先运行）**：`git diff --stat 78146d16..HEAD -- easytier/src/peers/peer_manager.rs easytier/src/peers/foreign_network_manager.rs easytier/src/common/stats_manager.rs easytier/src/tests`
> 如果本计划写成后任何范围内文件发生变化，继续前必须对照“当前状态”中的摘录与实时代码；如果不匹配，按 STOP 条件处理。

## 状态

- **优先级**: P1
- **工作量**: M
- **风险**: MED
- **依赖**: plans/001-thread-safe-metrics-throughput.md
- **类别**: perf
- **计划生成于**: commit `78146d16`, 2026-06-18

## 为什么重要

Peer RPC/control packet transport 当前使用 `mpsc::unbounded_channel()`，network-facing packet processor 对每个 RPC packet 直接 `send(...).unwrap()`。如果远端或本地 relay 突发控制面 packet，队列可以无限增长，导致内存膨胀和控制面延迟；如果 receiver 关闭，`unwrap()` 还会 panic。完成后应有明确 bounded capacity、drop/backpressure policy 和可观测 drop 计数。

## 当前状态

- `easytier/src/peers/peer_manager.rs` — local peer RPC transport 队列和 packet processor。
- `easytier/src/peers/foreign_network_manager.rs` — foreign-network RPC transport 队列和 relay/local packet ingestion。
- `easytier/src/common/stats_manager.rs` — 如果 001 已完成，应复用线程安全 metrics 记录 queue drops。

当前代码摘录：

```rust
// easytier/src/peers/peer_manager.rs:275
// TODO: remove these because we have impl pipeline processor.
let (peer_rpc_tspt_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
```

```rust
// easytier/src/peers/peer_manager.rs:1245
struct PeerRpcPacketProcessor {
    peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,
}

// easytier/src/peers/peer_manager.rs:1257
self.peer_rpc_tspt_sender.send(packet).unwrap();
```

```rust
// easytier/src/peers/foreign_network_manager.rs:362
let (rpc_transport_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();

// easytier/src/peers/foreign_network_manager.rs:529
rpc_sender.send(zc_packet).unwrap();
```

仓库约定：control-plane errors 通常通过 `tracing::{debug,warn,error}` 记录；packet hot path 应避免 blocking await。已有 data-plane queues elsewhere 倾向显式容量和丢弃策略；本计划应保持 hot path 非阻塞。

## 需要使用的命令

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all -- --check` | exit 0 |
| Lint | `cargo clippy --all-targets --features full --all -- -D warnings` | exit 0, no warnings |
| Feature check | `cargo hack check --package easytier --each-feature --exclude-features macos-ne --verbose` | exit 0 |
| Targeted tests | `cargo test --package easytier peer_manager --features full -- --nocapture` | exit 0; new queue tests pass if present |

## 临时目录约定

- 临时文件、scratch 目录和 disposable worktree 必须放在 `$HOME/tmp` 下。
- 如果 `$HOME/tmp` 不存在且本计划需要临时空间，先创建它。
- 不要把临时产物放进被修改仓库。

## 范围

**范围内**（只能修改这些文件）：
- `easytier/src/peers/peer_manager.rs`
- `easytier/src/peers/foreign_network_manager.rs`
- `easytier/src/common/stats_manager.rs`（仅用于添加/复用 drop metric names；不要重做 001）
- `easytier/src/tests/*`（仅新增/调整本计划相关测试）

**范围外**（即使看起来相关也不要触碰）：
- RPC protocol message definitions and generated protobuf code。
- Routing semantics、credential trust、foreign network topology logic。
- Frontend, web server, GUI。

## Git 工作流

- Branch: `advisor/002-bound-peer-rpc-queues`
- Commit message style follows existing conventional commits, for example `fix: route_update message is not lag`.
- Do NOT push or open a PR unless the operator instructed it.

## 步骤

### 步骤 1：定义 bounded capacity 和 overload policy

在两个文件中引入同一个小常量，建议名称为 `PEER_RPC_PACKET_QUEUE_CAPACITY`，初始值建议 `1024` 或 `4096`。如果已有相近 queue capacity 常量，复用仓库风格。

Policy 必须明确：packet hot path 不等待；当队列满或 receiver closed 时，丢弃当前 RPC/control packet，记录 `tracing::warn!` 或 rate-limited debug，并增加 drop counter。不要 panic。

**验证**：`cargo fmt --all -- --check` → exit 0。

### 步骤 2：替换 `peer_manager.rs` 的 unbounded channel

将 `mpsc::unbounded_channel()` 替换为 `mpsc::channel(PEER_RPC_PACKET_QUEUE_CAPACITY)`。更新 `RpcTransport`、`PeerRpcPacketProcessor` 字段类型，从 `UnboundedSender`/unbounded receiver 改成 bounded `Sender`/`Receiver`。

在 `try_process_packet_from_peer` 中不要 `.await`，使用 `try_send(packet)`。如果 `Full` 或 `Closed`，记录并返回 `None`，保持原有“这是 RPC packet，不再进入 data-plane pipeline”的行为。

**验证**：`cargo test --package easytier peer_manager --features full -- --nocapture` → exit 0；如果没有匹配测试，至少必须编译通过。

### 步骤 3：替换 `foreign_network_manager.rs` 的 unbounded channel

同样将 foreign-network RPC transport 改为 bounded channel，并在 ingestion path 使用 `try_send(zc_packet)`。不得保留 `unwrap()`。

如果两个文件都需要相同 helper，优先在各文件内保持小函数，避免为了复用引入新模块。最小正确改动优先。

**验证**：`cargo test --package easytier foreign_network_manager --features full -- --nocapture` → exit 0；如果没有匹配测试，至少必须编译通过。

### 步骤 4：添加队列满/receiver closed 的单元测试或小型回归测试

尽量在模块内新增不依赖真实网络 namespace 的测试：创建 bounded channel 容量为 1，填满后调用封装的 send helper，断言不会 panic 且返回/drop counter 行为正确。如果代码结构不允许直接测试 private helper，可以抽出一个 file-local helper function，例如 `try_enqueue_rpc_packet(...) -> bool`，测试 helper。

不要为了测试启动完整三节点网络；这属于慢集成测试，不适合验证 queue behavior。

**验证**：`cargo test --package easytier peer_rpc_queue --features full -- --nocapture` → exit 0；如果测试名不同，使用实际新增测试过滤器，输出中新增测试通过。

### 步骤 5：运行完整相关门禁

**验证**：
- `cargo fmt --all -- --check` → exit 0。
- `cargo clippy --all-targets --features full --all -- -D warnings` → exit 0。
- `cargo hack check --package easytier --each-feature --exclude-features macos-ne --verbose` → exit 0。

## 测试计划

- 新增 queue helper tests，覆盖队列未满、队列满、receiver closed 三种情况。
- 如果添加 drop metric，测试满队列时 counter 增加。
- 不要求新增 full network integration test；bounded queue behavior 应在 unit-level 可验证。

## 完成标准

- [ ] `peer_manager.rs` 不再为 peer RPC transport 使用 `mpsc::unbounded_channel()`。
- [ ] `foreign_network_manager.rs` 不再为 foreign-network RPC transport 使用 `mpsc::unbounded_channel()`。
- [ ] 相关 packet enqueue path 不再调用 `.unwrap()`。
- [ ] 满队列和 receiver closed 有明确非 panic 行为。
- [ ] 新增或更新测试覆盖 queue overload behavior。
- [ ] `cargo fmt --all -- --check` exits 0。
- [ ] `cargo clippy --all-targets --features full --all -- -D warnings` exits 0。
- [ ] `cargo hack check --package easytier --each-feature --exclude-features macos-ne --verbose` exits 0。
- [ ] 没有修改范围外文件。
- [ ] 已更新 `plans/README.md` 中本计划的状态行。

## STOP 条件

- 001 尚未完成，而本计划需要新增 metrics/drop counters；此时先执行 001 或报告阻塞。
- `PeerRpcManager` 或 transport trait 要求 unbounded receiver 类型且无法在范围内替换。
- 正确实现需要改变 RPC protocol semantics 或 routing trust logic。
- bounded queue 导致现有 integration tests 稳定失败，且不能通过容量或 policy 微调解决。

## 维护说明

- reviewer 应重点审查 drop policy 是否适合 control-plane：丢弃低优先级 sync packet 可以接受，但不能默默破坏必须可靠的 request/response path。
- 后续如果出现 reconnect storm 或 route sync loss，应结合 drop metrics 调整 capacity。
- 本计划不实现优先级队列；如果未来需要区分 `RpcReq`、`RpcResp`、`TaRpc` 优先级，应另写计划。

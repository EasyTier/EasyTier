# 计划 001：将共享 metrics/throughput 计数改为线程安全实现

> **执行者说明**：按步骤执行本计划。每一步都必须运行验证命令，并确认结果符合预期后再继续。如果触发“STOP 条件”中的任一情况，立即停止并报告，不要自行发挥。完成后更新 `plans/README.md` 中本计划的状态行，除非 reviewer 明确说明由他们维护索引。
>
> **漂移检查（首先运行）**：`git diff --stat 78146d16..HEAD -- easytier/src/common/stats_manager.rs easytier/src/tunnel/stats.rs easytier/src/tunnel/filter.rs easytier/src/proto/rpc_impl/server.rs easytier/src/tests`
> 如果本计划写成后任何范围内文件发生变化，继续前必须对照“当前状态”中的摘录与实时代码；如果不匹配，按 STOP 条件处理。

## 状态

- **优先级**: P1
- **工作量**: M
- **风险**: MED
- **依赖**: none
- **类别**: bug
- **计划生成于**: commit `78146d16`, 2026-06-18

## 为什么重要

核心 metrics 和 tunnel throughput 计数器当前用 `UnsafeCell<u64>` 保存，并通过 safe methods 在 `Send + Sync` 类型上暴露。VPN 核心运行在多线程 Tokio runtime 上，RPC、tunnel send/receive 和统计快照可能并发访问这些 counters；这会造成 Rust 层面的数据竞争和未定义行为，不只是“统计不准”。完成后应保证所有共享计数使用 atomic 或 lock-backed primitive，且新增并发测试证明 safe API 可多线程调用。

## 当前状态

- `easytier/src/common/stats_manager.rs` — 通用 metrics manager；当前 `UnsafeCounter` 和 `MetricData` 手写 `Send + Sync`。
- `easytier/src/tunnel/stats.rs` — tunnel throughput 统计；当前单独实现一套 `UnsafeCell` counters。
- `easytier/src/tunnel/filter.rs` — `StatsRecorderTunnelFilter` 在 send/receive filter 中更新 `Arc<Throughput>`。
- `easytier/src/proto/rpc_impl/server.rs` — RPC server paths 会更新 stats manager counters，可作为并发使用背景参考，不要求修改。

当前代码摘录：

```rust
// easytier/src/common/stats_manager.rs:406
pub unsafe fn add(&self, delta: u64) {
    let ptr = self.value.get();
    unsafe {
        *ptr = (*ptr).saturating_add(delta);
    }
}

// easytier/src/common/stats_manager.rs:455
unsafe impl Send for UnsafeCounter {}
unsafe impl Sync for UnsafeCounter {}

// easytier/src/common/stats_manager.rs:548
pub fn add(&self, delta: u64) {
    unsafe {
        self.metric_data.counter.add(delta);
        self.metric_data.touch();
    }
}
```

```rust
// easytier/src/tunnel/stats.rs:64
#[derive(Debug)]
pub struct Throughput {
    tx_bytes: UnsafeCell<u64>,
    rx_bytes: UnsafeCell<u64>,
    tx_packets: UnsafeCell<u64>,
    rx_packets: UnsafeCell<u64>,
}

// easytier/src/tunnel/stats.rs:83
unsafe impl Send for Throughput {}
unsafe impl Sync for Throughput {}
```

```rust
// easytier/src/tunnel/filter.rs:265
fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
    self.throughput.record_tx_bytes(data.buf_len() as u64);
    Some(data)
}

// easytier/src/tunnel/filter.rs:270
fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
    match data {
        Ok(v) => {
            self.throughput.record_rx_bytes(v.buf_len() as u64);
            Some(Ok(v))
        }
        Err(e) => Some(Err(e)),
    }
}
```

仓库约定：Rust 代码使用 `anyhow`/`thiserror` 做错误上下文，async tests 使用 `#[tokio::test]`；已有测试集中在 `easytier/src/tests/` 和各模块 `#[cfg(test)]` 中。保持现有 public method names，避免扩大 API 改动。

## 需要使用的命令

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all -- --check` | exit 0 |
| Lint | `cargo clippy --all-targets --features full --all -- -D warnings` | exit 0, no warnings |
| Feature check | `cargo hack check --package easytier --each-feature --exclude-features macos-ne --verbose` | exit 0 |
| Targeted tests | `cargo test --package easytier stats_manager --features full -- --nocapture` | exit 0; new stats tests pass |
| Targeted tests | `cargo test --package easytier tunnel::stats --features full -- --nocapture` | exit 0; new throughput tests pass |

## 临时目录约定

- 临时文件、scratch 目录和 disposable worktree 必须放在 `$HOME/tmp` 下。
- 如果 `$HOME/tmp` 不存在且本计划需要临时空间，先创建它。
- 不要把临时产物放进被修改仓库。

## 范围

**范围内**（只能修改这些文件）：
- `easytier/src/common/stats_manager.rs`
- `easytier/src/tunnel/stats.rs`
- `easytier/src/tunnel/filter.rs`（仅当 type/API 调整需要同步编译）
- `easytier/src/tests/mod.rs` 或同文件内 `#[cfg(test)]` 测试（仅用于新增测试入口）

**范围外**（即使看起来相关也不要触碰）：
- `easytier/src/peers/*` route 或 RPC 行为；这些由后续计划处理。
- `easytier-web/`、`easytier-gui/`、frontend packages。
- 任何 public metric names、labels、serialized output shape 的语义变更。

## Git 工作流

- Branch: `advisor/001-thread-safe-metrics-throughput`
- Commit message style follows existing conventional commits, for example `fix: clarify config parse errors` or `fix(connector): classify manual reconnect timeouts by stage`.
- Do NOT push or open a PR unless the operator instructed it.

## 步骤

### 步骤 1：替换 `UnsafeCounter` 为 atomic-backed counter

在 `easytier/src/common/stats_manager.rs` 中将 `UnsafeCounter` 改为持有 `AtomicU64`。保留现有 `new`、`new_with_value`、`add`、`inc`、`get`、`reset`、`set` 方法名，但将它们改成 safe methods，使用 `Ordering::Relaxed` 即可，因为这些 counters 只做统计，不承载同步 happens-before 语义。

同时移除 `UnsafeCounter` 的 manual `unsafe impl Send/Sync`，让 compiler 从 `AtomicU64` 自动推导。

**验证**：`cargo test --package easytier stats_manager --features full -- --nocapture` → exit 0；如果此时没有匹配测试，命令应显示 0 failed。

### 步骤 2：处理 `MetricData::last_updated`

`MetricData` 当前持有 `UnsafeCell<Instant>`。不要继续共享可变 `Instant`。二选一：

- 推荐：将 last update 表示为 `AtomicU64`，存储从 `StatsManager` 创建时刻起的 monotonic micros 或 millis；读取时只在内部转换为需要的 age/duration。
- 可接受：用 `parking_lot::Mutex<Instant>` 保护 `last_updated`，如果改动最小且性能足够。

选择方案后，移除 `MetricData` 的 manual `unsafe impl Send/Sync`。保持外部 behavior：counter update 后 last update 被刷新，过期清理逻辑仍能工作。

**验证**：`cargo clippy --all-targets --features full --all -- -D warnings` → exit 0, no warnings。

### 步骤 3：替换 `Throughput` 中的 `UnsafeCell` counters

在 `easytier/src/tunnel/stats.rs` 中将 `tx_bytes`、`rx_bytes`、`tx_packets`、`rx_packets` 改成 `AtomicU64`。`record_tx_bytes` 和 `record_rx_bytes` 使用 `fetch_add(..., Ordering::Relaxed)`；getter 使用 `load(Ordering::Relaxed)`。

更新 `Clone` 实现为加载旧值后创建新的 atomic counters。移除 `unsafe impl Send for Throughput` 和 `unsafe impl Sync for Throughput`。

**验证**：`cargo test --package easytier tunnel::stats --features full -- --nocapture` → exit 0；如果没有匹配测试，继续步骤 4 新增测试后重跑。

### 步骤 4：新增并发回归测试

为 `stats_manager` 添加一个多线程并发 increment 测试，建议放在 `easytier/src/common/stats_manager.rs` 的 `#[cfg(test)]` 模块中：创建一个 counter handle，启动多个 OS threads 或 `tokio::task::JoinSet`，每个 task 多次 `inc()`，最后断言总数等于预期。

为 `Throughput` 添加类似测试，创建 `Arc<Throughput>`，并发调用 `record_tx_bytes` 和 `record_rx_bytes`，最后断言 bytes 和 packets 全部精确匹配。

**验证**：`cargo test --package easytier stats_manager --features full -- --nocapture` 和 `cargo test --package easytier tunnel::stats --features full -- --nocapture` → exit 0；输出中新增测试通过。

### 步骤 5：运行完整相关门禁

运行格式、lint 和 feature check。

**验证**：
- `cargo fmt --all -- --check` → exit 0。
- `cargo clippy --all-targets --features full --all -- -D warnings` → exit 0。
- `cargo hack check --package easytier --each-feature --exclude-features macos-ne --verbose` → exit 0。

## 测试计划

- 新增 `stats_manager` 并发 increment 测试：覆盖多线程 safe API 读写。
- 新增 `Throughput` 并发 tx/rx 测试：覆盖 send/receive counters 同时更新。
- 现有 tunnel filter 行为不需要改业务测试，只需保证编译和 clippy 通过。

## 完成标准

- [ ] `easytier/src/common/stats_manager.rs` 不再包含 `UnsafeCell`-backed counter 或 manual `unsafe impl Send/Sync` for metric data。
- [ ] `easytier/src/tunnel/stats.rs` 不再包含 `UnsafeCell<u64>` 或 manual `unsafe impl Send/Sync` for `Throughput`。
- [ ] 新增并发测试存在并通过。
- [ ] `cargo fmt --all -- --check` exits 0。
- [ ] `cargo clippy --all-targets --features full --all -- -D warnings` exits 0。
- [ ] `cargo hack check --package easytier --each-feature --exclude-features macos-ne --verbose` exits 0。
- [ ] 没有修改范围外文件（`git status --short` 仅显示本计划范围内文件和 `plans/README.md` 状态更新）。
- [ ] 已更新 `plans/README.md` 中本计划的状态行。

## STOP 条件

- 当前状态中列出位置的代码与摘录不匹配。
- 你发现 `last_updated` 的 public API 依赖真实 `Instant` 值，无法用 atomic duration 或 mutex 在范围内保持行为。
- 修复需要改变 metrics output schema、metric names 或 label semantics。
- `cargo clippy` 因 atomic ordering 或 dead code 问题连续两次失败且无法在范围内解决。

## 维护说明

- 未来新增统计 primitive 时禁止再用 `UnsafeCell` + manual `Send/Sync` 暴露 safe shared mutation；默认使用 atomics 或明确锁。
- reviewer 应重点检查 atomic ordering 是否足够、是否移除了所有 unsafe shared counter paths、测试是否真的并发执行。
- 本计划不优化 metrics aggregation 性能；只消除 UB 和数据竞争风险。

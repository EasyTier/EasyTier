# 计划 004：复用 OSPF route-table 构图以减少拓扑更新成本

> **执行者说明**：按步骤执行本计划。每一步都必须运行验证命令，并确认结果符合预期后再继续。如果触发“STOP 条件”中的任一情况，立即停止并报告，不要自行发挥。完成后更新 `plans/README.md` 中本计划的状态行，除非 reviewer 明确说明由他们维护索引。
>
> **漂移检查（首先运行）**：`git diff --stat 78146d16..HEAD -- easytier/src/peers/peer_ospf_route.rs easytier/src/tests`
> 如果本计划写成后任何范围内文件发生变化，继续前必须对照“当前状态”中的摘录与实时代码；如果不匹配，按 STOP 条件处理。

## 状态

- **优先级**: P2
- **工作量**: M
- **风险**: MED
- **依赖**: plans/003-avoid-noop-ospf-route-rebuilds.md
- **类别**: perf
- **计划生成于**: commit `78146d16`, 2026-06-18

## 为什么重要

每次 OSPF 拓扑更新当前会分别为 least-hop 和 least-cost route table 调用 `build_from_synced_info`。每次调用都会从 synced info 重新构建 peer graph，并重新构建 peer/CIDR indexes。对于 peer 数和 proxy CIDR 数较大的 mesh，这把一次拓扑变化放大成两次完整构图和多次 map/trie 重建。完成后应保持 route selection 结果不变，同时复用同一份 graph/materialized synced view，减少 CPU 和分配成本。

## 当前状态

- `easytier/src/peers/peer_ospf_route.rs` — `update_route_table`、graph builder、least-hop/least-cost map generation、CIDR trie rebuild 均在此文件。

当前代码摘录：

```rust
// easytier/src/peers/peer_ospf_route.rs:1628
// build next hop map
let (graph, start_node) =
    Self::build_peer_graph_from_synced_info(my_peer_id, synced_info, cost_calc);

// easytier/src/peers/peer_ospf_route.rs:1649
if matches!(policy, NextHopPolicy::LeastHop) {
    self.gen_next_hop_map_with_least_hop(&graph, &start_node, version);
} else {
    self.gen_next_hop_map_with_least_cost(&graph, &start_node, version);
};

// easytier/src/peers/peer_ospf_route.rs:1655
let mut new_cidr_prefix_trie = PrefixMap::new();
let mut new_cidr_v6_prefix_trie = PrefixMap::new();
```

```rust
// easytier/src/peers/peer_ospf_route.rs:2453
fn update_route_table(&self) {
    // ...
    self.route_table.build_from_synced_info(
        self.my_peer_id,
        &self.synced_route_info,
        NextHopPolicy::LeastHop,
        calc_locked.as_ref().unwrap(),
    );

    self.route_table_with_cost.build_from_synced_info(
        self.my_peer_id,
        &self.synced_route_info,
        NextHopPolicy::LeastCost,
        calc_locked.as_ref().unwrap(),
    );
}
```

仓库约定：core routing behavior must be preserved。先添加 characterization tests，再重构；不要在同一计划里改 route policy。

## 需要使用的命令

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all -- --check` | exit 0 |
| Lint | `cargo clippy --all-targets --features full --all -- -D warnings` | exit 0, no warnings |
| Targeted tests | `cargo test --package easytier peer_ospf_route --features full -- --nocapture` | exit 0; route characterization tests pass |
| Archive tests | `cargo nextest archive --archive-file tests.tar.zst --package easytier --features full` | exit 0 |

## 临时目录约定

- 临时文件、scratch 目录和 disposable worktree 必须放在 `$HOME/tmp` 下。
- 如果 `$HOME/tmp` 不存在且本计划需要临时空间，先创建它。
- 不要把临时产物放进被修改仓库。

## 范围

**范围内**（只能修改这些文件）：
- `easytier/src/peers/peer_ospf_route.rs`
- `easytier/src/tests/*`（仅新增/调整 route-table characterization tests）

**范围外**（即使看起来相关也不要触碰）：
- Route protocol schema and wire format。
- Credential/trust semantics。
- Peer center、foreign network manager、data-plane tunnels。
- Any UI or config surface。

## Git 工作流

- Branch: `advisor/004-reuse-ospf-route-graph`
- Commit message style follows existing conventional commits, for example `refactor: introduce HedgeExt for task hedging; rewrite NatDstQuicConnector`.
- Do NOT push or open a PR unless the operator instructed it.

## 步骤

### 步骤 1：添加 route-table characterization tests

在修改实现前，新增测试覆盖至少一个包含以下元素的小拓扑：

- 本 peer、两个 reachable peers、一个 unreachable 或 outdated peer。
- 至少一个 IPv4 proxy CIDR 和一个 IPv6 proxy CIDR。
- least-hop 和 least-cost 结果不同或至少都被断言。

测试应断言当前 `route_table` 和 `route_table_with_cost` 对 peer next-hop、peer reachability、CIDR lookup 的结果。优先使用现有测试 helper；如果内部 API 不便，添加 `#[cfg(test)]` helper，不改变生产 API。

**验证**：`cargo test --package easytier peer_ospf_route --features full -- --nocapture` → exit 0；新增 characterization tests 在重构前通过。

### 步骤 2：抽出一次性 graph build 输入

在 `peer_ospf_route.rs` 中把 `build_from_synced_info` 内部的 graph construction 拆成私有 helper，例如：

- `build_peer_graph_from_synced_info(...)` 已存在则复用。
- 新增 small struct 持有 `graph`、`start_node`、`version` 和后续 index rebuild 需要的 synced snapshot references。

不要改变 `gen_next_hop_map_with_least_hop` 或 `gen_next_hop_map_with_least_cost` 的算法。

**验证**：`cargo test --package easytier peer_ospf_route --features full -- --nocapture` → exit 0。

### 步骤 3：让 `update_route_table` 对两种 policy 复用 graph

把 `update_route_table` 改为在持有 `cost_calculator` read lock 时构建一次 graph/materialized input，然后分别对 `self.route_table` 和 `self.route_table_with_cost` 应用 least-hop / least-cost generation。

如果现有 `RouteTable::build_from_synced_info` 是唯一封装点，可以新增一个 sibling method，例如 `build_from_prebuilt_graph(...)`，保持旧方法用于兼容 tests 或其他调用方。

**验证**：`cargo test --package easytier peer_ospf_route --features full -- --nocapture` → exit 0；characterization tests 仍通过。

### 步骤 4：避免重复构建共享 indexes

检查 `build_from_synced_info` 中 peer info map、IPv4 map、CIDR tries 的生成是否依赖 policy-specific next-hop map。如果只依赖 reachability 或 synced info，可移动到共享 helper；如果依赖每个 `RouteTable` 自己的 `next_hop_map`，不要强行共享，避免改变 semantics。

允许分阶段收益：只共享 graph build 也可完成本计划；共享 CIDR/index 只有在 characterization tests 能证明 behavior 不变时才做。

**验证**：`cargo test --package easytier peer_ospf_route --features full -- --nocapture` → exit 0。

### 步骤 5：运行完整相关门禁

**验证**：
- `cargo fmt --all -- --check` → exit 0。
- `cargo clippy --all-targets --features full --all -- -D warnings` → exit 0。
- `cargo nextest archive --archive-file tests.tar.zst --package easytier --features full` → exit 0。

## 测试计划

- 新增 route-table characterization tests，先在重构前证明现有行为，再在重构后保持通过。
- 测试覆盖 least-hop、least-cost、CIDR lookup、unreachable peer exclusion。
- 如果可行，加入一个轻量 counter/helper 在 test-only path 确认 graph builder 调用次数从 2 降为 1；如果这需要侵入生产代码，则不要做。

## 完成标准

- [ ] `update_route_table` 不再对同一 synced topology 构建两次 peer graph。
- [ ] least-hop 和 least-cost route outputs 与 characterization tests 中的旧行为一致。
- [ ] 没有改变 routing protocol、credential trust 或 config behavior。
- [ ] `cargo fmt --all -- --check` exits 0。
- [ ] `cargo clippy --all-targets --features full --all -- -D warnings` exits 0。
- [ ] `cargo nextest archive --archive-file tests.tar.zst --package easytier --features full` exits 0。
- [ ] 没有修改范围外文件。
- [ ] 已更新 `plans/README.md` 中本计划的状态行。

## STOP 条件

- `plans/003-avoid-noop-ospf-route-rebuilds.md` 未完成，且当前 route rebuild trigger 仍会对 no-op payload 重算。
- 复用 graph 需要改变 least-hop 或 least-cost algorithm。
- 现有代码让 `cost_calc` 在两次 build 之间发生有意状态变化；如果确认 `begin_update`/`end_update` 依赖两次独立 build，停止并报告。
- Characterization tests 无法稳定构造 route-table expected outputs。

## 维护说明

- reviewer 应重点审查是否在锁持有期间引入更长 critical section。
- 未来新增 route policy 时应复用本计划抽出的 prebuilt graph input，而不是再调用完整 `build_from_synced_info`。
- 本计划不拆分 `peer_ospf_route.rs` 大文件；只做局部性能重构。

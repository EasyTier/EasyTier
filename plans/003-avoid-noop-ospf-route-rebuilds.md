# 计划 003：避免 OSPF 对 stale/no-op sync payload 重算路由

> **执行者说明**：按步骤执行本计划。每一步都必须运行验证命令，并确认结果符合预期后再继续。如果触发“STOP 条件”中的任一情况，立即停止并报告，不要自行发挥。完成后更新 `plans/README.md` 中本计划的状态行，除非 reviewer 明确说明由他们维护索引。
>
> **漂移检查（首先运行）**：`git diff --stat 78146d16..HEAD -- easytier/src/peers/peer_ospf_route.rs easytier/src/tests`
> 如果本计划写成后任何范围内文件发生变化，继续前必须对照“当前状态”中的摘录与实时代码；如果不匹配，按 STOP 条件处理。

## 状态

- **优先级**: P2
- **工作量**: S
- **风险**: MED
- **依赖**: none
- **类别**: perf
- **计划生成于**: commit `78146d16`, 2026-06-18

## 为什么重要

OSPF sync handler 当前已经能判断 `peer_infos` 是否实际写入了更新版本，但函数只返回 `Result<(), Error>`，调用方仍对任何非空 payload 设置 `need_update_route_table = true`。在重复、乱序或旧版本 sync 消息较多时，会触发完整 route-table rebuild，造成不必要 CPU 和锁竞争。完成后只有 stored topology state 变化时才重算路由，同时保持 duplicate peer ID 检查和 trust 更新语义。

## 当前状态

- `easytier/src/peers/peer_ospf_route.rs` — OSPF route sync、state mutation 和 route-table rebuild 逻辑都在同一文件中。

当前代码摘录：

```rust
// easytier/src/peers/peer_ospf_route.rs:868
fn update_peer_infos(
    &self,
    my_peer_id: PeerId,
    my_peer_route_id: u64,
    dst_peer_id: PeerId,
    peer_infos: &[RoutePeerInfo],
    raw_peer_infos: &[DynamicMessage],
) -> Result<(), Error> {
    let mut need_inc_version = false;
    // ...
    if need_inc_version {
        self.version.inc();
    }
    Ok(())
}
```

```rust
// easytier/src/peers/peer_ospf_route.rs:3623
service_impl.synced_route_info.update_peer_infos(
    my_peer_id,
    service_impl.my_peer_route_id,
    from_peer_id,
    pi,
    rpi,
)?;
// ...
session.update_dst_saved_peer_info_version(pi, from_peer_id);
need_update_route_table = true;
```

```rust
// easytier/src/peers/peer_ospf_route.rs:3647
service_impl.synced_route_info.update_conn_info(conn_info);
session.update_dst_saved_conn_info_version(conn_info, from_peer_id);
need_update_route_table = true;
```

仓库约定：性能修复必须保守；route correctness 优先于少重算。已有 `foreign_network_changed` 风格 change flag，应匹配这种模式，不要引入复杂 scheduler。

## 需要使用的命令

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all -- --check` | exit 0 |
| Lint | `cargo clippy --all-targets --features full --all -- -D warnings` | exit 0, no warnings |
| Targeted tests | `cargo test --package easytier peer_ospf_route --features full -- --nocapture` | exit 0; new change-flag tests pass if present |
| Integration tests | `cargo nextest archive --archive-file tests.tar.zst --package easytier --features full` | exit 0 |

## 临时目录约定

- 临时文件、scratch 目录和 disposable worktree 必须放在 `$HOME/tmp` 下。
- 如果 `$HOME/tmp` 不存在且本计划需要临时空间，先创建它。
- 不要把临时产物放进被修改仓库。

## 范围

**范围内**（只能修改这些文件）：
- `easytier/src/peers/peer_ospf_route.rs`
- `easytier/src/tests/*`（仅当需要新增 route sync regression test）

**范围外**（即使看起来相关也不要触碰）：
- OSPF graph algorithm、route-table data structures、credential trust policy。
- protobuf schema and generated code。
- GUI/Web/frontend。

## Git 工作流

- Branch: `advisor/003-avoid-noop-ospf-route-rebuilds`
- Commit message style follows existing conventional commits, for example `fix: route_update message is not lag`.
- Do NOT push or open a PR unless the operator instructed it.

## 步骤

### 步骤 1：让 `update_peer_infos` 返回是否改变 state

将 `update_peer_infos` 返回类型从 `Result<(), Error>` 改为 `Result<bool, Error>`，返回 `need_inc_version`。保持 duplicate peer ID 检查、raw peer info 更新和 version increment 逻辑不变。

调用方保存为 `let peer_infos_changed = ...?;`。

**验证**：`cargo test --package easytier peer_ospf_route --features full -- --nocapture` → exit 0 或无匹配测试但编译通过。

### 步骤 2：确认 `update_conn_info` 是否已有 changed flag

阅读同文件中 `update_conn_info` 和 `update_conn_info_one_peer`。如果 `update_conn_info_one_peer` 已返回 `bool`，则让 `update_conn_info` 聚合并返回 `bool`。如果当前 `update_conn_info` 已返回 bool，只使用现有返回值，不重复实现。

不要改变 accept/reject credential conn info 的条件；只改变“是否设置 `need_update_route_table`”的判断。

**验证**：`cargo test --package easytier peer_ospf_route --features full -- --nocapture` → exit 0。

### 步骤 3：仅在 actual change 时设置 `need_update_route_table`

在 sync handler 中改为：

- `peer_infos_changed` 为 true 时才设置 `need_update_route_table = true`。
- `conn_info_changed` 为 true 时才设置 `need_update_route_table = true`。
- `session.update_dst_saved_peer_info_version(...)` 和 `session.update_dst_saved_conn_info_version(...)` 是否应在 unchanged payload 时调用，需要按现有 session version semantics 判断；如果它只是记录对端已发送版本，可保留调用，避免重复请求。

**验证**：`cargo clippy --all-targets --features full --all -- -D warnings` → exit 0。

### 步骤 4：新增 no-op update regression tests

优先添加 module-level unit tests，直接构造 `SyncedRouteInfo` 或现有内部结构：

- 首次插入较新 `RoutePeerInfo` 返回 `true`。
- 再次插入相同 version 或旧 version 返回 `false`。
- `update_conn_info` 对相同 connected peers 返回 `false`，对变化集合返回 `true`。

如果内部类型构造太复杂，使用现有 route sync tests 的 helper；不要为了测试暴露 public API，最多使用 `#[cfg(test)]` helper。

**验证**：使用实际新增测试过滤器运行，例如 `cargo test --package easytier noop_route_update --features full -- --nocapture` → exit 0；输出中新增测试通过。

### 步骤 5：运行完整相关门禁

**验证**：
- `cargo fmt --all -- --check` → exit 0。
- `cargo clippy --all-targets --features full --all -- -D warnings` → exit 0。
- `cargo nextest archive --archive-file tests.tar.zst --package easytier --features full` → exit 0。

## 测试计划

- 新增 `update_peer_infos` changed flag tests：newer version true，same/older version false。
- 新增 `update_conn_info` changed flag tests：changed topology true，identical topology false。
- 不要求跑完整 privileged nextest matrix；至少 archive 编译所有 tests。

## 完成标准

- [ ] stale/duplicate peer info 不再设置 `need_update_route_table = true`。
- [ ] unchanged conn info 不再设置 `need_update_route_table = true`。
- [ ] duplicate peer ID check 仍在 stale/no-op 判断前执行。
- [ ] 新增 tests 覆盖 true/false change flag。
- [ ] `cargo fmt --all -- --check` exits 0。
- [ ] `cargo clippy --all-targets --features full --all -- -D warnings` exits 0。
- [ ] `cargo nextest archive --archive-file tests.tar.zst --package easytier --features full` exits 0。
- [ ] 没有修改范围外文件。
- [ ] 已更新 `plans/README.md` 中本计划的状态行。

## STOP 条件

- `update_peer_infos` 的返回值已被其他分支重构，当前摘录不匹配。
- 判断 no-op 需要改变 route trust、credential 或 duplicate peer semantics。
- 无法构造可靠测试，且只能通过完整三节点集成测试验证；停止并报告需要 reviewer 决定测试策略。

## 维护说明

- 后续任何 route sync state mutation 都应返回 changed flag，并只在 actual change 时触发 route rebuild。
- reviewer 应重点检查 version bookkeeping：不要为了省重算而漏掉必要 route refresh。
- 本计划不减少单次 rebuild 的成本；那由 `plans/004-reuse-ospf-route-graph.md` 处理。

# 实施计划

由 improve skill 于 2026-06-18 生成，基于 commit `78146d16`。除非依赖关系另有要求，请按以下顺序执行。每个执行者在开始前必须完整阅读计划，遵守 STOP 条件，并在完成后更新自己的状态行。

## 执行顺序与状态

| Plan | 标题 | 优先级 | 工作量 | 依赖 | Status |
|------|------|--------|--------|------|--------|
| 001 | 将共享 metrics/throughput 计数改为线程安全实现 | P1 | M | — | DONE in worktree, not merged |
| 002 | 为 peer RPC/control packet 队列加入背压和过载行为 | P1 | M | 001 | DONE in worktree, not merged |
| 003 | 避免 OSPF 对 stale/no-op sync payload 重算路由 | P2 | S | — | DONE in worktree, not merged |
| 004 | 复用 OSPF route-table 构图以减少拓扑更新成本 | P2 | M | 003 | DONE in worktree, not merged |
| 005 | 补齐 SOCKS5 exit-node 集成测试覆盖 | P2 | M | — | DONE in worktree, not merged |

状态值：TODO | IN PROGRESS | DONE | DONE in worktree, not merged | BLOCKED（附一行原因） | REJECTED（附一行理由，例如 finding 已独立修复或方案放弃）

## Reconcile 2026-06-18

- 001: `/home/fanmi/tmp/easytier-exec-001`, branch `advisor/001-thread-safe-metrics-throughput`, commit `7b6e4dfe`; worktree clean; not contained in `main` at `78146d16`.
- 002: `/home/fanmi/tmp/easytier-exec-002`, branch `advisor/002-bound-peer-rpc-queues`, commit `34d2193d`; worktree clean; not contained in `main` at `78146d16`.
- 003: `/home/fanmi/tmp/easytier-exec-003`, branch `advisor/003-avoid-noop-ospf-route-rebuilds`, commit `1be77b51`; worktree clean; not contained in `main` at `78146d16`.
- 004: `/home/fanmi/tmp/easytier-exec-004`, branch `advisor/004-reuse-ospf-route-graph`, commit `325c2e5d`; worktree clean; not contained in `main` at `78146d16`.
- 005: `/home/fanmi/tmp/easytier-exec-005`, branch `advisor/005-cover-socks5-exit-node`, commit `2cb51b71`; worktree clean; not contained in `main` at `78146d16`.

## 依赖说明

- 002 依赖 001，因为队列背压计划应暴露 queue depth/drop counters；这些 counters 应复用 001 中线程安全后的 metrics primitive，避免在新代码里继续扩散 `UnsafeCell` 模式。
- 004 依赖 003，因为先抑制 no-op sync 的无效重算，再做共享构图重构，能让性能测试和行为变化更容易归因。
- 005 独立执行，但如果未来要修改 SOCKS5、exit-node 或 `0.0.0.0/0` proxy CIDR 行为，应先落地 005 作为 characterization baseline。

## 已考虑并拒绝的发现

- `/api/v1/generate-config` 和 `/api/v1/parse-config` 是否应要求登录：证据显示 route layering 可能使其公开，但可能是产品意图；不属于本次“正确性和性能”范围，且应先补意图测试再判断。
- OSPF 7k 行 god module 整体拆分：确认是技术债，但范围过大；应先执行 003、004 并增加 characterization tests 后再规划。
- 前端测试/DX、依赖清理、安全 hardening：有价值，但用户本次只要求正确性和性能计划。

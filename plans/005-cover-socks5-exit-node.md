# 计划 005：补齐 SOCKS5 exit-node 集成测试覆盖

> **执行者说明**：按步骤执行本计划。每一步都必须运行验证命令，并确认结果符合预期后再继续。如果触发“STOP 条件”中的任一情况，立即停止并报告，不要自行发挥。完成后更新 `plans/README.md` 中本计划的状态行，除非 reviewer 明确说明由他们维护索引。
>
> **漂移检查（首先运行）**：`git diff --stat 78146d16..HEAD -- easytier/src/tests/three_node.rs easytier/src/tests/mod.rs easytier/src/gateway easytier/src/vpn_portal easytier/src/peers`
> 如果本计划写成后任何范围内文件发生变化，继续前必须对照“当前状态”中的摘录与实时代码；如果不匹配，按 STOP 条件处理。

## 状态

- **优先级**: P2
- **工作量**: M
- **风险**: MED
- **依赖**: none
- **类别**: tests
- **计划生成于**: commit `78146d16`, 2026-06-18

## 为什么重要

测试文件顶部明确 TODO 指出需要覆盖 `socks5 + exit node == self || proxy_cidr == 0.0.0.0/0` 的出口节点能力。现有 `socks5_vpn_portal` 测试只覆盖固定 destination 和 `10.1.2.0/24` proxy CIDR，不能证明默认出口路由或 self-exit 场景。完成后，这条核心 VPN routing/use-case 会有 characterization test，后续修改 SOCKS5、proxy CIDR 或 exit-node 行为时不再盲改。

## 当前状态

- `easytier/src/tests/three_node.rs` — 三节点集成测试和 SOCKS5 portal 测试所在文件。
- `easytier/src/gateway/socks5.rs`、`easytier/src/gateway/socks5/dataplane.rs` — SOCKS5 gateway implementation；仅在测试失败定位时阅读，默认不修改。
- `easytier/src/peers/peer_ospf_route.rs` — proxy CIDR 和 route selection 行为；默认不修改。

当前代码摘录：

```rust
// easytier/src/tests/three_node.rs:16
// TODO: 需要加一个单测，确保 socks5 + exit node == self || proxy_cidr == 0.0.0.0/0 时，可以实现出口节点的能力。
```

```rust
// easytier/src/tests/three_node.rs:1753
pub async fn socks5_vpn_portal(
    #[values("10.144.144.1", "10.144.144.3", "10.1.2.4")] dst_addr: &str,
) {
    // ...
    let _insts = init_three_node_ex(
        "tcp",
        |cfg| {
            if cfg.get_inst_name() == "inst3" {
                // 添加子网代理配置
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
                    .unwrap();
            }
            cfg
        },
        false,
    )
    .await;
}
```

仓库约定：这些网络集成测试使用 `#[tokio::test]` 和 `#[serial_test::serial]`，部分测试需要 Linux network namespace/root capabilities。保持测试 isolated and repeatable；不要让新增测试依赖外部网络。

## 需要使用的命令

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all -- --check` | exit 0 |
| Lint | `cargo clippy --all-targets --features full --all -- -D warnings` | exit 0, no warnings |
| Targeted test | `cargo test --package easytier socks5_vpn_portal --features full -- --nocapture --test-threads 1` | exit 0; existing and new SOCKS5 tests pass |
| CI-style archive | `cargo nextest archive --archive-file tests.tar.zst --package easytier --features full` | exit 0 |

如果本地环境缺少 root/network namespace 能力，targeted test 可能失败。此时仍必须确保 compile/archive 通过，并在结果中明确记录环境缺口。

## 临时目录约定

- 临时文件、scratch 目录和 disposable worktree 必须放在 `$HOME/tmp` 下。
- 如果 `$HOME/tmp` 不存在且本计划需要临时空间，先创建它。
- 不要把临时产物放进被修改仓库。

## 范围

**范围内**（只能修改这些文件）：
- `easytier/src/tests/three_node.rs`
- `easytier/src/tests/mod.rs`（仅当需要注册 helper/module）

**范围外**（即使看起来相关也不要触碰）：
- Production SOCKS5/gateway/routing code。若测试暴露 bug，停止并报告；不要在本计划里修生产逻辑。
- Any CI workflow, docs, GUI/Web/frontend。
- Existing tests unrelated to SOCKS5 portal or exit-node behavior。

## Git 工作流

- Branch: `advisor/005-cover-socks5-exit-node`
- Commit message style follows existing conventional commits, for example `test: add tests` from `CONTRIBUTING.md`.
- Do NOT push or open a PR unless the operator instructed it.

## 步骤

### 步骤 1：阅读现有 `socks5_vpn_portal` helper pattern

在 `easytier/src/tests/three_node.rs` 中阅读完整 `socks5_vpn_portal` 测试，特别是如何启动三节点、如何启动 TCP listener、如何通过 `tokio_socks::tcp::socks5::Socks5Stream` 访问目标地址、如何 cleanup。

不要复制大量代码后分叉；优先抽取小 helper，例如 `run_socks5_tcp_echo_case(...)`，让现有测试和新增测试共享。

**验证**：`cargo fmt --all -- --check` → exit 0（如果尚未修改，仍应通过）。

### 步骤 2：新增 `0.0.0.0/0` proxy CIDR exit-node case

新增一个 serial async test，命名建议 `socks5_vpn_portal_default_ipv4_exit_node`。测试应：

- 使用 `init_three_node_ex` 创建三节点。
- 让某个非客户端节点配置 `cfg.add_proxy_cidr("0.0.0.0/0".parse().unwrap(), None).unwrap()`。
- 通过 SOCKS5 portal 访问一个由测试内部启动的 TCP echo server 地址。
- 断言 payload round-trip 成功。

测试目标地址必须是本地/测试 namespace 可控地址，不允许依赖公网。

**验证**：`cargo test --package easytier socks5_vpn_portal_default_ipv4_exit_node --features full -- --nocapture --test-threads 1` → exit 0；若因权限环境失败，错误必须是环境相关，而非编译或断言失败。

### 步骤 3：新增 self-exit case 或明确不可测原因

根据 TODO 中的 `exit node == self`，新增第二个测试，命名建议 `socks5_vpn_portal_self_exit_node`。它应覆盖 SOCKS5 入口节点同时也是 exit node 的场景。

如果现有 config API 没有清晰方式表达 “exit node == self”，不要猜测配置。先搜索现有 tests 中 `exit_nodes`、`add_proxy_cidr`、`vpn_portal` 的用法；如果仍不明确，STOP 并报告需要 maintainer 确认配置语义。

**验证**：`cargo test --package easytier socks5_vpn_portal_self_exit_node --features full -- --nocapture --test-threads 1` → exit 0；或 STOP 报告不可测配置语义。

### 步骤 4：移除或更新 TODO

如果两个场景都已覆盖，将 `three_node.rs:16` 的 TODO 删除或改成剩余未覆盖场景的精确 TODO。不要删除仍未覆盖的提醒。

**验证**：`cargo test --package easytier socks5_vpn_portal --features full -- --nocapture --test-threads 1` → exit 0；现有和新增 SOCKS5 portal tests 通过。

### 步骤 5：运行完整相关门禁

**验证**：
- `cargo fmt --all -- --check` → exit 0。
- `cargo clippy --all-targets --features full --all -- -D warnings` → exit 0。
- `cargo nextest archive --archive-file tests.tar.zst --package easytier --features full` → exit 0。

## 测试计划

- 新增 `socks5_vpn_portal_default_ipv4_exit_node`：覆盖 `proxy_cidr == 0.0.0.0/0`。
- 新增 `socks5_vpn_portal_self_exit_node`：覆盖 SOCKS5 入口节点作为出口节点。
- 复用现有 `socks5_vpn_portal` 的 TCP echo/payload pattern，保持 `#[serial_test::serial]`。

## 完成标准

- [ ] TODO 中提到的 `0.0.0.0/0` exit-node 场景有测试覆盖。
- [ ] TODO 中提到的 self-exit 场景有测试覆盖，或计划按 STOP 条件阻塞并说明配置语义缺口。
- [ ] 新测试不依赖公网服务。
- [ ] `cargo fmt --all -- --check` exits 0。
- [ ] `cargo clippy --all-targets --features full --all -- -D warnings` exits 0。
- [ ] `cargo nextest archive --archive-file tests.tar.zst --package easytier --features full` exits 0。
- [ ] 没有修改 production code 或范围外文件。
- [ ] 已更新 `plans/README.md` 中本计划的状态行。

## STOP 条件

- 新增测试暴露 production bug：不要修生产代码，停止并报告 failing test、命令和错误摘要。
- self-exit 的配置语义无法从现有代码/tests 中确认。
- 测试只能通过访问公网验证；这不符合仓库测试隔离要求。
- 为了让测试通过需要放宽 assertions 或增加 sleeps 超过现有测试风格。

## 维护说明

- reviewer 应重点审查测试是否真正走 SOCKS5 portal 和 exit-node route，而不是退化成本地直连。
- 后续修改 proxy CIDR、exit-node、SOCKS5 dataplane 时，应运行本计划新增的 targeted tests。
- 本计划只建立测试基线；如果发现 bug，应另写修复计划。

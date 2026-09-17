# TCP proxy flow-key 验证记录（2026-09-13）

本次验证没有发现只在修复版本出现的行为退化。同源端口、不同目标的
并发连接在六种代理模式下均由父提交的超时变为成功。验证中仍有半关闭
失败和 KCP 突发短连接超时，父提交也存在这些现象，不能将结果描述为
所有场景均无异常。

## 版本与范围

- 修复版本：`eb83655958be932d6de34e090dc361b6f3ba3393`。
- 父提交：`e0bdb516b6dc8a654940efbe12960dbfa846f424`。
- 本次提交仅新增测试与记录，生产代码保持上述修复版本的内容。
- Linux 测试在现有 `rust` 容器内运行，Rust 1.93.1。
- macOS arm64、Windows x64 原生测试使用 Rust 1.95.0。

父提交使用独立 worktree，但复用当前 worktree 的 `target`。第一次父提交
网关测试意外复用了修复版本的构建缓存，结果已排除。清理相应 package
的构建产物后重新编译，确认父提交网关测试为 189 项，修复版本原有
192 项。真实流量实验还通过 CLI 核对两端实际运行的版本号。

## 自动化验证

| 验证 | 结果 |
| --- | --- |
| 修复版本完整 `subnet_proxy_three_node_test` 矩阵 | 256/256，714.800 秒 |
| ACL、端口转发 ACL、配置更新、代理断连 | 父提交与修复版本各 14/14 |
| 父提交 Linux 网关测试 | 189/189 |
| 新增测试后的 Linux 网关测试 | 198/198 |
| 新增测试后的 macOS 原生网关测试 | 198/198 |
| 新增测试后的 Windows 原生网关测试 | 198/198 |

完整三节点矩阵覆盖 TUN/no-TUN、普通/公共中继、源端 KCP/QUIC 开关、
目标端 KCP/QUIC 开关及对应输入禁用组合。每个组合检查映射子网地址、
真实子网地址和节点虚拟地址上的 ICMP、TCP、UDP。

命令（Linux 需在容器内运行）：

```sh
cargo nextest run -p easytier --features full --lib \
  subnet_proxy_three_node_test --test-threads 1 --no-fail-fast

cargo test -p easytier-core --features proxy-smoltcp-stack --lib gateway::

cargo fmt --all -- --check

cargo clippy -p easytier-core \
  --features proxy-smoltcp-stack,ring-crypto --lib --tests -- -D warnings
```

格式检查和上述严格 Clippy 检查均通过。仅启用 `proxy-smoltcp-stack`
时，严格 Clippy 被未修改的 `tunnel/encrypt/mod.rs` 中
`assert_interoperable` 未使用警告阻断；增加 `ring-crypto` 会启用调用
该函数的现有后端互操作测试。本次没有修改或屏蔽该警告。

14 项补充集成测试来自以下测试组，使用各版本独立保存的测试二进制，
逐项 `--exact` 执行，避免不同进程同时操作相同的测试 network namespace：

- `acl_rule_test_inbound`：4 项。
- `acl_rule_test_subnet_proxy`：4 项。
- `port_forward_with_inbound_default_drop_acl_test`：3 项。
- `config_patch_test`：1 项。
- `proxy_three_node_disconnect_test`：2 项。

三节点矩阵与流量实验在新增测试前完成；新增测试不改变生产代码，随后
在三平台重新执行完整网关测试。macOS、Windows 的结果不包含原生 TUN
端到端验证。

## 新增回归测试

测试位于 `easytier-core/src/gateway/proxy/tcp_proxy_engine.rs`：

1. SYN 在 accept 前后重传，均保留转换端口，且不会重复 accept。
2. 旧连接处于 ClosingSrc、ClosingDst、Closed 时，被同一流的新连接
   替换；旧连接清理不会删除新映射，反向地址、端口和校验和仍正确。
3. 过期 SYN 同时释放两个索引，已 accept 的连接不受 SYN 超时清理影响。
4. 转换端口计数器回绕后跳过零、已占用端口和监听端口。
5. 实际填满同一源 IP 的 65,534 个转换端口后，新 SYN 被丢弃；其他源
   IP 仍可建立映射，释放一个条目后该端口可复用，clear 后也可重新分配。
6. 八个线程同时处理同一流，仅建立一个映射并成功 accept 一次。

端口池测试验证实际容量和恢复行为，没有将 debug 构建的耗时用作生产
性能阈值，也没有通过延长超时或添加重试改变被测行为。

## 真实流量对照

使用独立的 `flow_val_a`、`flow_val_b` namespace，物理链路为一对 veth。
虚拟地址为 `10.251.92.1/24` 和 `10.251.92.2/24`；目标端将
`192.0.2.0/24` 映射到 `198.18.0.0/24`。两个 TCP 服务监听真实地址
`.10`、`.11` 的 23456 端口，返回服务地址标记，并逐字节回显、校验数据。
底层隧道使用 UDP，两个节点均使用四线程运行时。

每个版本分别验证普通 TCP、KCP、QUIC 与内核/smoltcp 的六种组合。

| 场景 | 父提交 | 修复版本 |
| --- | --- | --- |
| 源 IP/端口相同、两个不同目标的并发连接，各进行 30 轮回显 | 6/6 超时 | 6/6 通过 |
| 同一四元组 RST 后重连，30 次，间隔 20ms | 6/6 通过 | 6/6 通过 |
| 普通 TCP、QUIC 的短连接，各 300 次、16 并发 | 各组合 300/300 | 各组合 300/300 |
| KCP 内核模式短连接，300 次、16 并发 | 4 次超时 | 4 次超时 |
| KCP smoltcp 模式短连接，300 次、16 并发 | 12 次超时 | 11 次超时 |
| 关闭客户端写端后等待服务端响应 | 6/6 无响应数据 | 6/6 无响应数据 |

各组合完成流量后等待 15 秒。修复版本两端的代理条目均回收为零，FD
数量回到接近起始水平（采样期间 RPC 连接带来约一个 FD 的差异）。这只能
证明本次有限负载下的回收行为，不能证明长期内存占用没有增长。

KCP 的超时阈值为 5 秒，尚未定位这些突发短连接超时的根因；两版都有
失败不等于已证明每次失败属于同一根因。半关闭实验的服务端在 EOF 后
返回响应；未修改的 `copy_bidirectional_no_shutdown` 在任一方向结束
后即退出转发，与两版都丢失该响应的现象一致。本次不修复这两类问题。

## 丢包与混合版本

- 在客户端 veth 出方向施加 `netem delay 10ms 3ms loss 1%`。
- 两版各六种模式，每个组合保持两个连接持续回显至少 15 秒，所有数据
  均通过逐字节校验；共 12/12 通过。
- 无 netem 时，旧源端/新目标端、新源端/旧目标端，各覆盖六种模式。
  两个连接持续回显至少 2 秒，共 12/12 通过。
- 混合版本验证使用不同客户端源端口，验证正常互通；它不意味着仍运行
  旧代理引擎的一端也获得了同源端口冲突修复。

## 证据与限制

本机原始日志、流量脚本、各阶段 JSON、二进制与 SHA-256 清单保存在：

```text
/data/project/tcp-flow-validation-20260913/
```

主要记录为 `manifest.json`、`current-matrix-summary.log`、
`*-extra.json`、`traffic-matrix.json`、`loss-interop.json` 和
`current-final*gateway.log`。矩阵记录是最终摘要，不是完整逐项日志。
实验进程、独立 namespace 和 netem 均已清理。

未覆盖 Windows/macOS 原生 TUN 路径、生产防火墙/conntrack 规则兼容性、
长期运行、吞吐回归基准，以及接近容量极限时的真实内核连接负载。
端口耗尽已在引擎级验证，但不能替代上述生产容量测试。

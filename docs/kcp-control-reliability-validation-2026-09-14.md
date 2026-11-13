# KCP 控制报文可靠性实现与验证（2026-09-14）

本文记录
[协议设计](kcp-control-reliability-design-2026-09-14.md)
的实现与验证，独立于此前的 TCP flow-key 和半关闭局部修复。

## 兼容测试维护整理

当前维护版本为 kcp-sys `268533568d734ae89dc89603078da3ca522effe1`。
保留 `d7427c22` 作为长期兼容基线，移除中间版本 `b37ee660` 的
`kcp-sys-baseline` dev-dependency 与三项重复用例；单次使用的宏展开为
普通测试函数。四项旧版兼容测试继续覆盖能力协商、双向数据、半关闭及
重复 SYN；15 项 library 与 12 项协议回归不变。

整理后 Linux 共 31/31 测试通过，格式与严格 Clippy 通过。EasyTier
同步依赖 pin 与锁文件，并通过 `cargo +1.95 check --locked -p easytier
--features full`。此次只整理测试与测试依赖，协议源码未改变。
历史三平台 34/34 和全部流量结果仍属于下述 `3ef5c416` 实现验证，
没有重写为整理后版本的执行结果。中间基线作为调查证据保留在本文。
本次日志位于 `/data/project/kcp-compat-cleanup-validation/`。

## 版本与实现

- kcp-sys 基线：`b37ee660fb70bb6d816fb8bbc08b140e55e7218b`。
- kcp-sys 初版实现：`c84733d4479b40a299d51f4c5b8bb02ccacadc68`。
- kcp-sys 最终实现：`3ef5c4161faf99940f3ed51efd43cef0cbc02b4f`，补齐
  可靠模式下未知连接 RST 输出队列饱和时的非阻塞处理。
- EasyTier 基线：`851e7523`；接入提交：`4fedbdd1`、`ee02b8f7`，
  仅修改依赖 pin 和 Cargo.lock。
- 最终真实流量二进制：`final-easytier-core`，SHA-256：
  `962f2480cb611ceb6cab293560d0dfb337218594cdc298a08f0e83801a2d17b8`。
  它在接入提交前构建，源码及依赖内容与该提交一致；识别产物以哈希和
  依赖 revision 为准，不单凭内嵌的 EasyTier git 版本字符串。

依赖已发布到 `EasyTier/kcp-sys` 的独立分支
`fix/control-reliability-20260914`，远端引用核对为上述最终 revision。
EasyTier 任务分支为 `fix/kcp-control-reliability`。

实现保留 14 字节 header，通过 SYN/SYNACK 的 `rsv` 协商可靠控制模式。
收到旧 SYNACK 后固定使用 legacy，旧源端连接新目标端也从头使用 legacy。
只有协商为可靠模式的连接使用独立 FIN_ACK 和新增恢复逻辑。

可靠模式在原连接 ID 上恢复 SYN、SYNACK 和 FIN；重复握手不重复交接。
最终 ACK 丢失后的空 FIN 可以同时确认握手并报告对端半关闭，反向仍能
发送数据。FIN_ACK 只确认收到 FIN，不关闭本端发送方向，也不提前释放
尚未被应用读取的接收数据。

控制请求和待发送应答在原连接状态中保存，由端点统一调度。输出队列
暂满不会丢失待发事实或延长固定期限；取消 connect 同步撤销本地状态。
状态检查、控制入队和清理保持一致锁序，不持锁跨 await。

初始重传间隔 200 ms、指数退避至 2 s；源端使用调用方连接超时，目标端
握手及 FIN 待确认期限为 60 s。正常双向关闭且接收排空后释放数据对象，
原状态表保留 65 s 的关闭记录，继续应答重复 FIN，并避免迟到心跳引出
RST。FIN 一旦确认，正常半关闭不受 FIN 重试期限限制。

## 自动化结果

| 验证 | 结果 |
| --- | --- |
| Linux kcp-sys | 15 library + 12 协议回归 + 7 真实旧依赖兼容，34/34 |
| macOS kcp-sys | 相同 34/34，两个 example target 通过 |
| Windows kcp-sys | 相同 34/34，两个 example target 通过 |
| Linux 两个 example target、格式、严格 Clippy | 通过 |
| macOS 格式、严格 Clippy | 通过 |
| Windows 格式、Clippy | 所选 stable 缺少组件，未执行 |
| Linux 原生网关测试 | 200/200 |
| macOS、Windows 原生网关测试 | 各 200/200 |
| EasyTier 完整三节点及补充集成测试 | 276/276，834.639 s |
| EasyTier Linux 严格 Clippy | 通过 |

macOS 首次获取依赖遇到 GitHub TLS 错误，随后导入本机真实 Git 对象与
checkout，在依赖 revision 不变的情况下离线测试；没有改成 path 依赖，
也没有用新实现替换旧依赖。Windows 原始日志为 UTF-16LE，另保存 UTF-8
副本。两平台复用原 target，没有另开编译目录绕过权限问题。

协议修改集中在 kcp-sys，EasyTier core 源码没有变化。原生网关验证检查
与现有相同 core 源码的兼容行为，不能替代上面的真实新旧 KCP 端点测试。
远端应用 manifest 仍锁定旧依赖 `d7427c2`，网关命令只选择 easytier-core；
关键转发文件 `tcp_proxy_service.rs` 哈希与本地一致。因此不能将这组
网关测试描述为完整原生应用已经接入最终新依赖。

## 失败到通过的对照

- 丢弃第一份最终握手 ACK：基线客户端 connect 返回，服务端 accept
  超过 5 s 仍未完成；实现后约 0.25 s 恢复，并成功发送服务端 greeting。
- 新源端连接真实旧依赖：基线仅因 SYN 尚未声明协商能力而未达到新协议
  测试要求；实现后 SYN 提出 `rsv=1`、旧 SYNACK 回复 `rsv=0`，后续
  数据与关闭均走 legacy。该项验证协商功能，不把它描述为旧版互通 bug。
- 原有 RST 单测曾在新连接上注入 `rsv=0` 的合成 RST，因可靠模式拒绝
  不匹配模式而超时；测试改为注入该连接实际协商版本的 RST 后通过。
  模式不匹配的报文不能用于证明正常 RST 错误传播失败。
- 新增双向大缓冲夹具最初单次写入超过既有 KCP send 的分片限制，出现
  `Err(-2)`。调整为与原有测试一致的 16 KiB 分块，仍验证双向各
  200 KiB 总数据和原 5 s 期限；本补丁没有修改既有单次大写入限制。

- 最终补查发现初版 `c84733d` 对未知可靠 FIN 的 RST 仍使用阻塞发送。
  填满输出队列后，新 SYN 不能在 100 ms 内进入状态表；改为可靠模式
  的无状态应答使用 try_send 后通过。需要重试的有状态控制仍由状态表
  保管；legacy 发送路径不变。

原始失败日志保留，未使用扩大业务超时或重跑通过覆盖失败记录。

## 协议与生命周期覆盖

12 项公有 API 协议回归使用真实端点及按报文类型过滤的链路：

- 连续丢 SYN、连续丢 SYNACK、丢最终 ACK 后的服务端 greeting。
- 所有空最终 ACK 均丢失，空 FIN 直接完成握手，EOF 后仍可回复。
- 单向 FIN 或 FIN_ACK 丢失，另一方向仍可传输。
- 双向 200 KiB 缓冲、双方首个关闭确认丢失、延后读取与排空。
- 半关闭后重复 SYN/SYNACK/ACK；握手 ACK 丢失时 DATA 乱序、重复。
- FIN 确认后推进 61 s，再恢复实际时钟，仍可反向传输。
- PONG 保留 `rsv=1`、非法 SYNACK flags、非空 SYNACK 均不能确认模式。
- 未知 SYNACK version 返回 `InvalidProtocolVersion`，不启用新模式。

15 项 library 测试包含原有 10 项以及五项生命周期与队列测试：取消 connect
立即释放状态；重复 SYN 与满输出队列不延长半开期限；未确认 FIN 超时
唤醒读端并释放状态；正常关闭记录应答迟到包、不引出 RST、不被延长，
保留期间跳过相同 ConnId，期满后删除旧记录而不影响新连接；满输出
队列下未知可靠 FIN 不能阻止后续 SYN 进入握手。

可控时钟只用于测试期限，不修改生产时间常量。数据测试仍通过实际 KCP
发送、接收及 AsyncRead/AsyncWrite 路径。

## 真实旧依赖兼容

dev-dependency 固定并实际运行 `d7427c2`、`b37ee660` 两个历史实现，
没有用新代码上的 legacy 开关模拟旧端。

7 项测试覆盖旧 SYN 处理探针和两个基线的新旧双向连接、256 KiB 双向
数据、半关闭、重复 SYN。报文捕获断言：新源初始 SYN 可为 `rsv=1`，
其余混合连接报文均为 `rsv=0`；没有 FIN_ACK、新增 RST 或重复 accept。

`d7427c2` 原有正常关闭被报告为 BrokenPipe 的行为仍在对照中保留。
兼容意味着旧节点仍可互通，不意味着它自动获得新协议的恢复能力。

## 实际代理流量

实验使用独立 namespace，底层 UDP，
覆盖 TCP/KCP/QUIC 与内核/smoltcp 六种模式。固定每轮 300 次短连接、
16 并发、5 s socket 超时，逐字节校验大小请求、纯空请求及反向半关闭。

验证分为两个阶段；不将初版流量统计冒充最终版本结果。

### 初版 c84733d

二进制 `protocol-easytier-core` 的 SHA-256 为
`f41ff98762ed1ce8691d8f83b8c9e47acc4548c76432a17cd2daba36e2cc7b80`。

- 六模式主矩阵：1,800 次短连接、12 次大小请求半关闭、6 次反向
  半关闭、192 次纯空请求，全部通过。
- KCP 每栈追加三轮，合并主矩阵共 2,400 次 KCP 短连接，全部通过。
- `netem delay 10ms 3ms loss 1%` 六模式：1,800 次短连接、12 次大小
  半关闭、6 次反向、192 次纯空及每组合 15 s 双连接持续流量，全部通过。
- 新旧双方向各六模式：3,600 次短连接、24 次大小半关闭、384 次纯空
  和每组合 3 s 持续流量通过；**反向半关闭为 11/12，存在一次失败**。

旧端为依赖 b37 的 `delivery-easytier-core`，SHA-256 为
`4635810ac9a536258f9b7ff606e5e1a5eb0243cb0f187825ba6f721d92dfc4fe`。
失败发生在新 source → 旧 destination 的 KCP/smoltcp，连接
`conv=3560055726`、源端口 `40748`：客户端已经收到完整 1 MiB，随后
等待 EOF 超过 5 s；因此未进入后发 256 KiB 阶段。旧目标端在
10:11:08.953 进入 LocalClosed，直到客户端超时才见客户端方向关闭。
DEBUG 不能确定旧端 FIN 后续的发送、到达或处理点，不能直接定性为
FIN 丢失，也不能把混合版本测试写成全部通过。

另一次有界 KCP/kernel 丢包 TRACE 测试中，300 次短连接及全部半关闭
通过。实际捕获的控制事件全部使用 version 1：连接 `1468864199` 的
重复 SYNACK 相隔约 200 ms，目标随后收到 ACK，业务完成；连接
`1468864161` 的重复 FIN 后收到 FIN_ACK。它们证明实际链路使用了
新控制恢复路径；单轮成功不代表任意丢包条件下都能成功。

### 最终 3ef5c416

- 六模式主矩阵全部通过：1,800 次短连接、12 次大小半关闭、6 次反向
  半关闭、192 次纯空请求。
- 六模式随机丢包全部通过：相同流量规模，另每组合 15 s 双连接持续
  逐字节回显。原 5 s socket 超时不变，没有添加应用重试。
- 混合版本无丢包，两连接方向 × 两个 KCP 栈全部通过：1,200 次短连接、
  8 次大小半关闭、4 次反向及 128 次纯空请求。该轮通过不覆盖初版
  混合实验中的 EOF 超时记录。
- KCP 每栈追加三轮全部通过；合并主矩阵为 **2,400/2,400** 次 KCP
  短连接；追加轮次的 12 次大小、6 次反向和 192 次纯空也全部通过。
混合丢包仍走 legacy，下表为单轮**失败数**，不重跑取最好结果。
每组合为 300 短连接、2 次大小半关闭、1 次反向、32 次纯空和 3 s 持续流量。

| 连接方向/栈 | 短连接失败 | 大小失败 | 反向失败 | 纯空失败 | 持续失败 |
| --- | --- | --- | --- | --- | --- |
| b37 → 最终新 / kernel | 6 | 0 | 0 | 16 | 0 |
| b37 → 最终新 / smoltcp | 2 | 0 | 0 | 13 | 0 |
| 最终新 → b37 / kernel | 7 | 1 | 0 | 16 | 0 |
| 最终新 → b37 / smoltcp | 1 | 0 | 0 | 14 | 0 |

唯一大小用例失败停在 greeting 阶段，5 s 超时；纯空失败为 response
阶段收到空 EOF。为判断兼容回退，另跑一次相同条件、相同业务参数的
b37 → b37 旧旧对照：kernel 短连接失败 2/300、纯空失败 12/32；
smoltcp 分别为 0/300、16/32。两栈的大小、反向与持续项目均通过。

旧旧 TRACE 确认了一条失败链：kernel 的 `conv=3046346801`、空请求
`id=3`、源端口 `35958`，目标在 10:30:44.112 先收到 FIN，直接
Closed 并发送 RST；10:30:44.115 才收到最终 ACK|DATA。源在 .113
收到 RST，客户端约 37 ms 后得到零字节 EOF。`src/state.rs` 的
SynReceived + FIN → Closed/RST 路径本次没有修改；可靠模式单独支持
FIN 完成握手，legacy 按已批准设计保留原行为。

这条时序证明上述失效路径在旧旧连接也存在，不能由随机样本的失败率
断言所有混合版本失败均已归因或已经排除一切回退。混合实验原 DEBUG
不足以逐包归因全部失败。兼容保证旧节点可按原协议互通；控制恢复能力
需要两端都协商为 version 1，混合部署仍不能获得这一保证。

最终丢包轮次直接启用 KCP TRACE：kernel 捕获 5 个成功连接收到重复
SYNACK、4 个收到重复 FIN；smoltcp 分别为 2 个、5 个。捕获的控制
报文均使用 version 1。详见 `final-control-recovery-*-summary.json`
及对应 `evidence.log`；这份证据直接绑定最终二进制。

资源观察区分应用代理条目与内部 KCP 状态。CLI 不直接暴露依赖内部
关闭记录，不能用 CLI 条目清零证明内部记录已经删除；内部期限由
生命周期测试验证。实际流量保存起始、结束、15 s、80 s 的 FD/RSS 与
应用代理条目。65 s 关闭记录属于设计成本，不能沿用旧的 15 s 内部
状态必须清零的断言。

最终每栈三轮连续负载的资源结果如下。a 为 source，b 为 destination。
该追加轮次的 FD 全程未增长；应用 proxy 条目在 15 s 与 80 s 均为零。

| 栈/节点 | FD 前后 | RSS 前 → 80 s（KiB） | 负载 CPU 秒 / 墙钟秒 | 静置 15–80 s 单核 CPU |
| --- | --- | --- | --- | --- |
| kernel/a | 15 → 15 | 46,944 → 50,792 | 2.20 / 2.697 | 0.29% |
| kernel/b | 15 → 15 | 46,580 → 49,344 | 1.12 / 2.694 | 0.31% |
| smoltcp/a | 14 → 14 | 46,784 → 50,352 | 4.39 / 5.378 | 0.49% |
| smoltcp/b | 14 → 14 | 46,024 → 49,060 | 2.32 / 5.368 | 0.48% |

CPU 来自 `/proc/PID/stat` 的 user/system ticks 与单调时钟差，包含
路由、心跳、代理、日志等全部进程工作。产物为 debug 构建，表中负载
CPU 也不是纯协议开销或吞吐基准。RSS 未回到起点，无法由这些采样区分
分配器缓存与其他长期对象，也不能推算每条关闭记录的精确内存成本。
内部对象期限由单测验证，生产规模的逐对象内存与长期容量验证仍未完成。
主矩阵 kernel/b 在 15 s 采样曾由 15 个 FD 暂升为 16，80 s 恢复为 15；
该瞬时变化同样保留在原始报告，未作为持续增长处理。
原始记录为 `final-kcp-repeat-kcp-*-resources.json`，换算另存
`final-resource-summary.json`。

## 审查、复现与限制

初轮独立子代理只读审查 `b37ee660..c84733d`，没有高置信度缺陷发现。
最终由新子代理审查完整 `b37ee660..3ef5c416` 及 EasyTier 最终 pin，
未发现 blocker / major；重点检查旧版输出规则、握手与关闭交叉状态、
队列、取消清理和锁序。

最终审查记录一项 **minor / high confidence** 待办：
`kcp-sys/src/endpoint.rs:922` 新 SYN 路径先 notify 再插入连接状态，
多线程时可能先消费通知并漏过首次 SYNACK 调度。正常源端约 200 ms 后
重发 SYN 即可恢复；若后续 SYN 未到达，则等待约 10 s 周期扫描。状态
不会丢失，也不会永久阻塞，但特别短的 connect 期限可能超时。按用户
minor 默认记录的规则保留；后续最小改动是将通知放到状态插入之后。

主要命令：

```sh
# kcp-sys 工作树
cargo test --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

# EasyTier，Linux root 集成测试在 rust 容器内执行
cargo +1.95 test --locked -p easytier-core \
  --features proxy-smoltcp-stack --lib gateway::
cargo +1.95 nextest run --locked -p easytier --features full --lib \
  -E 'test(subnet_proxy_three_node_test) | test(subnet_proxy_half_close_test) | test(acl_rule_test_inbound) | test(acl_rule_test_subnet_proxy) | test(proxy_three_node_disconnect_test) | test(config_patch_test) | test(port_forward_with_inbound_default_drop_acl_test)' \
  --test-threads 1 --no-fail-fast
cargo +1.95 clippy --locked -p easytier --features full \
  --lib --tests -- -D warnings
```

本机原始日志、脚本、JSON 与二进制：

```text
/data/project/kcp-control-validation-20260914/
```

主要证据为 `final-ack-red.log`、`final-ack-green.log`、
`final-dependency-tests.log`、`final-dependency-clippy.log`、
`unknown-close-full-output-red.log`、`legacy-final.log`、
`negotiation-lifetime-regressions.log`、`final-native-*-tests.log`、
`linux-gateway.log`、`integration-final.log`、`app-final-clippy.log`。
`integration-protocol.log` 是初版的中断轮次，切换最终实现后重新执行完整
矩阵，不计入最终通过数。
流量的准确 argv、产物 hash 和逐连接结果另存该目录。完整流量汇总为
`traffic-summary.md`，混合丢包对照为 `mixed-loss-analysis.md`，
旧旧逐包证据为 `legacy-fin-before-ack-evidence.log` 与
`legacy-fin-before-ack-client.json`。测试环境清理记录为 `cleanup.json`。

此前单次反向超时的具体丢包点仍不能由旧 DEBUG 日志倒推出。定点 FIN
丢失测试证明该类失效现在能够恢复，不能因此改写原事故的根因结论。
Windows/macOS 原生 TUN 端到端、生产规模长期负载、吞吐与容量上限仍
不是这些有限测试能够证明的事项。

# PeerConn 滑动窗口 UDP FEC

日期：2026-10-16。

本实现在 EasyTier 原有 PeerConn 接入点采用滑动窗口编码、恢复和发送策略。
协议仍是未合并的 `udp-fec-v1`，直接替换开发中的固定块 RS 格式，不保留
旧块格式、k/r 配置或版本兼容代码。已发布、不声明该 feature 的节点继续
使用普通 peer packet。

## 1. 范围与接入

FEC 属于 `peers/conn/fec` Module，在每个原生 UDP PeerConn 终止。编码
对象是完成业务过滤后的完整 peer packet；原包和恢复包都从原有接收
过滤链交付。FEC 不提供可靠流、有序交付、重传、拥塞控制或新的认证。
TCP、WebSocket 和可靠流 QUIC Tunnel 不启用编码。

本地声明 `udp-fec-v1` 表示准备好接收资源，不表示会发送 FEC。
`enabled` 控制本端发送；`force_peer` 通过原握手的
`udp-fec-force-peer-v1` 要求对端仅在当前连接上发送，沿用对端自己的
参数。两端发送独立，不取两端配置最小值，不修改全局配置，也不转发请求。

握手完成后按本地开关或对端请求创建 TX。无效参数或资源不足保留普通
发送路径。FEC 业务帧提前越过 Noise Msg3/legacy 最后响应时，仍有界
暂存，直到原握手和业务过滤链安装完成；握手控制包继续通行。

## 2. 发送窗口与修复

发送端保存最近 64 个成功交给 Tunnel Sink 的编码源包，每包最多保留
100ms。源包立即提交，不等封块。源符号为：

```text
original_peer_length:u16 LE | original_peer_packet | implicit zero padding
```

repair 对当前窗口的全部源符号做 GF(256) 线性组合，长度取窗口中最长
符号。系数由 repair ID 和窗口内索引经固定 SplitMix64 混合产生，范围
1..255；场多项式为 `0x11d`。GF 运算使用现有 `reed-solomon-erasure`
库的表运算，不再使用 RS block/profile/matrix cache。

这是随机线性编码，不承诺任意 r 个 repair 都能恢复 r 个丢包；恢复还
依赖方程的秩、窗口重叠和修复包到达。窗口数量与时限也限制可恢复的突发
丢失与抖动范围。

每个接受的 source 至多产生一个实际 repair。比例预算允许时立即尝试；
最后一个尚未被 repair 覆盖的 source 在空闲约 5ms 后还有一次尾包保护机会，
后续 source 会更新这个时间。任意 repair 覆盖最新 source 后取消尾包机会。
先检查实际字节额度与内存预算，再即时编码；没有独立的已编码 repair 队列。writer
在业务包之间发送 repair，持续非空的业务队列不能使它饿死。已经取出的
控制包优先通行。底层写入仍保持同一个 send future，维护计时器不会导致
重复 start_send；发送失败关闭连接并释放状态。

这里的“接受”是 Tunnel Sink 的 send/flush 成功，不等于 Host socket
发送成功或链路送达。通过当前 Tunnel Interface 无法识别更下游的本地
丢弃，这种损失仍可能进入对端观察到的序号缺口。

## 3. 字节预算与短流量

比例额度从两个本地 MTU 开始，上限也是两个 MTU。每个接受的 source 按其
旧格式 UDP payload 字节数乘当前冗余百分比补充额度；repair 按完整 UDP
payload 字节数扣除。比例额度不随空闲时间补充，也不在窗口过期、反馈变化或
每次短流量开始时重置。

尾包保护另有一份绝对额度：从首个已接受 source 开始，每秒补充一个本地
UDP payload MTU，初始为零，最多保留两个 MTU。它只用于空闲尾包修复，
不受当前自适应比例为零的限制。额度不足时仅等待到最新 source 过期之前；
资源不足则取消本次机会。没有新 source 就不会反复修复同一个尾包。
尾包发送定时器与缓存维护分开，底层 send/flush 阻塞时只维护缓存。
因此从首个 source 起经过 elapsed_seconds 后，总 repair 始终满足：

```text
repair_bytes <= 2 * udp_payload_mtu
                + max_repair_percent * source_baseline_bytes / 100
                + udp_payload_mtu * elapsed_seconds
```

有限初始额度让第一个孤立包也有一次立即修复机会。随后每秒一个小包可以
使用尾包绝对额度；短突发结束时，一份修复方程能保护窗口内任意一个源包
损失，多包损失仍需要更多方程。默认绝对补充速率为 1400B/s，这不是包含
外层 IP/UDP/Ethernet 头的物理带宽上限。混合长短包的 padding 计入 repair
成本，可能减少实际 repair 数。

这个上限只限制 repair，source 的额外封装与反馈字节单独统计。性能
对照必须使用实际总字节，不能把配置的百分比当作实际网络开销。

## 4. 接收与资源

接收端保留 256 个带完整 source ID 的槽和至多 64 个增量消元方程。
每行固定 256 个系数，RHS 按实际长度懒分配；不复制完整窗口来提交或
回滚。普通 source 立即交付并替代方程中的已知量；singleton 方程在
校验原始长度、peer 类型和零填充后产生恢复包。

槽位重用或未知符号到期时，丢弃仍依赖该列的整行，不能直接删掉一个
未知系数。已知 source 替代 pivot 时重新消元，维持唯一规范化 pivot。
不合法恢复会清掉方程及受影响的恢复缓存，保留原始 source 和已交付记录。

解码缓存寿命为 200ms，从 FEC Adapter 首次观察该符号开始；方程组合
不能延长最早证据的寿命。去重使用独立的 1024 个 source ID 记录，缓存
过期不清除交付身份。恢复结果队列最多 64 包；下游停止读取时 writer
仍驱动缓存过期。

沿用每连接 4MiB、每实例默认 64MiB 的 FEC 容量预算，普通连接与
foreign-network 连接共享实例预算。metadata 预留，符号、方程、临时
编码和输出 buffer 分配前计费。资源不足影响恢复能力，不扩大为无界
缓存。预算覆盖 FEC 拥有的容量，不代表进程 RSS，也不包含下游队列。

## 5. 丢包反馈与自适应

source 和 repair 共用一个连接内单调 transmission sequence；source
另有自己的 source ID。合法 FEC 帧在本地缓存/解码准入之前记为到达，
因此本地预算拒绝不会被误报为网络序号缺口。序号观察保留 256 槽，容忍
32 包乱序；超出该范围的迟到包不能回写已经确认的丢失。

接收端有新确认样本时，最多每 200ms 发送一次累计报告，包含最高观察
序号、累计确认样本和累计丢失数。只保留当前累计状态。报告丢失后，下一
份累计报告仍包含此前样本；没有新进展就不产生定时反馈流量。没有可靠
反馈 worker、新 ACK、第二套握手或路由健康控制。

发送端只在已有握手完成后使用报告。报告必须单调、丢失不超过样本、
最高观察序号不超过本地已接受序号，每次至少新增 32 个样本。
对端可能在本地 flush 完成前已收到帧；此时超出已接受上界的报告直接
忽略，后续累计报告可继续调整。

初始冗余率为配置上限。发送端保留最多 9 份累计报告，以报告边界计算
最近至少 256 个已结算样本的丢包比例；连接初期使用已有样本。这个快窗口
可以立即提高保护。另一个累计报告边界每积累至少 1024 个新样本，才允许
按这段独立样本降低保护，且不得低于快窗口要求。每完成一段都推进边界，
即使没有实际降档；重复反馈不能再次消费同一段无损证据。两个窗口都无损
才会回到零，空闲时间本身不算无损证据。

编码窗口已经过期且当前冗余率为零时，新源包重新启用启动保护，记录该源包的
外层序号。等待首份已结算该新源包的累计报告，以此建立下一段降档的采样边界；
延迟到达的旧报告不能充当新流量的证据。旧无损报告不能保护新突发在首份反馈到达
之前的丢包；TCP 会因此提前退出慢启动。已有非零保护时，后续空闲不能
重置采样进度，间歇性流量仍能积累足够样本降档。此操作不增加比例额度或
绝对尾包额度，两类预算的总上界保持不变。

预算目标考虑有限编码窗口内出现多个丢包的风险。令 `N` 为最近一次源包
被接受时的编码窗口包数，`p` 为该统计窗口观察到的丢包比例，选择最小的
修复包数 `r`，使独立包损失模型下的方程不足概率不超过 `1e-4`：

```text
p == 0: target = 0
0 < p < 1:
  choose r with P(Binomial(N + r, p) > r) <= 1e-4
  target = min(configured_cap,
               ceil(100 * r * repair_udp_bytes / (N * mean_source_baseline_bytes)))
p == 1 or target is unattainable within the byte cap: target = configured_cap
```

这是选择预算的风险代理，不是实际滑动窗口恢复的概率保证。旧未知符号、
系数矩阵的秩、成串丢失、发送排程和排队时延都可能使实际表现不同，必须
通过残余丢包和实际交付时间校准。它也不能仅凭丢包比例区分随机损失和拥塞。
例如独立等长包、`N=64` 时，1% 和 5% 丢失分别需要约 5 和 12 条方程，
而不是只补回平均丢失的包数。

`repair_udp_bytes`、源包平均成本与 `N` 都取最近一次接受源包时的同一个
有效编码窗口，包含变长包 padding。已过期的大包不再抬高新窗口的修复成本。
反馈是包丢失比例，必须先换算成字节额度；直接用包比例会使混合大小包
得不到足够的修复方程。窗口摘要独立于 100ms 编码缓存保存；窗口
已空时，反馈仍能调整后续流量的速率，不延长旧源包的可恢复时间。预算不足
时遵守本地上限，稀疏尾包仍使用前述有界绝对额度。

没有新反馈时维持当前速率。达到新目标直接更新额度的后续补充比例，不
补发历史额度，也不改变现有 PeerConn liveness 对连接故障的判断。

反馈与现有 FEC 外层一样没有新增密码学认证，只是不可信的统计提示。
完成握手不等于认证每份反馈。它始终受本地配置和字节额度约束，不改变
身份、路由或业务认证；恢复的业务包仍执行原有校验。未使用认证加密的
业务不能据此声称具有完整性保证。

## 6. 配置与线格式

```toml
[fec]
enabled = true
force_peer = true
max_repair_percent = 30
udp_payload_mtu = 1400
```

仅保留四个配置，发送参数在连接创建时捕获。冗余上限范围 1..100，MTU
范围 576..8192。关闭发送时保留原始 desired 值；若对端请求启动发送，
仍须校验这些值。CLI 对应 `--fec`、`--fec-force-peer`、
`--fec-max-repair-percent` 和 `--fec-udp-payload-mtu`。

沿用 UDP Data 和外层 peer header。PacketType 为 FecSource=22、
FecRepair=23、FecFeedback=24；FEC header 共 24 字节：

| 偏移 | 字段 | 字节 |
| --- | --- | --- |
| 0 | version=1 | 1 |
| 1 | repair 的源符号数；source/feedback 为 0 | 1 |
| 2 | payload 长度，LE | 2 |
| 4 | transmission sequence；feedback 为最高观察序号 | 8 |
| 12 | source ID / repair 首 source ID / feedback 累计样本 | 8 |
| 20 | repair ID；source/feedback 为 0 | 4 |

source payload 是完整 peer packet；repair payload 是编码符号；feedback
payload 是累计丢失数 u64 LE。64 位 source/传输序号耗尽后不再编码，
repair ID 的 32 位回绕按固定系数生成规则处理。

一个受保护 peer packet 需要额外 50 字节 UDP payload 空间：UDP framing
8、外层 peer 16、FEC header 24、编码长度 2。超过本地预算的原包按旧格式
旁路并计数；FEC 不自动修改 TUN MTU，也不新增分片重组。开启 FEC 不保证
所有业务包都落在保护范围内。

## 7. 验证

功能测试覆盖：独立收发与 force_peer、legacy/Noise 和早到握手、原生
非 UDP 旁路、首个孤立包、跨窗口突发丢失、repair 先到、变长包、pivot
替代、重复与过期、槽复用、预算耗尽、持续满队列调度、阻塞 flush 和
关闭、累计反馈丢失及速率限幅。

原生验收使用 `rust` 容器、真实 UDP/TUN 和独立 network namespaces。
比较旧 RS、滑窗以及关闭 FEC 下的正确唯一业务交付、延迟分位数、实际
网络开销和进程 CPU。固定损失模型与业务负载，区分功能 smoke 与性能
样本；恢复计数不能替代业务成功，配置上限相同也不代表实际开销相同。

本次代码验证（在 `rust` 容器执行 Rust 命令）：

- `cargo test -j 4 -p easytier -p easytier-core -p easytier-proto
  --features easytier-core/browser-config --lib fec`：53 项通过。
- 原生 UDP/AES-GCM `basic_three_node_test`：1 项通过。
- `cargo clippy -j 4 -p easytier -p easytier-core -p easytier-proto
  -p easytier-web --all-targets --features full -- -D warnings`：通过。
- `cargo fmt --all -- --check` 和 `git diff --check`：通过。
- `cargo check -j 4 -p easytier-core --target wasm32-wasip1
  --no-default-features --features wasm-host-tunnel`：通过；保留已有的四条
  非 FEC dead-code 警告。这是编译检查，不是 WASI 上的 UDP FEC 运行验证。
- 使用 protoc 36.1、protoc-gen-go 1.36.11 和仓库脚本重新生成 Go protobuf，
  `go test ./proto/...` 编译通过。
- frontend-lib 构建和 FEC enabled/disabled、force_peer、额度、MTU 的
  独立配置往返校验通过。

另有一个本次修改之前已存在的前端测试问题：`pnpm test:network-config`
的全字段 fixture 未覆盖上游 `9bc1a094` 引入的 `dhcp_ipv4_cidr`。
原 HEAD 的测试脚本也在相同生成 schema 上失败，完整往返测试亦缺少
该字段；未将这个独立 DHCP 问题混入 FEC 修改。Go 全量生成产物包含
schema 中已经存在的该字段。

## 8. 原生 UDP 对照样本

旧 RS 为 `2f26f901`，滑窗为 `31e2d031` 的生产源码。两者均在本机
`rust` 容器的两个独立 network namespace 内运行，使用真实 TUN、原生
UDP 和 legacy AES-GCM；TUN MTU 为 1300，FEC UDP payload MTU 为 1400。
测试脚本在两组相同的命名 TUN 上显式配置 overlay IPv4 地址。两者的
repair cap 都为 30%；旧 RS 使用默认 k=8、r=2、5ms 封块。

双向 netem 延迟均为 5ms，只有业务方向注入丢包，固定 seed=42：

- 随机模型：`loss random 5%`。
- 短突发模型：`loss gemodel 2.63% 50% 100% 0%`，约 5% 稳态丢包，
  坏状态平均持续两包。

每场景建立新连接、发送四秒业务：稀疏流为 100 包/s、300 字节；持续流
为 4000 包/s、1000 字节；混合流为 1000 包/s，80/300/1100/600 字节
轮换。接收端按业务序号去重并逐字节校验内容，用共享 monotonic clock
计算发送到交付的延迟。相同 seed 不代表两种编码丢弃相同的源包，因为
repair 和控制包也消耗 netem 随机序列。

| 场景 | RS 交付率 | 滑窗交付率 | RS / 滑窗总额外开销 | RS / 滑窗 P99，ms |
| --- | ---: | ---: | ---: | ---: |
| 随机／稀疏 | 96.750% | 99.000% | 38.343% / 26.493% | 5.370 / 35.201 |
| 随机／持续 | 99.688% | 99.825% | 28.718% / 15.846% | 6.831 / 16.891 |
| 随机／混合 | 98.700% | 99.000% | 35.327% / 24.356% | 9.092 / 25.183 |
| 短突发／稀疏 | 97.750% | 98.750% | 38.343% / 29.264% | 5.430 / 15.422 |
| 短突发／持续 | 97.306% | 98.831% | 28.750% / 15.891% | 6.230 / 18.873 |
| 短突发／混合 | 95.950% | 98.000% | 35.327% / 27.106% | 8.099 / 47.110 |

总额外开销为 `(source + repair + 双向 feedback - source baseline) /
source baseline`，字节包含 EasyTier UDP framing，不含 IP/UDP header。
它来自实际计数，包含测量区间的少量控制流量；相同 cap 不等于相同实际
开销。最终滑窗实际 repair 比例依上述顺序为 15.238%、12.135%、17.641%、
18.009%、12.181%、20.390%，反馈约 4.76–5 份/s。

所有场景 P50 在 5.04–5.20ms。随机持续流中，每轮发送/接收进程累计
CPU 为旧 RS 的 0.40/0.43s 与滑窗的 0.40/0.45s；短突发持续流分别为
0.45/0.48s 与 0.35/0.40s。CPU 计数精度为 10ms，最终滑窗测量时没有
并发编译或测试。所有最终场景的业务重复、内容损坏、抓包 socket 丢失、
协议/资源/窗口/接收队列错误均为零，发送调度迟到超过 1ms 的次数为零。

这组样本中滑窗交付更多、实际开销更低，但送达包 P99 更高。分位数只
统计送达包，旧 RS 未送达的包不进入其延迟分布，必须与交付率一起读。
单 seed、四秒样本不能证明统计性能优势、拥塞稳定性、吞吐上限或长期
资源表现，也不是同实际开销下的编码算法比较。

本地脚本、原始管理快照、抓包计数与二进制保存在
`.test-env/fec-sliding-20261016/`：`baseline-final/` 是旧版，
`sliding-padding-final/` 是最终版；`sliding-final/` 是未计 padding
成本的首次实验，不作为最终结果。最终 core 二进制 SHA-256 为
`77e743fc0d51d21a80c93b299688f2d1a8929d5d92ae5b0a42e5f71639f9b894`；
构建在创建提交前启动，版本标签仍为此前 HEAD，生产源码与 `31e2d031`
相同。全部测量完成后仅补充此文档，没有改动生产代码。

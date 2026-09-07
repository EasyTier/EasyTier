# feat/dns-policy 与 main 合并冲突分析

分析日期：2026-09-05。

后续策略更新：根据用户明确的优先级，保留 feat/dns-policy 的 DNS 设计，`abf03ca5` 功能若冲突可暂缓，并重点解除 DNS 对 NicCtx 的依赖。详见[更新后的合并策略](dns-policy-main-merge-strategy.md)。本报告的冲突清单与源码事实仍适用；涉及取舍的建议以下文链接的新策略为准。

这次合并的主要困难是：DNS 分支在旧的单 crate 架构上重写了 DNS，而 main 已把配置、路由、连接编排、实例生命周期和协议类型拆成了独立模块及 crate。双方不少改动仍然需要保留，但承载这些改动的位置、接口和生命周期已经不同。直接逐块选择一侧，无法得到正确的合并结果。

实际模拟得到 **33 个冲突文件：14 个内容冲突（25 个文本冲突块）、17 个修改/删除冲突、2 个重命名/删除冲突**。此外，自动合并通过的代码也存在协议文件缺失、旧类型引用、配置语义脱节等问题。后文将这些问题与纯格式冲突分开说明。

## 1. 分析基线与方法

| 项目 | 固定版本或结果 |
| --- | --- |
| 当前分支 | `feat/dns-policy`，`b207b8a7`，2026-05-15 |
| main | `f19bcfb4`，2026-09-05 |
| 共同祖先 | `811f15115593a15e036d1247244054aca8308592`，2026-05-15 |
| 当前分支独有提交 | 271 个，包含历史合并提交 |
| main 独有提交 | 80 个 |
| 分支相对共同祖先的净改动 | 68 个文件，增加 6,693 行、删除 2,345 行 |
| main 相对共同祖先的净改动 | 674 个文件，增加 156,494 行、删除 61,022 行 |

本报告使用本地已有的 main；分析开始时，`main`、`origin/main`、`upstream/main` 均指向 `f19bcfb4`。未执行 fetch，结论绑定于上述提交，不声称覆盖远端此后发生的变化。

分析采用共同祖先到双方分支的差异，而非只看两端文件差异；在 `/tmp` 的独立共享对象仓库中执行 `git merge-tree --write-tree HEAD origin/main`，方向为“将 main 合入当前分支”。这会生成含冲突标记的临时树，不修改原仓库的 HEAD、索引或工作树。

逐项检查了全部 33 个冲突文件的双方差异，并沿 DNS 的配置、路由通知、RPC、实例启动、系统集成、解析器、GUI 和测试调用链阅读 main 中的对应实现。没有逐行审计 main 全部 674 个变更文件；与 DNS 合并无直接关系的移动端、Web、数据平面等改动，仅纳入架构和接口影响分析。

原工作树已有 `Cargo.lock` 未提交修改，分析时为增加 211 行、删除 129 行，未纳入提交间的合并模拟，也未修改它。特别需要注意：**当前分支已提交的 Cargo.lock 与共同祖先完全相同**，因此它没有产生 Git 冲突，并不表示依赖已经兼容。

证据记法：下文 `B` 表示 `b207b8a7`，`M` 表示 `f19bcfb4`；文件行号属于对应提交。`S` 表示本次模拟树。可用 `git show <提交>:<路径>` 查看固定版本。迁移建议是分析结论，本次没有实施合并或修复。

## 2. 两边分别在做什么

### 2.1 DNS 分支：从旧 Magic DNS 转向 zone 配置和快照同步

分支删除 `instance/dns_server` 的旧主体实现，新增 `easytier/src/dns/`：

- `config/`：新增 `[dns]`、zone、记录、forwarders、监听地址、导入/导出策略结构，以及原始配置和解析后配置分离的 `ConfigBase`。
- `peer_mgr.rs`：读取路由中的 DNS 摘要，通过 `DnsPeerMgrRpc.GetExportConfig` 拉取 zone，缓存、重试，并在不可达时失效。
- `node.rs`：每个实例维护 DNS 节点；通过 `127.0.0.1:49813` 的监听竞争选出本机 DNS server，发送摘要或完整快照心跳，响应路由及配置事件。
- `node_mgr.rs`：汇总各实例快照、地址、监听器及 zone，构建 catalog。
- `zone.rs`、`utils/zone_handler.rs`：内存记录、转发和 fallthrough 查询处理。
- `server.rs`：使用真实 TCP/UDP socket 提供 DNS 服务，将 DNS 地址添加到 TUN，并配置系统 DNS；主实现已移除旧的数据包劫持路径。

同时升级 Hickory 0.25.2 → 0.26.0，将通用解析器移至 `utils/dns.rs`，弃用 `accept_dns`、`tld_dns_zone`、`enable_magic_dns`，改动主机名规范化和日志 builder。

这里不能把计划文档当作已完成的功能：`B:easytier/src/dns/config/policy.rs` 中 ACL 和 recursive 仍有 TODO；`dns_export_config()` 也有父 zone policy TODO。现有代码已实现的导出筛选包括 `export` 是否存在及 `disabled`，不等于完整的 DNS ACL 已落地。

### 2.2 main：拆分 portable core 与 native runtime

关键提交是 `021f5234`（2026-07-26，#2451）。当前 main 的归属如下：

| 领域 | 分支中的旧位置/依赖 | main 的新归属 |
| --- | --- | --- |
| TOML 模型和运行时配置 | `easytier/src/common/config.rs` | `easytier-core/src/config/`；native `common/config.rs` 主要提供适配和重导出 |
| 路由与 peer 状态 | `GlobalCtx`、`PeerManager`、`peers/peer_ospf_route.rs` | `easytier-core/src/peers/`、`PeerContext`、`PeerManagerCore` |
| 实例生命周期 | `instance/instance.rs` | `easytier-core/src/instance/`；native `instance/composition.rs` 和 `runtime_host/` 承载平台资源 |
| 连接器和 STUN 编排 | `connector/`、`common/stun.rs` | `easytier-core/src/connectivity/`，通过 Host 接口获取 DNS/socket 能力 |
| Protobuf、RPC 类型 | `easytier/src/proto/` 和 native build script | `easytier-proto/`；native 和 core 共用生成类型 |
| 实际网络、TUN、系统 DNS | 旧实例与通用模块直接持有 | native runtime 和 Host adapter；core 不直接操作 OS 网络 |

main 仍保留旧 Magic DNS 的产品语义，但拆出了 `gateway/magic_dns/{records,packet}.rs`，将路由快照、记录存储、数据包处理与 native server 分离。不能将 main 对旧目录的修改一概解释为“只搬了文件”。

其他直接相关的 main 提交包括：`5efbc858`（guarden 0.2）、`f0d00d61`（前端使用生成的 proto 类型）、`afbba5d9`（pnet → smoltcp）、`8c15941c`（可配置 TCP STUN）、`abf03ca5`（系统 DNS 超时后回退）。它们分别影响依赖、管理配置、测试、解析调用链。

架构归属依据：`M:docs/core-architecture.md`，并以对应实现核实。

## 3. 全部 Git 冲突清单

以下路径均为模拟合并结果中的路径；涉及重命名的另行注明。复杂度指后续处理工作，不表示已测得的运行时故障等级。

### 3.1 内容冲突：14 个文件、25 个冲突块

| 文件 | 块数 | 冲突变更及实际含义 |
| --- | ---: | --- |
| `easytier-core/src/peers/route/peer_ospf_route.rs` | 2 | B 在旧 `RoutePeerInfo` 和同步逻辑中增加 DNS 摘要、更新 ID 列表；M 把类型构造和上下文改为 core 接口，并替换原始 protobuf 处理。高复杂度，见 §4.3。 |
| `easytier/Cargo.toml` | 5 | Hickory 版本及 optional feature、guarden 版本、DNS 新依赖与 M 拆分后的依赖/feature 归属冲突。见 §4.6。 |
| `easytier/build/main.rs` | 1 | B 修改原 protobuf 生成流程并加入 dns.proto；M 已将整个生成流程移到 easytier-proto。见 §4.2。 |
| `easytier/src/common/config.rs` | 2 | B 新增 ConfigBase、DNS 配置和访问接口，修改默认 flags、hostname、LoggingConfig；M 把模型移到 core。大块冲突主要由代码归属改变引起。见 §4.1。 |
| `easytier/src/common/global_ctx.rs` | 3 | 显式块集中在 import；B 的 DNS 扩展和 PeerInfoUpdated 与 M 的上下文拆分还存在块外的语义冲突。 |
| `easytier/src/common/mod.rs` | 1 | B 删除 common::dns 导出；M 保留该模块作为 Host DNS adapter，并加入管理模块 feature gate。不能仅删除整块。 |
| `easytier/src/common/stun.rs` | 1 | B 改用 txt_resolve；M 已删除本地 HostResolverIter，改用 CoreStunInfoCollector。应迁移解析行为，不恢复旧编排。 |
| `easytier/src/dns/system/windows.rs` | 2 | M 的旧 Windows 文件随 B 的重命名进入新路径；冲突块在测试准备和启动部分：B 用 PeerManager/DnsNode，M 用 global_ctx/core_instance/CorePacketPlane。生产代码与测试需分别检查。 |
| `easytier/src/instance/mod.rs` | 1 | B 使用旧 instance 模块并移除 dns_server；M 导出 composition、factory、host、runtime_host 等新结构，且仍保留旧 DNS。 |
| `easytier/src/proto/mod.rs` | 1 | B 声明本地生成模块及 dns；M 从 easytier_proto 重导出。保留整个 B 块会恢复失效模块声明，并与新重导出重名。 |
| `easytier/src/tunnel/common.rs` | 1 | B 仅移动 `// endregion` 注释；M 删除 reserve_buf 并将 tests 限定为 cfg(test)/pub(crate)。这是低复杂度文本冲突，不是 B 新增网络逻辑。 |
| `easytier/src/tunnel/mod.rs` | 2 | B 将 socket_addrs 改为 utils::dns；M 拆出协议/传输并调整导出和 feature gate。旧宏和函数被卷入冲突，不能整块恢复。 |
| `easytier/src/utils/mod.rs` | 1 | B 增加 dirty、dns、hostname；M 移除旧 error/task 等模块并对 panic 加管理 feature gate。需明确保留的新工具及其依赖。 |
| `easytier/src/web_client/mod.rs` | 2 | B 改用统一 hostname helper；M 改用 runtime_one_shot_manual_connector 和 core 管理 runtime。不能用 B 的 hostname 小改动覆盖 M 的连接器初始化。 |

### 3.2 修改/删除冲突：17 个文件

| 文件 | B 的变化 | M 的变化与后续含义 |
| --- | --- | --- |
| `easytier/src/common/dns.rs` | 删除，替换为 utils/dns.rs | 扩展为支持 Host trait、netns、socket mark 和超时回退的解析器。双方有不同的功能增量。 |
| `easytier/src/connector/direct.rs` | 主要更换 DNS import | 删除旧位置；连接和解析已进入 core connectivity。 |
| `easytier/src/connector/dns_connector.rs` | 重写 TXT/SRV 消费方式，适配 Hickory 0.26 | 删除旧连接器；新发现逻辑在 core manual/discovery。 |
| `easytier/src/connector/manual.rs` | 更换 DNS import、整理 import | 删除旧位置；迁至 core connectivity/manual。 |
| `easytier/src/connector/mod.rs` | 更换 socket_addrs import | 删除旧工厂/编排；由 core connectivity 接管。 |
| `easytier/src/instance/dns_server/client_instance.rs` | 删除旧 DNS client | 改用 CorePacketPlane 路由来源、MagicDnsRoutePublisher 和 RuntimeRpcClient。 |
| `easytier/src/instance/dns_server/mod.rs` | 删除旧 DNS 模块 | 整理旧实现与常量/接口归属；native runtime 仍有调用者。 |
| `easytier/src/instance/dns_server/runner.rs` | 删除 DnsRunner | 构造参数从 PeerManager 改为 CorePacketPlane + GlobalCtx。 |
| `easytier/src/instance/dns_server/server.rs` | 删除旧 server | 清理旧 server 接口；仍基于 Hickory 0.25 authority。 |
| `easytier/src/instance/dns_server/server_instance.rs` | 删除旧 server instance | 改为使用 core 的记录存储、路由和 DNS packet resolver 注册接口。 |
| `easytier/src/instance/dns_server/system_config/mod.rs` | 新体系替代旧 OSConfig 接口 | 删除未完成的 Linux 模块导出，保留其他平台的旧接口。 |
| `easytier/src/instance/dns_server/tests.rs` | 删除，新增 dns/tests.rs | 测试环境改用 core instance/packet plane，旧 DNS 行为仍有测试。 |
| `easytier/src/instance/instance.rs` | 新增 DnsNode 启停、调整 NicCtx 容器与资源清理 | 删除整个旧 Instance；生命周期已进入 core，平台资源进入 runtime_host。 |
| `easytier/src/instance/proxy_cidrs_monitor.rs` | 净变化只有 import 调整 | 删除旧实现。不要因为历史提交曾涉及 DNS 路由，就把这里误判为最终仍有 DNS 功能增量。 |
| `easytier/src/instance_manager.rs` | 事件 match 增加 PeerInfoUpdated 的忽略分支 | 删除旧 manager；需要在新事件消费路径处理，而非恢复旧文件。 |
| `easytier/src/launcher.rs` | 删除 enable_magic_dns 与 flags 的双向转换及对应随机测试赋值 | 删除旧位置；同等转换在 core/config/api_input.rs 仍存在。删除冲突文件不会自动删除新位置的旧 DNS 语义。 |
| `easytier/src/proto/utils.rs` | 扩展 RepeatedMessageModel 的序列化，保留 DNS 所需摘要工具 | 删除旧通用 proto utils；新 DNS 依赖不能随旧文件一起丢失，也不宜原样塞回协议层。 |

### 3.3 重命名/删除冲突：2 个文件

| 模拟结果路径 | 双方变化 | 判断 |
| --- | --- | --- |
| `easytier-proto/proto/magic_dns.proto` | M 从 easytier/src/proto/ 搬入新 crate；B 删除旧协议 | 涉及旧协议是否保留、main 原有 RPC 调用者、build 列表和 feature；不是单一文件删除。 |
| `easytier/src/dns/system/linux.rs` | B 从旧 system_config/linux.rs 原样移动；M 在 #2451 删除旧文件 | B 与祖先的文件 blob 相同。当前 system::get() 对 Linux 仍返回 None；这是未完成实现的保留/删除分歧，不能算作已经可用的 Linux DNS 配置能力。 |

## 4. 核心冲突的代码级分析

### 4.1 配置模型：新 DNS 无处进入 main 的权威配置

**B 的变化。** `ConfigBase<Raw, Parsed, Data>` 保存原始输入、解析结果和派生数据；`DnsConfigRaw` 经默认值补齐得到 `DnsConfigParsed`；`Config` 内新增 dns 字段；ConfigLoader 获得 DNS 扩展接口。默认域仍为 `et.net.`，地址为 `100.100.100.101`，默认 `disabled` 为 false。因此，启用 magic-dns 编译 feature 时，新旧默认启用语义也不同。

**M 的变化。** native `common/config.rs:1` 明确是 core 配置的 adapter，实际 `TomlConfig` 和 `ConfigLoader` 在 `easytier-core/src/config/toml.rs:175,606`。`compose_native_core_instance()` 从该 TOML 生成 `CoreInstanceConfig`，并通过运行时配置模型管理状态。

**冲突后果。** 如果只在 native common/config.rs 保留 B 的私有 Config 和 get_dns/set_dns，就会与 main 实际使用的模型脱节；如果整块采用 M，则 B 的 DNS 配置无法被新实例读取。DNS 模型还直接引用 Hickory 的 LowerName、Zone 校验和 native 模块，不能不经拆分就放入 core 并反向依赖 native。

后续应在 core 的配置/归一化链中承载可移植 DNS 数据，再由 native 创建 Hickory handler、监听器和系统设置。配置写回、patch、托管配置同步也应一起接入。本文没有假定具体新字段设计已经确定。

**兼容性变化。** B 删掉 CLI 的 `--accept-dns`、`--tld-dns-zone` 及对应环境变量入口，并将 wire 字段标为 deprecated；M 的 API 转换仍在 `config/api_input.rs:488,682` 读写 enable_magic_dns。需要明确定义旧值到新 `[dns]` 的兼容转换，否则会出现 CLI 不再支持旧开关、GUI 仍写旧开关、新运行时却读另一字段的割裂。

**主机名。** B 的 sanitize 会执行 IDNA、转小写、替换不合法字符和 DNS label 限长；M 的 core 配置仅做可移植的主机名清理，缺失时返回空字符串，OS hostname 由 native Host 补充。两者同时改变命名结果和默认值归属，需要分别处理显示主机名与 DNS name/domain 的语义。

证据：`B:easytier/src/common/config.rs`；`B:easytier/src/dns/config/{dns,zone,policy}.rs`；`B:easytier/src/utils/dns.rs:18`；`M:easytier-core/src/config/toml.rs:768,1345`；`M:easytier/src/instance/composition.rs:44`。

### 4.2 协议与生成：路径迁移之外还有类型所有权变化

B 新增 `dns.proto`、`DnsPeerMgrRpc`、`DnsNodeMgrRpc`，在 RoutePeerInfo 中新增 **字段 20：bytes dns**。检查当前 M schema 后，字段 20 没有被另一个字段占用；因此这里不是 protobuf tag 撞号。

实际阻塞在三个地方：

1. `peer_rpc.proto` 自动搬到 easytier-proto 并成功合入 `import "dns.proto"`；B 新增的 dns.proto 却仍在 `easytier/src/proto/`。M 的生成器只使用 easytier-proto/proto 作为 include 目录。
2. M 的 `easytier-proto/build/main.rs:92` 仍列举 magic_dns.proto，没有新 DNS 的生成与导出设计；B 修改的 native build script 已不是新的协议生成入口。
3. B 的 `proto/dns.rs` 同时包含生成类型和 `impl ZoneData::new`、`HeartbeatRequest::update`，并依赖 native Fallthrough、LowerName、TransientDigest。生成类型移入独立 crate 后，这些方法不能原样在另一个 crate 中对外部类型定义 inherent impl；需要调整所有权、扩展 trait 或转换函数。

序列化也不能整块回退：B 延续 prost 的 serde derive 和 prost-reflect 构建；M 使用 pbjson_build、按 json-rpc feature 包含生成 serde，并根据 feature 选择 well-known types。RPC/配置 JSON 消费者已建立在新生成规则上。

`proto/utils.rs` 的 RepeatedMessageModel、RepeatedSerialize/Deserialize、TransientDigest 应按实际消费者迁移。尤其 ZoneGroup 是本地泛型容器的别名，B 在其上定义了方法；把容器随意搬到外部 crate，也要重新检查 Rust 的 inherent impl/trait 实现规则。

**已执行的验证：** 对 S 中自动合并后的 peer_rpc.proto，按 M 的 include 路径调用 protoc，退出码为 1：

```text
dns.proto: File not found.
.../easytier-proto/proto/peer_rpc.proto:5:1:
Import "dns.proto" was not found or had errors.
```

这项失败独立于 Rust 文件中的冲突标记，说明“proto 文件自动合并成功”确实不能作为构建可用的依据。

### 4.3 OSPF：DNS 摘要和变更通知必须进入新的路由上下文

B 为自身路由计算 `dns_export_config().digest()`，使其他 peer 通过摘要决定是否重新 RPC 拉取。B 还让 `update_peer_infos()` 返回 `Vec<PeerId>`，在同步完成后发出 `GlobalCtxEvent::PeerInfoUpdated`；DnsNode 订阅此事件触发 refresh，另有周期 reconcile 兜底。

M 则将路由实现搬入 core，使用 `PeerContext`；自身信息构造位于 `new_updated_self_route_peer_info()`，原 `impl RoutePeerInfo` 中的构造/转换逻辑已被拆开。M 还使用 `RawRoutePeerInfo` 和 `route_peer_wire.rs` 保留未知字段，替代 DynamicMessage 路径，并叠加 credential 路由校验和同步策略。

由此产生的两个大冲突块把 B 的旧 impl 整段留了下来。这里需要移植的核心是“摘要从何而来、何时更新、如何通知”，不是恢复旧 RoutePeerInfo 实现。RoutePeerInfo 已来自 easytier-proto，在 core 中恢复外部类型的 inherent impl 也不合法。

还有一个很容易漏掉的**块外错误**：S 的同步调用末尾已自动加入 B 的代码，执行 `.global_ctx.issue_event(...)`；而 M 的 service 使用 `.context`，且新位置的 `update_peer_infos()` 仍返回 `Result<(), Error>`。只处理前面的冲突标记，后面的 `.is_empty()` 和 GlobalCtx 调用依然不成立。

应把摘要纳入适当的 core 路由输入/状态，在有效路由更新后发出可跨 Host 边界的通知；若延用事件方案，需要同步更新 `CoreEvent`、native `CoreEventSink` 映射和所有 match 消费者。不能直接从 core 引用 native `dns::config` 或 GlobalCtx。

M 的 unknown-field 保留和 credential 路由校验应保留。字段 20 的透传、摘要变化触发更新、旧 peer 不发布摘要时的兼容，以及经过中间节点传播，需要一并验证。B 当前把空摘要视为没有可拉取的新 DNS 数据，并不自动把旧 Magic DNS RPC 转换为新 zone RPC。

证据：`B:easytier/src/peers/peer_ospf_route.rs:244,852,3557`；`B:easytier/src/dns/peer_mgr.rs:119`；`M:easytier-core/src/peers/route/peer_ospf_route.rs:744,774,1364`；`M:easytier-core/src/events.rs:14`；`M:easytier/src/instance/composition.rs:74`；`S` 路由文件约 4771–4791 行。

### 4.4 实例、网卡、旧 Magic DNS：服务机制也发生了分歧

B 在旧 `Instance::run()` 中启动 DnsNode，并在 clear_resources/Drop 中清理；将 NicCtx 容器改成 `Option<Box<dyn Any + Send>>`，让 DNS 持有 ArcNicCtx 并 downcast。DNS server 动态向网卡添加地址，绑定真实端口，再设置系统 DNS。

M 的旧 `instance.rs` 已删除。实际启动经过 composition 和 core lifecycle；native `runtime_host/magic_dns.rs` 仍根据 `flags.accept_dns` 启动 DnsRunner，并由桌面/移动 TUN runtime 持有和停止。旧 server 通过 `CorePacketPlane` 注册 Magic DNS packet resolver。

因此后续必须同时处理：

- 新 DnsNode 由哪个新 runtime 对象持有，何时启动、停止和重新配置。
- 是否整体替换 M 的旧 DNS runner、路由 publisher 和 packet resolver；若删除，需同步清理其调用者和构建项。
- 新的真实地址监听机制如何接入 desktop/mobile/no-tun/macos-ne 各路径。移动端由平台控制 TUN 地址、路由和 DNS，桌面添加 IP 的做法不能未经适配直接套用。
- TUN 重建、DHCP 地址变化、实例退出时，新 DNS 地址、监听器、系统配置和本机 server 选举如何衔接。

`virtual_nic.rs` 新增的四个 add/remove IPv4/IPv6 方法文本上能自动合并，但 B 取得 NicCtx 的方式已经与 M 的 runtime 持有方式不同；方法存在不代表调用链接好了。

旧 DNS 的 modify/delete 文件不应简单整批恢复。保留两套实现会留下两个配置入口、两套本机服务生命周期，以及对同一 DNS 地址的不同处理机制。也不能整批删除后不接入 DnsNode，否则实例虽可启动，DNS 服务却没有 owner。

证据：`B:easytier/src/instance/instance.rs:933,1491`；`B:easytier/src/dns/server.rs:113,207`；`M:easytier/src/instance/runtime_host/{magic_dns,tun_common,tun_desktop,tun_mobile}.rs`；`M:easytier-core/src/gateway/magic_dns.rs`。

### 4.5 通用 DNS、TXT/SRV 和 STUN：解析上下文与可暂缓的超时修复

B 将通用 DNS 移到 utils/dns.rs，提供 `txt_lookup`、`txt_resolve`、`srv_lookup` 和 socket_addrs；txt_resolve 汇总 TXT 结果并按 whitespace 分割，SRV 消费者适配 Hickory 0.26 字段访问。

M 的 `common/dns.rs` 现在实现 `DnsResolver` / `DnsRecordResolver`，每次查询携带 `DnsQuery` 和 `SocketContext`。实际 socket 能使用 netns 和 socket mark；普通系统查询增加 **800ms 超时**，超时/失败后回退 Hickory，并用 semaphore 限制仍在后台阻塞的系统查询，避免反复重连积累任务。

B 的 socket_addrs 仍直接 await lookup_host，没有这一超时保护；其全局 resolver 也没有 M 的每请求 SocketContext。因此以 B 的新路径全面替换 M 解析器，会改变这些行为。按后续用户优先级，abf03ca5 的超时与阻塞查询限流可以暂缓；Host 查询上下文在该提交之前已存在，仍需接通。

M 中 TXT/SRV 的发现策略在 `core/connectivity/manual/discovery/implementation.rs`，STUN 编排在 `core/connectivity/stun/`。B 的文本分割/多结果行为应通过 Host 解析接口和对应消费逻辑迁移。不要为保留几行 import 更换而恢复整个旧 connector/HostResolverIter。

证据：`B:easytier/src/utils/dns.rs:94,137`；`M:easytier/src/common/dns.rs:71,107,148,213`；`M:easytier-core/src/host/dns.rs:10`；相关提交 `abf03ca5`、`8c15941c`。

### 4.6 依赖和 feature：版本冲突只是其中一部分

Hickory 不是单行版本替换。B 使用 `hickory_net::runtime`、`ConnectionConfig`、`InMemoryZoneHandler`、`ForwardZoneHandler` 和新的 RequestHandler 签名；M 的 native resolver/旧 DNS 使用 `hickory_proto::runtime`、GenericConnector 和 Authority 系列接口。应统一选定版本并适配需要保留的调用者。

M 将解析器做成 `dns-resolver` optional feature，将 magic-dns 与 core 的 proxy-packet、proto feature 关联，并新增大量 compact/native/management 的 feature 切分。S 中 hickory-server 的 0.26 升级已经自动合入，hickory-client 依赖已被删除，但 main 侧的 magic-dns feature 冲突块仍引用 `dep:hickory-client`。如果只保留该 feature 块，会留下悬空依赖引用。

其余依赖需按消费者判断：

- `getset`、`optionize`、`indexmap`、`maplit`、`serde_with`、`delegate`、`itertools` 有 B 的新 DNS/配置消费者。
- `petgraph`、`ordered_hash_map` 等旧路由依赖已随路由进入 core，不能因为与 indexmap 同处冲突块就一并恢复到 native。
- guarden 从 B 的 0.1 到 M 的 0.2，需要核实 B 新增 guarded/defer 代码与新版 API 的兼容；本次未据此断言存在编译错误。
- B 删除 gethostname、换用 hostname；M 新增的 native instance/config.rs 和 GlobalCtx 仍调用 gethostname。S 会留下消费者但失去对应直接依赖。
- M 移除 pnet packet 依赖并迁至 smoltcp，B 新 DNS 测试仍构造 pnet 包；至少测试代码及其依赖需适配。
- B 的 node.rs 无条件匹配 ConfigPatched，而 M 将该事件置于 management feature 下；需要检查 magic-dns 单独启用的组合。

Cargo.lock 没有文本冲突的原因是 B 已提交版本未改变。最终要根据决定后的 workspace manifests 重新求解并验证 lockfile；这与本地已有的未提交 Cargo.lock 修改是两件事。

### 4.7 Windows/Linux 与测试：哪些只是表面冲突

Windows 两个文本块都在测试部分，根因是测试依赖的实例/网卡所有权不同。B 对生产实现还引入 SystemConfigurator 的 clean 等变化，不能通过只调整测试形参就认为系统 DNS 生命周期已经正确。

Linux 文件是 B 原样重命名、M 删除；B 的 system::get() 并未返回 Linux configurator，文件中也有未完成的配置器逻辑。因此这里不能声称“main 删除了本分支新实现的 Linux 自动 DNS 功能”。

`proxy_cidrs_monitor.rs` 的分支净变化只有 import；`tunnel/common.rs` 只有注释位置变化。这两处应按 main 的新归属和可见性处理，不需要恢复旧功能体。

相反，测试自动合并成功的地方仍需检查：`three_node.rs` 加入了 B 的 DNS 导出/链式传播测试；新 `dns/tests.rs` 及各 DNS 单元测试还引用旧 PeerManager、packet channel、mock helpers 和 NicCtx 构造。需要把测试接到 main 的 core instance/Host fixtures 上，保留行为断言。

## 5. Git 未完整标出的隐藏冲突

下表区分直接源码证据与尚需后续构建/运行验证的后果，避免把静态分析写成已执行的测试结果。

| 位置 | 自动合并或遗漏的变化 | 影响与证据等级 |
| --- | --- | --- |
| `easytier-proto/proto/peer_rpc.proto` | import 已迁移，dns.proto 未迁移 | **已用 protoc 复现失败**，见 §4.2。 |
| OSPF 同步调用末尾 | B 的 Vec/GlobalCtx 通知代码进入 M 的 context 路径 | **源码接口确定不匹配**；需迁移返回值及事件桥接，未进行 Rust 全量构建。 |
| M 的新自身路由构造函数 | `new_updated_self_route_peer_info` 没有计算 B 的 DNS 摘要 | 若直接丢弃旧 impl 冲突块，摘要会继续取默认空值；显式字段构造处也需补充新字段。属于可定位的迁移遗漏。 |
| `easytier-gui/src-tauri/src/lib.rs` | B 的 `LoggingConfig::builder()` 自动合入 | M 的 LoggingConfig 在 core/toml.rs 仍 derive_builder，使用 LoggingConfigBuilder。若保留 M 的模型而不迁移 builder，GUI 调用不成立。 |
| `easytier/src/core.rs`、新 `core/config/api_input.rs`、前端配置 | CLI 删除旧开关自动合入；旧 API 的 bool↔flags 转换仍留在 main 新位置 | 产品配置语义不一致；应制定兼容映射并做往返验证。 |
| `easytier/src/dns/{node,server,peer_mgr}.rs` | 分支新文件通常原样保留，无共同祖先可产生内容冲突 | 引用已删除的 peers、旧 standalone RPC、tunnel::tcp 和 Instance 类型。需要接口迁移。 |
| `easytier/src/utils/task.rs` | M 删除该文件，B 相对祖先无净修改，因此直接接受删除 | 新 DNS 仍引用该文件中的 CancellableTask。M 的 foundation/task.rs 没有同名现成替代，需明确保留/迁移其取消和 Drop 语义。 |
| `easytier/src/instance/virtual_nic.rs` | 四个地址增删方法自动保留 | B 的 ArcNicCtx 获取和 downcast 方式与 M 新 runtime 不同；需重新接入。 |
| `easytier/src/tests/three_node.rs` 及 `dns/*` 测试 | 新测试自动拼接，原测试辅助代码在 M 中迁移 | 测试数量增加不代表能编译或仍覆盖新实例生命周期。 |
| `easytier/Cargo.toml` 的非冲突行 | 删除 gethostname/hickory-client、升级 hickory-server 自动合入 | 与 M 新代码或保留的 feature 产生依赖缺口。 |
| `Cargo.lock` | B 相对共同祖先无变化，M 的 lockfile 自动进入结果 | 不覆盖 B 新增/升级依赖的最终组合；没有 Git 冲突不等于 `--locked` 可用。 |

## 6. 后续合入的建议顺序

本节是初步分组；具体设计与优先级已由[后续策略](dns-policy-main-merge-strategy.md)细化。当前建议保留 DNS 分支的设计和实现主体，接通 main 的配置、peer 与 native Host 边界，保留分支历史进行合并。这里没有执行 rebase、cherry-pick 或提交。

1. **先确定配置与协议归属。** 定义 core 中可移植的 DNS 配置/状态，迁移 dns.proto 和生成导出，保留 main 的 protobuf JSON 约定；明确旧 flags/API/CLI 的兼容方案。
2. **接通路由摘要、peer RPC 和通知。** 移植 DNS 摘要生成、有效更新通知和 RPC 拉取，保留 main 的 wire unknown-field 和 credential 校验逻辑。
3. **接入 native DNS runtime。** 迁移 zone/catalog/server 与本机快照心跳；将 DnsNode 的启动、停止、网卡及系统 DNS 操作接入新的 runtime owner，处理旧 Magic DNS 调用链。
4. **统一通用解析器和依赖。** 以分支 Hickory 0.26 为基础，接通 Host DNS 上下文，保留分支 TXT/SRV 消费语义和工具类型，整理 feature；800ms 回退与阻塞查询限流按用户优先级可暂缓。
5. **处理产品入口、平台与测试。** 接通管理配置、GUI builder、desktop/mobile/no-tun 分支；改造 DNS 测试夹具，最后协调并更新 lockfile。

其中 `zone.rs`、fallthrough、快照摘要/心跳、peer cache/重试等新功能具有较明确的可迁移逻辑；最需要重新设计接缝的是配置归属、PeerContext、事件桥接和 DnsNode 的资源所有权。整合工作量不能从“只有 33 个冲突文件”直接估算。

## 7. 验证范围与后续验收重点

本次已完成：固定提交对比、Git 合并模拟、全部冲突分类、关键调用链静态核对，以及对自动合并 proto 的单独生成验证。**未解决冲突，未运行合并结果的 Cargo/GUI 全量构建，也未启动网络实例或改写系统 DNS。** 不能把本文当作可合入或测试通过的声明。

后续实施后的重点验证应包括：

- proto 生成、描述符和 JSON 配置往返；RoutePeerInfo 字段 20 经旧/新中间 peer 的透传。
- DNS 本机多实例选举、首次全量/后续摘要心跳、resync、退出后接管、缓存失效和分区恢复。
- 三节点 DNS 导出与链式传播、zone 变更、禁用/重新启用，以及旧配置入口的明确兼容行为。
- desktop TUN 重建、DHCP 变化、DNS 地址增删、Windows/macOS 系统 DNS 清理；移动端与 no-tun 路径分别验证。
- TXT 多记录/空白分割、SRV 端口和优先级、netns/socket mark 传递；系统解析超时回退与阻塞查询限制在恢复 abf03ca5 功能时另行验证。
- default、magic-dns、无 magic-dns、无 management 等必要 feature 组合，以及 core 的 portable/WASI 构建边界；GUI 构建。

## 附录：复现与现场证据

本次临时目录为 `/tmp/easytier-conflict-review.ud45L3/`：`merge-tree.txt` 是完整 Git 输出，`main/` 是 M 快照，`merged/` 是含标记的 S 快照，`repo/` 是隔离仓库。该目录属于临时分析产物，系统清理后可按以下步骤重建。

```bash
# 在原仓库中执行。mktemp 创建独立目录；不 checkout 或 merge 原工作树。
review_dir=$(mktemp -d /tmp/easytier-conflict-review.XXXXXX)
git clone --shared --no-checkout /home/luna/EasyTier "$review_dir/repo"

# 有冲突时退出码 1 是预期结果；输出第一行为临时合并树 SHA。
git -C "$review_dir/repo" merge-tree --write-tree \
  b207b8a7 f19bcfb4 > "$review_dir/merge-tree.txt"

git merge-base b207b8a7 f19bcfb4
git rev-list --left-right --count b207b8a7...f19bcfb4
git diff --stat 811f1511 b207b8a7
git diff --stat 811f1511 f19bcfb4

# 查看某项结论对应的固定版本代码。
git show b207b8a7:easytier/src/dns/node.rs
git show f19bcfb4:easytier/src/instance/runtime_host/magic_dns.rs
```

本次 S 的 tree SHA 为 `d38a1b6ba2e8b3a82a6b8246f9abb535419272d6`，仅存在于临时分析仓库的对象库中。上述复现用提交 SHA 而非分支标签作为 merge-tree 参数，冲突标记标签也会随之变化，因此不要要求重建的 tree SHA 与本次完全相同。

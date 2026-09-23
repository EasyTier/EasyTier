# 保留 feat/dns-policy 设计的 main 合并策略

本轮分析基于 `feat/dns-policy@b207b8a7` 与 `main@f19bcfb4`，沿用[冲突分析报告](dns-policy-main-conflict-report.md)中的模拟结果。没有实施代码合并。

本轮明确优先级：**以 feat/dns-policy 的 DNS 架构、配置语义和 Hickory 0.26 实现为主体；main 提供新的实例、路由、配置持久化和平台运行时接口。`abf03ca5` 的系统解析超时功能若妨碍整合，可以暂缓。**

这一策略替代前一报告中“必须同时保留 800ms 回退”的建议。33 个冲突文件的事实清单仍适用，但各冲突应保留哪一侧，需要按本轮优先级重新决定。

## 1. 建议保留的设计，以及真正需要修改的边界

DNS 的职责拆分有明确价值：`DnsPeerMgr` 处理远端 zone 获取，`DnsNode` 处理实例级快照和本机协调，`DnsNodeMgr` 聚合本机节点，`DnsServer` 持有服务端运行状态，`Zone` 与 handler 处理查询。OSPF 只传播摘要、完整 zone 通过 RPC 按需拉取，也避免把 DNS 记录体积引入路由泛洪。

建议保留这些职责和主算法。合并工作集中于外部依赖和生命周期接缝：

| 范围 | 本轮建议 |
| --- | --- |
| `DnsNode / DnsPeerMgr / DnsNodeMgr / DnsServer` 分层 | 保留，调整其获取宿主能力的方式 |
| Raw/Parsed 配置、zone 文本、forwarders、fallthrough | 保留现有实现与外部语义 |
| RoutePeerInfo 摘要 + peer RPC 拉取 | 保留，接入 main 的路由状态和 RPC owner |
| 本机 TCP RPC 选举、心跳、resync | 保留，包括跨进程竞争监听端口的性质 |
| DNS addresses 的真实地址配置与 socket 绑定 | 保留当前代码行为 |
| DNS 持有 NicCtx、downcast、网卡内部锁 | 去除，改为窄的 native 能力接口 |
| 旧 GlobalCtx/PeerManager/Instance 的直接依赖 | 按实际能力替换；不恢复被 main 删除的旧生命周期 |
| main 的旧 Magic DNS runner、publisher、packet filter | 新 DNS 接通后退出对应调用链；逐项检查还有没有其他消费者 |
| `abf03ca5` 的 800ms 超时和系统查询并发限制 | 可后置；不作为本次 DNS 迁移的验收前提 |
| DNS 模块全面可移植化、拆成独立配置 crate | 不是本次合并的前置条件 |

重要的源码基线：`dns/plan.md` 和 `dns/readme.md` 仍有“addresses 不 bind、UDP/ICMP 劫持”等旧说明；当前 `server.rs:149` 已对 `addresses ∪ listeners` 做真实 TCP/UDP bind，`:223` 将 addresses 对应 IP 加入 TUN。本次保留的是当前实现。后续应更新这些说明，避免在迁移时误接回 main 的旧劫持机制。

## 2. abf03ca5 可以独立暂缓，Host 查询上下文仍需接通

检查完整提交 `abf03ca5214ee9e4f4b6ff2ed7830a1a23033740` 后，它只修改两个文件：

- `easytier/src/common/dns.rs`：增加 SystemDnsResolver、800ms 回退、阻塞系统查询的并发限制及测试，重排对应 resolver 调用。
- `easytier/src/host_runtime.rs`：调整关于无状态服务的注释；Host 本体和 DNS capability 在此前已存在。

因此可以在移植时先采用分支的解析顺序，保留 Hickory 0.26 的实现，不移植这项超时策略。main 的 `DnsQuery / SocketContext / DnsResolver / DnsRecordResolver` 则仍需适配：netns 和 socket mark 的支持不属于该提交，丢掉它们会影响已有实例的网络上下文。

建议以分支的 `utils/dns.rs` 为解析实现基础，保留/补充一个实现 main Host trait 的 adapter。它负责请求上下文、结果类型转换和 Hickory runtime provider 的适配。TXT 多记录和 whitespace 分割保留分支行为，不能让 adapter 又退回 main 当前“首条记录的首个片段”语义。

第一阶段可以暂时保留两个模块路径，由一处实现、另一处重导出或适配；不需要为了统一路径重建旧 connector。core 的 `connectivity/manual/discovery`、`connectivity/stun` 继续承担各自的连接策略。

暂缓的实际代价要明确：main 的 manual connector 有总超时预算，系统 getaddrinfo 卡住时可能在进入 Hickory 前耗尽预算；后台阻塞查询的限制也暂时不具备。这是本轮优先级允许暂缓的行为，不应标记为已修复。无需为了省略这项功能，在原分支执行 revert。

## 3. 去掉 NicCtx：DNS 表达需求，native 持有平台资源

### 3.1 DnsNode 应属于实例，不能重新绑定每一代网卡

main 的 `runtime_host/tun_common.rs:12` 将旧 MagicDnsRuntime 放在 NicCtxContainer 里，TUN 更换会停止并重新启动旧 DNS。这个生命周期不适合分支的新设计：没有 TUN 的 DnsNode 仍能发布快照，显式 listeners 也可以独立工作，本机选举不应该因 DHCP 换网卡而被迫重启。

建议由 `NativeInstanceRuntimeHost` 持有实例级 DNS runtime，并在 `InstanceRuntimeHost::prepare/shutdown` 内接入 DnsNode。main `easytier-core/src/instance/lifecycle.rs:121` 已在 peer runtime 启动后调用 prepare，DHCP 则在 prepare 返回后启动。因此 DnsNode 必须允许“暂时尚无网卡”的初始状态。

TUN 层只负责网卡资源的代际变化。DnsNode 的心跳、RPC 注册与选举不随 NicCtx 的创建/销毁反复重启。

### 3.2 一个专用 adapter 足够，不需要新的平台框架

建议增加一个窄的 DNS Host 接口，具体名称可在实现时决定。接口位于 native DNS 与 runtime 的边界即可，无需先把它放入 core。

| 能力 | DNS 提供 | native adapter 负责 |
| --- | --- | --- |
| 接口状态订阅 | 订阅变化 | 区分可用、暂不可用、平台不支持；提供接口 generation |
| 应用 DNS 地址 | 本次服务任期所需的 `Set<IpAddr>` | 在当前 TUN 上添加地址，记录实际成功和资源归属，返回结果 |
| 应用系统 DNS | 可用 nameserver、search/match domains | 根据平台设置系统 DNS，绑定到当前资源所有者 |
| 释放资源 | 本次服务的 lease/owner | 只清理本次实际取得的资源，避免操作新一代 TUN |

可以用一个 `DnsHostLease` 封装 owner 和 generation，不必把它做成通用资源管理系统。接口不应返回 NicCtx、Any 容器或网卡锁。

专用 adapter 只持有 TunNicState 等受控平台状态。应避免 `NativeInstanceRuntimeHost → DnsNode → Arc<NativeInstanceRuntimeHost>` 的强引用环，也不需要把整个 CoreInstance 传进 DnsServer。

这里还能顺便减小依赖：当前 `server.rs` 的 `peer_mgr` 字段只在构造时保存，没有生产逻辑读取；`global_ctx` 的生产用途主要是 update_system 获取域配置。去掉无用 PeerManager 字段，并显式传入系统 DNS 所需配置后，DnsServer 可以保留其现有职责，同时不再依赖完整实例上下文。

### 3.3 生命周期及清理顺序

建议保持以下约束，而不是依靠 Drop 的偶然析构顺序：

1. 实例启动 DnsNode，注册 peer DNS 服务并准备本机协调；网卡可以尚未可用。
2. 绑定本机选举 RPC 端口成功后，创建 DnsServer 和本次服务的 Host lease。
3. 聚合快照后，先申请所需 IP，再绑定 DNS sockets；只将确实可用、符合 OS 格式的地址发布为系统 nameserver。listeners 不自动要求向 TUN 添加 IP。
4. TUN 重建时，native 递增 generation；即使 DNS 配置没有变化，也重放所需地址和系统设置。旧代清理只能影响旧代实际资源。
5. 正常停机时，停止接收新变更，撤销本次系统 DNS 设置、停止并等待实际 Hickory 后台、释放地址等资源，最后释放本机选举 RPC 端口；整个清理期保持选举所有权。
6. native 再析构 TUN，core 再完成 peer 资源清理。紧急取消/Drop 作为兜底，不能代替显式 stop 的完成保证。

需要特别调整锁顺序：main `runtime_host.rs:66` 当前持有 operation 锁再关闭 TUN。若新 DNS adapter 也使用这把锁，不能在持锁时等待 dns.stop()，否则 DNS 的 cleanup 可能等待同一把锁。应在取得网卡析构锁之前等待 DNS 清理。

macOS resolver 文件使用跨 generation 共用的路径，因此换代时还需先完成旧设置清理，再发布新设置；给 lease 增加 generation 标记，本身不会让现有按文件标记扫描的 clean() 自动实现代际隔离。

### 3.4 与本次解耦直接相关的现有问题

这些是源码检查发现的具体问题，建议随 Host 接缝一起修正；它们不要求重写 DNS 的同步或查询设计。

| 位置 | 当前问题 | 建议处理 |
| --- | --- | --- |
| `server.rs:279,303` | stop guard 捕获局部 `runtime = None`，实际 Hickory task 存在 `self.runtime` 中 | 从实际持有者取出任务并等待停止；不要只依赖后续 Drop abort |
| `server.rs:145,269` | rebind 忙时返回 Ok(false)，另一条 reload 已修改 desired；较早的 rebind 可能应用旧集合而丢掉最后一次更新 | 串行应用最新状态，或保留 revision/pending 并重试；catalog 查询层无需因此重写 |
| `server.rs:212,233,252` | 地址集合相同就跳过；添加地址失败却仍保存期望集合 | 区分 desired/applied，失败保留重试；TUN generation 变化也触发应用 |
| `server.rs:216,240` | 按带协议和端口的 NameServerAddr 差集删除 IP | 先投影成 IP 集合；同 IP 的 UDP 被删除而 TCP 保留时不能删除仍需的 IP |
| `server.rs:283` | cleanup 重新查询“现在的 NicCtx”，可能已不是当初应用资源的网卡 | 按 lease 和 generation 清理，并记录哪些 IP 是本次真正添加的 |

上表的并发后果属于可从代码构造出的时序风险，本轮未运行竞争测试。后续实现应使用可控 Host fixture 复现并验证。

### 3.5 no_tun winner、跨实例和平台边界

当前是 server 聚合多个节点的 addresses，却使用 winner 自己的网卡。换成 Host adapter 后，这个限制仍然存在。

本次建议明确支持 listener-only 和“暂时无 TUN、稍后出现”的情况；不把所有 no_tun 实例排除选举，否则全部实例 no_tun 的合法 listener 场景也会失效。混合实例中如何优先选有 TUN 的 winner，可以另行设计。

不要用进程内 singleton/registry 替代当前 TCP 选举来声称解决跨实例问题。当前端口竞争也可能跨进程；一个进程内找到另一实例的 NicCtx，并不能替另一个进程管理其网卡。若以后支持无 TUN 的 winner 使用其他实例的接口，需要额外的协作与所有权协议，本次不引入。

系统 DNS 配置本身也有现有限制：Linux 的 system::get() 返回 None；Windows 的 clean() 目前为空操作；macOS 会按 EasyTier 标记清理 resolver 文件。此次应先保证清理对象和先后顺序正确，不能将 Host 接口的存在描述成各平台均已实现完整恢复。移动端的 TUN fd、地址、系统 DNS 由平台控制，须按实际能力单独接入和验证。

## 4. 配置：保留 Raw/Parsed，接入 main 的单一持久化来源

### 4.1 推荐第一阶段的归属

建议在 core 私有 TOML `Config` 中增加具名的 `dns: Option<toml::Table>`，由 core 负责保存和传递完整 `[dns]` section。native DNS 继续用现有 `DnsConfigRaw → DnsConfigParsed / ZoneConfig` 解析与校验。

`ConfigBase` 当前的两个消费者都是 DNS alias，可将它从 native `common/config.rs` 移入 `dns/config/base.rs`，保持实现和 native 类型所有权。无需为了 main 的配置搬家，把 ConfigBase、Zone、Hickory server 或 optionize 整体搬入 core。

这样仍只有一份权威配置：main 的 TomlConfig。DNS 解析结果是它的派生视图；允许缓存不可变的已解析版本，但不再提供一份绕过 TomlConfig 的独立可写配置仓库。

`Option<Table>` 要保留“缺省”与“显式配置”的区别。这里保存的是配置值的语义，不承诺保留原 TOML 注释和排版。

### 4.2 已核实可保留原始 section 的 main 路径

- `easytier-core/src/config/toml/snapshot.rs:4,11` 直接克隆/替换完整 Config。
- `config/toml.rs:627` 的 dump 从完整 Config 克隆，只整理 source、flags 等字段。
- `management/full/config_patch.rs` 从 detached snapshot 改候选，再验证、持久化和提交。
- native `instance/composition.rs:44` 把同一 TOML 来源传给 core 和 native context；normalization 不要求丢弃原始模型。

所以新增具名 dns 字段后，常规 hostname 等字段的 patch 可以自然保留 DNS，无需泛型化整个 TomlConfig/manager/factory。

### 4.3 必须恢复“输入非法就报错”的保证

原来 ZoneConfig 在反序列化期间调用 `Zone::try_from` 校验。改用 raw Table 后，core 只能保证 TOML 表结构合法；DNS 语义校验必须显式接回。

建议提供单一的 native DNS 验证/编译入口，返回 Result。首阶段可将读取改为 `try_get_dns()` 等显式错误边界；后续再按配置 revision 缓存只读解析结果。不能解析失败后 `.unwrap_or_default()`，也不能在实例启动后才通过 panic 暴露配置错误。

验证至少接入：

1. native 配置文件入口与直接 compose 入口。
2. 管理替换实例之前的验证阶段：`management/full/process_rpc.rs:265` 的 pre-run 阶段在写配置、删除旧实例之前，是需要覆盖的位置。
3. 管理 ValidateConfig：该文件 `:574` 当前只做 `gen_config()?.dump()`，不会经过 pre-run hook；必须调用同一个纯验证能力。不要为了校验调用可能附带其他动作的整个 pre-run hook。
4. 以后若新增 DNS 热 patch，应在候选配置持久化/提交之前验证，失败保留原状态。

普通 core/WASI Host 可以保留该原始 section，但这不等于它们能执行 native DNS 或完整验证 Hickory zone。完整 portable DNS 校验如成为产品要求，再考虑提取轻量配置 crate。

### 4.4 管理 API 和旧配置的策略

仅加入 raw section 不能完成所有配置往返。main 的 NetworkConfig 仍主要是逐字段投影，从默认值重建配置；它只有旧 enable_magic_dns，没有 zone section。完整 TOML 保存与 NetworkConfig 读改写必须分别检查。

建议第一阶段补一个可选的 DNS section 文本承载字段（例如 `dns_toml`，名称待实现时确定），完成 proto、双向转换和前端生成类型更新。它承载 `[dns]` 的完整语义，native 用同一解析器校验。即使本次暂不开发完整 DNS 可视化编辑器，也不能让用户修改一个无关 GUI 字段就丢失 DNS 配置。

若将这个字段后置，则应阻止缺少 DNS 的投影覆盖已配置 DNS 的实例，并明确只能用完整 TOML 修改；这只能算受限过渡方案，不能标记为完整产品合入完成。

兼容优先级建议：显式的新 `[dns]` 优先；没有新配置时，才翻译显式旧 accept_dns/enable_magic_dns/tld_dns_zone。**不能拿 main 已归一化的默认 accept_dns=false 来推导 disabled=true**，否则会把分支缺省启用的行为整体改掉。需要在输入阶段保留旧字段是否显式出现的信息。

旧 CLI 选项是否保留为过渡 alias，可以在同一转换入口处理，不必让运行时继续读两套配置。新 disabled、addresses/listeners 的语义仍由 DNS 分支决定。

### 4.5 暂不优先的替代方案

| 方案 | 本次不优先的原因 |
| --- | --- |
| 把整个 DNS 模块放进 core | 会牵动实际 socket、Hickory runtime、系统 DNS 和网卡操作，扩大迁移范围 |
| 立即提取完整 DNS 配置 crate | 当前配置校验调用 Zone，地址类型含 resolver 转换，需先拆这些依赖；可后续独立完成 |
| `TomlConfig<Extension>` 泛型化 | 会沿 main 的 instance manager、factory、management 和持久化接口扩散 |
| native 独立保存一份 DNS 配置 | 容易与 core 的候选配置、回滚、持久化形成两份可写真相 |

这里没有断言所有 Hickory 类型都不可移植。选择 raw section 的理由是迁移边界和保留现有设计，不是用库名代替依赖分析。

## 5. peer 接缝：保留摘要/RPC，提供窄的 core 投影

main 的 CorePacketPlane 当前提供旧 MagicDnsRouteSource 和 packet resolver 注册，但没有完整的新 DNS peer 能力。PeerManagerCore 内部具备相应路由和 RPC 基础，没必要把整个对象重新暴露给 DNS。

建议从现有 CorePacketPlane 提供一个 DNS peer 投影句柄（例如 `dns_peer()`，以下均为待实现接口概念），使 main 现有 prepare 参数就能到达所需能力。该句柄应集中以下操作：

- 获取本 peer 身份与当前本机地址/名称的必要只读视图。
- 列举可达 peer、读取其 DNS 摘要。
- 调用 peer 的 GetExportConfig。
- 注册/注销本实例的 DNS 导出服务，并用受控 registration/guard 管理生命周期。
- 发布本实例已编译的 DNS 导出状态，订阅路由及本机相关状态变化。

DnsPeerMgr 的 cache、重试、快照拼装继续留在原 DNS 模块。是否再为测试抽一个 native trait，按 fixture 需要决定，不必叠加两层只有转发作用的 wrapper。

### 5.1 摘要与导出响应共用同一个已发布版本

建议用一个不可变的已编译导出状态，包含 export response、digest 和本地 generation。native 根据配置及本机地址变化生成它，core 的路由公告与 peer RPC 响应读取同一状态来源。

不建议只给 PeerRuntimeSnapshot 填一个裸 digest，RPC 却继续临时从 GlobalCtx 拼 zone。main 的 DHCP 和配置替换可以独立改变运行时快照，容易导致摘要与内容不同步，或整份替换时覆盖 DNS 派生字段。

首阶段可用独立、受控发布的 DNS 导出状态；它是 TOML/本机身份的派生结果，不是第二份配置。更新状态要唤醒路由刷新；main 已有周期路由更新可作为兜底。本机地址变化也必须从实际 core 状态到达 DNS，不能只依赖某个 GUI/management 事件。

即使共享了本地状态，跨网络查询仍可能遇到“收到旧路由摘要，但 RPC 已返回新版本”的正常竞态。客户端要按内容摘要缓存并继续收敛，不应把它直接当成不可恢复错误。同一 peer 的并发 refresh 还应串行化或检查版本，避免较早启动、较晚结束的响应覆盖已更新的缓存；本地异步编译也不能在输入版本过期后覆盖新发布状态。

### 5.2 通知必须在可读的新路由状态发布之后

分支通过 PeerInfoUpdated 通知 DnsNode refresh；这个机制可以保留，但不能机械复制原发送位置。main 的同步处理先接收信息和做 credential/trust 处理，到 `peers/route/peer_ospf_route.rs:4071` 附近才发布新 route table。

应收集被接受的变更，在新可达路由状态发布后通知，保证 DNS refresh 随后读到的是新状态。拓扑删除和不可达变化也需要失效通知或周期 reconcile 兜底。

可以保留 PeerInfoUpdated 的语义，经 CoreEvent/native bridge 传递；也可以用路由 revision watch 加变更集合。第一阶段选改动较小的一条即可，不要求重构整个事件系统。main 的 credential 校验、路由过滤和 unknown-field 保留应继续执行。

## 6. protobuf 与工具类型：移动生成代码，保留领域 helper 的归属

`dns.proto` 及生成 RPC/消息进入 easytier-proto，适配它的 build、descriptor 和 feature。RoutePeerInfo 的字段 20 继续是 bytes，main 当前没有占用该 tag。

当前 peer_rpc.proto 的 `import "dns.proto"` 实际未使用 DNS 消息类型，可以删除这个多余 import，减少 schema 耦合；dns.proto 自身仍须独立加入构建和导出。DNS RPC 不依赖 management API 的语义，不要为了复用旧 magic-dns feature 给它引入不必要的 API 依赖。

生成类型移出 native 后，原 `impl ZoneData::new` 不能继续在 native 定义为外部类型的 inherent impl。建议把依赖 LowerName/Fallthrough 的方法改为 native 扩展 trait 或转换函数；纯消息/摘要 helper 可放在适当的公共层。main 的 pbjson 生成约定继续保留，不恢复旧整套 prost-reflect/serde 生成器。

ConfigBase 和 RepeatedMessageModel 的本地类型所有权应保留。它们在分支中还有针对 alias 的 inherent impl 和转换实现；不能因为原文件名含 common/proto 就机械移动到外部 crate。

`CancellableTask` 可保留一个只包含 DNS 所需取消/等待能力的 native 实现。无需为保留它而恢复 main 已搬走的整份旧 utils/task.rs 及其他任务工具。

## 7. 实施分组、验收范围和暂缓项

建议继续保留当前 feature 分支历史，在隔离工作树中将 main 合入；按以下分组处理冲突和适配。不要对 271 个历史提交整体 rebase 作为首选，也不要用整目录 ours/theirs 决定最终实现。一次未完成的 merge 可以按组检查修改，不要求每个中间阶段都可编译或提交。

| 分组 | 主要工作 | 可验证的完成条件 |
| --- | --- | --- |
| A. 协议与依赖 | dns.proto 生成/导出；Hickory 0.26；移除旧 DNS 悬空构建项；暂缓 abf03ca5 | proto 独立生成通过，相关 Cargo feature 没有悬空依赖 |
| B. 配置接入 | core 具名 raw section、native 原解析器、错误边界、管理验证/往返 | 原 DNS 配置语义保持；非法 zone 不覆盖运行实例；无关配置修改不丢 DNS |
| C. peer 接入 | 窄投影、导出状态、摘要、RPC、路由发布后的通知 | 新 DNS 导出/拉取及三节点传播保持；空摘要/旧 peer 行为明确 |
| D. native 生命周期 | 实例级 DnsNode、DnsHost lease、TUN generation、实际后台停止 | DHCP 后出现 TUN、同配置换 TUN、失败重试、停止接管均可验证 |
| E. 产品与平台收尾 | GUI builder、旧字段转换、生成类型、测试 fixture、lockfile | 明确支持的 feature/平台构建通过，配置/服务均有完整入口 |

与此次迁移直接相关的运行验证包括：地址和 listener 并发更新、同 IP 的 UDP/TCP 部分删除、TUN 重建、持锁停机、正常退出后端口释放、跨实例选举接管、DNS 配置往返、摘要变化后可读新路由。

以下不作为“先完成才能合并”的统一前置条件，但需要明确记录现状，不能在报告里声称已经具备：

- abf03ca5 的系统查询超时和并发限制。
- DNS 全模块可移植化或提取独立配置 crate。
- 更完整的 DNS policy/ACL、缓存过期后的应用刷新、复杂转发回环等独立完善工作。
- 混合 no_tun/TUN 实例的跨进程接口选择协议。
- 当前尚不存在的 Linux 自动 DNS 配置和各系统完整恢复能力。

本轮分析没有运行新的合并构建、网络实例或系统 DNS 操作。新增建议接口尚未实现；当前工作树的代码和已有 Cargo.lock 修改保持原样。

## 8. 主要源码依据

分支侧：`easytier/src/dns/{node,peer_mgr,node_mgr,server,zone}.rs`、`dns/config/`、`dns/system/`、`proto/dns.rs`、`utils/dns.rs`、`utils/task.rs`。以上均按 `b207b8a7` 检查。

main 侧按 `f19bcfb4` 检查：

- `easytier/src/instance/runtime_host.rs` 及 `runtime_host/{implementation,tun_common,tun_desktop,tun_mobile,magic_dns}.rs`。
- `easytier-core/src/instance/{lifecycle,packet_plane}.rs`。
- `easytier-core/src/config/{toml,api,api_input,runtime}.rs` 及 `config/toml/snapshot.rs`。
- `easytier-core/src/management/full/{process_rpc,config_patch}.rs`。
- `easytier-core/src/peers/route/peer_ospf_route.rs`、`host/dns.rs`。
- `easytier/src/common/dns.rs`、`host_runtime.rs`，以及 abf03ca5 的完整提交差异。

本轮对配置、peer、Host 三个接缝进行了并行只读分析，并对关键生命周期、配置保存和路由通知位置再次核对。上述方案是下一轮实现的具体依据，不是已经完成的合并结果。

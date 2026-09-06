# EasyTier DNS 模块设计说明（重构版）

> 本文档基于 `easytier/src/dns` 当前代码实现与 `plan.md`。  
> 当前先给出第一部分：**整体架构与基础逻辑**。

## 1. 模块目标与定位

`dns` 模块是对旧 `instance/dns_server` 方案的重构，目标是把 DNS 能力从“单点功能”升级为“可同步、可扩展、可自治”的子系统。它同时承担三类职责：

1. **本机 DNS 服务能力**：
   - 能监听配置中的 `listeners`（UDP/TCP）作为标准 DNS server。
   - 能对配置中的 `addresses` 做流量劫持（UDP DNS + ICMP echo）。

2. **多 Peer DNS 配置同步能力**：
   - 每个实例作为 `DnsNode` 生成快照并定期心跳。
   - 机器上被选举出的 `DnsServer` 聚合所有 Node 快照并动态重建 Catalog。

3. **系统 DNS 接入能力**（tun 场景）：
   - 把 DNS nameserver/search/match domain 写入系统配置（当前主要是 Windows/macOS，Linux 仍在演进中）。

---

## 2. 顶层架构（角色分层）

从职责上看，模块分成 4 层：

- **配置层**（`config/*`）
  - 解析 TOML 的 `[dns]`、`[[dns.zone]]`、策略字段。
  - 产出 `DnsConfig`、`ZoneConfig`，并提供默认值（如默认域名 `et.net`、默认地址 `100.100.100.101:53`）。

- **节点层（控制面）**（`node.rs` + `peer_mgr.rs`）
  - `DnsNode`：本实例的 DNS 控制器，负责选举、心跳、事件监听、重建 snapshot。
  - `DnsPeerMgr`：维护远端 peer 的 DNS 摘要与配置拉取，拼装 `DnsSnapshot`。

- **服务层（数据面）**（`server.rs` + `node_mgr.rs` + `zone.rs`）
  - `DnsServer`：真正处理 DNS 请求、维护监听 socket、管理 hijack addresses。
  - `DnsNodeMgr`：服务端的快照管理器，接收 Node 心跳，维护节点 TTL 与 dirty 状态。
  - `Zone`/`ZoneGroup`：把 records + forwarders 变成 Hickory `ZoneHandler` 并装配 `Catalog`。

- **系统集成层**（`system/*`）
  - 将当前 DNS 配置下发到 OS（`SystemConfigurator` 抽象）。
  - 服务退出/变更时负责清理或覆盖。

---

## 3. 关键对象与数据模型

- **`DnsConfig`**（`config/dns.rs`）
  - 核心字段：`zones`、`policies`、`name`、`domain`、`addresses`、`listeners`。
  - `get_fqdn()` 用 `name + domain` 生成本机 FQDN。

- **`ZoneData` / `Zone`**（`proto/dns.proto` + `zone.rs`）
  - `ZoneData` 是网络传输模型（protobuf），含 `id/origin/ttl/records/forwarders`。
  - `Zone` 是运行期模型：
    - `records -> InMemoryZoneHandler`
    - `forwarders -> ForwardZoneHandler`
    - 同 origin 可链式共存（ChainedZoneHandler 语义）。

- **`DnsSnapshot`**（`proto/dns.proto`）
  - Node 发给 Server 的完整状态：`zones + addresses + listeners`。

- **`HeartbeatRequest`**
  - 发送 `id + digest + optional snapshot`。
  - digest 一致时可只发轻量心跳，不带 snapshot。

- **`DirtyFlag`**（`utils/dirty.rs`）
  - 全模块统一的“脏标记 + 通知器”，用于节流和增量触发（不是每次事件都全量重建）。

---

## 4. 基础运行逻辑（主链路）

### 4.1 本地节点启动

`Instance` 在 `magic-dns` feature 下创建并启动 `DnsNode`。`DnsNode` 启动后并行跑两个循环：

1. **选举循环**（`run_election`）
   - 周期尝试绑定固定 RPC 地址 `tcp://127.0.0.1:49813`。
   - 绑定成功者成为本机 `DnsServer` 持有者；失败者继续只做 `DnsNode`。

2. **主循环**（`run`）
   - 监听配置变更/IP 变化/PeerInfo 更新。
   - 维护 dirty 状态并按节奏发送 heartbeat。

### 4.2 快照构建与同步

`DnsPeerMgr::snapshot()` 组装快照：

- 本机 zones：`dns_iter_zones()`（包含“自有专用 zone” + 用户配置 zone）。
- 远端 zones：从 peer RPC 拉取并缓存的 export zones。
- 本机 `addresses/listeners`：来自 `DnsConfig`。

Node 发送 heartbeat 时：

- dirty 或首包 -> 带 `snapshot` 全量发送。
- 未 dirty -> 只发 `digest`（轻量心跳）。
- Server 返回 `resync=true` -> 立刻补发全量 snapshot。

### 4.3 服务端聚合与生效

`DnsNodeMgr` 收到 heartbeat 后：

- 若 snapshot digest 改变：更新节点缓存并标记 dirty（catalog/addresses/listeners 分开标记）。
- 若仅 digest 且本地无该节点或不一致：返回 `resync=true`。

`DnsServer::run()` 有三个独立 reload 循环：

- `reload_catalog`：替换 `DynamicCatalog`。
- `reload_addresses`：更新 hijack 地址，并尝试下发系统 DNS。
- `reload_listeners`：重绑 DNS listener socket。

这三个循环彼此解耦，避免单一失败阻塞全部 DNS 功能。

---

## 5. 数据面请求路径（DNS/ICMP 劫持）

`DnsServer` 作为 `NicPacketFilter` 挂入 packet pipeline：

1. 检查目的 IP 是否命中 `addresses`。
2. UDP：
   - 解析 DNS 请求 -> 投递给 `catalog.handle_request()`。
   - 用响应覆盖原 UDP payload，修正长度与校验和。
3. ICMP：
   - 对 EchoRequest 直接改写为 EchoReply。
4. 最后交换源/目的 IP，并把包回注到本机 peer pipeline。

这使得 `addresses` 不要求真实 bind/listen，也能作为“虚拟 DNS 入口地址”。

---

## 6. 可靠性与收敛机制

- **服务高可用（单机维度）**：
  - 任何实例都可竞选 Server；现任退出后其余实例会重试接管。

- **配置高效同步（全网维度）**：
  - `RoutePeerInfo` 只传播 DNS digest，不直接携带全量记录。
  - digest 变化后才通过 RPC 拉取详情，降低路由泛洪压力。

- **自动过期清理**：
  - `DnsNodeMgr` 通过 `moka::Cache` TTL 自动淘汰失联节点配置（心跳过期）。

- **回环防护**：
  - 重建 zones 时会从 forwarders 中剔除本地 `addresses/listeners`，避免显式自环。

---

## 7. 当前实现状态（对应 plan.md）

从代码可见，以下主干能力已经落地：

- Node/Server 双角色、选举、心跳与 resync。
- 快照机制（zone/addresses/listeners）与 digest 驱动同步。
- 自有专用 zone 自动生成与 export。
- Catalog 动态替换、listener/address 分离热更新。
- UDP DNS 劫持 + ICMP 响应。
- forwarder 的本地回环剔除。

仍在计划中的重点：

- 系统 DNS 配置改造（尤其 Linux 路径统一与清理语义完善）。
- 更完整的单元测试覆盖与 CLI 状态输出。

---

## 8. 配置层详解（`config/*`）

这一层负责把 TOML 配置映射成可校验、可传播、可计算 digest 的运行模型。

### 8.1 常量与默认值（`config/mod.rs`）

- `DNS_DEFAULT_TLD = et.net.`：`domain` 缺省值。
- `DNS_DEFAULT_ADDRESS = udp://100.100.100.101:53`：`addresses` 缺省值。
- `DNS_SERVER_RPC_ADDR = tcp://127.0.0.1:49813`：本机 DNS Server 选举地址。
- `DNS_SERVER_ELECTION_INTERVAL = 5s`：选举重试周期。
- `DNS_SUPPORTED_PROTOCOLS = [Udp, Tcp]`：地址/转发器协议白名单。

### 8.2 `DnsConfig`（`config/dns.rs`）

`DnsConfig` 是 `[dns]` 根配置，关键点如下：

- `zones: Vec<ZoneConfig>` 对应 `[[dns.zone]]`。
- `policies: HashMap<LowerName, DnsPolicyConfig>` 用 `#[serde(flatten)]` 承接 `[dns."origin".import]` 形式策略。
- `name/domain` 组合 FQDN。
- `addresses/listeners` 使用 `NameServerAddrGroup`（支持 `ip`、`ip:port`、`udp://`、`tcp://` 解析）。

约束与语义：

- `deserialize_addresses()` 强制 `addresses` 只能是 UDP（与当前 hijack 数据面能力一致）。
- `get_name()`：若 `name` 为空，回退系统 hostname。
- `get_fqdn()`：将 `name` 拼接 `domain` 得到完整域名。
- `set_fqdn()`：反向拆分 FQDN 到 `name` 和 `domain`。

### 8.3 `ZoneConfig` 与专用 Zone（`config/zone.rs`）

`ZoneConfig` 由两部分构成：

- `ZoneData`：用于 protobuf 传输（`id/origin/ttl/records/forwarders`）。
- `ZoneConfigInner`：配置层字段（含 policy）。

关键设计：

- `TryFrom<ZoneConfigInner> for ZoneConfig` 会立即调用 `Zone::try_from(&ZoneData)` 做语法校验，确保“能进配置就能进运行时”。
- `ZoneConfig::dedicated(...)` 用于自动生成“本节点专用 zone”：
  - `origin = 节点 fqdn`
  - records 自动填充 `@ IN A/AAAA ...`
  - `policy.export = Some(default)`，默认可导出给 peers。

### 8.4 策略结构体现状（`config/policy.rs`）

策略模型已就位，但功能并未完全落实到执行路径：

- `AclPolicy { whitelist, blacklist }`
- `FunctionalityPolicy { disabled }`
- `DnsPolicy { recursive }`

目前代码中的直接使用点主要是：

- `dns_export_config()` 只检查 `zone.policy.export.is_some()` 决定是否导出。
- `import/recursive/acl` 仍处于待完整落地状态（与 `plan.md` 的 TODO 对齐）。

### 8.5 `DnsGlobalCtxExt`：配置到发布面的桥（`config/dns.rs`）

`GlobalCtx` 被扩展出 3 个关键方法：

- `dns_self_zone()`：基于当前 IP 与 FQDN 生成专用 zone。
- `dns_iter_zones()`：`self_zone + 用户配置 zones`。
- `dns_export_config()`：从 `dns_iter_zones()` 中筛选可导出的 zones，并附加本机 `fqdn`。

这三个方法是后续 `RoutePeerInfo.dns` digest 与 RPC 拉取的源头。

---

## 9. 节点控制面详解（`node.rs` + `peer_mgr.rs`）

### 9.1 `DnsNode` 初始化与 RPC 注册

`DnsNode::new(...)` 会创建 `DnsPeerMgr`，并把 `DnsPeerMgrRpcServer` 注册到 peer RPC registry。  
这使“我给别人提供 DNS 导出配置”与“我向别人拉取导出配置”在同一组件闭环。

### 9.2 选举循环（`DnsNode::run_election`）

选举逻辑是“抢占固定地址”的单机 leader 机制：

1. 周期或被 `elect.notify_one()` 触发。
2. 尝试 `StandAloneServer(TcpTunnelListener(DNS_SERVER_RPC_ADDR)).serve()`。
3. 绑定成功 -> 启动 `DnsServer`，注册 `DnsNodeMgrRpc`，并挂载 NIC packet pipeline。
4. `DnsServer` 退出后清理 pipeline，回到选举循环。

要点：

- 不依赖外部分布式锁，仅利用本机 socket 独占。
- 失败不是错误态，意味着“已有实例担任 Server”。

### 9.3 主循环（`DnsNode::run`）

主循环负责“何时重建、何时发全量、何时触发重选举”：

- 维护 `HeartbeatRequest { id, digest, snapshot? }`。
- 基于 `DirtyFlag` 动态调整心跳节奏：
  - dirty 时更积极（`rr_interval`）
  - clean 时更快短轮询（`rr_interval / 8`）
- 监听 `GlobalCtxEvent`：
  - `PeerInfoUpdated` -> 并发调用 `mgr.refresh(peer_id)`
  - IP 变化、配置变化、事件丢失（lagged）-> `dirty.mark()`
- 心跳失败 -> 触发一次选举通知（可能是 Server 挂了）。

### 9.4 心跳协议（`DnsNode::heartbeat`）

发送策略：

- 首次或 dirty -> `heartbeat.update(self.mgr.snapshot())`，发送全量 snapshot。
- 非 dirty -> 尽量只发 digest（轻量包）。

服务端响应：

- `resync = true` 时，客户端立刻再发一次带 snapshot 的心跳。

这实现了“正常轻量保活 + 状态漂移时快速自愈”。

### 9.5 `DnsPeerMgr`：远端配置拉取与去抖

`DnsPeerMgr` 核心职责：

- 本地缓存：`Cache<PeerId, DnsPeerInfo>`（TTL = 3s）。
- `refresh(peer_id)`：
  - 先读路由里的 `route.dns` digest。
  - 若与本地缓存一致则跳过 RPC。
  - 不一致才调用 `fetch(peer_id)` 拉取 `GetExportConfigResponse`。
- `snapshot()`：拼接
  - 本机 zones（`dns_iter_zones()`）
  - 所有远端缓存 zones
  - 本机 addresses/listeners

这正是 `plan.md` 中“RoutePeerInfo 仅携带 hash，详情按需拉取”的落地实现。

---

## 10. 服务聚合与数据面详解（`node_mgr.rs` + `server.rs`）

### 10.1 `DnsNodeMgr`：服务器侧状态机

`DnsNodeMgr` 保存每个 Node 的最新状态：

- `nodes: Cache<Uuid, DnsNodeInfo>`（TTL = 5s，心跳过期即自动淘汰）。
- `DnsNodeInfo = digest + zones + addresses + listeners`。
- `dirty` 分三类：`catalog`、`addresses`、`listeners`。

`heartbeat()` 判定逻辑：

- 请求带 snapshot：
  - 反序列化为 `DnsNodeInfo`。
  - digest 变化才更新缓存并打脏标记。
  - 此分支返回 `resync = false`。
- 请求不带 snapshot：
  - 若本地没有该 node 或 digest 不一致 -> `resync = true`。

### 10.2 Catalog 构建（`DnsNodeMgr::catalog/collect_zones`）

构建步骤：

1. 聚合全部节点 zones。
2. 追加 `Zone::system()` 作为 root zone。
3. 收集本地所有 `addresses + listeners` 形成 `local` 集合。
4. 遍历每个 zone 的 forwarders，剔除命中 `local` 的 nameserver（避免显式回环）。
5. 以 `origin -> zone_handlers[]` 方式 `upsert` 到 Hickory `Catalog`。

### 10.3 `DnsServer::run`：三路热重载

`DnsServer` 使用 3 个异步循环处理不同脏标记：

- `reload_catalog`：`DynamicCatalog::replace(...)` 原子替换目录。
- `reload_addresses`：更新劫持地址集合，并尝试下发系统 DNS。
- `reload_listeners`：重建 `ServerFuture` 的 UDP/TCP 监听 socket。

每路失败都会重新 `mark()` 自己，避免瞬时错误导致永久失效。

### 10.4 listener/address 的行为边界

- `listeners`：真正 bind 的服务地址；单个地址 bind 失败会打印错误并跳过，不导致整体停机。
- `addresses`：仅用于劫持匹配，不需要 bind；可用于 `no_tun=false` 下的虚拟 DNS 入口。
- `addresses` 与 `listeners` 分离，符合 `plan.md` 中“hijack 地址不等于监听地址”的设计。

### 10.5 NIC 数据面处理（`NicPacketFilter`）

处理链：

1. `handle_ip_packet()` 解析 IPv4 头并检查目标 IP 是否属于 hijack 地址集合。
2. UDP 分支：
   - `MessageRequest::from_bytes` 解包 DNS 查询。
   - 交给 `catalog.handle_request(...)` 获取响应。
   - 回填 payload，修正 UDP/IP 长度与 checksum。
3. ICMP 分支：
   - EchoRequest 改写为 EchoReply。
4. 统一收尾：交换 src/dst IP，并把包路由回本机 `peer_id`。

该路径让 DNS 响应无需经过用户态 socket recv/send，直接在 packet pipeline 内完成。

---

## 11. Zone 组装与权威链详解（`zone.rs`）

### 11.1 `Zone` 运行时模型

`Zone` 包含：

- `id: Uuid`（来源于配置/网络数据）
- `origin: LowerName`
- `records: BTreeMap<RrKey, RecordSet>`
- `forward: Option<ForwardConfig>`

`PartialEq` 对 `forward` 使用自定义比较（只比较 nameserver 序列），避免与无关字段耦合。

### 11.2 反序列化与校验（`TryFrom<&ZoneData>`）

转换过程：

1. 必须有 `id`，否则报错。
2. 用 Hickory `Parser` 解析 zone 文本（origin + RR）。
3. 把 `forwarders` URL 转成 `NameServerAddr`，为空则 `forward=None`。

这确保网络收到的 `ZoneData` 能直接映射成可执行 zone_handler。

### 11.3 ZoneHandler 构建策略

- `create_memory_zone_handler()`：仅当 records 非空时创建 `InMemoryZoneHandler`。
- `create_forward_zone_handler()`：仅当 forward 非空时创建 `ForwardZoneHandler`。

因此允许 3 种 zone 形态：

1. 纯记录（权威回答）
2. 纯转发（forward-only）
3. 记录 + 转发（链式）

### 11.4 `ZoneGroup` 与同源链式行为

- `ZoneGroup::into_groups()` 按 `origin` 分组。
- `iter_zone_handlers()` 对每个 zone 按顺序产出：先 memory，再 forward。
- `DnsNodeMgr::catalog()` 把同 origin 的多个 zone zone_handler 以数组形式 `upsert`。

结果是同 origin 下可自然形成 ChainedZoneHandler，不做“硬合并单 Zone”，与 `plan.md` 一致。

### 11.5 `Zone::system()` 的作用边界

`Zone::system()` 读取系统 resolver 作为 root zone forwarders。  
在当前文档范围内仅关注它在 catalog 聚合中的语义：**兜底递归出口**。

---

## 12. 文档后续范围

后续若继续扩写，将集中在以下主题（不再展开 `system/*`）：

1. 策略执行链路补齐：`import/recursive/acl` 如何从配置走到查询路径。
2. 测试矩阵梳理：单元测试、集成测试与故障注入测试的覆盖面。
3. CLI 状态输出：如何观测 node/server 角色、snapshot digest、zone 来源与健康状态。

---

## 13. 策略执行链路现状与缺口

本节专门回答一个容易误解的问题：**配置里有策略字段，不等于运行时已经完全执行**。

### 13.1 已生效的策略相关行为

当前代码中，和策略直接相关且已生效的路径主要有一条：

- `GlobalCtx::dns_export_config()` 在导出 zones 时仅检查：
  - `zone.policy.export.is_some()`

也就是说，当前“导出/不导出”是可工作的，但粒度仍偏粗。

### 13.2 已建模但尚未完整落地的策略字段

以下字段在 `config/policy.rs` 已定义，但执行链路尚未完全打通：

- `import.whitelist / import.blacklist`
- `import.disabled`
- `import.recursive`
- `export` 内更细粒度 ACL

从调用路径看：

- `DnsPeerMgr::snapshot()` 只做本地 + 远端 zones 拼接，不做 import/export ACL 过滤。
- `DnsNodeMgr::collect_zones()` 只做聚合与回环剔除，不做来源级策略裁剪。
- `DnsServer::handle_ip_packet()` 是纯查询执行，不做请求来源与策略绑定。

### 13.3 代码中的明确信号（TODO）

当前有两个关键 TODO 信号：

- `dns_export_config()` 里标注了 `TODO: check policies of parent zones`。
- `policy.rs` 中 `AclPolicy`、`recursive` 旁边保留了 TODO 注释。

这说明作者已经把策略模型前置到配置层，但执行面仍属于“进行中”。

### 13.4 文档使用建议（给维护者）

在策略彻底落地前，建议把语义按两层理解：

1. **已可依赖**：`zone.policy.export.is_some()` 控制是否导出。
2. **暂不可依赖**：import/export ACL、recursive、disabled 的全链路行为。

---

## 14. 测试体系与覆盖面

本模块测试不是集中在一个文件，而是“按组件就地内嵌”。

### 14.1 测试分布

- `dns/tests.rs`：测试基建与辅助函数（构造环境、启动 `DnsNode`、DNS 查询断言工具）。
- `dns/server.rs`：数据面与 server 行为主测试集。
- `dns/node_mgr.rs`：聚合 catalog 的基本可用性测试。
- `dns/zone.rs`：配置解析、记录转换、zone_handler 装配测试。

> 说明：`system/*` 也有测试，但本轮文档按约定不展开。

### 14.2 `server.rs` 覆盖要点

`server.rs` 的测试集中验证了以下核心行为：

- `DynamicCatalog::replace()` 可安全替换。
- hijack 判定：`is_hijacked_ip` / `is_hijacked_addr`。
- ICMP 改写：EchoRequest -> EchoReply。
- UDP DNS 包内联处理：解析请求、生成应答、回填 payload。
- 一个基础端到端路径：真实 UDP listener + Hickory client 查询。

这些测试对应模块里最复杂、最容易回归的包处理逻辑。

### 14.3 `node_mgr.rs` 覆盖要点

`node_mgr.rs` 的测试重点是：

- 人工插入节点 zone 后，`catalog()` 能查到预期记录。

它验证了“快照聚合 -> Catalog 查询可用”的最小闭环，但尚未覆盖复杂心跳时序、TTL 过期后的清理行为。

### 14.4 `zone.rs` 覆盖要点

`zone.rs` 的测试覆盖了：

- TOML `DnsConfig` 解析。
- `ZoneConfig -> ZoneData -> Zone` 转换链。
- record 解析/TTL 基本行为。
- memory/forward zone_handler 构建，以及通过 server 查询验证。

该测试更多是“模型与解析正确性”，不是策略执行链路完整验证。

### 14.5 当前测试缺口

结合 `plan.md` 与现有测试，仍建议补充：

- `DnsNode` 心跳 + resync + 重选举的并发时序测试。
- `DnsNodeMgr` TTL 过期淘汰与脏标记联动测试。
- 策略字段（import/export ACL、recursive）的行为测试。
- 多 peer、同 origin 多 zone 的优先级/去重回归测试。

---

## 15. CLI 与可观测性现状

### 15.1 CLI 现状

从当前代码看，`easytier/src/easytier-cli.rs` 没有 DNS 专用子命令。  
因此“查看 DNS 子系统状态”主要依赖日志与通用状态接口，而非专门 CLI 面板。

### 15.2 日志观测点（已存在）

`dns` 子系统已经布置了较多 `tracing` 埋点，关键入口包括：

- `DnsNode election loop`
- `DnsNode main loop`
- `DnsServer main loop`
- `DnsNodeMgr::heartbeat`（含来源 id 与 snapshot 信息）

可用于定位：

- 当前实例是否赢得选举。
- 心跳是否失败、是否触发 `resync`。
- catalog/addresses/listeners 是否持续重载失败。

### 15.3 当前可观测性短板

- 缺少 DNS 专项 CLI 展示：
  - 本机角色（Node/Server）
  - 当前 snapshot digest
  - zone 来源与数量
  - 监听地址与 hijack 地址状态
- 缺少结构化指标（metrics），目前偏日志驱动排障。

### 15.4 建议的最小可观测面

后续若补 CLI，可先实现一个最小 DNS 状态视图：

1. 角色与选举状态（是否持有 `DNS_SERVER_RPC_ADDR`）。
2. 最近心跳时间、`resync` 次数。
3. 已装载 zone 数量（按本地/远端分组）。
4. listeners 与 addresses 当前集合。

该视图不改变数据面行为，但能显著降低线上排障成本。

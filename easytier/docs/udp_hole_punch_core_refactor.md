# UDP 打洞迁移到 easytier-core 重构计划

## 背景

本轮 core crates 重构的长期目标是：`easytier-core` 承载可复用的
control-plane 和 peer 通信能力，`easytier` crate 退回 runtime
Adapter 角色，负责 OS、socket、netns、UPnP、STUN 网络探测和具体
tunnel implementation。

UDP 打洞现在仍在 `easytier/src/connector/udp_hole_punch/`。这部分代码
同时包含两类能力：

- 打洞 Module：peer 选择、NAT 类型决策、信令编排、blacklist、backoff、
  cone/sym/easy-sym 状态机、任务调度。
- runtime Adapter：真实 `tokio::net::UdpSocket`、netns、UPnP/NAT-PMP、
  STUN 映射查询、`UdpTunnelListener` / `UdpTunnelConnector`。

目标不是只把策略 helper 挪进 core。目标是让 `easytier-core` 拥有 UDP
打洞 Module：调用方给 core 提供 socket 构造能力、STUN/公网映射探测
能力、UDP 打洞信令能力和 tunnel sink 后，core 可以自行完成 UDP 打洞。
成功建立的 `Tunnel` 交给调用方提供的 sink，而不是让 UDP 打洞 Module
直接依赖 peers Module。

## 当前问题

### 打洞 Module 和 runtime Adapter 混在一起

`UdpHolePunchConnector` 当前直接依赖：

- `PeerManager`
- `GlobalCtx`
- `NetNS`
- `StunInfoCollectorTrait`
- `upnp::resolve_udp_public_addr`
- `tokio::net::UdpSocket`
- `UdpTunnelListener`
- `UdpTunnelConnector`

这导致打洞流程不能进入 `easytier-core`，也难以用 mock socket 和 mock
STUN 做稳定的 core-level 测试。

UDP 打洞真正需要的不是 `PeerManager` 这个大 Module，而是更窄的能力：
候选 peer 列表、UDP 打洞信令、成功 tunnel 的接收方、以及本地
STUN/socket runtime。这些能力应由独立 Interface 注入。

### UDP listener 生命周期缺少清晰 seam

当前 `UdpHolePunchListener` 同时负责：

- bind UDP socket。
- 通过 UPnP/NAT-PMP 和 STUN 获取 mapped address。
- 用同一个 socket 创建 `UdpTunnelListener`。
- 后台 accept tunnel 并调用 `peer_mgr.add_tunnel_as_server`。
- 保持 port-mapping lease 存活。
- 统计连接数和 last active time，供 listener 复用策略使用。

这是一块深 Implementation，但它的 runtime 部分和 core 部分没有拆开：
core 应该管理 listener 的复用和 accept 后加入 peer graph 的行为；runtime
只应该提供 listener 的 socket、mapped address、acceptor 和 lease。

### UDP socket pool 依赖具体 socket 类型

`UdpSocketArray` 是 symmetric NAT 打洞的关键实现，内部会创建多个 UDP
socket，监听 hole-punch packet，并按 transaction id 找出 punched socket。
这部分属于 UDP 打洞 Module，应迁入 core；但它当前直接依赖
`tokio::net::UdpSocket` 和 `NetNS`。

### 打洞 packet builder 放在 runtime tunnel 文件中

`new_hole_punch_packet` 现在在 `easytier/src/tunnel/udp.rs`。UDP 打洞进入
core 后，hole-punch packet 的构造和最小解析应属于 core，因为它是打洞
协议的一部分，不是 runtime tunnel implementation 的私有细节。

## 目标架构

### Module 归属

目标文件布局：

```text
easytier-core/src/hole_punch/
  mod.rs
  udp/
    mod.rs
    runtime.rs
    common.rs
    cone.rs
    sym_to_cone.rs
    both_easy_sym.rs

easytier/src/connector/udp_hole_punch/
  mod.rs                 # runtime adapter + compatibility wrapper
```

`easytier-core::hole_punch::udp` 是深 Module，拥有 UDP 打洞的状态机
和任务生命周期。它不能 import `crate::peers::*`。`easytier` 中的
UDP hole-punch runtime 目录最终只保留 Adapter implementation、peer RPC
bridge、以及迁移期需要的 re-export / compatibility wrapper。

### 根概念归属

`PeerId`、network name、P2P flags、peer feature flag、NAT info、候选 peer
描述都不是 peers Module 私有概念。UDP 打洞 Module 可以依赖这些
`easytier-core` 根概念或自己的 public model，但不能通过 `peers` Module
拿到这些类型。

建议逐步收敛到：

- `easytier-core::config::PeerId` 继续作为根 peer id 类型，或后续移动到
  `easytier-core::types`。
- `P2pPolicyFlags` / `UdpPunchCandidate` 由 `hole_punch` 或 core 根模块定义。
- `PeerFeatureFlag` / `StunInfo` 可以继续来自 `easytier-proto` 的 core feature。
- `ExternalTaskSignal` 这类通用任务唤醒原语如需复用，应从
  `peers::peer_task` 下沉到 core root task Module，而不是让 UDP 打洞依赖
  `peers`。

### Module 独立性约束

`peers` 和 `hole_punch` 必须是相邻 Module，而不是父子关系：

- `hole_punch::udp` 不依赖 `peers`。
- `peers` 不依赖 `hole_punch::udp`。
- 两者通过上层 wiring / Adapter layer 集成。
- peer RPC 的 generated client/server、registry、scoped client 等大概念不能出现在
  UDP 打洞 Module 的 Interface 中。
- UDP 打洞只暴露和消费自己的窄信令 Interface。

### Core 职责

`easytier-core` 负责：

- `UdpHolePunchConnector` 生命周期。
- inbound UDP 打洞信令 handler。
- outbound UDP 打洞信令调用，且只通过窄 `UdpHolePunchSignaling` Interface。
- candidate collect 决策和打洞 task 调度。
- NAT 类型判断和 punch method 选择。
- cone-to-cone、sym-to-cone、easy-sym-to-easy-sym 状态机。
- `UdpSocketArray` socket pool、transaction id 跟踪和 punched socket 获取。
- blacklist、backoff、sym punch lock。
- listener 复用策略。
- accept 到 server tunnel 后调用注入的 tunnel sink。
- client 打通后调用注入的 tunnel sink。

### Runtime Adapter 职责

`easytier` 负责：

- 创建真实 UDP socket，并在创建时进入正确 netns。
- 通过现有 STUN collector 获取 `StunInfo`。
- 对指定 socket 查询 UDP mapped address。
- 建立 UPnP/NAT-PMP lease，并保证 lease 生命周期跟随 listener。
- 用指定 UDP socket 创建真实 `UdpTunnelListener` acceptor。
- 用 punched UDP socket 和 remote mapped address 构造真实 `Tunnel`。
- 处理 runtime feature、平台差异和 socket mark / bind device 等 OS 细节。
- 实现 peer-source、tunnel-sink、UDP 打洞 signaling，以及把 inbound handler
  bridge 到现有 peer RPC。

## Core Interface 草案

UDP 打洞 Module 的 Interface 分三类：peer-independent core model、打洞
信令 seam、以及 UDP socket/STUN runtime seam。所有 Interface 都应围绕 UDP
打洞的领域动作命名，不暴露 `rpc_client()`、`rpc_registry()`、
`PeerManagerCore` 或 `PeerMap`。

### Peer-independent model 和 peer source

候选 peer 由外部 Adapter 组装后喂给 UDP 打洞 Module。UDP 打洞不读取 route
table，也不判断 peer map；它只消费已经归一化后的候选信息。

```rust
pub struct P2pPolicyFlags {
    pub disable_udp_hole_punching: bool,
    pub disable_sym_hole_punching: bool,
    pub lazy_p2p: bool,
    pub disable_p2p: bool,
    pub need_p2p: bool,
}

pub struct UdpPunchCandidate {
    pub peer_id: PeerId,
    pub udp_nat_type: NatType,
    pub feature_flag: Option<PeerFeatureFlag>,
    pub has_direct_connection: bool,
    pub has_recent_traffic: bool,
}

#[async_trait::async_trait]
pub trait UdpHolePunchPeerSource: Send + Sync {
    fn local_peer_id(&self) -> PeerId;
    fn network_name(&self) -> &str;
    fn p2p_policy_flags(&self) -> P2pPolicyFlags;

    async fn candidates(&self) -> Vec<UdpPunchCandidate>;
}
```

这样 lazy P2P、disable P2P、need P2P 等规则仍由 UDP 打洞 Module 统一判断；
而 route table、PeerMap、recent traffic tracker 如何读取，全部留在 Adapter
Implementation 内。

### Signaling seam

UDP 打洞只需要“向某个 peer 发送某种 UDP 打洞信令”。它不需要知道这条信令
底层是 peer RPC、测试内存通道，还是未来其他控制面。

```rust
#[derive(Debug, thiserror::Error)]
pub enum UdpHolePunchSignalError {
    #[error("invalid service key")]
    InvalidServiceKey,
    #[error("timeout")]
    Timeout,
    #[error("remote rejected: {0}")]
    RemoteRejected(String),
    #[error("transport: {0}")]
    Transport(String),
}

#[async_trait::async_trait]
pub trait UdpHolePunchSignaling: Send + Sync {
    async fn select_punch_listener(
        &self,
        dst_peer_id: PeerId,
        request: SelectPunchListener,
    ) -> Result<SelectPunchListenerResponse, UdpHolePunchSignalError>;

    async fn send_punch_packet_cone(
        &self,
        dst_peer_id: PeerId,
        request: SendPunchPacketCone,
    ) -> Result<(), UdpHolePunchSignalError>;

    async fn send_punch_packet_hard_sym(
        &self,
        dst_peer_id: PeerId,
        request: SendPunchPacketHardSym,
    ) -> Result<SendPunchPacketHardSymResponse, UdpHolePunchSignalError>;

    async fn send_punch_packet_easy_sym(
        &self,
        dst_peer_id: PeerId,
        request: SendPunchPacketEasySym,
    ) -> Result<(), UdpHolePunchSignalError>;

    async fn send_punch_packet_both_easy_sym(
        &self,
        dst_peer_id: PeerId,
        request: SendPunchPacketBothEasySym,
    ) -> Result<SendPunchPacketBothEasySymResponse, UdpHolePunchSignalError>;
}
```

`SelectPunchListener`、`SendPunchPacketCone` 等 DTO 应是 `hole_punch::udp`
自己的 Rust model，或者是从 proto model 轻量转换后的 model。第一阶段可以
在 Adapter Implementation 内继续使用现有 `peer_rpc.proto` request/response，
但不能把 generated `UdpHolePunchRpc` trait、RPC client factory、registry
暴露到 UDP 打洞 Interface。

### Inbound handler seam

UDP 打洞 Module 对外暴露 inbound handler 方法；上层 wiring 负责把这些方法
接到现有 peer RPC server。

```rust
#[async_trait::async_trait]
pub trait UdpHolePunchInbound: Send + Sync {
    async fn select_punch_listener(
        &self,
        request: SelectPunchListener,
    ) -> Result<SelectPunchListenerResponse, UdpHolePunchSignalError>;

    async fn send_punch_packet_cone(
        &self,
        request: SendPunchPacketCone,
    ) -> Result<(), UdpHolePunchSignalError>;

    async fn send_punch_packet_hard_sym(
        &self,
        request: SendPunchPacketHardSym,
    ) -> Result<SendPunchPacketHardSymResponse, UdpHolePunchSignalError>;

    async fn send_punch_packet_easy_sym(
        &self,
        request: SendPunchPacketEasySym,
    ) -> Result<(), UdpHolePunchSignalError>;

    async fn send_punch_packet_both_easy_sym(
        &self,
        request: SendPunchPacketBothEasySym,
    ) -> Result<SendPunchPacketBothEasySymResponse, UdpHolePunchSignalError>;
}
```

这个 seam 的关键点是：注册 RPC 是上层 wiring 的 Implementation，不是 UDP
打洞 Module 的 Interface。

### Tunnel sink seam

UDP 打洞成功后只知道“我有一条 tunnel”，不知道这条 tunnel 应该进入哪个
peer graph。

```rust
#[async_trait::async_trait]
pub trait UdpHolePunchTunnelSink: Send + Sync {
    async fn add_client_tunnel(&self, tunnel: Box<dyn crate::tunnel::Tunnel>)
        -> anyhow::Result<()>;

    async fn add_server_tunnel(&self, tunnel: Box<dyn crate::tunnel::Tunnel>)
        -> anyhow::Result<()>;
}
```

### UDP socket/STUN runtime seam

第一版建议用带关联类型的 runtime trait，而不是纯 `dyn UdpPunchSocket`。
这样 STUN 的 `get_udp_port_mapping_with_socket` 可以拿到 runtime 自己的具体
socket wrapper，不需要 `Any` downcast。

```rust
#[async_trait::async_trait]
pub trait UdpPunchSocket: Send + Sync {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr>;

    async fn send_to(
        &self,
        data: &[u8],
        addr: std::net::SocketAddr,
    ) -> std::io::Result<usize>;

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddr)>;
}

#[async_trait::async_trait]
pub trait UdpPunchAcceptor: Send {
    async fn accept(&mut self) -> anyhow::Result<Box<dyn crate::tunnel::Tunnel>>;
}

pub trait UdpPunchConnCounter: Send + Sync {
    fn get(&self) -> Option<u32>;
}

pub trait UdpPortMappingLease: Send + Sync + std::fmt::Debug {}

pub struct UdpPunchListener<S> {
    pub socket: std::sync::Arc<S>,
    pub mapped_addr: std::net::SocketAddr,
    pub conn_counter: std::sync::Arc<dyn UdpPunchConnCounter>,
    pub acceptor: Box<dyn UdpPunchAcceptor>,
    pub port_mapping_lease: Option<Box<dyn UdpPortMappingLease>>,
}

#[async_trait::async_trait]
pub trait UdpHolePunchRuntime: Send + Sync + 'static {
    type Socket: UdpPunchSocket + 'static;

    fn stun_info(&self) -> crate::proto::common::StunInfo;

    async fn bind_udp(
        &self,
        port: Option<u16>,
    ) -> anyhow::Result<std::sync::Arc<Self::Socket>>;

    async fn resolve_udp_public_addr(
        &self,
        socket: std::sync::Arc<Self::Socket>,
    ) -> anyhow::Result<std::net::SocketAddr>;

    async fn create_listener(
        &self,
        prefer_port_mapping: bool,
    ) -> anyhow::Result<UdpPunchListener<Self::Socket>>;

    async fn connect_with_socket(
        &self,
        socket: std::sync::Arc<Self::Socket>,
        remote: std::net::SocketAddr,
    ) -> anyhow::Result<Box<dyn crate::tunnel::Tunnel>>;
}
```

命名可以在实现时按仓库风格调整，但 Interface 必须满足这些约束：

- UDP 打洞 Module 不能 import `crate::peers::*`。
- UDP 打洞 Module 不能看到 peer RPC client、server registry、scoped client。
- peer id、network name、flags、candidate info 是 core 根概念或 UDP 打洞
  public model，不是 peers 私有类型。
- core 不能看到 `tokio::net::UdpSocket`。
- core 不能看到 `NetNS`、`GlobalCtx`、UPnP/NAT-PMP 类型。
- listener 的 port-mapping lease 必须被 core 持有，以保证 listener 存活时
  mapping 不被释放。
- acceptor 被 core 消费并由 core 调用 `UdpHolePunchTunnelSink`，避免 runtime
  反向持有 peer graph。
- socket pool 使用同一个 `Socket` associated type，避免 punched socket 和
  STUN probe socket 类型不一致。

## 迁移后的核心数据流

### Server 侧 select listener

1. 上层 wiring 收到现有 peer RPC 或其他控制面请求。
2. wiring 将请求转换成 UDP 打洞 DTO，调用 `UdpHolePunchInbound`。
3. core 根据 listener 数量、连接数、last active time、port-mapping 状态判断
   是否需要新建 listener。
4. core 调用 `runtime.create_listener(prefer_port_mapping)`。
5. runtime bind socket，查询 mapped address，构造 `UdpTunnelListener`
   acceptor，并返回 `UdpPunchListener`。
6. core 把 `acceptor` 移入后台 task，循环 accept tunnel。
7. core 保存 listener record：socket、mapped address、conn counter、lease、
   last select time、last active time、accept task。
8. core 返回 selected listener mapped address。
9. wiring 将 UDP 打洞 DTO 转回控制面响应。

### Server 侧发送 punch packet

1. 上层 wiring 收到 `send_punch_packet_cone` /
   `send_punch_packet_hard_sym` / `send_punch_packet_easy_sym` /
   `send_punch_packet_both_easy_sym` 控制面请求。
2. wiring 将请求转换成 UDP 打洞 DTO，调用 `UdpHolePunchInbound`。
3. core 按请求中的 listener mapped address 找到 listener socket。
4. core 构造 hole-punch packet bytes。
5. core 通过 `UdpPunchSocket::send_to` 发 packet。

### Client 侧 cone-to-cone

1. core 从 `UdpHolePunchPeerSource::candidates()` 得到候选 peer。
2. core 按 NAT 类型、P2P flags、recent traffic、direct connection 状态选择目标。
3. core 通过 `UdpHolePunchSignaling` 调用远端 `select_punch_listener`。
4. core 调用 `runtime.bind_udp(None)` 创建本地 socket。
5. core 调用 `runtime.resolve_udp_public_addr(socket)` 获取本地 mapped address。
6. core 把 socket 加入 `UdpSocketArray`，注册 transaction id。
7. core 通过 `UdpHolePunchSignaling` 调用远端 `send_punch_packet_cone`，
   同时本地周期性向远端 listener mapped address 发送 hole-punch packet。
8. core 从 `UdpSocketArray` 取出 punched socket。
9. core 调用 `runtime.connect_with_socket(socket, remote_mapped_addr)` 得到
   `Tunnel`。
10. core 调用 `UdpHolePunchTunnelSink::add_client_tunnel(tunnel)`。

### Client 侧 symmetric 流程

sym-to-cone 和 both-easy-sym 的状态机迁入 core 后保留现有行为：

- hard symmetric 使用 `UdpSocketArray` 多 socket birthday attack。
- easy symmetric 使用 base port 和 inc/dec 预测。
- both-easy-sym 继续使用全局 sym punch lock，避免同一 peer 上并发 symmetric
  打洞互相污染。
- 每轮失败时保留现有 backoff / round / port index 更新语义。

## 分阶段落地计划

### 阶段 0：基线确认

不改行为，只确认当前测试和编译基线。

建议命令：

```bash
cargo check -p easytier-core --no-default-features
cargo check -p easytier --no-default-features
cargo test -p easytier connector::udp_hole_punch -- --nocapture
cargo test -p easytier upnp_test -- --nocapture
```

集成测试如果涉及 root/netns，使用本机 `rust` 容器执行。

### 阶段 1：建立独立 core 模块骨架和纯逻辑迁移

新增 `easytier-core::hole_punch::udp`，先迁移不依赖真实 socket 的
类型和纯逻辑：

- `BackOff`
- `UdpNatType`
- `UdpPunchClientMethod`
- `BLACKLIST_TIMEOUT_SEC`
- `handle_rpc_result`
- `should_create_public_listener`
- `select_reusable_public_listener_idx`
- `select_reusable_port_mapping_listener_idx`
- `can_reuse_public_listener`
- `can_reuse_port_mapping_listener`

同时把 P2P task collect 需要的策略函数迁到 core root 或
`hole_punch` public model，避免 UDP 打洞依赖 `easytier::connector` 或
`easytier-core::peers`。

验收：

- core 单测覆盖 NAT method selection。
- core 单测覆盖 listener reuse selection。
- 模块不 import `crate::peers::*`。
- runtime 旧测试仍通过。

### 阶段 2：引入独立 Interface

在 core 增加独立 Interface：

- peer source：提供本地 peer id、network name、P2P flags、候选 peer。
- signaling：提供 UDP 打洞的 outbound 信令调用。
- inbound handler：由 UDP 打洞 Module 暴露，上层 wiring 负责注册到控制面。
- tunnel sink：接收打洞成功后的 client/server tunnel。
- runtime：提供 UDP socket、STUN/public addr、listener、connect-with-socket。

在 `easytier` 增加 runtime Adapter：

- `RuntimeUdpHolePunchPeerSource` 从 peer graph/route/recent traffic 组装候选
  peer，但这个 Adapter 不属于 `peers` Module。
- `RuntimeUdpHolePunchSignaling` 内部可以使用现有 peer RPC client，但
  Interface 不暴露 peer RPC。
- `RuntimeUdpHolePunchRpcBridge` 把现有 generated peer RPC server 转接到
  `UdpHolePunchInbound`。
- `RuntimeUdpHolePunchTunnelSink` 内部调用 peer graph 的 tunnel admission。
- `RuntimeUdpPunchSocket` 包装 `Arc<tokio::net::UdpSocket>`。
- `RuntimeUdpPunchAcceptor` 包装 `UdpTunnelListener`。
- `RuntimeUdpPunchConnCounter` 包装现有 `TunnelConnCounter`。
- `RuntimeUdpPortMappingLease` 包装 `upnp::UdpPortMappingLease`。
- `RuntimeUdpHolePunchRuntime` 持有 `ArcGlobalCtx`。

这一阶段不替换旧 `UdpHolePunchConnector`，只让 Adapter 能独立编译和测试。

验收：

- Adapter 可以 bind socket 并查询 local addr。
- Adapter 可以创建 listener，listener 的 mapped address 可获取。
- Adapter drop listener record 后 port-mapping lease 生命周期保持原语义。
- UDP 打洞 Module 的 public Interface 不出现 `rpc_client`、`rpc_registry`、
  `PeerManagerCore`、`PeerMap`。

### 阶段 3：迁移 UdpSocketArray 和 punch packet

把 `UdpSocketArray` 和 `PunchedUdpSocket` 迁入 core，并改为泛型：

```rust
pub struct PunchedUdpSocket<S> {
    pub socket: Arc<S>,
    pub tid: u32,
    pub remote_addr: SocketAddr,
}

pub struct UdpSocketArray<R: UdpHolePunchRuntime> {
    sockets: DashMap<SocketAddr, Arc<R::Socket>>,
    runtime: Arc<R>,
    ...
}
```

把 `new_hole_punch_packet` 或等价函数迁入 core。core 应只迁入 hole-punch
packet 需要的最小 UDP tunnel header 构造，不把整个 `UdpTunnelConnector`
迁入 core。

验收：

- core mock socket 测试 `add_new_socket`、`send_with_all`、
  `try_fetch_punched_socket`。
- punched packet 的 header/type/len/transaction id 与旧实现一致。

### 阶段 4：迁移 listener common 和 inbound handler

把 `PunchHoleServerCommon` 和 UDP inbound handler 迁入 core。

核心调整：

- `PunchHoleServerCommon<R>` 持有 `Arc<R>` runtime。
- `select_listener` 调用 `runtime.create_listener`。
- core 消费 listener acceptor 并在后台 task 中调用
  `UdpHolePunchTunnelSink::add_server_tunnel`。
- listener cleanup 逻辑保留：不活跃超过 40 秒且最近 30 秒未被选中过的
  listener 被释放。
- inbound handler 的请求/响应 model 保持与现有 RPC shape 可无损转换。

验收：

- `select_punch_listener` inbound handler 能返回 mapped address。
- cone server `send_punch_packet_cone` 能通过 listener socket 发 packet。
- listener accept 成功后由 core 通过 tunnel sink 添加 server tunnel。

### 阶段 5：迁移 cone client/server

把 `PunchConeHoleServer` 和 `PunchConeHoleClient` 迁入 core。

行为保持点：

- 先 signaling `select_punch_listener`，成功后才为本地 socket 做 public addr
  resolution，避免 listener RPC 失败时提前触发 UPnP。
- 本地发送和远端发送 batch 参数保持不变。
- punched socket 连接失败时保留现有重试次数。
- signaling error 为 `InvalidServiceKey` 时继续写 blacklist。

验收：

- 现有 cone-to-cone 单测迁到 core mock 测试一部分。
- runtime 现有 `hole_punching_cone` 保持通过。
- `cone_hole_punch_does_not_create_upnp_mapping_before_listener_rpc_succeeds`
  保持通过。

### 阶段 6：迁移 sym-to-cone

把 `PunchSymToConeHoleServer` 和 `PunchSymToConeHoleClient` 迁入 core。

行为保持点：

- `UDP_ARRAY_SIZE_FOR_HARD_SYM` 不变。
- hard-sym shuffled port vec 生成逻辑不变。
- easy-sym base port 获取逻辑通过 runtime public addr/STUN Interface 完成。
- `remote_send_hole_punch_packet_predicable` 和
  `remote_send_hole_punch_packet_random` signaling 参数不变。
- `last_port_idx` 更新逻辑不变。
- 非 symmetric NAT 时清理 UDP socket array 的行为不变。

验收：

- core mock 测试覆盖 easy-sym inc/dec request 生成。
- runtime symmetric 相关单测保持通过。

### 阶段 7：迁移 both-easy-sym

把 `PunchBothEasySymHoleServer` 和 `PunchBothEasySymHoleClient` 迁入 core。

行为保持点：

- busy lock 语义不变。
- both easy-sym port prediction 参数不变。
- `is_busy` 时 backoff rollback 语义不变。
- signaling request/response shape 不变。

验收：

- core mock 测试覆盖 busy lock 路径。
- runtime both-easy-sym 单测保持通过。

### 阶段 8：迁移 UdpHolePunchConnector 和 task scheduler

把 `UdpHolePunchConnector`、UDP 打洞 task scheduler、
`UdpHolePunchConnectorData` 迁入 core。这里不能依赖
`peers::peer_task::PeerTaskManager`；如果需要复用现有任务调度能力，应先把
通用 task manager 下沉为 core root Module。

`UdpHolePunchConnector::run` 在 core 中完成：

- 读取 `UdpHolePunchPeerSource::p2p_policy_flags()` 判断
  `disable_udp_hole_punching`。
- 启动 UDP 打洞内部 task scheduler。
- 暴露 `UdpHolePunchInbound` handler；不注册 RPC。

`collect_peers_need_task` 在 core 中完成：

- 从 `UdpHolePunchPeerSource::candidates()` 读取候选 peer。
- 使用 `UdpHolePunchRuntime::stun_info()` 获取本地 UDP NAT 类型。
- 使用 candidate 中的 peer UDP NAT 类型。
- 使用 core P2P policy 判断 lazy/static/dynamic P2P。
- 使用 candidate 中的 `has_recent_traffic` 实现 lazy P2P demand。
- 使用 candidate 中的 `has_direct_connection` 跳过已直连 peer。

验收：

- `lazy_p2p` 相关 UDP task collect 测试迁入或保留 runtime 测试。
- `disable_udp_hole_punching` 路径不启动任务；RPC 注册由 wiring 控制。
- peer blacklist cleanup 行为不变。
- `hole_punch::udp` 不 import `peers`。

### 阶段 9：替换 runtime wiring

在 `Instance::new` 或等价 composition root 中构造 Adapter，然后构造 core
UDP 打洞 connector：

```rust
let udp_peer_source = Arc::new(RuntimeUdpHolePunchPeerSource::new(peer_manager.clone()));
let udp_signaling = Arc::new(RuntimeUdpHolePunchSignaling::new(peer_manager.clone()));
let udp_tunnel_sink = Arc::new(RuntimeUdpHolePunchTunnelSink::new(peer_manager.clone()));
let udp_runtime = Arc::new(RuntimeUdpHolePunchRuntime::new(global_ctx.clone()));

let udp_hole_puncher = Arc::new(Mutex::new(
    easytier_core::hole_punch::udp::UdpHolePunchConnector::new(
        udp_peer_source,
        udp_signaling,
        udp_tunnel_sink,
        udp_runtime,
    ),
));

RuntimeUdpHolePunchRpcBridge::new(udp_hole_puncher.clone())
    .register(peer_manager.core().get_peer_rpc_mgr(), global_ctx.get_network_name());
```

这里 `RuntimeUdpHolePunchRpcBridge` 属于 wiring / Adapter layer，不属于
`peers`，也不属于 `hole_punch::udp`。它可以依赖现有 generated peer RPC，
但只把请求转换为 `UdpHolePunchInbound` 调用。

旧 `easytier/src/connector/udp_hole_punch` 目录在此阶段缩成：

- runtime adapter。
- 测试辅助。
- compatibility re-export。

验收：

- `Instance::run` 调用新 connector。
- `easytier` 不再拥有 UDP 打洞状态机。
- runtime tests 仍从旧路径 import 时可以通过 re-export 兼容。

### 阶段 10：删除旧实现和收敛测试

删除或缩减旧 runtime 实现文件：

- `common.rs`
- `cone.rs`
- `sym_to_cone.rs`
- `both_easy_sym.rs`

保留必要的 adapter 和 test utilities。最终 runtime 文件不应再包含打洞
状态机，只包含真实 I/O Adapter。

验收命令：

```bash
cargo fmt --all
cargo check -p easytier-core --no-default-features
cargo test -p easytier-core
cargo check -p easytier --no-default-features
cargo check -p easytier
cargo test -p easytier connector::udp_hole_punch -- --nocapture
cargo test -p easytier upnp_test -- --nocapture
cargo test -p easytier --no-run
```

必要时补充：

```bash
docker exec rust bash -lc \
  'cd /data/project/EasyTier && CARGO_TARGET_DIR=/tmp/easytier-codex-target cargo test -p easytier three_node -- --nocapture'
```

## 测试策略

### Core mock tests

core 应新增 mock runtime，覆盖不稳定网络行为以外的确定性逻辑：

- mock socket send/recv packet。
- transaction id 匹配。
- listener selection。
- NAT method selection。
- blacklist。
- lazy P2P task collect。
- signaling `InvalidServiceKey` -> blacklist。
- sym punch lock busy。

这些测试应尽量不依赖真实 UDP socket，避免 flaky。

### Runtime adapter tests

runtime 测试只验证 Adapter 是否正确桥接真实 implementation：

- bind 进入 netns。
- public addr resolution 调用 STUN/UPnP 的顺序不变。
- `UdpTunnelListener` acceptor 可以从 core task 消费。
- `connect_with_socket` 保留原 `UdpTunnelConnector` 行为。

### Integration tests

保留现有三节点拓扑测试，验证打洞迁移后实际 peer route cost 和 direct conn
状态不回退。

## 风险和处理

### listener lifetime / port mapping lease

风险：listener record 被清理时 lease 过早释放或过晚释放。

处理：

- lease 作为 `UdpPunchListenerRecord` 字段由 core 持有。
- cleanup 只删除 record，不额外调用 runtime。
- adapter lease 的 Drop 保持现有删除/停止 renew 行为。

### acceptor 所有权

风险：core 既要保存 listener socket，又要后台 accept，容易出现所有权拆分不清。

处理：

- runtime 返回 split object：socket/mapped/counter/lease/acceptor。
- core 立即把 acceptor 移入 accept task。
- core 只在 listener record 保存 socket/mapped/counter/lease/task metadata。

### 泛型扩散

风险：`UdpHolePunchConnector` 为 peer source、signaling、tunnel sink、runtime
引入多个泛型参数后，类型签名可能变长。

处理：

- 第一版接受泛型，换取 socket/STUN 和 signaling 类型安全。
- 如果后续发现泛型污染 `Instance` 或测试过重，再用 trait object +
  `as_any` downcast 收敛到 dyn runtime。

### packet 格式回退

风险：迁移 `new_hole_punch_packet` 时改变 UDP header 字段或 body 长度。

处理：

- 在 core 增加 byte-level golden test。
- 对比旧 `UdpPacketType::HolePunch`、conn id、len、body length。

### task shutdown

风险：`JoinSet` / `AbortOnDropHandle` 迁移后后台 task 生命周期变化。

处理：

- 保留原 `join_joinset_background` 语义，或复用 core 已有 task helper。
- connector drop 后 client loop、listener accept loop、socket recv loop 都应停止。

### lazy P2P 行为

风险：task collect 迁到 core 后，`lazy_p2p` 与 recent traffic 的触发条件变更。

处理：

- 迁移前后都保留测试：无 recent traffic 不发起，mark recent traffic 后发起。
- 如果需要外部唤醒，先把 task wake primitive 做成 core root 概念，
  不从 `peers` Module 引用。

### UPnP 触发顺序

风险：提前查询本地 public addr 会导致 UPnP 在远端 RPC 失败时被误触发。

处理：

- cone flow 保持先 `select_punch_listener` 成功，再创建本地 socket 和 public addr。
- 保留现有 upnp attempt 计数测试。

## 非目标

本轮 UDP 迁移不做：

- 不迁移 TCP 打洞。
- 不迁移 direct/manual connector。
- 不把真实 `tokio::net::UdpSocket` 放进 `easytier-core`。
- 不把 UPnP/NAT-PMP crate 放进 `easytier-core`。
- 不重写 UDP tunnel 协议。
- 不改变 peer RPC request/response protobuf shape。
- 不把 peer RPC 的 client、registry、generated trait 暴露到 UDP 打洞
  Module 的 Interface。
- 不改变 NAT 类型枚举语义。

## 推荐提交拆分

建议按以下粒度提交，便于 review 和 bisect：

1. `refactor: add core udp hole punch module skeleton`
2. `refactor: move udp hole punch policy into core`
3. `refactor: add udp hole punch runtime adapter interface`
4. `refactor: implement runtime udp hole punch adapter`
5. `refactor: move udp socket array into core`
6. `refactor: move udp hole punch server common into core`
7. `refactor: move cone udp hole punch flow into core`
8. `refactor: move symmetric udp hole punch flow into core`
9. `refactor: move udp hole punch connector into core`
10. `refactor: route instance udp hole punching through core`
11. `test: cover core udp hole punch behavior`
12. `refactor: remove runtime udp hole punch state machine`

每个代码提交后都需要按项目规则触发提交后审查。纯文档提交不需要审查子代理。

## 完成标准

UDP 打洞迁移完成后应满足：

- `easytier-core` 拥有 UDP 打洞 Module 和状态机。
- `easytier-core` 给定 peer source、signaling、tunnel sink、runtime
  socket/STUN Adapter 后可以完成打洞。
- `easytier-core::hole_punch::udp` 不依赖 `easytier-core::peers`。
- `easytier` 只保留真实 I/O Adapter 和兼容 re-export。
- 现有 UDP 打洞 RPC 行为不变。
- 现有 cone/sym/easy-sym 流程行为不变。
- lazy P2P、blacklist、listener reuse、UPnP 触发顺序都有测试覆盖。
- `cargo check -p easytier-core --no-default-features` 通过。
- `cargo test -p easytier-core` 通过。
- `cargo check -p easytier` 和 `cargo test -p easytier --no-run` 通过。

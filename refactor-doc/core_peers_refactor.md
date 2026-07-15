# easytier-core Peers 重构第一阶段方案

> 状态：历史迁移计划，迁移已经完成。`easytier/src/peers` 已删除，
> portable peer ownership 全部位于 `easytier-core::peers`。当前契约见
> [`core_ownership_finalization.md`](core_ownership_finalization.md)。

## 背景

本轮 core crates 重构的出发点是：把 EasyTier 的跨平台核心能力收敛到 `easytier-core` / `easytier-proto`，并保证 `easytier-core` 可以在 `wasm32-wasip1` 下编译。

目标不是把现有代码拆成纯逻辑 helper，也不是在 `easytier` runtime 里继续维护一套核心状态后让 core 被动参与计算。目标是让 core crates 承载可跨平台复用的 control-plane 和 packet-routing 能力；`easytier` crate 则退回 runtime Adapter 角色，负责 OS/socket/TUN/netns/DNS/CLI/service 等平台能力。

在这个目标下，`easytier/src/peers/` 是第一阶段最合适的入手点。这个目录实现的是 EasyTier 的核心 peer 通信和包路由能力：peer 连接、握手、PeerSession、peer RPC、OSPF route、next-hop 决策、peer/NIC packet 转发。它应该进入 `easytier-core`。问题是当前 `peers` 目录混入了大量 runtime-only 依赖，导致它不能直接作为 wasm-safe core Module 迁移。

因此第一阶段的任务是：把 `peers` 重构成 `easytier-core::peers` 深 Module，同时把 OS/runtime 能力抽到 Adapter seam 后面。

## Core Crates 职责

### `easytier-proto`

`easytier-proto` 承载 protobuf 生成类型和 RPC trait 生成物。core 和 runtime 都可以依赖它。

第一阶段需要保证 peer RPC、route、PeerSession、core config 所需 proto 类型都能通过 `core` feature 在 wasm target 下编译。

`easytier-proto` 不承载可运行的 RPC runtime。generated traits/types、controller/error/descriptor 等类型层支持留在 `easytier-proto`；会启动 task、收发 packet、做 request/response matching 的 bidirect RPC runtime 应进入 `easytier-core`。

### `easytier-core`

`easytier-core` 承载 OS-free 的核心能力：

- packet format：`ZCPacket`、packet header、`PacketType`、compressor/encryption tail 等 peers 需要的包格式。
- peer communication：`PeerManager`、`PeerMap`、`Peer`、`PeerConn`、PeerSession、peer RPC。
- packet routing：direct peer send、next-hop route、relay/foreign network control-plane 状态。
- OSPF route：route graph、sync session、next-hop/cost、foreign network route info。
- tunnel Interface：core 只依赖上移后的 `Tunnel` trait，不依赖真实 socket/tunnel implementation。

`easytier-core` 可以依赖 Tokio 的 wasm-stable 子集：

```toml
tokio = { version = "1", default-features = false, features = [
  "rt",
  "time",
  "sync",
  "macros",
  "io-util",
] }
```

### `easytier`

`easytier` crate 是 runtime Adapter 和产品入口：

- CLI/TOML/service manager。
- TUN/NIC 系统集成。
- 真实 socket/listener/dialer。
- 真实 tunnel 实现：tcp、udp、quic、kcp、wg、ring 等。
- netns、socket mark、DNS、magic DNS、UPnP、STUN 网络探测。
- runtime config 到 core config/proto config 的转换。
- event、metrics、credential persistence、平台能力的 Adapter。

迁移完成后，`easytier` 不应继续拥有一套独立的核心 `PeerMap` / `PeerManager` 状态。迁移期可以保留 re-export 或薄包装以兼容调用路径。

## 第一阶段目标

把 `easytier/src/peers/` 重构到 `easytier-core::peers`，使 core 在外部提供 `Tunnel` Adapter 后可以直接完成 peer 间通信。

第一阶段完成后应满足：

- `easytier-core` 拥有 peer 通信栈状态和任务。
- `easytier-core` 不依赖 OS socket、TUN、netns、DNS、socket mark、真实 tunnel implementation。
- `easytier-core` 不依赖 `GlobalCtx`、TOML、CLI 或 service manager。
- `easytier-core` 可以通过 `wasm32-wasip1` 编译。
- `easytier` 通过 Adapter 启动 core，而不是构造自己的 peer map 再调用 core helper。

### 当前完成状态

第一阶段的 peers 迁移已经完成。`easytier-core::peers` 现在承载 peer 通信栈的核心状态和生命周期，包括 `PeerManagerCore`、`PeerMap`、`Peer`、`PeerConn`、PeerSession、安全 datagram、peer RPC、relay peer map、foreign network manager/client、traffic metrics、credential manager、public IPv6 control-plane、OSPF route 和 ACL 处理。

但当前完成状态仍有一个未关闭的架构缺口：`PeerManagerCore` 中的 remote address 虚拟网段检查仍直接通过 `Url::socket_addrs` 触发 DNS 解析，而不是经由 runtime 注入的地址解析 Adapter。该路径需要按下文的 DNS / Address Resolution Seam 修正后，才能认为 peers 第一阶段满足“core 不依赖 DNS resolver implementation”的目标。

`easytier` 中剩余的 `peers` 文件是 runtime Adapter 或测试：

- `peer_manager.rs`：保留产品侧 `PeerManager` 包装，负责选择 runtime 配置、真实 tunnel connect/netns、管理 API DTO 转换和 node info 拼装；核心 peer graph 由 `easytier-core::peers::peer_manager::PeerManagerCore` 构造和运行。
- `foreign_network_manager.rs`：仅保留 generated direct connector RPC server 的 Host Adapter、管理 DTO 转换和集成测试；foreign context 构造、资源、状态、entry 生命周期和 packet/route 逻辑均在 core。
- `peer_rpc_service.rs`：保留真实 IP 收集、listener 展示和 UDP hole-punch packet 发送，属于 socket/OS runtime 能力。
- `rpc_service.rs`：保留管理 API、ACL/Credential API 和 API DTO 组装，属于产品入口层。
- `encrypt/`：保留 runtime feature 下的 OpenSSL/ring backend 选择；core 已有 wasm-safe encryptor surface 和纯 Rust backend。
- `tests.rs` 及各文件内测试：保留 runtime/integration 测试，core 也已有对应单测。

当前验收已覆盖：

```bash
cargo check -p easytier-proto --target wasm32-wasip1
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features
cargo test -p easytier-core
cargo check -p easytier --no-default-features
cargo check -p easytier
cargo test -p easytier --no-run
docker exec rust bash -lc 'cd /data/project/EasyTier && CARGO_TARGET_DIR=/tmp/easytier-codex-target cargo test -p easytier foreign_network -- --nocapture'
```

## 非目标

第一阶段不做：

- 不支持 browser `wasm32-unknown-unknown`。
- 不把真实 socket/tunnel/TUN 迁进 core。
- 不一次性完成所有 hole-punch/proxy runtime 迁移。
- 不为了 wasm 编译删除核心通信能力。
- 不引入一批浅 helper 替代真正的 Module 迁移。

## 当前 Peers 目录的问题

`easytier/src/peers/` 里的核心能力和 runtime-only 能力交织在一起：

- `peer_map.rs`：核心 peer registry 和 next-hop/send 能力，但依赖 `GlobalCtxEvent`、真实 `PeerConnInfo`、client URL runtime 状态。
- `peer.rs`：核心多连接管理和 credential consistency，但依赖 runtime `PeerConn` 和 `GlobalCtx` event。
- `peer_conn.rs`：核心握手、Noise、session binding、收发 loop，但依赖 `GlobalCtx` 和当前位于 `easytier` runtime crate 的 `Tunnel` 抽象及真实 tunnel filter。
- `peer_rpc.rs`：核心 peer RPC dispatch，Interface 已经接近 `send/recv ZCPacket`，适合优先迁移。
- `peer_session.rs` / `secure_datagram.rs`：核心安全会话和 packet 加解密状态，应进入 core。
- `peer_ospf_route.rs`：核心 route graph 和 sync state，但依赖 `GlobalCtxEvent`、STUN snapshot、public IPv6 runtime 状态。
- `peer_manager.rs`：核心 packet routing 主循环，但混入 connector、netns、metrics、stun、foreign runtime glue。
- `acl_filter.rs`：ACL 逻辑有 core 价值，但当前依赖 `pnet`，需要先改为基于 core packet parser。
- `credential_manager.rs`：credential 内存状态有 core 价值，文件持久化必须留在 runtime Adapter。

这些问题说明 `peers` 应整体成为 core 的深 Module，但必须先明确 Adapter seam。

## Scope 修正：保留 peers 现有模块分割

`easytier/src/peers/` 现在的目录和文件分割已经基本对应了 peer control-plane 的自然领域边界：peer RPC、PeerSession、PeerConn、PeerMap、PeerManager、OSPF route、credential、relay/foreign network 等都已经是有状态、有生命周期的 Module。后续迁移应尽量按这些现有 Module 边界整体迁入 `easytier-core::peers`，而不是继续把 OSPF 或 peers 拆成一批更小的纯逻辑 helper。

这意味着：

- `peers` 目录的现有模块边界默认是目标结构，只有遇到明确的 runtime-only 依赖或循环依赖时才调整。
- 已经临时迁出的 route table / route graph 逻辑只是过渡状态，不是继续按算法、cleanup、foreign-network、next-hop 等细粒度 helper 拆分 OSPF 的方向。
- OSPF 的最终目标是让 `PeerRouteServiceImpl`、`RouteSessionManager`、`SyncedRouteInfo`、route table、stale cleanup、foreign network route info 和 next-hop policy 回到同一个 core OSPF Module 内，保持状态和生命周期的 locality。
- 如果某个依赖阻止整体迁移，应优先判断该依赖是否本身属于 core；属于 core 的依赖应一起迁移或先迁移，而不是为了绕开依赖继续拆浅 helper。

## Core 信息类型归属

迁移 `peers` 前需要先处理 proto/model 的 feature 分层问题。当前部分核心状态信息类型放在 `proto::api::instance` 下，例如 route list、peer conn info 等。这些类型现在只在 `easytier-proto` 的 `api` feature 下导出，而 `easytier-core` 只能依赖 `core` feature。

这些信息本身不是管理 API 私有 DTO。peer、conn、route 的状态描述属于 core model，应该迁到 core feature 可见的 proto/model 中，而不是在 `easytier-core` 中再定义一套平行的 `CoreRouteInfo` / `CorePeerConnInfo`。

第一阶段应先完成：

- 将 peer/conn/route 的核心信息类型从 `api::instance` 下沉到 `core` feature 可见的位置。
- 可选位置包括新的 `core_peer.proto` / `core_route.proto`，或语义合适时放入现有 `peer_rpc.proto`。
- `easytier-core` 的 `route_trait`、`PeerMap`、`PeerConn` 只能依赖这些 core feature 可见类型。
- `proto::api::instance` 只保留管理 API 展示层扩展，或者 re-export/wrap/convert core 信息类型。
- 如果管理 API 需要 UI/runtime 专用字段，例如平台 tunnel URL、服务状态、展示用统计字段，这些字段由 `easytier` runtime Adapter 拼装，不能反向污染 core Interface。

因此迁移 `route_trait.rs` 时，`list_routes()` 这类 Interface 不应继续返回 `proto::api::instance::Route`；它应返回下沉后的 core route 信息类型。迁移 `peer_conn.rs` / `peer_map.rs` 时也同理，`PeerConnInfo` 的核心字段应来自 core proto/model，API response 只在 runtime 管理接口处组装。

## 必要 Seam 和 Adapter

### Tunnel Seam

core 需要的 Interface 本质上就是现有 `easytier::tunnel::Tunnel`：一条可收发 `ZCPacket` 的 peer connection。迁移时不应再新造一个与 `Tunnel` 平行的 `PacketTransport` 概念，而应把现有 tunnel 抽象上移到 `easytier-core`。

目标是：

```text
easytier-core
  - tunnel trait
  - ZCPacket stream/sink types
  - 最小 core tunnel error 类型

easytier
  - tcp/udp/quic/kcp/wg/ring tunnel implementations
  - socket/listener/dialer implementations
```

这样 `PeerConn` 进入 core 后仍然可以依赖 `Box<dyn Tunnel>`，只是这个 `Tunnel` trait 来自 `easytier-core`，真实 tcp/udp/quic/kcp/wg/ring tunnel 留在 `easytier` 作为 Adapter。

第一阶段只上移 core-safe 的 tunnel surface：

- `Tunnel` trait。
- `ZCPacketStream` / `ZCPacketSink` 和 split tunnel 类型。
- 最小 core tunnel error 类型，例如 `Io`、`InvalidPacket`、`ExceedMaxPacketSize`、`BufferFull`、`Timeout`、`Shutdown`、`Other(String)`。

这些内容足够支撑 core `PeerConn` 完成握手、收发、pingpong 和 packet routing。runtime tunnel implementation 负责把 tcp/udp/quic/kcp/wg/websocket/DNS 等具体错误映射成 core tunnel error。

以下内容第一阶段不进入 core：

- `TunnelConnector` / `TunnelListener`。
- URL 解析和真实 connect/listen。
- bind addr、IP version、socket mark。
- DNS/WebSocket/QUIC/KCP/WG 等 runtime-specific 错误枚举。

`TunnelInfo` 需要谨慎处理。它当前在 `proto::common` 下，可以作为 optional metadata 暂时被 core 类型引用；但 core 不应依赖 tunnel URL、协议字符串、runtime 地址等展示/平台字段做核心决策。如果后续发现 `TunnelInfo` 字段混入过多 runtime 语义，应再拆出 core-safe tunnel metadata。

当前 `easytier-core/src/transport.rs` 中的 `PacketTransport` / `TunnelIo` / `SocketFactory` 是前一轮错误重构遗留的浅 Interface。它们不应与上移后的 core `Tunnel` 并存。第一阶段应删除这套遗留 `transport.rs` 抽象，并在后续以上移后的 `easytier-core::tunnel::Tunnel` 作为唯一 peer connection seam。

### Listener/Dialer Seam

core 后续可以拥有 listen/dial 编排，但不拥有真实 bind/connect 实现。

第一阶段可以先支持“外部把已建立 `Tunnel` 注入 core”，这样能更快迁移 `PeerConn` / `PeerMap` 并完成 wasm-safe 通信测试。后续再把 listener/dialer orchestration 迁入 core，通过 `SocketFactory` / `TunnelFactory` Adapter 完成真实 I/O。

这里提到的 listener/dialer Adapter 需要在删除遗留 `transport.rs` 后重新设计，不能复用现有 `SocketFactory` 作为 core peer connection Interface。`SocketFactory` 只能作为更底层的真实 I/O Adapter 候选，不能替代 `Tunnel`。

### DNS / Address Resolution Seam

DNS implementation 属于 runtime Adapter，但 DNS-dependent decision 可以留在
`easytier-core`。也就是说，core 可以知道“这里需要把 remote URL 解析成 IP 后
检查是否落在虚拟网段内”，但 core 不能自己决定如何解析 hostname。

这个 seam 应由 `easytier-core` 定义一个小 Interface，由 `easytier` runtime
提供 Adapter implementation：

```rust
#[async_trait::async_trait]
pub trait AddressResolver: Send + Sync {
    async fn resolve_remote(
        &self,
        remote_addr: &url::Url,
        default_port: Option<u16>,
    ) -> Result<AddressResolution, Error>;
}

pub enum AddressResolution {
    IpAddrs(Vec<std::net::SocketAddr>),
    NotIpBased,
    Unavailable,
}
```

具体类型命名可以在实现时调整，但 Interface 需要表达三类结果：

- `IpAddrs`：runtime 已按当前平台策略解析出一个或多个 `SocketAddr`。
- `NotIpBased`：`ring`、`unix` 或其他非 IP tunnel，不应做虚拟网段 IP 检查。
- `Unavailable`：解析失败、resolver 被禁用、或当前 target 没有 DNS 能力；为兼容现有行为，调用方通常应跳过该检查，而不是把它当作连接失败。

runtime Adapter 负责所有会触发解析或影响解析策略的 Implementation，包括：

- `Url::socket_addrs` / `std::net::ToSocketAddrs`。
- 系统 resolver、Hickory resolver、magic DNS、SRV lookup。
- netns、socket mark、系统 DNS 开关、默认端口选择。
- listener URL、connector URL、peer URL、DNS connector 结果等来源的地址解析。

`PeerManagerCore` 保留 remote address 虚拟网段检查的 locality，但只调用注入的
`AddressResolver` Interface。这样 core 仍负责“解析出的 remote IP 不能来自本
虚拟网络”这个 peer safety rule；runtime 只负责“如何解析 remote URL”这个平台
能力。

`TunnelInfo` 的使用也要遵守这个 seam：

- `TunnelInfo.remote_addr` 可以作为 `AddressResolver` 的输入和诊断/展示字段。
- `TunnelInfo.resolved_remote_addr` 可以作为 runtime Adapter 的快速路径或缓存，
  但 core 不应把它作为唯一来源，否则会把解析策略散落到 tunnel implementation
  里。
- 如果 resolver 返回 `NotIpBased` 或 `Unavailable`，core 应跳过需要 IP 的检查；
  如果返回 `IpAddrs`，core 对每个非 loopback IP 执行虚拟网段检查。

当前具体修复方向是：`PeerManagerCore::check_remote_addr_not_from_virtual_network`
不能再直接调用 `Url::socket_addrs`。`PeerManagerCore` 构造时应接收
`Arc<dyn AddressResolver>` 或通过 `PeerContext` 暴露该 Interface；`easytier`
runtime Adapter 复用 `easytier/src/common/dns.rs::socket_addrs` 实现真实 DNS。
core 单测使用 static/no-op resolver，wasm runtime 可以注入只处理 IP literal
且对 domain 返回 `Unavailable` 的 Adapter。

验收时需要同时检查代码形态和编译结果。`cargo check -p easytier-core
--target wasm32-wasip1 --no-default-features` 只能证明 core 可编译，不能证明没有
运行期 DNS implementation。应额外确认 `easytier-core` 中没有 DNS-capable
implementation，例如：

```bash
rg 'Url::socket_addrs|ToSocketAddrs|lookup_host|lookup_ip|hickory_resolver' easytier-core/src
```

### Core Context Seam

`GlobalCtx` 不能整体进入 core，但不能因此让 core 缺少 peers 本来需要的核心上下文。正确做法是把 `GlobalCtx` 拆出一个 core-needed subset，由 runtime Adapter 持有完整 `GlobalCtx` 并向 core 提供这个子集。

这个 core context subset 包括：

- config snapshot：network name、network secret digest、secure mode、encryption algorithm、feature flags。
- key store：本地 keypair、secret proof、trusted pubkey 查询。
- event sink：peer added/removed、conn added/removed、route changed、credential changed。
- metrics sink：可选，core 不应要求 native stats manager。
- disconnect action：core 决定断开，runtime 执行真实关闭。

其中 disconnect peer 不应成为 runtime 反向驱动 core 状态的理由。core 可以输出 disconnect action 或调用 callback；runtime 只负责执行真实 tunnel/peer 关闭。

### Core 依赖归属

迁移 OSPF 和 peers 时，不应把所有当前来自 `easytier` crate 的依赖都视为 runtime-only。以下依赖更接近 core capability，应纳入 core 或以 core seam 表达：

- `PeerRpcManager`：属于 core。request/response matching、RPC dispatch、peer RPC client/server 管理应进入 `easytier-core`；runtime 只提供 transport、metrics、event Adapter。
- `credential_manager`：credential 信任状态、校验、轮转/撤销等内存状态属于 core；文件持久化、管理 API 展示和外部配置加载留在 runtime Adapter。
- public IPv6 provider/control-plane：当前看起来主要是 OS-independent state/provider，默认按 core Module 处理；如果后续发现真实 OS 探测或路由安装逻辑，再把那部分抽成 runtime Adapter。
- STUN：探测 I/O 和平台网络行为留在 runtime；core 只依赖 NAT/public endpoint snapshot trait 或 provider trait。
- `GlobalCtx`：按上一节拆 core context subset，不把完整 runtime context 传进 core。
- disconnect peer：作为 core action/callback，不作为保留 OSPF 或 PeerMap 在 runtime 的理由。

这些依赖的处理原则是：能成为 core Module 的就迁入 core；确实触碰 OS、socket、文件、service、API 的部分才留作 Adapter。

### Packet/NIC Seam

core 的 packet-routing 入口应是 `ZCPacket` stream。runtime 从 TUN/NIC 读包后交给 core，core 输出需要写回 TUN/NIC 或发往 peer 的包。

core 不直接依赖 TUN。

## 目标结构

```text
easytier-core
  peers/
    peer_manager.rs
    peer_map.rs
    peer.rs
    peer_conn.rs
    peer_conn_ping.rs
    peer_rpc.rs
    peer_session.rs
    peer_ospf_route.rs
    relay_peer_map.rs
    foreign_network_*.rs
    route_trait.rs
  packet.rs
  tunnel.rs
  config.rs

easytier
  runtime adapters:
    tunnel adapters
    socket/listener/dialer adapters
    DNS/address-resolution adapter implementation
    tun/nic adapter
    global ctx adapter
    credential persistence adapter
    metrics/event adapter
  public compatibility:
    re-export easytier_core::peers where needed
```

## 建议迁移顺序

### 0. 先稳定 core 基础类型

- 删除前一轮错误重构遗留的 `easytier-core/src/transport.rs`，移除 `PacketTransport` / `TunnelIo` / `SocketFactory` 这套与 `Tunnel` 平行的传输抽象。
- 确认 `easytier-core::packet` 覆盖 peers 需要的 packet 类型。
- 定义最小 core tunnel surface：上移 `Tunnel` trait、`ZCPacket` stream/sink 类型和最小 core tunnel error；`TunnelConnector`、`TunnelListener`、URL 解析、socket mark、DNS/WebSocket 等 runtime-specific 能力留在 `easytier`。
- 定义 DNS / Address Resolution Seam：core 定义 `AddressResolver` Interface 并保留需要解析结果的 peer safety rule；runtime Adapter 负责 DNS、SRV、系统 resolver、netns/socket mark 影响下的地址解析 implementation。
- 将 peer/conn/route 的核心信息类型从 `proto::api::instance` 下沉到 `easytier-proto` 的 `core` feature 可见位置，避免 `easytier-core` 依赖管理 API DTO。
- 确认 `easytier-proto` 的 `core` feature 覆盖 peer RPC 和 route 所需 proto。
- 将 `easytier/src/proto/rpc_impl` 中通用 bidirect RPC runtime 迁到 `easytier-core`。generated RPC traits/types 留在 `easytier-proto`。
- 迁移 bidirect RPC runtime 时，移除对 `MpscTunnel`、ring tunnel、`StatsManager` 等 runtime-only 类型的直接依赖，改为依赖 core `Tunnel` / peer RPC transport Interface，以及可选 metrics Adapter。

验收：

```bash
cargo check -p easytier-proto --target wasm32-wasip1
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features
```

### 1. 迁移 peer RPC 和 PeerSession

- 迁移 `peer_rpc.rs`，让它只依赖 core packet、core `Tunnel` 抽象，或 `PeerRpcManagerTransport` 这类 RPC 层内部 Interface、`easytier-proto`。
- 迁移 `peer_session.rs`、`secure_datagram.rs`。
- 保留 `easytier::peers::peer_rpc::*` 的 re-export。

验收：

```bash
cargo test -p easytier-core
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features
```

### 2. 迁移 PeerConn

- `PeerConn` 进入 core，持有 `Box<dyn easytier_core::tunnel::Tunnel>` 或等价 core tunnel handle。
- Noise handshake、secure mode、session binding、recv/send loop 进入 core。
- `GlobalCtx` 调用替换为 Core Context seam。
- 真实 tcp/udp/quic/kcp/wg/ring tunnel implementation 留在 runtime Adapter。若 `MpscTunnel`、`TunnelFilterChain` 只是 core tunnel 抽象的通用组合工具，可随 tunnel trait 一起迁入 core；若依赖 runtime 细节，则留在 `easytier`。

验收：core 单测使用 in-memory `Tunnel` 建立两端 `PeerConn`，完成握手并收发 `ZCPacket`。

### 3. 迁移 Peer 和 PeerMap

- `Peer` 进入 core，统一维护 conn set、default conn、peer identity/public key、add/remove 生命周期。
- `PeerMap` 进入 core，统一维护 direct peer registry、route fallback、direct send。
- `easytier` 不再构造自己的核心 `PeerMap`。

验收：core 单测构造两个 core peer manager，通过 in-memory `Tunnel` 发送一个 packet。

### 4. 迁移 PeerManager packet-routing 主循环

- 迁移 NIC packet pipeline、peer packet pipeline、fanout、route decision、relay decision。
- connector、TUN、netns、runtime metrics 仍由 Adapter 提供。

验收：core 单测构造三节点拓扑并验证 packet forwarding。

### 5. 迁移 OSPF route

- 在 core `PeerMap` / `PeerRpcManager`、core context subset、credential manager、public IPv6 provider、STUN snapshot trait 稳定后，整体迁移 OSPF。
- 不继续把 OSPF 拆成 route graph、sync session、stale cleanup、foreign network route info 等零散 helper。迁移目标是一个有状态的 core OSPF Module，保留现有 `peer_ospf_route.rs` 的领域边界和生命周期关系。
- `GlobalCtxEvent` 替换成 core event 或 event sink；disconnect peer 替换成 core action/callback。
- STUN/public IPv6 信息通过 core provider/snapshot trait 注入；OS 探测或平台 I/O 由 runtime Adapter 提供。

验收：core 单测覆盖 route convergence、stale cleanup、foreign network merge、next-hop policy。

## 第二阶段：UDP/TCP Proxy Core 化

peers 第一阶段完成后，下一阶段只迁移 UDP proxy 和 TCP proxy。目标是把
proxy 的 packet classification、NAT 状态、CIDR 映射、fragment/rewrite/checksum、
TCP stack seam、TCP proxy 使用的 smoltcp stack adapter，以及与
`PeerManagerCore` 的 packet pipeline 对接一起放进 `easytier-core`。`easytier`
继续作为 runtime Adapter 提供真实 socket、TUN/netns、配置、stats 和管理 DTO。

这一阶段的核心判断是：UDP/TCP proxy 不是纯 runtime 能力。它们决定哪些 peer
packet 被代理、如何建立 NAT entry、如何改写 IP/TCP/UDP header、如何标记
`no_proxy`、如何把 response packet 送回 peer。这些规则与 peer packet routing
紧密相关，应成为 core 的深 Module，换取 locality 和更好的 core 单测。

### 第二阶段 Scope

只迁移以下 Module 的核心 Implementation：

- `easytier/src/gateway/mod.rs::CidrSet`
- `easytier/src/gateway/ip_reassembler.rs`
- `easytier/src/gateway/udp_proxy.rs`
- `easytier/src/gateway/tcp_proxy.rs`
- TCP proxy 内部直接使用的 smoltcp stack adapter
- TCP/UDP proxy 与 `PeerManagerCore` packet pipeline 的对接
- `easytier/src/peers/peer_manager.rs` 中 runtime `PeerManager` wrapper 的最小
  ownership 调整，用于向 core proxy service 提供 `Arc<PeerManagerCore>`

不迁移以下内容：

- KCP proxy 本体。
- QUIC proxy 本体。
- `wrapped_proxy.rs` 中 KCP/QUIC wrapped source 逻辑；该逻辑在下一阶段单独迁移。
- socks5 / fast_socks5。
- smoltcp 在 socks5 或其他 runtime 场景中的使用。
- 真实 `UdpSocket`、`TcpListener`、`TcpStream`、raw socket、TUN、netns。
- proxy RPC、管理 DTO、CLI 展示。

迁移 `TcpProxy` 的内部 Interface 时，KCP/QUIC 必须通过 runtime 兼容 wrapper
维持现有行为和领域结构。本阶段不借 TCP proxy core 化顺手重构 KCP/QUIC。
如果现有 KCP/QUIC 调用路径依赖 `TcpProxy` 自身实现 packet filter，允许做最小
调用点调整，把注册目标切到 `TcpProxy` facade 暴露的 core service handle；不允许
借此改 KCP/QUIC 的 proxy 语义或内部领域结构。

KCP/QUIC 兼容 wrapper 的保留边界必须明确：

- `TcpProxyMode::KcpSrc` / `TcpProxyMode::QuicSrc` 继续作为 TCP proxy core 的 mode
  输入，不能被合并成普通 TCP 模式。
- KCP/QUIC 的 transport type、stats label 和 wrapped-src NIC filter 行为仍由
  runtime wrapper 维护。
- `TcpProxy` facade 可以继续暴露 `get_transport_type()`、`is_tcp_proxy_connection()`
  和 `list_proxy_entries()` 这类兼容 API。`get_transport_type()` 可以读取 runtime
  connector 的 immutable metadata；entry/list/connection 判断只能读 core
  service/engine snapshot，不能重新拥有 packet filter 或 NAT state。
- KCP/QUIC 需要注册 packet pipeline 时，只能注册 core service handle，不能注册
  runtime `TcpProxy` facade。

### 目标结构

```text
easytier-core
  proxy/
    mod.rs
    cidr_table.rs
    ip_reassembler.rs
    udp_proxy_engine.rs
    udp_proxy_service.rs
    tcp_proxy_engine.rs
    tcp_proxy_service.rs
    tcp_stack.rs
    smoltcp_stack.rs   # only with feature = "proxy-smoltcp-stack"

easytier
  gateway/
    mod.rs             # runtime re-export / adapter glue
    udp_proxy.rs       # runtime socket adapter
    tcp_proxy.rs       # runtime facade + kernel socket adapter, no smoltcp import
    wrapped_proxy.rs   # unchanged in this phase; removed in wrapped proxy phase
    kcp_proxy.rs       # unchanged in this phase
    quic_proxy.rs      # unchanged in this phase
    socks5*.rs         # unchanged in this phase
```

`easytier-core::proxy` 应是 stateful dataplane Module，而不是一组浅 helper。
runtime `gateway` 保留现有启动路径和产品入口，内部委托给 core Module。

### PeerManagerCore 边界

第二阶段的最优边界是让 TCP/UDP proxy 成为 `easytier-core` 内的 core service，
直接接入 `easytier-core::peers::peer_manager::PeerManagerCore`。`easytier`
中的 `PeerManager` 只是 runtime wrapper，负责组合 `GlobalCtx`、netns、
foreign network manager 和产品侧管理能力；TCP/UDP proxy core 不依赖这个 wrapper。

core proxy service 负责：

- 持有 `Arc<PeerManagerCore>`。
- 注册 `PeerPacketFilter` 和 `NicPacketFilter`。
- 调用 `PeerManagerCore::get_nic_channel` 把 packet 送回本地 NIC path。
- 调用 `PeerManagerCore::send_msg_by_ip` 把 stack egress packet 送回 peer network。
- 调用 `PeerManagerCore::send_msg_for_proxy` 把已知目标 peer 的 proxy response
  发回 peer network。
- 在 core 内维护 packet pipeline、NAT entry、stack ingress/egress 和 cleanup。
- 持有 packet pipeline registration guard，并在 service stop/drop 时注销。

runtime Adapter 负责：

- 从 runtime `PeerManager` 取出 `Arc<PeerManagerCore>` 并交给 core proxy service。
- 提供真实 socket/listener/stream、netns guard、deny proxy、stats 和管理 DTO。
- 不直接注册 TCP/UDP proxy packet filter 的核心逻辑。
- 不直接调用 TCP proxy 使用的 smoltcp stack，也不暴露 `smoltcp::*` 类型。

这样 TCP proxy 的 smoltcp stack 不泄漏到 runtime `gateway/tcp_proxy.rs`，
`PeerManagerCore` 也不会被绕开。后续如果 runtime `PeerManager` wrapper 继续
变薄，TCP/UDP proxy 不需要再调整架构边界。

`PeerManagerCore` 的 packet pipeline 注册必须有显式 lifecycle：

```rust
pub struct PipelineRegistrationId(uuid::Uuid);

pub struct PipelineRegistrationGuard {
    id: PipelineRegistrationId,
    kind: PipelineKind,
    registry: std::sync::Weak<PipelineRegistry>,
}

impl PipelineRegistrationGuard {
    pub fn close(&self);
}

impl PeerManagerCore {
    async fn add_packet_process_pipeline(
        &self,
        pipeline: BoxPeerPacketFilter,
    ) -> PipelineRegistrationGuard;

    async fn add_nic_packet_process_pipeline(
        &self,
        pipeline: BoxNicPacketFilter,
    ) -> PipelineRegistrationGuard;
}
```

`PipelineRegistrationGuard::close()` 和 `Drop` 必须是同步、不可阻塞、无需
`.await` 的 unregister 路径。pipeline registry 必须保留当前有序执行语义，新注册
的 filter 仍按现有行为优先执行；实现可以用 ordered list 加同步 remove，或用
ordered list + active flag 标记失效再由后台任务 prune。不能用 unordered
`DashMap` iteration 作为执行顺序来源。packet pipeline 执行时必须立即跳过
inactive registration，不能依赖异步清理完成后才停止调用。

core proxy service `start()` 注册 pipeline 并保存 guard；`stop()` 显式调用
`close()`；`Drop` 作为兜底也必须关闭 guard。`start()` 必须是幂等的，不能重复
注册同一个 service。注册到 pipeline 的 filter 不能强持有 core proxy service；
必须使用只持有 `Weak<TcpProxyService>` / `Weak<UdpProxyService>` 的轻量 filter
handle，或者由外部 owner 同时持有 service 和 guard，避免形成
`PeerManagerCore -> pipeline -> service -> PeerManagerCore` 的强引用环。
Weak handle upgrade 失败时必须 pass/drop 并触发 registration cleanup。
runtime `TcpProxy`/`UdpProxy` facade 不实现 packet filter trait，也不把自身注册进
pipeline；KCP/QUIC 兼容路径只能通过 facade 间接启动或获取 core service handle。

迁移 proxy service 前必须先调整 runtime `PeerManager` wrapper 的 ownership：

- `easytier/src/peers/peer_manager.rs::PeerManager` 持有
  `Arc<PeerManagerCore>`，而不是按值持有 `PeerManagerCore`。
- runtime `PeerManager` 暴露 `core(&self) -> Arc<PeerManagerCore>` 这类只读
  accessor，供 core proxy service 构造使用。
- 现有 `PeerManager` 方法继续作为 runtime wrapper API，内部委托给
  `PeerManagerCore`，避免调用点直接拿 runtime wrapper 做 proxy core 逻辑。

### Runtime Adapter Seams

core proxy service 可以编排 packet pipeline，但不能持有真实 socket，也不能直接
调用 `GlobalCtx::should_deny_proxy`。这些 runtime 能力必须通过 core 定义的
Adapter trait 注入，由 `easytier` 实现。

共享 runtime snapshot seam：

```rust
pub struct ProxyRuntimeSnapshot {
    pub local_inet: Option<cidr::Ipv4Inet>,
    pub virtual_ipv4: Option<std::net::Ipv4Addr>,
    pub no_tun: bool,
    pub enable_exit_node: bool,
    pub smoltcp_enabled: bool,
    pub latency_first: bool,
}

pub trait ProxyRuntimeInfo: Send + Sync {
    fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot;
    fn is_ip_local_virtual_ip(&self, ip: &std::net::IpAddr) -> bool;
}
```

core 只读取这个 snapshot 和 `is_ip_local_virtual_ip`，不直接访问 `GlobalCtx`。
`local_inet`、`virtual_ipv4`、`no_tun`、`enable_exit_node`、`smoltcp_enabled`
和 `latency_first` 这些会影响 proxy dataplane 的状态必须统一通过该 seam
注入，避免把 config 查询散落在 runtime gateway 中。core proxy service 在调用
`PeerManagerCore::send_msg_for_proxy` 前必须按 `latency_first` 设置 packet
header，保持当前 UDP proxy response 的路由语义。core proxy service 不得只在
启动时读取一次 runtime snapshot；必须在 packet handling 时读取最新 snapshot，
或由 core service 维护明确的 refresh loop。

UDP 侧 seam：

```rust
#[async_trait::async_trait]
pub trait UdpProxyResponseSink: Send + Sync {
    async fn handle_socket_response(
        &self,
        entry_id: UdpNatEntryId,
        src: std::net::SocketAddr,
        payload: bytes::Bytes,
    );
}

#[async_trait::async_trait]
pub trait UdpProxyRuntime: ProxyRuntimeInfo {
    fn should_deny_udp_proxy(&self, dst: std::net::SocketAddr) -> bool;
    fn udp_response_ipv4_mtu(&self) -> usize;

    async fn send_udp_to_socket(
        &self,
        entry_id: UdpNatEntryId,
        dst: std::net::SocketAddr,
        payload: bytes::Bytes,
        response_sink: std::sync::Weak<dyn UdpProxyResponseSink>,
    ) -> Result<(), UdpProxyRuntimeError>;

    fn close_udp_socket(&self, entry_id: UdpNatEntryId);
}
```

runtime `UdpSocket` receive task 只负责把 socket response 回调给
`UdpProxyResponseSink::handle_socket_response(entry_id, src, payload)`。runtime 只能
持有 weak response sink，每次收到 response 时临时 upgrade；upgrade 失败、
`close_udp_socket(entry_id)` 被调用、socket 出错或 service stop 时，receive task
必须退出并释放 socket。这样避免形成
`UdpProxyService -> runtime -> receive task -> UdpProxyService` 的强引用环。该
方法进入 core 后组装 response packet，并通过
`PeerManagerCore::send_msg_for_proxy` 执行 peer egress。

`UdpProxyService` 是 NAT entry 生命周期的 owner。entry expired、entry remove 或
service stop/drop 时，core 必须同步调用
`UdpProxyRuntime::close_udp_socket(entry_id)`。该方法必须是同步、非阻塞、可在
`Drop` 中调用的 cancellation/close seam，并且必须关闭 fd 或触发 cancellation
handle，让阻塞中的 receive task 尽快醒来并退出。runtime 不维护独立 NAT cleanup
策略。

UDP response packetization 也归 core。runtime 只通过 `udp_response_ipv4_mtu()`
提供当前 IPv4 link MTU，即包含 IPv4 header 的最大 IPv4 packet length；
`UdpProxyEngine` 负责扣除 IPv4/UDP header，计算 UDP payload chunk。除最后一个
fragment 外，每个 IPv4 fragment payload 长度必须按 8-byte boundary 向下取整。
`UdpProxyEngine` 持有 IPv4 ID allocator，负责把大 UDP response 按 MTU 切成 IPv4
fragments、重算 IPv4/UDP checksum。每个 response datagram 只分配一个 IPv4 ID，
并把同一个 ID 写入该 datagram 的所有 fragments；allocator 在 datagram 之间递增。
runtime socket receive task 不能自己决定是否分片或生成 IPv4 ID。

TCP 侧 seam：

```rust
#[async_trait::async_trait]
pub trait TcpProxyRuntime: ProxyRuntimeInfo {
    fn should_deny_tcp_proxy(&self, dst: std::net::SocketAddr) -> bool;

    async fn bind_kernel_listener(
        &self,
    ) -> Result<Box<dyn TcpProxyKernelListener>, TcpProxyRuntimeError>;

    async fn connect_dst(
        &self,
        ctx: TcpProxyConnectContext,
    ) -> Result<Box<dyn TcpProxyDstStream>, TcpProxyRuntimeError>;

    async fn copy_bidirectional_no_shutdown(
        &self,
        entry_id: TcpNatEntryId,
        src: &mut dyn TcpProxySrcStream,
        dst: &mut dyn TcpProxyDstStream,
    ) -> Result<(), TcpProxyRuntimeError>;
}

pub trait TcpProxyStream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
{
}

pub trait TcpProxySrcStream: TcpProxyStream {}
pub trait TcpProxyDstStream: TcpProxyStream {}

pub struct TcpProxyConnectContext {
    pub entry_id: TcpNatEntryId,
    pub src: std::net::SocketAddr,
    pub real_dst: std::net::SocketAddr,
    pub mapped_dst: std::net::SocketAddr,
    pub transport_type: TcpProxyEntryTransportType,
}

#[async_trait::async_trait]
pub trait TcpProxyKernelListener: Send + Sync {
    fn local_port(&self) -> u16;
    fn close(&self);

    async fn accept(
        &self,
    ) -> Result<(std::net::SocketAddr, Box<dyn TcpProxySrcStream>), TcpProxyRuntimeError>;
}
```

runtime `KernelTcpStack` 只实现真实 bind/accept/connect/copy/shutdown 和 netns
guard。accepted source stream 只能通过
`TcpProxyService::handle_kernel_accept(src_addr, src_stream)` 进入 core service；core
根据 `src_addr` 查找 NAT entry，调用 `connect_dst(TcpProxyConnectContext)`
建立目标连接，再调用
`copy_bidirectional_no_shutdown` 执行流复制。copy 完成或失败后，runtime 只返回结果；
`ConnectingDst`、`Connected`、`ClosingSrc`、`ClosingDst`、`Closed`、FIN grace 和
remove 仍由 core service 更新。core 先把 entry 置为 `ClosingSrc` 并调用
`AsyncWriteExt::shutdown(&mut src)`，再置为 `ClosingDst` 并调用
`AsyncWriteExt::shutdown(&mut dst)`，最后进入 FIN grace 和 remove 流程。
`copy_bidirectional_no_shutdown` 必须是 no-shutdown copy primitive；
runtime 不允许使用会隐式 half-shutdown/full-shutdown stream 的 helper，也不允许把
copy、两个方向 shutdown 和 entry remove 包成一个 opaque 操作。core
`SmolTcpStack` 不使用这个 kernel socket seam。

`TcpProxyConnectContext` 中的 `real_dst`、`mapped_dst` 和 `transport_type` 由 core
service 从 NAT entry 和 runtime connector mode 组装后传给 runtime。runtime 仍然
负责记录 connect stats，但不得为了 stats 重新读取或维护 NAT state。

TCP service stop lifecycle 由 core service 管理。`stop()` 必须先注销 pipeline
guard，再调用 `TcpProxyKernelListener::close()` 让阻塞中的 `accept()` 尽快返回，
随后 abort core 持有的 accept/connect/copy task set。runtime 的 listener、
connect 和 copy future 必须是 cancel-safe：被 abort/drop 后释放 fd、stream 和
netns guard。in-flight entry 被取消时，由 core service 统一设置 `Closed` 并移除
NAT entry。

kernel stack 启动顺序必须保持现有语义：`TcpProxyService` 先调用
`bind_kernel_listener()`，读取 `TcpProxyKernelListener::local_port()`，写入
`TcpProxyEngine::set_local_port(local_port)`，然后才能注册 peer/NIC pipeline 或处理
任何 peer SYN packet。smoltcp 模式也同理，core `SmolTcpStack` 初始化完成并确定
fake local port 后，必须先写入 `TcpProxyEngine` 再开放 packet pipeline。

### Proxy CIDR Seam

当前 `CidrSet` 同时持有 `GlobalCtx`、轮询 config、维护 mapped CIDR，并提供
lookup。这是一个浅 seam：核心 lookup 逻辑和 runtime config polling 混在一起。

第二阶段先把它拆成：

- runtime `ProxyCidrSnapshotProvider`：只从 `GlobalCtx.config.get_proxy_cidrs()`
  读取完整 proxy CIDR snapshot。
- core `ProxyCidrTable`：从 snapshot 构建 lookup table，并独占 mapped-to-real
  lookup 和地址转换规则。

迁移后的 runtime Adapter 不再拥有 lookup 和 mapped CIDR 转换实现。它只提供完整
snapshot：

```rust
pub trait ProxyCidrSnapshotProvider: Send + Sync {
    fn proxy_cidr_snapshot(&self) -> ProxyCidrSnapshot;
}

pub struct ProxyCidrSnapshot {
    pub rules: Vec<ProxyCidrRule>,
}

pub struct ProxyCidrRule {
    pub cidr: cidr::Ipv4Cidr,
    pub mapped_cidr: Option<cidr::Ipv4Cidr>,
}
```

`ProxyCidrTable` 是 core-owned Implementation，可以缓存 snapshot 生成的表，也
可以在 snapshot 更新时整体替换。lookup 结果类型如果需要存在，应是 core
内部类型，而不是 runtime seam 的一部分。这样 runtime Interface 很薄，core
保留 CIDR lookup、mapped CIDR 转换和测试的 locality。

为了保持本阶段排除的 KCP/QUIC/socks5 不被迫重构，`easytier/src/gateway/mod.rs`
中的 `CidrSet` 可以暂时保留为兼容 facade：它负责 polling runtime config 并实现
`ProxyCidrSnapshotProvider`，同时把旧的 lookup API 委托给内部 `ProxyCidrTable`。
这个 facade 不能复制 mapped CIDR 算法，也不能维护第二套 lookup table；它只是给
未迁移模块保留旧调用路径。等 KCP/QUIC/socks5 后续迁移时，再删除这些兼容 lookup
API。

第二阶段的 CIDR refresh lifecycle 由 `CidrSet` 兼容 facade 单独持有。core
proxy service 直接共享该 facade 内部的 `Arc<ProxyCidrTable>`，不再启动第二个
CIDR refresh task。这样本阶段只有一张 refreshed table：已迁移的 UDP/TCP proxy
和未迁移的 KCP/QUIC/socks5 旧 lookup API 都读同一个 `ProxyCidrTable`。等
KCP/QUIC/socks5 后续迁移完成后，再把 refresh lifecycle 从 runtime `CidrSet`
facade 收敛到 core proxy service，并删除 runtime 兼容 lookup API。

### IP Packet Seam

`ip_reassembler.rs` 和 IPv4 compose/rewrite 属于 core packet dataplane。迁移时应
保持以下原则：

- `IpReassembler`、fragment expiration、IPv4 compose 进入 core。
- UDP/TCP checksum 和 IPv4 checksum rewrite 进入 core。
- core 不引入 `pnet` 作为长期依赖，也不自研一套裸字节 packet parser。
- IPv4/TCP/UDP header parse、field rewrite、checksum 和 packet emit 基于
  `smoltcp::wire`，例如 `Ipv4Packet`、`Ipv4Repr`、`TcpPacket`、`UdpPacket`、
  `IpProtocol` 和 `IpAddress`。
- 只需要 header parse/rewrite 的代码走 core `proxy-packet` feature，不启用完整
  smoltcp TCP stack。
- 真实 TUN/NIC 读写仍留在 runtime Adapter。

建议 feature 拆分：

```toml
proxy-packet = [
  "dep:smoltcp",
  "smoltcp/std",
  "smoltcp/proto-ipv4",
  "smoltcp/proto-ipv4-fragmentation",
]

proxy-smoltcp-stack = [
  "proxy-packet",
  "smoltcp/medium-ip",
  "smoltcp/socket-tcp",
  "smoltcp/socket-udp",
  "smoltcp/async",
]
```

`proxy-packet` 是 UDP/TCP proxy core 的 packet 操作依赖；`proxy-smoltcp-stack`
才启用完整 smoltcp TCP stack。feature 名称实现时可以调整，但这两个能力不能
混成一个 seam，否则 UDP proxy 和普通 TCP rewrite 会被迫依赖完整 TCP stack。

smoltcp 的 IPv4 reassembly 主要在 `iface` 内部，相关 assembler 不适合作为
公开 seam。`IpReassembler` 可以继续作为 core Module 存在，但它应基于
`smoltcp::wire::Ipv4Packet` 读取 fragment id/offset/flags，并避免自己实现
IPv4 header parser/checksum。

### UDP Proxy Module

UDP proxy 应优先迁移，因为它比 TCP proxy 更少依赖 stream stack。目标是把
`UdpNatKey`、`UdpNatEntry`、NAT table、packet classification、fragment
reassembly、UDP response compose 和 entry cleanup 收敛到 core。

core `UdpProxyEngine` 的 Interface 应围绕 packet 和 runtime action，而不是直接
操作 socket：

```rust
pub enum UdpProxyAction {
    ForwardToSocket {
        entry_id: UdpNatEntryId,
        dst: std::net::SocketAddr,
        payload: bytes::Bytes,
    },
    SendToPeer {
        dst_peer: PeerId,
        packet: ZCPacket,
    },
    Drop,
    Pass(ZCPacket),
}
```

core `UdpProxyService` 持有 `UdpProxyEngine` 和 `PeerManagerCore`，注册
`PeerPacketFilter`，把 core action 分发给 peer egress 和 runtime socket
adapter。`UdpProxyEngine` 保持纯 packet/state，不直接依赖 `PeerManagerCore`。

runtime Adapter 负责：

- 创建和持有真实 `UdpSocket`。
- 在正确 netns 下 `send_to` / `recv_from`。
- 调用 runtime `should_deny_proxy`。
- 只通过 weak `UdpProxyResponseSink` 把 socket response 交回 core service。
- 响应 `close_udp_socket(entry_id)`，关闭 socket 和 receive task。
- 启动/停止 task，处理 socket I/O 错误。
- 提供当前 UDP response IPv4 link MTU，不参与 response packetization。

core 负责：

- 注册 peer packet pipeline。
- 判断 packet 是否是可代理 UDP IPv4 packet。
- 处理 proxy CIDR、exit node、no-tun local virtual IP 规则。
- 创建/维护 NAT entry 状态。
- 处理 denied entry 的 drop/pass 行为。
- 处理 UDP fragment reassembly。
- 把 socket response 组装为 `ZCPacket`，设置 `PacketType::Data` 和 `no_proxy`。
- 对大 UDP response 做 IPv4 fragmentation，并由 core IPv4 ID allocator 为每个
  datagram 分配一个所有 fragments 共用的 ID。
- 按 `ProxyRuntimeSnapshot::latency_first` 设置 proxy response header。
- 通过 `PeerManagerCore::send_msg_for_proxy` 执行已知目标 peer 的 proxy response
  egress。
- entry expired/remove/stop 时关闭 runtime UDP socket。
- entry active/expired 状态。

`UdpProxyEngine` 单测应直接喂 `ZCPacket` 和 fake socket response，不需要真实 UDP
socket。

### TCP Proxy Module

TCP proxy 不能简单按“core packet rewrite + runtime smoltcp”拆分。当前
`TcpProxy` 与 smoltcp 耦合很深：

- `TcpProxy` 持有 smoltcp stack channel、`Net`、listener tx 和 enabled state。
- smoltcp 模式下 peer packet 进入 stack，而不是写回 NIC。
- smoltcp stack 输出的 IP packet 再通过 peer send Adapter 发回 peer。
- `wrapped_proxy.rs` 会根据 `is_smoltcp_enabled()` 决定 net-to-net wrapped TCP
  是否允许；该判断应在下一阶段迁入 wrapped TCP proxy core 规则中。

因此 TCP proxy 迁移时应把 TCP proxy 使用的 smoltcp dataplane 一起纳入
`easytier-core`，但必须作为 optional feature。

目标拆分：

- core `TcpProxyEngine`：维护 SYN map、conn map、addr conn map、NAT entry state、
  peer packet classification、NIC response rewrite、checksum、mapped dst、local
  fake IP 规则、entry listing 的 core model。
- core `TcpProxyService`：持有 `TcpProxyEngine`、`TcpStack` 和 `PeerManagerCore`，
  注册 peer/NIC packet pipeline，执行 core action，并统一调度 stack
  ingress/egress。
- core `TcpStack` Interface：抽象“把 rewritten packet 交给 TCP stack”和“从
  TCP stack 输出 IP packet”。
- core `SmolTcpStack` Adapter：在 `#[cfg(feature = "proxy-smoltcp-stack")]` 下实现
  `TcpStack`，承载当前 `ChannelDevice`、`Net`、smoltcp listener、stack pump 和
  stack egress 相关逻辑。
- runtime `KernelTcpStack` Adapter：保留真实 `TcpListener/TcpStream`、socket
  keepalive、netns bind/connect/no-shutdown-copy 和 stream AsyncRead/AsyncWrite。
- runtime `TcpProxy` facade：保留当前外部调用路径，内部委托 core
  `TcpProxyService` 和 runtime `KernelTcpStack` Adapter。

`TcpProxyEngine` 保持纯 packet/state，不直接依赖 `PeerManagerCore`。依赖
`PeerManagerCore` 的层级是 core `TcpProxyService`，不是 runtime facade。
`TcpProxyEngine` 通过 action 描述需要执行的动作：

```rust
pub enum TcpProxyAction {
    SendToNic(ZCPacket),
    SendToPeerByIp {
        dst: std::net::IpAddr,
        packet: ZCPacket,
        not_send_to_self: bool,
    },
    ConnectDst {
        entry_id: TcpNatEntryId,
        src: std::net::SocketAddr,
        real_dst: std::net::SocketAddr,
        mapped_dst: std::net::SocketAddr,
        transport_type: TcpProxyEntryTransportType,
    },
    Drop,
    Pass(ZCPacket),
}
```

runtime Adapter 负责：

- 根据 config 选择 runtime kernel stack；smoltcp 模式固定使用 core `SmolTcpStack`。
- 在 netns 中 bind/listen/connect。
- 执行 no-shutdown stream copy，并通过 `TcpProxyStream` 的 `AsyncRead/AsyncWrite`
  能力暴露单方向 shutdown。
- 查询 `should_deny_proxy`。
- 记录 stats 和组装管理 DTO。
- 把 runtime `PeerManager` wrapper 中的 `PeerManagerCore` 交给 core
  `TcpProxyService`。

core 负责：

- 注册 peer/NIC packet pipeline。
- SYN packet 建立 NAT entry。
- 非 SYN packet 只允许已存在 entry。
- peer packet rewrite 到 local TCP stack。
- NIC/stack response rewrite 回 mapped dst。
- 处理 runtime kernel listener accept 返回的 source stream，并把 stream lifecycle
  映射到 NAT entry state。
- smoltcp stack ingress/egress 和 listener adapter。
- 通过 `PeerManagerCore::send_msg_by_ip` / NIC channel 执行 peer/NIC packet egress。
- `no_proxy` 标记和 packet type restore。
- fake local IPv4 规则。
- entry state 和 cleanup。

### smoltcp Feature 约束

`easytier-core` 中所有 smoltcp 相关能力必须是 optional feature，不进入 default
feature。引入这些 feature 后需要满足：

- `proxy-packet` 只启用 `smoltcp::wire` 所需的最小协议 feature。
- `proxy-smoltcp-stack` 才启用 `medium-ip`、`socket-tcp`、`socket-udp` 和 `async`。
- `TcpProxyEngine` 的普通 NAT/packet rewrite 不依赖完整 smoltcp TCP stack。
- `SmolTcpStack` 只在 `#[cfg(feature = "proxy-smoltcp-stack")]` 下编译。
- smoltcp 只能通过 core `TcpStack` Interface 与 `TcpProxyEngine` 交互。
- `easytier/src/gateway/tcp_proxy.rs` 不允许直接 import `smoltcp`。
- core 对外 public API 不暴露 `smoltcp::*` 类型。
- smoltcp 迁入 core 后，`wasm32-wasip1` 必须在开启 packet feature 和 stack
  feature 时都能编译。

涉及 UDP/TCP packet rewrite 的 commit 必须额外跑：

```bash
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features --features proxy-packet
```

涉及完整 smoltcp stack 的 commit 必须额外跑：

```bash
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features --features proxy-smoltcp-stack
```

如果 stack feature 不能通过，说明 `SmolTcpStack` Adapter 的 feature 形态或
runtime 依赖边界仍然错误。必须继续收窄 feature、拆出 runtime I/O Adapter、
调整 task driver，直到 `proxy-smoltcp-stack` 在 core 内通过 wasm 编译。不能把
TCP proxy 使用的 smoltcp stack 继续留在 runtime 作为最终状态。

### 第二阶段迁移顺序

1. 迁移 `ProxyCidrTable`
   - core 新增 table 和 mapped CIDR 单测。
   - runtime `CidrSet` 退化为 snapshot provider + 兼容 lookup facade，旧 lookup
     API 必须委托给 core `ProxyCidrTable`。

2. 迁移 IP packet reassembly/compose
   - core 新增 fragment reassembly 和 IPv4 compose 单测。
   - 用 `smoltcp::wire` 替换 core 迁移路径中的 `pnet` 依赖。

3. 调整 `PeerManager` runtime wrapper
   - runtime `PeerManager` 改为持有 `Arc<PeerManagerCore>`。
   - runtime `PeerManager` 暴露 core accessor，供 core proxy service 构造使用。
   - 现有 runtime API 继续委托给 `PeerManagerCore`，避免引入第二套 peer 状态。

4. 建立 proxy runtime adapter seam
   - core 新增 `UdpProxyRuntime` 和 `TcpProxyRuntime` trait。
   - runtime 实现 socket send/connect、netns guard 和 deny-proxy policy。
   - core 新增 packet pipeline registration guard，保证 start/stop 不泄漏 filter。
   - core proxy service 只依赖这些 trait，不依赖 `GlobalCtx` 或真实 socket 类型。

5. 迁移 UDP proxy core
   - core 新增 `UdpProxyEngine`、`UdpProxyService`、NAT table、runtime socket action。
   - core `UdpProxyService` 直接接入 `PeerManagerCore` 并注册 peer pipeline。
   - runtime `UdpProxy` 保留 socket task 和 socket Adapter。
   - 单测覆盖 proxy CIDR、mapped CIDR、fragment、denied entry、response compose。

6. 迁移 TCP proxy core 和 stack seam
   - core 新增 `TcpProxyEngine`、`TcpProxyService` 和 `TcpStack` Interface。
   - core `TcpProxyService` 直接接入 `PeerManagerCore` 并注册 peer/NIC pipeline。
   - runtime 保留 kernel socket Adapter。
   - smoltcp stack adapter 作为 core optional `proxy-smoltcp-stack` feature 迁入。
   - kernel/smoltcp local port 必须在 pipeline 注册前写入 `TcpProxyEngine`。
   - runtime `TcpProxy` facade 尽量保持现有外部 Interface，避免触碰 KCP/QUIC/socks5。

7. 清理 runtime gateway 兼容层
   - 删除已迁移的重复 NAT/packet rewrite 状态。
   - 删除 `gateway/tcp_proxy.rs` 中的 smoltcp channel、listener、device 和 stack pump。
   - 保留管理 DTO、runtime task、socket/netns Adapter。
   - `wrapped_proxy.rs`、`kcp_proxy.rs`、`quic_proxy.rs`、`socks5*.rs` 不纳入本阶段重构。

### 第二阶段验收

每一步至少需要：

```bash
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features
cargo test -p easytier-core
cargo check -p easytier --no-default-features
```

涉及 smoltcp 时额外需要：

```bash
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features --features proxy-packet
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features --features proxy-smoltcp-stack
```

涉及 runtime gateway 行为时，需要补充 runtime 测试或最小集成验证，至少覆盖：

- UDP proxy request/response。
- TCP proxy SYN/response rewrite。
- mapped CIDR。
- no-tun local virtual IP。
- smoltcp enabled 和 disabled 两条路径。
- UDP proxy response 保留 `latency_first` header 语义。
- UDP socket receive task 只持有 weak response sink，service stop/drop 后会退出。
- UDP proxy 大 response 按 runtime IPv4 link MTU 分片，同一 datagram 的所有
  fragments 使用同一个 core-allocated IPv4 ID，非末尾 fragment payload 按
  8-byte boundary 对齐。
- UDP NAT entry expired/remove/stop 会调用同步 runtime socket close seam。
- runtime `CidrSet` 兼容 lookup API 委托给 core `ProxyCidrTable`，KCP/QUIC/socks5
  不需要在本阶段重构 CIDR 调用路径。
- TCP kernel accept/connect/copy completion 只通过 core service 更新 NAT entry state。
- TCP runtime copy seam 不执行隐式 shutdown，`ClosingSrc`/`ClosingDst` 状态变化前
  不会关闭对应方向。
- TCP connect stats 保留 transport type、real dst 和 mapped dst labels。
- TCP service stop 会关闭 listener、取消 accept/connect/copy task，并释放 fd/stream。
- TCP kernel/smoltcp local port 在 peer/NIC pipeline 注册前写入 `TcpProxyEngine`。
- core proxy service stop/drop 会同步注销 peer/NIC pipeline guard，重复 start 不会重复注册。
- pipeline 执行顺序保持现有新注册优先语义，pipeline handle 不强持有 service。
- fake provider 更新 proxy CIDR 和 runtime snapshot 后，新 packet 使用最新 snapshot。
- `rg 'smoltcp::|tokio_smoltcp|ChannelDevice|SmolTcpListener|\\bNet\\b'
  easytier/src/gateway/tcp_proxy.rs` 无结果。
- TCP/UDP proxy packet pipeline 注册在 core proxy service 中完成。
- `rg 'impl.*(PeerPacketFilter|NicPacketFilter) for (TcpProxy|UdpProxy)'
  easytier/src/gateway/{udp_proxy.rs,tcp_proxy.rs}` 无结果。
- `rg 'add_(nic_)?packet_process_pipeline'
  easytier/src/gateway/{udp_proxy.rs,tcp_proxy.rs}` 无结果；KCP/QUIC 兼容 wrapper
  如需注册，只能注册 core service handle，不能注册 runtime `TcpProxy` facade。
- `rg 'add_(nic_)?packet_process_pipeline.*TcpProxy|Box::new\\([^)]*tcp_proxy'
  easytier/src/gateway/{kcp_proxy.rs,quic_proxy.rs}` 无结果，避免 KCP/QUIC 继续把
  runtime `TcpProxy` facade 注册进 pipeline。
- `rg 'send_msg_by_ip|get_nic_channel|send_msg_for_proxy'
  easytier/src/gateway/{udp_proxy.rs,tcp_proxy.rs}` 无结果。

## 第三阶段：Wrapped TCP Proxy 与 Proxy ACL Core 化

UDP/TCP proxy core 化完成后，本阶段迁移 `wrapped_proxy.rs`。这一阶段只处理
KCP/QUIC wrapped TCP source 的 NIC packet 规则，以及 stream proxy ACL helper。
KCP/QUIC endpoint、QUIC/KCP transport、connection map、stats label 和 runtime
启动路径不纳入本阶段。

### 第三阶段 Scope

迁移以下内容：

- `TcpProxyForWrappedSrcTrait::try_process_wrapped_packet_from_nic` 中的 wrapped TCP
  NIC packet 判断和 header 改写规则。
- `ProxyAclHandler`，因为 `AclFilter`、`AclProcessor` 和 `PacketInfo` 已经在
  `easytier-core`，该 helper 不应继续留在 runtime gateway。
- KCP/QUIC runtime wrapper 中与 wrapped TCP NIC filter 相关的最小 adapter。

不迁移以下内容：

- KCP proxy 本体和 KCP endpoint。
- QUIC proxy 本体、QUIC endpoint、quinn socket/stream。
- runtime `NatDstConnector`、stream connect、connection cache 和 transport stats。
- socks5 / fast_socks5。

### 目标结构

```text
easytier-core
  proxy/
    proxy_acl.rs          # stream ACL copy helper
    wrapped_tcp_proxy.rs  # KCP/QUIC wrapped TCP NIC packet rules

easytier
  gateway/
    kcp_proxy.rs          # runtime KCP endpoint + adapter
    quic_proxy.rs         # runtime QUIC endpoint + adapter
```

本阶段不要把 wrapped TCP proxy 机械拆成 `engine`/`service` 两个文件。当前
wrapped source 逻辑没有独立 NAT table，也没有复杂 lifecycle；一个
`wrapped_tcp_proxy.rs` 更符合实际复杂度。只有当后续引入独立状态表、pipeline
guard 或多 backend lifecycle 时，才考虑再拆 service 文件。

### Wrapped TCP Proxy 边界

core `wrapped_tcp_proxy.rs` 负责：

- 解析 `ZCPacket` payload 中的 IPv4/TCP header。
- 只允许 SYN 创建 wrapped 输入；非 SYN 必须命中已存在的 TCP proxy connection。
- 在非 smoltcp 模式下拒绝 net-to-net wrapped TCP 输入。
- 将 packet header 标记为 KCP src modified 或 QUIC src modified。
- 将 `to_peer_id` 改写成本机 peer id。

runtime KCP/QUIC adapter 只负责：

- 提供 transport kind：KCP 或 QUIC。
- 提供目标 IP 是否允许 wrapped input 的 async policy。
- 提供本机 peer id、本地 IPv4、smoltcp enabled snapshot，以及
  `TcpProxyEngine` connection lookup。
- 注册 core wrapped TCP NIC filter 到 runtime 当前既有 pipeline 位置。

core 不允许依赖：

- runtime `TcpProxy` facade。
- `GlobalCtx`。
- `NatDstConnector`。
- QUIC/KCP endpoint 或具体 stream 类型。

### Proxy ACL 边界

`ProxyAclHandler` 迁入 `easytier-core/src/proxy/proxy_acl.rs`。它可以继续持有
`Arc<AclFilter>`、`PacketInfo` 和 `ChainType`，并提供 stream copy helper：

```text
AsyncRead/AsyncWrite stream
  -> InspectReader
  -> AclFilter::get_processor().process_packet(...)
  -> AclFilter::handle_acl_result(...)
  -> copy_bidirectional(...)
```

`ProxyAclHandler` 不属于 wrapped TCP packet engine，不能和
`wrapped_tcp_proxy.rs` 混在一起。它处理 stream payload ACL；wrapped TCP proxy
处理 NIC packet rewrite。

### 第三阶段迁移步骤

1. 新增 core `proxy_acl.rs`
   - 移入 `ProxyAclHandler`。
   - runtime KCP/QUIC 引用 core `ProxyAclHandler`。
   - 不改变 ACL 处理语义和 stream copy 行为。

2. 新增 core `wrapped_tcp_proxy.rs`
   - 定义 wrapped transport kind、runtime snapshot/context、packet action。
   - 迁移 IPv4/TCP parse、SYN 判断、established connection 判断、net-to-net
     smoltcp gating 和 header mark 规则。
   - 用 `smoltcp::wire` 或已有 core packet parser，避免在 core 新增 runtime-only
     parsing 依赖。

3. 改造 KCP/QUIC wrapper
   - 删除 runtime `TcpProxyForWrappedSrcTrait`。
   - KCP/QUIC wrapper 缩成 runtime adapter，只实现 allow-check 和 transport kind。
   - NIC pipeline 注册 core wrapped TCP filter，不注册 runtime `TcpProxy` facade。

4. 删除 `gateway/wrapped_proxy.rs`
   - `ProxyAclHandler` 调用点改到 `easytier_core::proxy::proxy_acl`。
   - wrapped TCP packet 处理调用点改到 `easytier_core::proxy::wrapped_tcp_proxy`。

### 第三阶段验收

- `rg 'TcpProxyForWrappedSrcTrait|try_process_wrapped_packet_from_nic'
  easytier/src/gateway` 无结果。
- `rg 'ProxyAclHandler' easytier/src/gateway/wrapped_proxy.rs` 无结果，且该文件被删除。
- `rg 'gateway::tcp_proxy::TcpProxy|GlobalCtx|NatDstConnector'
  easytier-core/src/proxy/wrapped_tcp_proxy.rs` 无结果。
- `rg 'pnet::packet' easytier-core/src/proxy/wrapped_tcp_proxy.rs` 无结果。
- KCP/QUIC wrapped TCP src modified 语义保持不变。
- net-to-net wrapped TCP 在非 smoltcp 模式下仍被拒绝。
- non-SYN packet 只有命中已存在 TCP proxy connection 时才允许 wrapped input。

## 每个代码 Commit 的硬验收

```bash
cargo check -p easytier-proto --target wasm32-wasip1
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features
cargo test -p easytier-core
rg 'Url::socket_addrs|ToSocketAddrs|lookup_host|lookup_ip|hickory_resolver' easytier-core/src
```

影响 `easytier` runtime 时还要跑：

```bash
cargo check -p easytier --no-default-features
cargo check -p easytier
```

## core 禁止依赖

`easytier-core` 中不得引入：

- `tokio::net`
- `socket2`
- `nix`
- `pnet`
- `tun`
- DNS resolver
- netns
- socket mark
- 真实 tunnel implementation
- `GlobalCtx`
- TOML/CLI/service manager

## 迁移原则

- core 是 stateful control-plane，不是纯函数 helper 集合。
- `peers` 的现有模块分割默认保留；不要为了短期绕依赖把它继续拆成小 helper。
- 状态和生命周期逻辑必须留在同一个 core Module 内，尤其是 `Peer` 的 conn set、credential、add/remove 并发状态。
- runtime Adapter 只提供变化点，不承载核心 peer registry。
- 迁移期可以用 re-export 保持兼容，但不允许长期维护两套 `PeerMap`。
- 如果某一步需要大量 stub 才能 wasm 编译，说明 seam 选错，应先调整 Interface。

## 结论

第一阶段从 `easytier/src/peers/` 入手是合理的，但背景必须明确：我们是在构建可 wasm 编译、只保留核心能力的 core crates。`peers` 之所以成为第一阶段，是因为它实现了 EasyTier 最核心的 peer 通信和 packet-routing 能力。正确方向是把它迁成 `easytier-core::peers` 深 Module，并让 `easytier` 提供 runtime Adapter，而不是把 core 做成 runtime 调用的零散 helper。

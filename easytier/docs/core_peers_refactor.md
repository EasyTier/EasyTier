# easytier-core Peers 重构第一阶段方案

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

## 每个代码 Commit 的硬验收

```bash
cargo check -p easytier-proto --target wasm32-wasip1
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features
cargo test -p easytier-core
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

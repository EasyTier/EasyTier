# Connector Socket 重构方向

## 背景

当前 connector 相关代码的最大架构问题是：connector 的最终产物是
`Tunnel`。例如 direct/manual 路径通过 `TunnelConnector::connect()` 直接拿到
`Box<dyn Tunnel>`，UDP hole punch 的 core Module 也通过
`UdpHolePunchTunnelSink` 把成功结果交给 peers。

这个 Interface 把三层职责压在一起：

- 如何建立连接：dial、bind、hole punch、listener accept。
- 如何按 schema 升级连接：tcp、udp、ws、quic、wg、ring。
- 如何把 tunnel 交给 core peers：handshake、admission、PeerConn 注册。

目标是把 connector 的 seam 下沉到裸 socket 层。connector 只负责交付裸
`TcpSocket` / `UdpSocket` / `RingSocket`，完全不感知 tunnel schema。
orchestrator 根据 schema 把 socket 升级成 tunnel，再把 tunnel 交给
`easytier-core::peers`。

## 设计结论

### Connector 的产物是 socket，不是 tunnel

目标模型：

```text
manual/direct/hole-punch connector
  -> ConnectedSocket
  -> orchestrator upgrades socket by schema
  -> Box<dyn Tunnel>
  -> core peers admission
```

`ConnectedSocket` 表示 connector 已经完成连接建立或打洞：

```rust
pub enum ConnectedSocket {
    Tcp(TcpSocket),
    Udp(ConnectedUdpSocket),
    Ring(RingSocket),
}

pub struct ConnectedUdpSocket {
    pub socket: UdpSocket,
    pub remote_addr: SocketAddr,
}
```

这里的 `TcpSocket` / `UdpSocket` 是裸 socket 语义。runtime 中可以是
`tokio::net::TcpStream`、`tokio::net::UdpSocket + remote_addr`；core 中如需
引用，则只能通过保持裸 socket 语义的 thin Interface 或 endpoint 类型表达，
不能重新包装成 tunnel-like transport。

### SocketConnectPlan 属于 orchestrator

`SocketConnectPlan` 是 orchestrator 解析用户 URL、route candidate 或
hole-punch 结果后得到的连接计划。它不是 connector，也不是 tunnel。它只说明
如何拿到 socket：

```rust
pub enum SocketConnectPlan {
    Tcp {
        remote_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        ip_version: IpVersion,
    },
    Udp {
        remote_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        ip_version: IpVersion,
    },
    Ring {
        remote_id: RingId,
    },
}
```

schema 不进入 connector。示例：

```text
ws://1.2.3.4:11010
  -> SocketConnectPlan::Tcp(...)
  -> WebSocket upgrader

quic://1.2.3.4:11010
  -> SocketConnectPlan::Udp(...)
  -> Quic upgrader

wg://1.2.3.4:11010
  -> SocketConnectPlan::Udp(...)
  -> WireGuard upgrader

ring://uuid
  -> SocketConnectPlan::Ring(...)
  -> Ring upgrader
```

`tcp://` 和 `udp://` 也应被看作 upgraders：它们把裸 TCP/UDP socket 包装成
EasyTier 的 packet tunnel，而不是 connector 自己产出 tunnel。

### RingSocket 提升到 core socket 层

`ring` 是特殊的 in-process socket primitive。它不应该继续作为
`RingTunnelConnector` 直接产出 `Box<dyn Tunnel>`，而应该提升到
`easytier-core`，和 TCP/UDP socket 处在同一层级：

```text
easytier-core::socket
  tcp.rs    # core-visible TCP socket endpoint Interface
  udp.rs    # core-visible UDP socket endpoint Interface
  ring.rs   # concrete in-process RingSocket primitive

orchestrator
  RingSocket -> RingTunnel

easytier-core::peers
  Box<dyn Tunnel> -> PeerConn admission
```

`RingSocket` 的 Interface 必须保持 socket 语义：

- 不实现 `Tunnel`。
- 不包含 `TunnelInfo`。
- 不知道 `TunnelScheme` / URL schema。
- 不知道 `PeerManager` / peer admission。
- 可以复用当前 ring queue 的实现，但 `RingTunnel` 必须是外层 upgrader。

这样 Ring 和 TCP/UDP 的角色一致：connector 拿到连接，orchestrator 决定如何
升级，peers 只消费已经升级好的 tunnel。

## Module seam

### Socket connector seam

connector Module 只负责交付 `ConnectedSocket`：

```rust
#[async_trait::async_trait]
pub trait SocketConnector {
    async fn connect(&mut self) -> Result<ConnectedSocket, Error>;
}
```

manual、direct、TCP hole punch、UDP hole punch 都应落到这个 seam：

- manual：根据用户配置和 orchestrator plan dial TCP/UDP/Ring socket。
- direct：根据 peer route/candidate dial TCP/UDP socket。
- TCP hole punch：通过 punch 流程交付已连通的 TCP socket。
- UDP hole punch：通过 punch 流程交付绑定过的 UDP socket 和 remote addr。
- ring：通过 in-process registry 交付 `RingSocket` pair 的一端。

connector 不接收 `TunnelScheme`，不调用 `TunnelConnector`，不构造
`Box<dyn Tunnel>`。

### Tunnel upgrader seam

upgrader Module 负责从 socket 到 tunnel：

```rust
#[async_trait::async_trait]
pub trait TunnelUpgrader {
    async fn upgrade(&self, socket: ConnectedSocket) -> Result<Box<dyn Tunnel>, Error>;
}
```

一个 schema 对应一个 upgrader Adapter：

- `TcpTunnelUpgrader`
- `UdpTunnelUpgrader`
- `WebSocketTunnelUpgrader`
- `QuicTunnelUpgrader`
- `WireGuardTunnelUpgrader`
- `RingTunnelUpgrader`

upgrader 可以知道 schema、framing、crypto handshake、协议 metadata；connector
不能知道这些。

### Peer admission seam

core peers 的 Interface 保持在 tunnel 层：

```text
Box<dyn Tunnel> -> PeerConn handshake -> PeerMap registration
```

也就是说，`easytier-core::peers` 不关心 socket 是 manual、direct、
hole punch 还是 ring 来的。它只关心已经升级好的 `Tunnel`。

## 当前代码中的问题点

- `TunnelConnector::connect()` 直接返回 `Box<dyn Tunnel>`，让 connector seam
  停在 tunnel 层。
- `PeerManager::connect_tunnel()` 同时做 netns 切换、connector connect 和
  tunnel admission，职责跨度过大。
- `ManualConnectorManager` 的 reconnect 路径先 `create_connector_by_url()`，
  再 `pm.connect_tunnel()`，说明 URL schema 解析和 socket 建立还没拆开。
- UDP hole punch core 当前返回 `Box<dyn Tunnel>`，并通过
  `UdpHolePunchTunnelSink` 注入 peers，导致打洞状态机依赖 tunnel 产物。
- `RingTunnelConnector` 和 `RingTunnelListener` 直接生产 tunnel，导致 ring
  无法作为 socket primitive 被 orchestrator 统一编排。

## 迁移顺序

1. 新增 `easytier-core::socket::ring`，把当前 ring queue 能力沉淀为
   `RingSocket` / `RingListener` / `RingDialer`，但暂不删除旧
   `RingTunnelConnector`。
2. 新增 `ConnectedSocket` 和 `SocketConnectPlan`，先放在 orchestrator/runtime
   侧，避免过早污染 core peers Interface。
3. 为现有 tcp/udp/ws/quic/wg/ring tunnel 实现补齐 socket-to-tunnel upgrader
   Adapter。
4. 改 manual/direct 路径：URL schema 解析由 orchestrator 完成，connector 只
   根据 `SocketConnectPlan` 拿 socket。
5. 改 TCP/UDP hole punch：成功结果从 `Tunnel` 改成 socket endpoint，sink 从
   `TunnelSink` 改成 endpoint sink。
6. 收敛 `PeerManager::connect_tunnel()`：改为 orchestrator 完成
   `socket -> tunnel`，PeerManager 只接收 tunnel admission。
7. 删除或降级旧的 `TunnelConnector` / `TunnelListener` compatibility wrapper。

## 第一阶段执行计划

第一阶段使用 `socket` 作为 Module 名，不使用 `transport`。`transport` 容易把
裸 socket 和升级后的 tunnel 混在一起；`socket` 能直接表达这个 Module 的
Interface 层级。

目标布局：

```text
easytier-core/src/socket/
  mod.rs
  udp.rs      # 已存在：VirtualUdpSocket、UdpBindOptions、VirtualUdpSocketFactory
  tcp.rs      # 新增：VirtualTcpSocket、TCP connect/listen factory Interface
  ring.rs     # 新增：RingSocket in-process primitive

easytier-core/src/tunnel.rs
  Tunnel       # 保持现有位置，不移动到 socket Module
  ring.rs      # RingSocket<ZCPacket> -> RingTunnel
```

执行边界：

- `VirtualUdpSocket` 继续留在 `socket::udp`，不在 hole-punch Module 内重新定义。
- `VirtualTcpSocket` 新增到 `socket::tcp`，只表达裸 TCP stream I/O 和地址。
- `RingSocket<T>` 新增到 `socket::ring`，只表达 in-process socket primitive；
  `tunnel::ring` 选择 `T = ZCPacket` 并提供 core 内唯一的 in-memory
  `RingTunnel`。
- `Tunnel` 继续留在 `easytier-core::tunnel`，明确它是 orchestrator upgrade
  后的产物。
- 删除 `tunnel::memory`，避免 core 中同时存在两套 in-memory tunnel
  implementation。
- 本阶段不迁移 manual/direct/hole-punch 调用路径，不删除旧
  `TunnelConnector`。

## 非目标

- 不让 connector 解析或持有 tunnel schema。
- 不让 connector 直接构造 `TunnelInfo`。
- 不把 `PeerManager` 作为 connector 的依赖。
- 不把 URL 解析、DNS、netns、SO_MARK 等 runtime policy 混入 core socket
  primitive。
- 不把 `RingSocket` 设计成 `Tunnel` 的别名；`RingTunnel` 必须是 upgrader
  的产物。

## 验收标准

- manual、direct、TCP hole punch、UDP hole punch 的成功结果都可以表达为
  `ConnectedSocket`。
- ring 可以作为 `ConnectedSocket::Ring` 参与同一套 orchestrator 流程。
- `easytier-core::peers` 仍只消费 `Box<dyn Tunnel>`，不反向依赖 connector。
- `easytier-core::hole_punch::udp` 不再出现 `Box<dyn Tunnel>` 或
  `TunnelSink`。
- `TunnelConnector::connect()` 不再是 connector 主 Interface；旧接口只作为
  迁移期 Adapter 存在。

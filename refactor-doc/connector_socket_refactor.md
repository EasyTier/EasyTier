# Connector Socket 重构方向

> 状态：历史设计输入。当前实施顺序以
> [`core_refactor_roadmap.md`](core_refactor_roadmap.md) 为准；本文关于
> “先产出 Socket、再升级 Tunnel”的目标仍然有效，代码现状需重新核对。

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
    FakeTcp(FakeTcpSocket),
    Unix(UnixSocket),
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

### SocketDialRequest 属于 core socket 层

`SocketDialRequest` 是一次 socket dial 请求。它不是用户 URL，也不是 tunnel
schema；它说明要 dial 哪一类 socket、目标 endpoint 是域名还是地址、有哪些
bind candidates，以及创建 socket 时需要应用的 socket context。

DNS 解析不在 orchestrator 里提前做完。core 会提供单独的 DNS hook Module，
runtime 在启动时把 DNS resolver Adapter 注册到 core；connector/dialer 可以接收
domain，并在执行 `SocketDialRequest` 时通过 core DNS hook 解析。

bind addr 也不是 `Option<SocketAddr>`。每一个 bind addr 都对应一个独立 socket
attempt，因此 bind candidate 应该提升为 core socket 层的一等概念：

```rust
pub struct SocketDialRequest {
    pub socket_kind: SocketKind,
    pub remote: RemoteEndpoint,
    pub binds: Vec<BindEndpoint>,
    pub context: SocketContext,
}

pub enum SocketKind {
    Tcp,
    Udp,
    FakeTcp,
    Unix,
    Ring,
}

pub enum RemoteEndpoint {
    Domain { host: String, port: u16 },
    Addr(SocketAddr),
    Ring(RingId),
    UnixPath(PathBuf),
}

pub enum BindEndpoint {
    Default,
    Addr(SocketAddr),
    Device(String),
    AddrOnDevice { addr: SocketAddr, device: String },
}

pub struct SocketContext {
    pub ip_version: IpVersion,
    pub socket_mark: Option<u32>,
    pub netns: Option<NetNamespace>,
}
```

core socket dialer 执行 request 时负责展开 attempts：

```text
RemoteEndpoint::Domain
  -> core DNS hook
  -> Vec<IpAddr>

resolved IPs + RemoteEndpoint port
  -> Vec<SocketAddr>

bind candidates x resolved socket addrs
  -> independent socket attempts
  -> first successful ConnectedSocket
```

`SocketDialRequest` 只是一段数据；DNS resolution 和 attempt expansion 属于 core
socket dialer / `SocketAttemptBuilder` 的 implementation。orchestrator 只负责从
schema 得出 socket kind 和 upgrader，不把域名提前压成单个 `SocketAddr`，也不把
多个 bind candidates 压成一个 `bind_addr`。示例：

```text
ws://example.com:11010
  -> SocketDialRequest { socket_kind: Tcp, remote: Domain(...), binds: ... }
  -> WebSocket upgrader

quic://example.com:11010
  -> SocketDialRequest { socket_kind: Udp, remote: Domain(...), binds: ... }
  -> Quic upgrader

wg://example.com:11010
  -> SocketDialRequest { socket_kind: Udp, remote: Domain(...), binds: ... }
  -> WireGuard upgrader

ring://uuid
  -> SocketDialRequest { socket_kind: Ring, remote: Ring(...) }
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
    async fn connect(&mut self, request: SocketDialRequest) -> Result<ConnectedSocket, Error>;
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

### Socket listener seam

listener 的 connector seam 也必须停在 socket 层。旧 `TunnelListener::accept()`
直接返回 `Box<dyn Tunnel>`，严格方案下需要替换为 socket listener：

```rust
#[async_trait::async_trait]
pub trait SocketListener {
    async fn listen(&mut self, request: SocketListenRequest) -> Result<(), Error>;
    async fn accept(&mut self) -> Result<ConnectedSocket, Error>;
}
```

inbound 路径和 outbound 路径共享同一个 upgrader seam：

```text
listener config
  -> SocketListenRequest
  -> SocketListener
  -> ConnectedSocket
  -> TunnelUpgrader selected by schema and server role
  -> Box<dyn Tunnel>
  -> peer admission
```

因此删除旧 `TunnelListener` production 路径时，不是让 listener 逻辑消失，而是
把 listener accept 的产物从 tunnel 改成 socket。TCP/UDP/Ring/FakeTCP/Unix
listener 都应落到这个 seam；WebSocket/QUIC/WireGuard 的 server-side handshake
属于 upgrader，不属于 listener。

### Tunnel upgrader seam

upgrader Module 负责从 socket 到 tunnel：

```rust
pub enum TunnelUpgradeRole {
    Client,
    Server,
}

#[async_trait::async_trait]
pub trait TunnelUpgrader {
    async fn upgrade(
        &self,
        socket: ConnectedSocket,
        role: TunnelUpgradeRole,
    ) -> Result<Box<dyn Tunnel>, Error>;
}
```

一个 schema 对应一个 upgrader Adapter：

- `TcpTunnelUpgrader`
- `UdpTunnelUpgrader`
- `WebSocketTunnelUpgrader`
- `QuicTunnelUpgrader`
- `WireGuardTunnelUpgrader`
- `FakeTcpTunnelUpgrader`
- `UnixTunnelUpgrader`
- `RingTunnelUpgrader`

upgrader 可以知道 schema、framing、crypto handshake、协议 metadata；connector
不能知道这些。

### 不引入 LegacyTunnelConnectorUpgrader

严格方案下不引入 `LegacyTunnelConnectorUpgrader`，也不在新 orchestrator 中保留
`TunnelBuildPlan::Legacy` 这类 fallback。原因是 legacy `TunnelConnector`
自己 dial socket 并直接产出 `Tunnel`，它不是 socket-to-tunnel upgrader；把它
包装成 upgrader 会让 connector seam 继续携带 `Tunnel` 语义。

迁移期可以暂时保留旧代码供未迁移调用点编译，但它不能成为新路径的一部分：

- 新 `connector` Interface 中不能出现 `Tunnel` / `TunnelInfo` /
  `TunnelConnector`。
- 新 `orchestrator` 只执行 socket dial/listen request -> `ConnectedSocket` ->
  `TunnelUpgrader` -> `Box<dyn Tunnel>`。
- `ws` / `quic` / `wg` 必须在本轮补齐真正的 socket-to-tunnel upgrader，而不是
  通过 legacy tunnel connector fallback。
- 旧 `TunnelConnector` 只作为待删除的 compatibility surface 存在；迁移完成
  后从 production connector 路径移除。

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
2. 新增 `ConnectedSocket`、`SocketDialRequest`、`SocketListenRequest`、
   `RemoteEndpoint`、`BindEndpoint` 和 core DNS hook，放在 core socket 层，
   避免污染 core peers Interface。
3. 新增严格的 `TunnelUpgrader` seam，为 tcp/udp/ws/quic/wg/faketcp/unix/ring
   全部补齐 socket-to-tunnel upgrader Adapter；不引入 legacy tunnel connector
   fallback。
4. 改 manual/direct 路径：URL schema 解析由 orchestrator 完成，connector 只
   根据 `SocketDialRequest` 拿 socket。
5. 改 TCP/UDP hole punch：成功结果从 `Tunnel` 改成 socket endpoint，sink 从
   `TunnelSink` 改成 endpoint sink。
6. 收敛 `PeerManager::connect_tunnel()`：改为 orchestrator 完成
   `socket -> tunnel`，PeerManager 只接收 tunnel admission。
7. 删除旧的 production `TunnelConnector` / `TunnelListener` connector 路径；
   tunnel Module 可以保留 listener/upgrader 所需的 tunnel implementation，但
   connector Module 不再暴露 tunnel-producing Interface。

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

## 第二阶段执行计划：严格 socket connector

第二阶段的目标是建立完整的新路径，不用 legacy tunnel connector fallback：

```text
outbound:
URL / route candidate / hole-punch result
  -> orchestrator parses schema and selects socket kind + upgrader
  -> SocketDialRequest with domain/address and bind candidates
  -> SocketConnector
  -> core DNS hook + bind candidate expansion
  -> ConnectedSocket
  -> TunnelUpgrader selected by schema and client role
  -> Box<dyn Tunnel>
  -> peer admission

inbound:
listener config
  -> orchestrator parses schema and selects socket kind + upgrader
  -> SocketListenRequest with bind candidates
  -> SocketListener
  -> ConnectedSocket
  -> TunnelUpgrader selected by schema and server role
  -> Box<dyn Tunnel>
  -> peer admission
```

第二阶段需要同时补 core socket Module 和 runtime orchestrator Module：

```text
easytier-core/src/socket/
  dns.rs        # DNS resolver hook Interface，runtime 启动时注册 Adapter
  dial.rs       # SocketDialRequest、SocketConnector、SocketAttemptBuilder
  listen.rs     # SocketListenRequest、SocketListener

easytier/src/orchestrator/
  mod.rs
  socket.rs      # schema -> socket kind / request builder
  upgrade.rs     # TunnelUpgrader、TunnelUpgradePlan
  schema.rs      # URL/TunnelScheme -> socket request + upgrade plan
```

`SocketDialRequest` 只描述如何得到裸 socket，不携带 tunnel schema：

```rust
pub struct SocketDialRequest {
    pub socket_kind: SocketKind,
    pub remote: RemoteEndpoint,
    pub binds: Vec<BindEndpoint>,
    pub context: SocketContext,
}
```

`SocketListenRequest` 同样只描述如何 listen/accept 裸 socket：

```rust
pub struct SocketListenRequest {
    pub socket_kind: SocketKind,
    pub endpoint: ListenEndpoint,
    pub binds: Vec<BindEndpoint>,
    pub context: SocketContext,
}
```

`ListenEndpoint` covers listener endpoints that are not IP bind candidates:

```rust
pub enum ListenEndpoint {
    Ip,
    Ring(RingId),
    UnixPath(PathBuf),
}
```

DNS hook 和 bind expansion 是 core socket dialer 的 implementation：

```text
SocketDialRequest {
  remote: Domain(host, port),
  binds: [BindEndpoint::Addr(a), BindEndpoint::Addr(b)],
  context: SocketContext { ip_version, netns, socket_mark },
}

core dns hook resolves host with the same SocketContext -> [ip1, ip2]
SocketAttemptBuilder combines each IP with the RemoteEndpoint port

attempts:
  bind a -> connect (ip1, port)
  bind a -> connect (ip2, port)
  bind b -> connect (ip1, port)
  bind b -> connect (ip2, port)
```

这样每个 bind candidate 都会创建自己的 socket；失败重试、并发 race、地址族筛选
和成功 socket 的选择都集中在 core socket dialer，调用方不需要自己复制这套逻辑。
DNS resolve 和后续 socket connect 使用同一个 `SocketContext`，避免 netns /
socket mark 等 request-scoped policy 通过 side channel 传递。

`TunnelUpgradePlan` 只描述如何把已连接 socket 升级为 tunnel：

```rust
pub enum TunnelUpgradePlan {
    Tcp(TcpUpgradePlan),
    Udp(UdpUpgradePlan),
    WebSocket(WebSocketUpgradePlan),
    Quic(QuicUpgradePlan),
    WireGuard(WireGuardUpgradePlan),
    FakeTcp(FakeTcpUpgradePlan),
    Unix(UnixUpgradePlan),
    Ring(RingUpgradePlan),
}
```

同一个 URL schema 会拆成两部分：

```text
tcp://host:port
  -> SocketDialRequest { socket_kind: Tcp, remote: Domain(host, port), ... }
  -> TunnelUpgradePlan::Tcp

udp://host:port
  -> SocketDialRequest { socket_kind: Udp, remote: Domain(host, port), ... }
  -> TunnelUpgradePlan::Udp

ws://host:port / wss://host:port
  -> SocketDialRequest { socket_kind: Tcp, remote: Domain(host, port), ... }
  -> TunnelUpgradePlan::WebSocket

quic://host:port
  -> SocketDialRequest { socket_kind: Udp, remote: Domain(host, port), ... }
  -> TunnelUpgradePlan::Quic

wg://host:port
  -> SocketDialRequest { socket_kind: Udp, remote: Domain(host, port), ... }
  -> TunnelUpgradePlan::WireGuard

ring://uuid
  -> SocketDialRequest { socket_kind: Ring, remote: Ring(uuid), ... }
  -> TunnelUpgradePlan::Ring

faketcp://host:port
  -> SocketDialRequest { socket_kind: FakeTcp, remote: Domain(host, port), ... }
  -> TunnelUpgradePlan::FakeTcp

unix://path
  -> SocketDialRequest { socket_kind: Unix, remote: UnixPath(path), ... }
  -> TunnelUpgradePlan::Unix
```

其他现有 schema 也要从 tunnel-producing connector 中拆出来：

- `http://` / `https://`：不是 socket connector，而是 discovery resolver；
  它解析出最终 tunnel URL 后重新生成 `SocketDialRequest + TunnelUpgradePlan`。
- `txt://` / `srv://`：不是 socket connector，而是 DNS discovery resolver；
  它解析出最终 tunnel URL 后重新进入 orchestrator plan 生成流程。

### 第二阶段 Adapter 切分

- `TcpSocketConnector`：执行 `SocketDialRequest` 的 TCP dial。它可以接收
  `RemoteEndpoint::Domain`，通过 core DNS hook 解析，并按 `BindEndpoint`
  展开独立 socket attempts；不构造 `TunnelInfo`。
- `UdpSocketConnector`：执行 `SocketDialRequest` 的 UDP dial/connect 或
  bind + remote endpoint。它同样通过 core DNS hook 和 bind expansion 创建
  `ConnectedUdpSocket`；不构造 UDP tunnel。
- `TcpSocketListener`：只负责 TCP listen/accept，返回 TCP socket；不构造
  `TcpTunnel`。
- `UdpSocketListener`：只负责 UDP listen/accept 语义所需的 socket endpoint；
  不构造 UDP tunnel。
- `RingSocketConnector`：只负责从 core ring registry dial `RingSocket`；不构造
  `RingTunnel`。
- `RingSocketListener`：只负责从 core ring registry accept `RingSocket`；不构造
  `RingTunnel`。
- `FakeTcpSocketConnector` / `FakeTcpSocketListener`：只负责建立 FakeTCP
  virtual socket；不构造 tunnel framing。
- `UnixSocketConnector` / `UnixSocketListener`：只负责建立 local stream socket；
  不构造 tunnel framing。
- `TcpTunnelUpgrader`：消费 TCP socket，构造 EasyTier TCP packet tunnel 和
  `TunnelInfo`。
- `UdpTunnelUpgrader`：消费 `ConnectedUdpSocket`，构造 EasyTier UDP packet
  tunnel 和 `TunnelInfo`。
- `WebSocketTunnelUpgrader`：消费 TCP socket，执行 websocket client/server
  handshake，再构造 websocket tunnel。
- `QuicTunnelUpgrader`：消费 UDP socket endpoint，创建/注册 QUIC endpoint，
  执行 QUIC connect/open stream，再构造 QUIC tunnel。
- `WireGuardTunnelUpgrader`：消费 UDP socket endpoint，执行 WireGuard tunnel
  初始化；现有 `connect_with_socket` 形态应下沉为 upgrader implementation。
- `RingTunnelUpgrader`：消费 `RingSocket`，包装成 core `RingTunnel`。
- `FakeTcpTunnelUpgrader`：消费 FakeTCP virtual socket，构造 FakeTCP packet
  tunnel 和 `TunnelInfo`。
- `UnixTunnelUpgrader`：消费 local stream socket，构造 Unix packet tunnel 和
  `TunnelInfo`。

### 第二阶段执行边界

- 不实现 `LegacyTunnelConnectorUpgrader`。
- 不新增任何返回 `Box<dyn Tunnel>` 的 connector Interface。
- 不新增任何返回 `Box<dyn Tunnel>` 的 listener Interface。
- 不让 `SocketConnector` 接收 `TunnelScheme`、URL schema 或 tunnel-specific
  config。
- 不让 `SocketListener` 接收 tunnel-specific config；它只能接收
  `SocketListenRequest` 中的 socket kind、bind candidates 和 socket context。
- `TunnelInfo` 只在 upgrader 中构造，因为它描述的是 tunnel 产物，不是 socket。
- `PeerManager` 不调用 connector；它只接收 orchestrator 已经升级好的
  `Box<dyn Tunnel>`。
- 如果某个旧 connector 的 implementation 暂时还存在，必须标记为待删除，不得
  被新 orchestrator 路径调用。

### ws/quic/wg 的迁移要求

`ws` / `quic` / `wg` 不走 legacy fallback，而是在第二阶段完成最小可用
upgrader：

- `ws`：先抽出 websocket handshake helper，使它可以从已连接 TCP socket 构造
  tunnel；旧 `WsTunnelConnector::connect()` 的 dial 逻辑移入
  `TcpSocketConnector`。
- `wg`：复用现有 socket-based 初始化路径，把 UDP socket 获取逻辑移入
  `UdpSocketConnector`，WireGuard config 和握手逻辑留在
  `WireGuardTunnelUpgrader`。当前代码已先把 legacy `WgTunnelConnector` /
  `WgTunnelListener` 内部迁移到 `UdpSessionSocket`，后续只需要把外层
  `TunnelConnector` compatibility wrapper 拆成正式的 socket connector +
  upgrader。
- `quic`：拆分 `QuicEndpointManager::connect(global_ctx, addr)`，让 endpoint
  creation 可以消费 orchestrator 提供的 UDP socket endpoint；QUIC connect 和
  stream open 留在 `QuicTunnelUpgrader`。

如果 `quic` endpoint 复用需要绑定地址级缓存，缓存属于 `QuicTunnelUpgrader`
implementation 或其内部 helper，不属于 connector Interface。connector 仍只
交付 UDP socket endpoint。

## 非目标

- 不让 connector 解析或持有 tunnel schema。
- 不让 connector 直接构造 `TunnelInfo`。
- 不把 `PeerManager` 作为 connector 的依赖。
- 不把 URL schema 解析混入 core socket primitive；schema 属于 orchestrator。
- 不把 runtime DNS implementation 混入 core；core 只定义 DNS hook Interface，
  runtime 负责注册 Adapter。
- 不把 OS-specific netns、SO_MARK、bind-device implementation 混入 core；
  core 只定义 socket context 和 bind endpoint，runtime socket Adapter 负责应用。
- 不把 `RingSocket` 设计成 `Tunnel` 的别名；`RingTunnel` 必须是 upgrader
  的产物。
- 不引入 `LegacyTunnelConnectorUpgrader` 或任何新 legacy tunnel connector
  fallback。

## 验收标准

- manual、direct、TCP hole punch、UDP hole punch 的成功结果都可以表达为
  `ConnectedSocket`。
- ring 可以作为 `ConnectedSocket::Ring` 参与同一套 orchestrator 流程。
- `easytier-core::peers` 仍只消费 `Box<dyn Tunnel>`，不反向依赖 connector。
- `easytier-core::hole_punch::udp` 不再出现 `Box<dyn Tunnel>` 或
  `TunnelSink`。
- `ws` / `quic` / `wg` 都有真实的 socket-to-tunnel upgrader，不能通过
  `TunnelConnector` fallback 进入新路径。
- `TunnelConnector::connect()` 不再是 connector Interface；production
  connector 路径中不再出现 tunnel-producing connector。

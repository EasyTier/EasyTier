# UDP Socket 重构方向

## 背景

EasyTier 现有 UDP transport 不是裸 UDP tunnel。它复用一个 UDP port，在 UDP
payload 前加 `UDPTunnelHeader`，通过 `conn_id` 路由多条虚拟连接，并用
`Syn` / `Sack` 做建连握手。listener 侧还在同一个 UDP socket 上处理 STUN、
hole punch 和连接分发。

这和 `wg` / `quic` 的需求不同。`wg` / `quic` 需要的是一个已经绑定 peer 的
UDP packet socket，payload 应该原样交给上层协议，不应该被 EasyTier UDP
header 包裹。

因此 UDP socket 层需要区分两个 Interface：

- `VirtualUdpSocket`：runtime 提供给 core 的裸 UDP socket Adapter，用于创建和
  操作真实 UDP socket。
- `UdpSessionSocket`：core 交付给 connector/orchestrator 的 peer-scoped UDP
  session socket，不暴露 `from` / `to`，只暴露对已连接 peer 的 datagram 收发
  能力。

## 设计结论

### VirtualUdpSocket 是 runtime Adapter

`VirtualUdpSocket` 是 runtime 创建真实 UDP socket 的 seam。core 不直接依赖
`tokio::net::UdpSocket`、平台 socket API 或 FFI socket，而是通过 runtime
注册的 factory 创建底层 UDP socket：

```rust
#[async_trait::async_trait]
pub trait VirtualUdpSocketFactory: Send + Sync {
    type Socket: VirtualUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions)
        -> anyhow::Result<std::sync::Arc<Self::Socket>>;
}

#[async_trait::async_trait]
pub trait VirtualUdpSocket: Send + Sync {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr>;

    async fn send_to(
        &self,
        payload: &[u8],
        remote: std::net::SocketAddr,
    ) -> std::io::Result<usize>;

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddr)>;
}
```

`VirtualUdpSocket` 是 core UDP session implementation 的输入，不是 connector
最终交付给 orchestrator 的 socket。connector 可以通过 core UDP session API
请求创建 session，也可以在 hole punch 已经拿到 socket 时把
`VirtualUdpSocket` 移交给 core；移交后 recv/send ownership 归 core UDP
session layer。

### Core 对外交付 UdpSessionSocket

UDP socket seam 只保留一个对外 Interface：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSessionKind {
    Direct,
    EasyTierMux,
}

#[async_trait::async_trait]
pub trait UdpSessionSocket: Send {
    fn kind(&self) -> UdpSessionKind;
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr>;
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr>;

    async fn send(&self, payload: &[u8]) -> std::io::Result<usize>;
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
}
```

所有对外 `UdpSessionSocket` 都是 ring-backed endpoint。`send()` 写入
session ring command，并等待 core 内部发送任务返回 completion；`recv()` 只从
session ring 读取。真实 UDP socket 的 `send_to`/`recv_from`、EasyTier
`UDPTunnelHeader` 编解码、WG/QUIC packet classification 都留在 core 内部。
这样 upgrader 拿到的始终是同一种 peer-scoped socket，而不是混合了 raw socket
和 mux session 的半成品。

core UDP session dial/listen seam 使用 peer-scoped request：

```rust
pub struct UdpSessionConnectRequest {
    pub remote_addr: SocketAddr,
    pub bind: UdpBindOptions,
}

pub struct UdpSessionListenRequest {
    pub bind: UdpBindOptions,
}

#[async_trait::async_trait]
pub trait UdpSessionConnector {
    type Session: UdpSessionSocket;

    async fn connect(
        &mut self,
        request: UdpSessionConnectRequest,
    ) -> anyhow::Result<Self::Session>;
}

#[async_trait::async_trait]
pub trait UdpSessionListener {
    type Session: UdpSessionSocket;

    async fn listen(&mut self, request: UdpSessionListenRequest)
        -> anyhow::Result<()>;

    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    async fn accept(&mut self) -> anyhow::Result<Self::Session>;
}
```

`UdpSessionKind` 只用于 debug、日志和 metrics。编排层、upgrader、connector
不能根据 `UdpSessionKind` 做协议分支；它不参与 tunnel schema 决策。

`UdpSessionSocket` 的语义：

- 保留 UDP datagram 边界，不提供 stream 语义。
- 绑定一个 peer，`send` 永远发给这个 peer。
- `recv` 只返回来自这个 peer 的 payload。
- 不暴露 `send_to` / `recv_from`。
- 不包含 tunnel schema、`TunnelInfo`、peer admission 信息。

### 不引入 VirtualUdpDatagramSocket

`VirtualUdpDatagramSocket` 会把底层 UDP port 的寻址细节泄漏给 upgrader。
`wg` / `quic` 不应该关心 `from` / `to`，它们只需要一个能收发 UDP datagram
的 connected socket。

如果某个上游库必须接受 `send_to` / `recv_from` 形态，应该由 upgrader 内部
提供 adapter：

```text
recv_from() -> session.recv(), session.peer_addr()
send_to(buf, addr) -> assert addr == session.peer_addr(); session.send(buf)
```

这个 adapter 是上游库兼容层，不属于 core socket Interface。

### 同一个 Interface 覆盖多类协议分支

`UdpSessionSocket` 可以来自不同协议分支：

```text
direct/WG/QUIC UDP session
  core UDP hub + protocol classifier + fixed peer/session key
  payload 原样收发
  适合 wg/quic upgrade

EasyTier mux UDP session
  core UDP hub + EasyTier branch + conn_id + Syn/Sack
  payload 进入/离开 socket 时由 core 包装/拆掉 UDPTunnelHeader
  适合 EasyTier udp transport upgrade
```

这些差异属于 implementation detail。core 对外不暴露
`DirectUdpSessionSocket` / `MuxUdpSessionSocket` 这种不同类型，只返回同一个
`UdpSessionSocket` Interface。`UdpSessionKind` 只反映来源，不能改变调用语义。

`UdpSession` 的实现必须是 ring-backed：

```text
VirtualUdpSocket recv loop
  -> protocol classifier
  -> per-session RingSocket sender
  -> UdpSessionSocket.recv()

UdpSessionSocket.send()
  -> per-session RingSocket receiver
  -> protocol branch encoder
  -> VirtualUdpSocket.send_to()
```

底层 `send_to` / `recv_from` 不穿透到 connector 或 upgrader。

### UDP session layer 接管底层 socket

core UDP session layer 消费 `VirtualUdpSocket`：

```text
VirtualUdpSocket
  -> core UDP socket hub / session layer
       owns recv loop
       owns send path
       owns protocol classifier
       owns protocol-specific session maps
  -> UdpSessionSocket
```

真实 UDP socket 只能有一个 recv owner。`wg`、`quic`、EasyTier UDP mux 不能
同时直接 `recv_from` 同一个 socket，否则包会被随机抢走。所有接收必须经过
core UDP session layer 的 demux，再投递到对应的 `UdpSessionSocket`。

这里不引入 public `UdpPort` seam。实现中可以有私有 manager/registry 结构，
但架构 Interface 只有 runtime adapter `VirtualUdpSocket` 和对外交付的
`UdpSessionSocket`。

## UDP Hub 和 Demux 规则

本阶段不修改 EasyTier UDP wire protocol。demux 必须基于现有包格式实现。
`Syn` / `Sack`、V4/V6 hole-punch packet builder、STUN classifier 和 UDP
session datagram parser 属于 core socket 层 helper；`easytier` crate 不再保留
这些 packet helper 的重复实现。

core UDP hub 是两级 demux：

```text
VirtualUdpSocket.recv_from()
  -> datagram classifier
       -> STUN / local hole-punch control
       -> EasyTier UDP branch
       -> WireGuard branch
       -> QUIC branch
  -> protocol-specific sessionization
       -> per-session RingSocket
       -> UdpSessionSocket
```

`conn_id` 只属于 EasyTier UDP branch。WG/QUIC 不能被塞进 EasyTier `conn_id`
模型，它们必须由各自协议分支基于 packet shape、remote addr 和协议自己的
connection/session identity 投递到对应 ring-backed `UdpSessionSocket`。

### 已建立 EasyTier UDP session

已建立的 EasyTier mux session 按 `(remote_addr, conn_id)` 路由：

```text
remote_addr + header.conn_id -> UdpSessionSocket
```

只有命中 session map 的 `Data` 包才投递给对应 socket。

### 新建 EasyTier UDP session

EasyTier UDP session 的建连首包仍使用现有 `Syn` 格式：

```text
datagram_len == UDP_TUNNEL_HEADER_SIZE + 8
header.msg_type == UdpPacketType::Syn
header.len == 8
payload.len == 8
```

listener 收到后创建新的 `UdpSessionSocket`，发送 `Sack`，并把 socket 交给
accept path。

旧协议没有 magic/version，因此这个识别不是严格 magic-level demux。当前阶段
接受这个限制，不在本重构里升级协议。

### STUN 和 hole punch

现有 STUN、`HolePunch`、`V4HolePunch`、`V6HolePunch` 行为保留在 core UDP
session layer 内部处理。它们不是 `UdpSessionSocket` payload，不应该暴露给
upgrader。

### Direct UDP session

direct/WG/QUIC 这类裸 UDP payload session 以协议分支自己的 session key
作为接收路由 key。最小 direct branch 可以只用 peer addr：

```text
remote_addr -> UdpSessionSocket
```

它用于 `wg` / `quic` 这类需要裸 UDP payload 的 upgrader。payload 不加
EasyTier UDP header。

当前兼容阶段的 fallback 规则是：STUN、hole-punch control、合法 EasyTier
`Data` / `Syn` / `Sack` 仍优先留在 EasyTier branch；解析失败或未知
`msg_type` 的 datagram 才按 `remote_addr` 投递到 direct session。旧协议没有
magic，因此如果某个 WG/QUIC 包刚好伪装成合法 EasyTier 包，仍存在误分类风险；
这个问题留到 UDP protocol v2 增加 magic/version 时解决。

在旧 EasyTier UDP 协议下，如果同一个 `remote_addr` 同时存在 direct UDP
session 和 EasyTier mux session，新建 mux session 的首包只能通过现有
`Syn + len == 8` 规则识别，不能做到 100% 无歧义。这个限制应记录为当前阶段
约束，后续协议升级时再通过 magic/version 解决。

## Connector 和 Upgrader 分工

connector 通过 core UDP session API 拿到 `UdpSessionSocket`：

```text
direct/manual/hole-punch connector
  -> core UDP session dial/listen API
  -> VirtualUdpSocketFactory or transferred VirtualUdpSocket
  -> core UDP session layer
  -> UdpSessionSocket
  -> orchestrator upgrades socket by tunnel schema
  -> Box<dyn Tunnel>
  -> core peers admission
```

connector 不直接读写 `VirtualUdpSocket`，也不自己运行 UDP recv loop。hole punch
如果已经创建了底层 UDP socket，也只是把 `VirtualUdpSocket` 移交给 core UDP
session API，由 core 负责后续 demux、session map 和 socket ownership。

upgrader 根据 schema 消费同一个 UDP session Interface：

```text
quic://
  UdpSessionSocket -> QuicTunnel

wg://
  UdpSessionSocket -> WgTunnel

udp://
  UdpSessionSocket -> EasyTierUdpTunnel
```

`udp://` 不再表示 connector 直接产出 tunnel。它只是一个 upgrader，把
`UdpSessionSocket` 升级成 EasyTier packet tunnel。

## 迁移步骤

1. 在 core socket 层定义 `VirtualUdpSocket`、`VirtualUdpSocketFactory`、
   `UdpSessionSocket`、`UdpSessionKind` 和 request 类型。
2. 引入 core UDP session layer，消费 `VirtualUdpSocket` 并接管 recv loop、
   send path、demux 和 session map。
3. 把现有 `easytier/src/tunnel/udp.rs` 中的 `conn_id`、`Syn` / `Sack`、STUN、
   hole punch、session map 逻辑下沉到 core UDP socket implementation。
4. 调整 UDP connector/listener，使其返回 `UdpSessionSocket`，不再构造
   `Box<dyn Tunnel>`。
5. 调整 `wg` / `quic` upgrader，通过 `UdpSessionSocket` adapter 接入需要
   `send_to` / `recv_from` 的库接口。
6. 调整 `udp://` upgrader，使其消费 `UdpSessionSocket` 并产出 EasyTier UDP
   tunnel。
7. 完成 connector socket 化后，再单独评估 UDP protocol v2 的 magic/version
   升级，不混入本阶段重构。

## 当前实现状态

已经完成的部分：

- UDP packet helper 已移动到 `easytier-core::socket::udp`，wire shape 未改变。
- core 已有 `VirtualUdpSocket`、`UdpSessionSocket`、`UdpSessionKind` 和统一的
  `UdpSessionLayer`，EasyTier mux 只是其中一个协议分支。
- `UdpSession` 已调整为 ring-backed endpoint：外部 `send`/`recv` 只操作
  per-session ring；`send` 等待内部发送 completion，EasyTier Data packet
  编解码和真实 `send_to` 由 core 内部 task 负责。
- `UdpSessionLayer` 已接管 connector 侧的 `conn_id` 生成、`Syn`
  发送/重发、`Sack` 校验、`HolePunch` 唤醒和 Data demux。
- `UdpTunnelConnector` 已改为通过 `UdpSessionLayer::connect` 获取
  `UdpSessionSocket`，再由临时 compatibility bridge 升级成现有 ring-backed
  UDP tunnel。
- `UdpTunnelConnector` 内部已拆分为 `connect_udp_session_with_runtime_socket`
  和 `upgrade_connected_session_to_legacy_tunnel` 两步：前者产出
  `UdpSessionSocket`，后者只是当前 `TunnelConnector` trait 的 legacy
  compatibility wrapper。
- `RuntimeUdpSocket` 已成为 easytier runtime 侧共享的
  `tokio::net::UdpSocket` adapter，hole-punch runtime 不再保留重复
  `VirtualUdpSocket` implementation。

本阶段继续完成的部分：

- `UdpTunnelListener` 已迁移到 `UdpSessionLayer::accept`。
- listener 侧不再维护 `UdpConnection`、`sock_map`、raw recv loop、`Syn` /
  `Sack` accept path 或 Data demux。
- hole-punch listener 和 outbound connect 复用同一个 `RuntimeUdpSocket` 上缓存的
  `UdpSessionLayer`，避免同一个真实 UDP socket 出现多个 recv owner。
- listener compatibility wrapper 仍把 accepted `UdpSessionSocket` 临时升级成
  ring-backed legacy `Tunnel`。
- connector 和 listener 共享 `upgrade_udp_session_to_legacy_tunnel` 兼容层，避免
  在两侧重复表达 session-to-tunnel upgrade 逻辑。
- `UdpSessionLayer` 已在 core 内部识别 STUN 和 V4/V6 hole-punch
  control packet，并通过独立的 `UdpSessionControlHandler` 触发 response /
  punch 发包。`VirtualUdpSocket` 保持裸 UDP socket 语义。
- core UDP hub 已增加 direct UDP session registry。direct session 不再需要自己
  持有同一底层 UDP socket 的独立 recv loop；非 EasyTier UDP datagram 由 hub
  按 `remote_addr` 投递到对应 ring-backed `UdpSessionSocket`。
- direct accept path 已提供给后续 WG/QUIC listener 使用：开启 direct accept 后，
  未命中 EasyTier branch 的首个 raw datagram 会创建 peer-scoped
  `UdpSessionSocket`，并把首包投递到该 session ring。

仍待完成的部分：

- UDP hub 的 WG/QUIC branch 仍待接入；core 已具备 direct/raw datagram session
  branch，但 WG/QUIC upgrader 还没有改成消费 `UdpSessionSocket`。
- STUN response 的 EasyTier runtime codec 仍由 easytier crate 中的
  `RuntimeUdpSessionControlHandler` 调用本地 helper。core 已拥有 classifier 和
  control path；后续如果要进一步收敛，需要把 codec helper 也提升到 core 可依赖
  的位置。
- `wg` / `quic` / `udp` upgrader 仍需要改为消费 `UdpSessionSocket`，当前
  `udp://` 仍通过 compatibility bridge 产出旧 `Tunnel`。

## Listener 迁移方案

本阶段迁移 `UdpTunnelListener`，目标是删除 easytier crate 中 listener 侧的
重复 EasyTier UDP session logic。

### Core 层补齐 listener 所需能力

`UdpSessionLayer` 已经能够识别 `Syn`、发送 `Sack`、维护 session map、
投递 Data，并把 STUN / V4 hole-punch / V6 hole-punch 分类为
`UdpSessionLayerControl`。listener 迁移需要补齐两个只读/控制能力：

- 暴露 active mux session count，供旧 `TunnelConnCounter` compatibility wrapper
  使用。
- 明确 control packet 的处理边界。STUN 和 hole-punch classification 属于 core
  UDP session layer；涉及 runtime 平台能力的实际发包可以通过
  `UdpSessionControlHandler` 调用 runtime adapter 完成。v6 hole-punch 的
  preferred source/ifindex 不能泄漏回 connector，也不能下沉到裸
  `VirtualUdpSocket` trait。

### easytier crate listener compatibility bridge

迁移后的 `UdpTunnelListener::listen()`：

```text
UdpTunnelListener::listen()
  -> bind or reuse tokio UdpSocket
  -> RuntimeUdpSocket
  -> UdpSessionLayer
  -> spawn accept loop
```

accept loop：

```text
UdpSessionLayer::accept()
  -> UdpSessionSocket
  -> bridge UdpSessionSocket <-> RingSocket
  -> TunnelWrapper
  -> legacy TunnelListener::accept()
```

这个 bridge 是 compatibility code，只为了让当前 `TunnelListener` interface 继续
工作。它不能重新实现 `conn_id`、`Syn` / `Sack` 或 socket recv demux。

control handling：

```text
UdpSessionLayer recv loop
  -> classify STUN / V4 hole punch / V6 hole punch
  -> enqueue bounded UdpSessionControlHandler task
  -> runtime control adapter performs platform-specific send behavior
```

listener wrapper 不再 spawn control loop，也不再消费 raw datagram。
`recv_control()` 可以暂时保留给测试、metrics 或后续观测用途，但 runtime
behavior 不依赖 easytier crate 轮询 control queue。

### 删除的 easytier crate 代码

listener 迁移完成后，`easytier/src/tunnel/udp.rs` 中这些结构已删除：

- `UdpConnection`
- `forward_from_ring_to_udp`
- `udp_recv_from_socket_forward_task`
- `UdpTunnelListenerData::handle_new_connect`
- `UdpTunnelListenerData::do_forward_one_packet_to_conn`
- listener-local `sock_map` 和 close-event cleanup path

保留的代码应只包括：

- runtime adapter `RuntimeUdpSocket`
- `UdpSessionSocket` 与 legacy ring tunnel 的临时 bridge
- `TunnelListener` compatibility wrapper

## 当前阶段非目标

- 不修改 EasyTier UDP wire protocol。
- 不引入 `VirtualUdpDatagramSocket`。
- 不在 connector 中保留 tunnel schema 分支。
- 不要求 `UdpSessionSocket` 支持 QUIC connection migration 或 WG endpoint
  roaming。后续如果需要，应在 socket 内部增加受控 peer update 能力，而不是把
  `from` / `to` 重新暴露给 core Interface。

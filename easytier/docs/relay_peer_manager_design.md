# Relay Peer 管理模块设计文档

## 背景与现状

当前出站转发路径中，PeerManager 根据路由直接选择下一跳并发送，转发路径以“取下一跳 → 发送”为核心流程：

- 发送内部路径：[peer_manager.rs:L1053-L1082](file:///data/project/EasyTier/easytier/src/peers/peer_manager.rs#L1053-L1082)
- 数据面发送入口：[peer_manager.rs:L1187-L1238](file:///data/project/EasyTier/easytier/src/peers/peer_manager.rs#L1187-L1238)

现状缺少面向“非直连目标”的统一管理模块，无法对 Relay Peer 进行会话、状态与策略层面的治理。

## 设计目标

- 对非直连 Relay Peer 做生命周期管理
- 提供统一的会话（如 PeerSession）与路径选择入口
- 与现有路由模块解耦，只消费下一跳候选与路由变更信息
- 不改变现有数据面主路径流程

## 架构设计

### 模块命名

**RelayPeerMap**

### 引用关系

- **PeerManager**: 作为顶层协调者，同时持有 `Arc<PeerMap>` 和 `Arc<RelayPeerMap>`。
- **RelayPeerMap**: 持有 `Arc<PeerMap>`（或 `Weak<PeerMap>`），用于在决策后调用底层发送能力。
- **PeerMap**: 专注直连 Peer 管理与基础路由表维护，不直接持有 RelayPeerMap（避免循环依赖）。

### 职责划分

- **PeerManager**: 
  - 发送入口。
  - 判断目标是否直连：
    - 若目标在 PeerMap：直接调用 `PeerMap` 发送。
    - 若目标不在 PeerMap：调用 `RelayPeerMap` 处理。
- **RelayPeerMap**: 
  - 维护非直连 Peer 的状态（会话、健康度）。
  - 决策下一跳（Next Hop）。
  - 调用 `PeerMap` 将数据包发送给下一跳。
- **ForeignNetworkManager**:
  - 拥有独立的 RelayPeerMap 实例，用于 foreign network 的非直连转发。
- **PeerMap**: 
  - 维护直连 Peer 连接。
  - 提供基础路由表查询。
  - 执行向直连邻居的物理发送。

## 数据模型

### RelayPeerKey

- **dst_peer_id** (PeerId)
- 注：RelayPeerMap 实例隶属于特定网络上下文，因此 Key 仅需 PeerId。

### RelayPeerState

- selected_next_hop: PeerId
- session: Option<PeerSessionHandle>
- last_active_at: Instant
- path_metrics: latency, loss, hop_count (可选)

### RelayPathCandidate

- next_hop_peer_id
- cost / latency / availability

## 简化状态管理

不再引入复杂状态机（如 Establishing/Suspect 等），仅依赖以下状态判断：

- **会话是否存在**：`session.is_some()`
- **会话是否有效**：检查 session 过期时间或 generation
- **路由是否可达**：检查路由表中是否有 next hop

## 关键流程

### 出站发送流程（非直连）

1. **PeerManager** 接收发送请求（目标 `dst_peer_id`）。
2. **PeerManager** 检查 `PeerMap` 是否直连 `dst_peer_id`。
3. 若非直连，**PeerManager** 将请求转交给 **RelayPeerMap**。
4. **RelayPeerMap** 处理：
   - 查找 `RelayPeerState`。
   - 若首次与该 Relay Peer 通信，创建 RelayPeerState 并进入握手流程。
   - 确保会话存在（若无则触发握手与同步）。
   - 选择下一跳（由 RelayPeerMap 决策）。
   - 调用 **PeerMap** 的 `send_msg_directly(next_hop, packet)`。

### Relay 数据面握手出站流程（Relay Peer 特例）

说明：Relay Peer 初次通信前必须先完成基于数据面消息的 Noise 握手，否则无法安全发送加密数据面包。握手消息通过普通数据面路径转发，但其目标是创建会话而非携带业务数据。

流程要点（发起方视角）：

1. 发送路径命中 `dst_peer_id` 为非直连目标后，进入 RelayPeerMap 流程。
2. 若目标会话不存在或已失效，则发送 **RelayHandshake** 消息（携带 `m1`），通过 `send_msg_directly(next_hop, packet)` 转发给对端。
3. 对端收到后返回 **RelayHandshakeAck**（携带 `m2`）沿原路径回传，双方派生会话并落库。
4. 握手完成后，使用已建立会话的密钥对数据面包加密/鉴别，再走正常转发流程。
5. 若握手失败或控制面公钥信息缺失，则不进入数据发送，返回可重试的错误（由上层决定重试节奏）。

### Relay 会话建立流程（数据面 + Noise 1-RTT）

背景：直连 Peer 的 Noise 握手在 `PeerConn` 内完成；Relay Peer 没有 `PeerConn`，因此无法复用该握手逻辑。Relay 会话需要通过 **数据面握手消息** 完成握手与密钥派生，并把结果落到 `PeerSessionStore`（或等价的会话存储）中供数据面复用。

关键假设：Relay Peer 握手前即可拿到对端静态公钥（通过 OSPF 等控制面传播），因此可选用 **1-RTT 的 Noise 握手模式**（例如 IK/KK 一类的两报文握手），并将“两报文”映射为 **RelayHandshake / RelayHandshakeAck** 两种数据面消息。

建议流程（以本端作为 initiator 为例）：

1. `ensure_session(dst_peer_id)` 发现无可用会话，触发一次握手流程（可选：对并发请求做 in-flight 去重）。
2. 从控制面缓存中读取 `dst_peer_id` 的静态公钥（若不存在则等待控制面收敛，或退化为非 1-RTT 的握手模式）。
3. 生成 Noise 握手首报文 `m1`（包含必要的认证信息与抗重放字段，例如 session generation / nonce / 时间窗等）。
4. 发送 `RelayHandshake(m1)`，对端返回 `RelayHandshakeAck(m2)`。
5. initiator 处理 `m2`，双方派生出相同的会话密钥与会话标识，将会话写入 `PeerSessionStore`，供后续发送复用。
6. 后续 Relay 数据面包使用该会话密钥进行加解密/鉴别（具体包格式不在本层定义，保持与直连会话的语义一致）。

实现要点：

- **角色确定**：为避免并发双向握手导致的竞态，可使用确定性规则选择 initiator（如 `min(peer_id)` 发起），或由第一次发送方发起并在冲突时做幂等合并。
- **幂等与重试**：数据面握手应支持重试（同一 generation/nonce 重放可安全拒绝或复用），并与路由收敛解耦。
- **会话绑定**：握手需绑定 `dst_peer_id` 与其静态公钥指纹，避免控制面短暂不一致造成的密钥混用。

### 会话管理

- PeerSessionStore 仅用于 secure mode，会话创建与密钥派生在该模式下生效。
- 在发送时若发现无会话，则触发 Create/Join/Sync 逻辑。
- 对于 Relay Peer，会话创建阶段由 **数据面握手消息承载 Noise 握手**（见上节），以替代直连 `PeerConn` 内的握手流程。

### PacketType 规划（新增）

- 新增 PacketType：
  - `RelayHandshake`：承载 `m1`（initiator -> responder）
  - `RelayHandshakeAck`：承载 `m2`（responder -> initiator）
- 载荷建议：
  - `RelayHandshake`: `RelayNoiseMsg1Pb`（包含 a_session_generation/conn_id/算法等字段）
  - `RelayHandshakeAck`: `RelayNoiseMsg2Pb`（包含 b_session_generation/root_key/initial_epoch/算法等字段）
- 约束：
  - 两类包应与普通 Data 包一样可被转发，但不应被当作业务数据消费。
  - 需要在路由转发链路中识别为“握手控制类”消息。

## 策略设计

- 下一跳策略由 RelayPeerMap 决策，可结合 latency_first 选择 LeastHop 或 LatencyFirst。
- 握手策略：优先采用“已知对端静态公钥”的 **1-RTT Noise 握手**，并通过 **RelayHandshake/RelayHandshakeAck** 消息触发会话建立。
- 失败处理：依赖上层重试或底层路由收敛，暂不在此层做复杂的 Failover 状态流转。
- 公钥来源：对端静态公钥以控制面传播为准；在控制面信息缺失或变更时，应阻止复用旧会话或触发重新握手。

## 接口草案

### RelayPeerMap 接口

- `send_msg(packet, dst_peer_id)`: 处理非直连发送逻辑。
- `ensure_session(dst_peer_id)`: 确保会话可用。
- `handshake_session(dst_peer_id)`: 通过握手消息完成 Relay 会话握手（对上层透明，可由 `ensure_session` 内部调用）。
- `remove_peer(dst_peer_id)`: 删除已经失效的 Peer。
## 监控与指标建议

- Relay 会话数
- Relay 发送成功/失败计数

## 渐进式落地计划

### 阶段 1：基础能力

- 引入 RelayPeerMap 结构。
- 在 PeerManager 中集成 RelayPeerMap。
- 实现基础的“非直连转发”委托逻辑。

## 兼容性说明

- 需要新增 PacketType 用于 RelayHandshake/RelayHandshakeAck。
- 在 secure mode 下，压缩由 PeerManager 完成；加密由 PeerConn（直连）或 RelayPeer（非直连）完成。
- RelayPeer 在 secure mode 下需要提供会话级加密/解密入口：
  - 发送：在 RelayPeerMap 决策完成后、调用 `send_msg_directly` 前，用 Relay 会话密钥加密。
  - 接收：在数据面包进入业务处理前，按 `from_peer_id/to_peer_id` 定位会话并解密。
- PeerSessionStore 为 secure mode 的会话兼容性保留，非 secure mode 仅保持现有行为。
- 不改变路由模块的计算结果。

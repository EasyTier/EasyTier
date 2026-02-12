# PeerConn Secure Mode（乱序隧道友好）

本文是对“PeerConn 安全模式”下一阶段协议的完整规格草案，目标是在底层 `Tunnel` **不保证顺序交付**（可能乱序/丢包）的前提下：

- 仍使用 Noise 进行握手（加密、认证、channel binding）
- 数据面不使用 `snow::TransportState` 逐包加解密（因为它隐式递增 nonce，要求有序）
- 在数据包尾部携带 **12B 明文 nonce**（与项目当前的“包尾 nonce”加密格式对齐），并把 **epoch 编进 nonce**
- 以尽可能低的内存开销实现 anti-replay（默认窗口 256）
- 多条 PeerConn 之间复用同一份 Peer 级安全会话（PeerSession）

该文档只描述协议与数据结构；实现时以本文为准做迭代。

---

## 背景

### 节点角色

系统中常见两类角色（由配置与信任锚点决定，而非代码里硬编码的“节点类型”）：

- **用户节点（同网节点）**：通常持有 `network_secret`，期望与同一 `network_name` 的其他节点建立强认证连接。
- **共享节点（基础设施节点）**：通常不持有用户的 `network_secret`，用于为多个用户网络提供转发/中继能力；客户端可通过 pinning 共享节点的长期 static 公钥获得“服务器认证”。

基于握手中交换的 `network_name` 可以得到 **角色提示（role hint）**：

- `a_network_name == b_network_name`：同网提示
- 否则：共享节点/外网提示

但 `network_name` 不是认证锚点；安全决策应基于 pinning 或 `network_secret_confirmed`（见 8）。

### 连接方式与 PeerConn

在实现中，“peer 与 peer 之间的连接”由 `PeerConn` 表示，它绑定一条底层 `Tunnel`（可能是 tcp/udp/quic/wg/ring 等），并以 `PeerManagerHeader` 承载上层消息：

- `PacketType::HandShake`：传统 PeerConn 握手
- `PacketType::NoiseHandshake`：安全模式下的 Noise 握手

参考：[packet_def.rs](file:///data/project/EasyTier/easytier/src/tunnel/packet_def.rs#L59-L77)。

PeerManager 会在连接建立时走不同入口：

- 主动方：`add_client_tunnel` -> `PeerConn::do_handshake_as_client`
- 被动方：`add_tunnel_as_server` -> `PeerConn::do_handshake_as_server`

参考：[peer_manager.rs](file:///data/project/EasyTier/easytier/src/peers/peer_manager.rs#L361-L379)。

### 多连接与 foreign network

同一对 peer 之间可能出现多条 PeerConn（多路径、多协议、重连等），因此需要一个 Peer 级别的“安全会话”来复用认证结果与数据面密钥（见 7.3 的 PeerSession）。

此外，当握手得到的对端 `network_name` 与本地不一致时，PeerManager 会将该连接纳入 foreign network 相关逻辑（例如 foreign network client/manager）以支持“共享节点”模式与跨网络转发：

参考：[peer_manager.rs](file:///data/project/EasyTier/easytier/src/peers/peer_manager.rs#L361-L377)。

### 为什么需要本方案

若数据面直接使用 `snow::TransportState` 逐包加解密，会隐式递增 nonce，从而要求底层按序交付。由于本项目的数据加密格式本就采用“包尾明文 nonce”（例如 `AesGcmTail.nonce[12]`，以及 ring ChaCha20-Poly1305 的同形 tail），因此本文延续“尾部 nonce”风格，并将 nonce 结构化为 `epoch||seq`，以满足：

- 乱序可解密
- 低内存 anti-replay
- epoch/key 轮换
- 多 PeerConn 复用 PeerSession

参考：[packet_def.rs:AesGcmTail](file:///data/project/EasyTier/easytier/src/tunnel/packet_def.rs#L266-L273)、[ring_chacha20.rs](file:///data/project/EasyTier/easytier/src/peers/encrypt/ring_chacha20.rs#L69-L93)。

---

## 0. 约束与假设

- 底层 tunnel 可能乱序/丢包；因此数据面必须支持乱序解密。
- 外层已有 `PeerManagerHeader`，包含 `from_peer_id` / `to_peer_id`，可作为对端身份索引，数据面无需额外携带 `session_id`。
- 保持既有的安全语义目标：
  - 共享节点 pinning（基于对端 Noise static pubkey）
  - network_secret 的 channel binding 确认（`handshake_hash`）
  - “尽早交换 network_name”用于角色判断（同网/共享节点）

---

## 1. 术语

- **PeerConn**：一条具体的底层连接/路径（可能同一对 peer 存在多条）。
- **PeerSession**：Peer 级别的安全会话状态（密钥、epoch、nonce、anti-replay、认证等级等）。
- **epoch**：数据面密钥版本号（key id）。编码进 12B nonce 的高 4B。
- **seq**：发送序号（per-direction 单调递增 u64）。编码进 12B nonce 的低 8B。
- **nonce12**：明文 12B nonce，按 `epoch||seq` 编码，附在密文尾部。
- **AAD**：AEAD 的附加认证数据。本文建议使用空 AAD（与项目当前的 ring/openssl 加密实现一致），未来可扩展为覆盖部分 header。

---

## 2. 关键 wire 结构（参考）

### 2.1 PeerManagerHeader（16B）

来自 [packet_def.rs](file:///data/project/EasyTier/easytier/src/tunnel/packet_def.rs#L93-L105)：

| 字段            |     类型 |    大小 |
| --------------- | -------: | ------: |
| from_peer_id    | u32 (LE) |       4 |
| to_peer_id      | u32 (LE) |       4 |
| packet_type     |       u8 |       1 |
| flags           |       u8 |       1 |
| forward_counter |       u8 |       1 |
| reserved        |       u8 |       1 |
| len             | u32 (LE) |       4 |
| **合计**        |          | **16B** |

### 2.2 AES-GCM 包尾（28B）

来自 [packet_def.rs](file:///data/project/EasyTier/easytier/src/tunnel/packet_def.rs#L266-L273)：

```text
AesGcmTail {
  tag:   [u8; 16]  // 16B
  nonce: [u8; 12]  // 12B
} // 合计 28B
```

ring ChaCha20-Poly1305 的尾部结构与之同形：
[ring_chacha20.rs](file:///data/project/EasyTier/easytier/src/peers/encrypt/ring_chacha20.rs#L8-L16)。

---

## 3. 数据面：nonce/epoch/seq 规格

### 3.1 Nonce12（12B，明文附在包尾）

定义：

| 字段     | 编码           |    大小 |
| -------- | -------------- | ------: |
| epoch    | u32 big-endian |       4 |
| seq      | u64 big-endian |       8 |
| **合计** |                | **12B** |

记为：

```text
nonce12 = epoch_be_u32 || seq_be_u64
```

### 3.2 发送端规则（每方向）

- `seq`：u64 单调递增，从 0 开始，每发送一个包 `seq += 1`。
- `epoch`：u32，初始为 0。轮换时 `epoch += 1` 并切换到新 key。
- `nonce12`：按 `epoch||seq` 生成，作为 AEAD nonce，同时明文写入包尾。

**安全性要求**：同一把 data key 下，`nonce12` 必须不重复。该要求通过“epoch 变化必然对应 key 变化 + 同一 epoch 内 seq 单调递增”保证。

### 3.3 接收端规则（每方向）

通信是双向的：双方都会为每个对端 peer 维护一份 `PeerSession`。其中发送方向状态用于生成 `nonce12`（见 3.2），接收方向状态用于乱序解密与 anti-replay（见本节与第 5 节）。本节仅描述“接收路径”的处理流程：

1. 从包尾读取 `nonce12`，解析出 `(epoch, seq)`。
2. 选择对应 epoch 的 data key（允许短期保留多个 epoch，见 6.2）。
3. 执行 anti-replay 检查（见 5）。
4. AEAD 解密 payload（tag 校验失败视为丢包）。

---

## 4. 数据面：AEAD 封装

### 4.1 选择算法

本文以“尾部 tag(16) + nonce(12)”为基准，兼容：

- AES-256-GCM（tag=16, nonce=12, key=32）
- ChaCha20-Poly1305（tag=16, nonce=12, key=32）

### 4.2 密文布局（以 AEAD tail 形式描述）

```text
wire_payload = ciphertext || tag16 || nonce12
```

其中：

- `ciphertext`：对原 payload 的加密结果（与原明文等长）
- `tag16`：AEAD tag（16B）
- `nonce12`：明文（12B），用于乱序解密与 anti-replay

### 4.3 AAD

默认：`AAD = empty`（与项目当前 ring encryptor 一致）。

扩展（可选）：未来可把 `PeerManagerHeader` 的部分字段纳入 AAD（例如 from/to/packet_type/flags），以抵御“改 header 不改密文”的攻击面。该扩展不影响 nonce/epoch/seq 设计。

---

## 5. anti-replay（最小内存配置）

### 5.1 默认窗口参数

- `window_size = 256`
- `keep_epochs = 2`（current + previous）
- `evict_idle_after = 30s`（某 epoch 长时间无包则回收其窗口与 key）

### 5.2 ReplayWindow256（概念结构与大小）

按“尽可能低内存”为目标，建议使用固定大小窗口（bitmap）：

```text
ReplayWindow256 {
  max_seq: u64        // 8B
  bitmap: [u8; 32]    // 256bit = 32B
} // 合计 40B（按字段大小计，不含语言实现的对齐/额外元数据）
```

说明：

- `bitmap` 的第 0 位表示 `max_seq` 是否已见；第 i 位表示 `max_seq - i` 是否已见。
- 若 `seq > max_seq`：右移窗口并置位。
- 若 `seq <= max_seq`：计算 `delta = max_seq - seq`，若 `delta >= 256` 丢弃（视为太旧）；否则检查 bitmap 是否已置位，已置位则丢弃（重放），未置位则接受并置位。

### 5.3 ReplayState（每个对端、每个方向、每个 epoch）

为减少内存，可用“固定 2 个 epoch 槽位”而非 HashMap：

```text
EpochRxSlot {
  epoch: u32              // 4B
  window: ReplayWindow256 // 40B
  last_rx_ms: u64         // 8B（用于 30s 淘汰）
  valid: bool             // 1B（实现细节）
}
```

每个对端、每个方向保留 2 个 `EpochRxSlot`：

- current_epoch_slot
- previous_epoch_slot

内存量级（按字段大小粗算）：

- 单方向：约 2 * (4 + 40 + 8 + 1) ≈ 106B
- 双方向：约 212B

加上 epoch key 缓存（见 6.2）仍处于“每对端几百字节”级别。

---

## 6. epoch 与密钥派生/轮换

### 6.1 密钥层次

推荐将 Noise 仅用于握手与认证绑定，数据面 key 由一个会话根密钥 `root_key` 派生：

```text
root_key: [u8; 32]  // 会话根密钥材料
```

随后对每个 epoch 与方向派生 traffic key：

```text
k(epoch, dir) = HKDF(root_key, "et-traffic" || epoch_u32_be || dir_byte)
```

- `dir_byte`：发送方向标识（例如 0=tx, 1=rx）
- 输出长度：32B（用于 AES-256-GCM 或 ChaCha20-Poly1305）

### 6.2 key 缓存（keep_epochs = 2）

对每个对端 peer、每个方向，缓存 2 个 epoch 的 key：

```text
EpochKeySlot {
  epoch: u32
  key: [u8; 32]   // 32B
  valid: bool
}
```

接收时按 `(epoch)` 选择 key；若 epoch 是 current 或 previous 则可解密，否则丢弃（或可选：尝试少量临近 epoch，代价是试解密）。

### 6.3 轮换策略（默认无额外控制消息）

为减少协议复杂度，默认策略：

- 发送端在满足“包数阈值”或“时间阈值”时将 `epoch += 1` 并开始使用新 key。
- 接收端不需要提前知道轮换点：从明文 `nonce12.epoch` 即可选择正确 key。
- 接收端保留 `keep_epochs=2`，保证轮换期间乱序旧包仍可解密。

可选增强（未来）：

- 若希望更强一致性，可定义一个控制包通告 `epoch_advance`，但不是本方案的必要条件。

---

## 7. 握手层：Noise_XX + 角色/认证/会话根密钥

### 7.1 目标

在每条 PeerConn 建立时运行 Noise_XX 握手，完成：

- 交换 `network_name`（尽早判断同网/共享节点）
- 完成共享节点 pubkey pinning（若配置）
- 完成 `network_secret_confirmed`（若双方都有 secret）
- 协商 PeerSession（join 或 create），并在需要时同步 `root_key` 与 `epoch` 起点

### 7.2 prologue

prologue 固定为协议版本字符串，不包含 `network_name`，以避免跨 network_name 的连接被拒绝：

```text
prologue = "easytier-peerconn-noise"
```

### 7.3 PeerSession：join / create / sync 规则

本文引入 Peer 级会话 `PeerSession`（每个对端 peer 一份），用于跨多条 PeerConn 复用数据面密钥与 anti-replay 状态。

#### 7.3.1 PeerSession 的身份字段

数据面不携带 `session_id`，因此会话的“索引键”是外层 `PeerManagerHeader.from_peer_id`（对端 peer_id）。但为了在握手阶段判断 join/create/sync，需要额外维护：

```text
PeerSessionMeta {
  session_generation: u32  // 4B，单调递增，会话根密钥 root_key 的版本号
  auth_level: u8           // 1B，对齐 secure_auth_level 的枚举语义
}
```

语义：

- `session_generation` 变化表示 `root_key` 发生轮换（create）。
- `session_generation` 不变表示复用已有 `root_key`（join）。

#### 7.3.2 参与方角色

- Initiator：发起连接的一方（A）
- Responder：接收连接的一方（B）

在本方案中，**Responder 对会话选择具有权威性**：最终使用哪一代 `root_key` 以 msg2 返回为准。

#### 7.3.3 Responder 的决策（核心）

Responder 在收到 msg1 后，读取 Initiator 提供的 `a_session_generation`（可选）并与本地 PeerSession 进行对比，按以下优先级决策：

1. **本地不存在 PeerSession**：执行 `CREATE`（生成新的 `root_key` 与 `session_generation=1`）。
2. **本地存在 PeerSession 且 a_session_generation 与本地一致**：执行 `JOIN`（不轮换 root_key）。
3. **本地存在 PeerSession 但 a_session_generation 缺失或不一致**：执行 `SYNC`（不轮换 root_key，但在 msg2 中携带当前 `root_key` 与 `session_generation`，使对端同步到本地会话）。

安全性与 DoS 说明：

- 默认不允许对端通过握手触发 root_key 轮换（避免对端反复拨号导致会话重置）。
- 只有在“本地不存在会话”或“本地策略显式要求轮换”（例如人工触发、密钥泄露处置）时才执行 `CREATE`。

#### 7.3.4 Initiator 的行为

Initiator 在握手开始前读取本地是否已有对端 PeerSession：

- 若存在：在 msg1 中携带本地 `a_session_generation`。
- 若不存在：msg1 不携带 `a_session_generation`。

Initiator 在收到 msg2 后：

- 若 msg2 为 `JOIN`：继续使用本地 `root_key` 与 `session_generation`（不重置 epoch/seq）。
- 若 msg2 为 `SYNC` / `CREATE` 且携带 `root_key`：用 msg2 携带的 `root_key` 覆盖本地会话，并将数据面计数器重置为 `initial_epoch`、`seq=0`，重放窗口清空。

### 7.4 握手 payload 编码：protobuf vs 固定布局

推荐使用 protobuf（pb）来编码 Noise 握手消息的 payload，原因：

- 易演进（字段可选、可扩展、兼容旧版本）
- 项目内已广泛使用 pb（例如 `HandshakeRequest`）
- 开销可控：除去字符串外，核心字段均为固定长度 bytes（16/32/12），pb 仅增加少量 tag/len varint

可选方案：固定布局。若你追求极致性能/可预测大小，可将同等字段按固定布局编码。本文以下默认以 protobuf 形式定义字段；固定布局可按同样字段直接平铺实现。

### 7.5 握手消息（Noise_XX 的 3 条消息）

记：

- msg1: A -> B（payload 明文）
- msg2: B -> A（payload 加密）
- msg3: A -> B（payload 加密）

#### 7.5.1 pb 定义（字段类型与语义大小）

下述为“协议级定义”（概念 proto），不要求立刻落入代码生成；实现可在 proto 中新增 message，或先在 Rust 侧用 prost 定义本地 message。

```proto
message PeerConnNoiseMsg1Pb {
  uint32 version = 1;                 // varint
  string a_network_name = 2;          // len <= 64 bytes (建议约束)
  optional uint32 a_session_generation = 3; // varint，可选
  bytes a_conn_id = 4;                // 16B (UUID)
}

enum PeerConnSessionActionPb {
  JOIN = 0;   // 不发送 root_key，表示“继续使用既有会话”
  SYNC = 1;   // 发送 root_key，用于对端同步到本地会话
  CREATE = 2; // 发送 root_key，表示本地新建会话
}

message PeerConnNoiseMsg2Pb {
  string b_network_name = 1;          // len <= 64 bytes
  uint32 role_hint = 2;               // 1=同网提示, 2=共享节点/外网提示

  PeerConnSessionActionPb action = 3; // JOIN/SYNC/CREATE
  uint32 b_session_generation = 4;    // varint

  optional bytes root_key_32 = 5;     // 32B，当 action=SYNC/CREATE 时必须存在
  uint32 initial_epoch = 6;           // u32（编码为 varint 或 fixed32 均可），建议语义为 BE u32 值

  bytes b_conn_id = 7;                // 16B (UUID)
  bytes a_conn_id_echo = 8;           // 16B (UUID)
}

message PeerConnNoiseMsg3Pb {
  bytes a_conn_id_echo = 1;           // 16B
  bytes b_conn_id_echo = 2;           // 16B

  // 可选：network_secret_confirmed 的 proof
  optional bytes secret_proof_32 = 3; // 32B
}
```

字段语义大小（不含 pb tag/len）：

- UUID：16B
- root_key：32B
- secret_proof：32B
- initial_epoch：4B（逻辑大小；pb 编码本身为 varint/fixed32，wire 大小可变或 4B）

#### 7.5.2 msg1 payload（A -> B，明文）

```text
payload_bytes = PeerConnNoiseMsg1Pb.encode_to_vec()
```

说明：

- 该 payload 为明文，因此不放 `root_key` 等敏感材料。
- `a_network_name` 用于角色提示。
- `a_session_generation` 用于 Responder 做 join/sync/create 决策。
- `a_conn_id` 用于本次连接绑定（防拼接），将在 msg2/msg3 回显。

#### 7.5.3 msg2 payload（B -> A，加密）

```text
payload_bytes = PeerConnNoiseMsg2Pb.encode_to_vec()
```

说明：

- `action` 决定本次握手是否会更新会话根密钥：
  - `JOIN`：不发送 `root_key_32`，表示“继续使用既有会话”
  - `SYNC`：发送 `root_key_32`，用于对端同步到本地既有会话
  - `CREATE`：发送 `root_key_32`，表示本地创建新会话
- `initial_epoch` 默认 0；若需要随机化，可设置为随机 u32，但需要接收端 key/窗口缓存支持更复杂的淘汰策略。
- `a_conn_id_echo` 与 `b_conn_id` 用于连接绑定；msg3 将回显两者以确认双方看到同一组值。

#### 7.5.4 msg3 payload（A -> B，加密）

```text
payload_bytes = PeerConnNoiseMsg3Pb.encode_to_vec()
```

`secret_proof_32`（可选）用于 `network_secret_confirmed`：

```text
secret_proof = HMAC-SHA256(
  key = derive(network_secret),
  data = role_byte || handshake_hash
)
```

其中 `handshake_hash` 由 Noise 提供，`role_byte` 用于区分双方角色（client/server）。

### 7.6 pinning（共享节点）

- 配置位置：`PeerConfig.peer_public_key`（base64，32B）。
- 校验时机：Noise 握手结束后，A 读取 `remote_static_pubkey`，若配置了 pinned 则必须匹配，否则断连。

---

## 8. 角色判断与安全语义

- `network_name` 的比较足以用于 **角色提示**：
  - `a_network_name == b_network_name`：同网提示
  - 否则：共享节点/外网提示
- 但 `network_name` **不是认证锚点**。安全决策仅应基于：
  - 共享节点 pinning 成功（`shared_node_pubkey_verified`）
  - 或 network_secret_confirmed 成功（`network_secret_confirmed`）
- 在未完成上述任一认证前，连接为 `encrypted_unauthenticated`：仅保证机密性/完整性，不保证对端身份，存在 MITM 风险。

---

## 9. 与包尾 nonce 加密格式的关系

项目当前的 ring chacha20 加密实现使用随机 nonce 并将 nonce 明文附在包尾：
[ring_chacha20.rs](file:///data/project/EasyTier/easytier/src/peers/encrypt/ring_chacha20.rs#L69-L93)

本文将随机 nonce 替换为结构化 `epoch||seq`：

- 仍为 12B
- 仍明文放包尾
- 但语义从“随机唯一”变为“可乱序解密 + 可 anti-replay + 可轮换”

---

## 10. 默认参数汇总

- nonce：12B = epoch(u32 BE) + seq(u64 BE)
- tag：16B
- key：32B（AES-256-GCM 或 ChaCha20-Poly1305）
- replay window：256（bitmap 32B）
- keep_epochs：2（current + previous）
- evict_idle_after：30s

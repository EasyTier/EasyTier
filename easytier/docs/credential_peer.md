# 临时凭据（Credential）系统实现计划

## Context

EasyTier 的 secure mode 已实现 Noise XX 握手 + X25519 静态公钥认证。当前节点通过 `network_secret` 双向确认身份。用户需要一种"临时凭据"机制：

- **管理节点**（任何持有 network_secret 的节点）可为当前网络生成凭据
- **新节点**可使用凭据代替 `network_secret` 加入网络
- **管理节点**可撤销凭据
- **撤销后**，使用该凭据接入的节点被全网踢出

**核心设计**：凭据 = X25519 密钥对。完全复用现有 Noise `Noise_XX_25519_ChaChaPoly_SHA256` 握手流程，无需修改握手消息格式。通过 OSPF 路由同步传播可信公钥列表，撤销时全网自然断开。

## 整体架构

```
凭据 = X25519 密钥对
  - 管理节点生成密钥对，将公钥加入可信列表
  - 临时节点持有私钥，用作 Noise static key
  - 全网通过 OSPF 路由同步可信公钥列表

管理节点 (持有 network_secret):
  1. generate_credential() → 生成 X25519 密钥对
  2. 公钥记入 trusted_credential_pubkeys → 随 RoutePeerInfo 通过 OSPF 传播
  3. revoke → 从 trusted 列表移除 → OSPF 同步 → 全网感知

临时节点 (持有凭据私钥):
  1. 使用凭据私钥作为 SecureModeConfig.local_private_key
  2. Noise 握手完全走现有流程（XX 模式交换 static pubkey）
  3. 不持有 network_secret，secret_proof 验证会失败，但公钥在可信列表中即可
  4. RoutePeerInfo.noise_static_pubkey 自然携带凭据公钥

校验逻辑（每个节点在路由同步时执行）:
  1. 从全网 RoutePeerInfo 中收集管理节点的 trusted_credential_pubkeys（取并集）
     **安全约束: 仅信任 secure_auth_level=NetworkSecretConfirmed 的节点发布的列表**
     临时节点（CredentialAuthenticated）发布的 trusted_credential_pubkeys 必须被忽略
  2. 对每个 peer，如果其 secure_auth_level < NetworkSecretConfirmed:
     - 检查其 noise_static_pubkey 是否在可信公钥集合中
     - 不在 → 从路由表移除 → 断开连接
```

## 详细设计

### Step 1: Protobuf 定义

**文件: `easytier/src/proto/peer_rpc.proto`**

在 `RoutePeerInfo` 新增字段（利用已有 `noise_static_pubkey` 字段 #18）:
```protobuf
message TrustedCredentialPubkey {
  bytes pubkey = 1;              // X25519 公钥 (32 bytes)
  repeated string groups = 2;   // 该凭据所属的 ACL group（管理节点声明，无需 proof）
  bool allow_relay = 3;         // 是否允许该临时节点提供 peer relay 能力
  int64 expiry_unix = 4;          // 必选：过期时间（Unix timestamp），过期后自动失效
  repeated string allowed_proxy_cidrs = 5; // 允许该临时节点声明的 proxy_cidrs 范围
}

message RoutePeerInfo {
  // ... existing fields 1-18 ...
  // 管理节点发布的可信凭据公钥列表（含 group 关联）
  repeated TrustedCredentialPubkey trusted_credential_pubkeys = 19;
}
```

临时节点无需新字段——其 `noise_static_pubkey`（字段 18）已经在 OSPF 中传播，只需在校验端判断该公钥是否在可信列表中。

新增 `SecureAuthLevel` 枚举值:
```protobuf
enum SecureAuthLevel {
  None = 0;
  EncryptedUnauthenticated = 1;
  SharedNodePubkeyVerified = 2;
  NetworkSecretConfirmed = 3;
  CredentialAuthenticated = 4;  // 新增：凭据公钥已验证
}
```

**文件: `easytier/src/proto/api_instance.proto`**

新增凭据管理 RPC:
```protobuf
message GenerateCredentialRequest {
  repeated string groups = 1;   // 可选: 凭据关联的 ACL group
  bool allow_relay = 2;         // 可选: 是否允许该临时节点提供 peer relay
  repeated string allowed_proxy_cidrs = 3; // 可选: 限制可声明的 proxy_cidrs
  int64 ttl_seconds = 4;        // 必选: 凭据有效期（秒）
}
message GenerateCredentialResponse {
  string credential_id = 1;       // 公钥的 base64
  string credential_secret = 2;   // 私钥的 base64
}
message RevokeCredentialRequest { string credential_id = 1; }
message RevokeCredentialResponse { bool success = 1; }
message ListCredentialsRequest {}
message CredentialInfo {
  string credential_id = 1;       // 公钥 base64
  google.protobuf.Timestamp created_at = 2;
}
message ListCredentialsResponse { repeated CredentialInfo credentials = 1; }

service CredentialManageRpc {
  rpc GenerateCredential(GenerateCredentialRequest) returns (GenerateCredentialResponse);
  rpc RevokeCredential(RevokeCredentialRequest) returns (RevokeCredentialResponse);
  rpc ListCredentials(ListCredentialsRequest) returns (ListCredentialsResponse);
}
```

### Step 2: 凭据管理模块

**新文件: `easytier/src/peers/credential_manager.rs`**

```rust
use x25519_dalek::{StaticSecret, PublicKey};

pub struct CredentialManager {
    // 本节点管理的可信凭据
    credentials: DashMap<String, CredentialEntry>,  // credential_id (pubkey base64) -> entry
    storage_path: Option<PathBuf>,                  // 可选: 凭据 JSON 文件路径
}

struct CredentialEntry {
    pubkey_bytes: [u8; 32],
    groups: Vec<String>,           // 关联的 ACL group（管理节点声明）
    allow_relay: bool,             // 是否允许 relay
    allowed_proxy_cidrs: Vec<String>, // 允许声明的 proxy_cidrs 范围
    expiry: SystemTime,             // 过期时间（必选）
    created_at: SystemTime,
}

impl CredentialManager {
    /// 生成新凭据（含 group 关联）
    /// 返回 (credential_id=公钥base64, credential_secret=私钥base64)
    pub fn generate_credential(&self, groups: Vec<String>, allow_relay: bool, expiry: SystemTime) -> (String, String) {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        let id = BASE64_STANDARD.encode(public.as_bytes());
        let secret = BASE64_STANDARD.encode(private.as_bytes());
        self.credentials.insert(id.clone(), CredentialEntry {
            pubkey_bytes: *public.as_bytes(),
            groups,
            allow_relay,
            expiry,  // 由调用方传入
            created_at: SystemTime::now(),
        });
        self.save_to_disk();  // 持久化
        (id, secret)
    }

    /// 撤销凭据
    pub fn revoke_credential(&self, credential_id: &str) -> bool;

    /// 获取可信凭据列表（用于 RoutePeerInfo.trusted_credential_pubkeys）
    pub fn get_trusted_pubkeys(&self) -> Vec<TrustedCredentialPubkey>;

    /// 列出所有凭据
    pub fn list_credentials(&self) -> Vec<CredentialInfo>;
}
```

### Step 3: Noise 握手适配（最小改动）

**文件: `easytier/src/peers/peer_conn.rs`**

临时节点的握手流程**完全不需要修改**，因为:
- 临时节点配置 `SecureModeConfig { enabled: true, local_private_key: 凭据私钥, local_public_key: 凭据公钥 }`
- `get_keypair()` (line 434) 自然返回凭据密钥对
- Noise XX 握手正常交换 static pubkey
- 唯一区别：`secret_proof_32` 验证会失败（临时节点没有 network_secret）

需要修改 `do_noise_handshake_as_server()` (line 934):
- **当前行为**: `secret_proof` 验证失败 → 返回错误断开连接 (line 1059)
- **修改为**: `secret_proof` 验证失败时，不立即断开，而是将 `secure_auth_level` 保持为 `EncryptedUnauthenticated`
- 后续由 OSPF 路由同步阶段决定该 peer 是否可信（公钥是否在 trusted 列表中）

同样修改 `do_noise_handshake_as_client()` (line 680):
- 当临时节点连接管理节点时，`secret_proof` 验证失败不应报错
- 临时节点可以通过 `pinned_remote_pubkey` 或不验证来处理

**NoiseHandshakeResult** 新增:
```rust
// 标记此连接使用了凭据而非 network_secret
is_credential_conn: bool,
```

### Step 4: RoutePeerInfo 传播凭据信息

**文件: `easytier/src/peers/peer_ospf_route.rs`**

修改 `RoutePeerInfo::new_updated_self()` (line 164):
- 管理节点（持有 network_secret）: 从 `CredentialManager.get_trusted_pubkeys()` 获取列表，填入 `trusted_credential_pubkeys`
- 临时节点: **不填写 `trusted_credential_pubkeys`**（该字段留空），即使收到其他管理节点传播的列表也不转发
  - 实现方式: 在 `new_updated_self()` 中检查节点身份，临时节点跳过 trusted_credential_pubkeys 填充
- 临时节点: 无需额外操作，`noise_static_pubkey` 已自然包含凭据公钥

### Step 5: 全网校验与自动踢出（核心逻辑）

**文件: `easytier/src/peers/peer_ospf_route.rs`**

在 `SyncedRouteInfo` 中新增:
```rust
// 从全网管理节点汇总的可信凭据公钥集合
trusted_credential_pubkeys: DashSet<Vec<u8>>,  // pubkey bytes
```

新增校验方法（类似 `verify_and_update_group_trusts` line 743）:
```rust
fn verify_credential_peers(&self, peer_infos: &[RoutePeerInfo]) {
    // 1. 收集管理节点的 trusted_credential_pubkeys（取并集）
    //    **安全约束: 仅信任 secret_digest 与本网络匹配的节点（即持有 network_secret 的管理节点）**
    //    临时节点的 trusted_credential_pubkeys 直接忽略，防止恶意临时节点自我授权
    let mut all_trusted = HashSet::new();
    for info in peer_infos {
        if self.is_peer_secret_verified(info.peer_id) {
            // 该 peer 通过了 network_secret 双向确认，是合法管理节点
            for tc in &info.trusted_credential_pubkeys {
                all_trusted.insert(tc.pubkey.clone());
            }
        }
        // else: 该 peer 未通过 network_secret 确认（含临时节点），忽略其 trusted 列表
    }
    self.trusted_credential_pubkeys = all_trusted;

    // 2. 检查所有 peer 的凭据状态
    for info in peer_infos {
        if !self.is_peer_secret_verified(info.peer_id)
           && !info.noise_static_pubkey.is_empty()
        {
            if !self.trusted_credential_pubkeys.contains(&info.noise_static_pubkey) {
                // 该 peer 既不持有 network_secret，其公钥也不在可信列表中
                // → 标记为不可信，后续从路由表移除
                self.mark_peer_untrusted(info.peer_id);
            }
        }
    }
}
```

在 `do_sync_route_info()` (line 2614) 中调用此校验。

在路由表构建中（`update_route_table_and_cached_local_conn_bitmap()`）:
- 不可信 peer 不加入路由图
- 已连接的不可信 peer 调用 `PeerMap::close_peer()` 断开

**判断 peer 是否持有 network_secret**: 利用现有 `secret_digest` 字段。管理节点的 `RoutePeerInfo` 中 `secret_digest` 与本节点匹配，说明双方持有相同的 network_secret。

### Step 6: GlobalCtx / Config 集成

**文件: `easytier/src/common/global_ctx.rs`**

在 `GlobalCtx` 新增:
```rust
credential_manager: Arc<CredentialManager>,  // 所有节点都持有，管理节点用于生成/撤销
```

**文件: `easytier/src/common/global_ctx.rs` - `GlobalCtxEvent`**

新增:
```rust
CredentialChanged,  // 触发 OSPF 立即同步
```

**文件: `easytier/src/common/config.rs`**

临时节点的配置方式: 直接使用凭据私钥作为 `SecureModeConfig.local_private_key`。
可在 `TomlConfigLoader` 中新增便捷字段或 CLI 参数:
- `--credential <私钥base64>`: 临时节点使用凭据私钥加入网络
- `--credential-file <path>`: 管理节点指定凭据存储 JSON 文件路径

### Step 7: RPC 服务 + CLI

**文件: `easytier/src/peers/rpc_service.rs`**

实现 `CredentialManageRpc`，参考 `PeerManagerRpcService` 模式。

**CLI** (`easytier-cli`):
```
easytier-cli credential generate
  输出: credential_id=<公钥base64>  credential_secret=<私钥base64>

easytier-cli credential revoke <credential_id>
easytier-cli credential list
```

**临时节点启动**:
```bash
# 方式1: 直接传入凭据私钥
easytier-core --network-name test \
  --secure-mode \
  --credential <私钥base64> \
  --peers tcp://管理节点:11010

# 内部实现: 将凭据私钥设为 SecureModeConfig.local_private_key
```

### Step 8: 连接时验证（握手后快速拒绝，必选）

在 `do_noise_handshake_as_server()` 完成后，**必须**进行快速检查:
- 如果对端 `secret_proof` 验证失败（非管理节点），且对端 `noise_static_pubkey` 不在本节点已知的 `trusted_credential_pubkeys` 中
- 立即断开连接

这是**必选的安全措施**（非可选优化）。因为 Step 3 放宽了 secret_proof 失败的处理，如果不做快速拒绝，任何随机节点都能与管理节点建立加密连接并持有，浪费资源。

```rust
// 在 handshake 完成后
if !secret_proof_verified {
    let remote_pubkey = handshake_result.remote_static_pubkey;
    if !self.global_ctx.credential_manager.is_pubkey_trusted(&remote_pubkey) {
        return Err(Error::AuthError("unknown credential".to_string()));
    }
    // 公钥在 trusted 列表中 → 允许连接，标记为 CredentialAuthenticated
    handshake_result.secure_auth_level = SecureAuthLevel::CredentialAuthenticated;
}
```

## 关键文件清单

| 文件 | 修改内容 |
|------|----------|
| `easytier/src/proto/peer_rpc.proto` | `RoutePeerInfo` 加 `trusted_credential_pubkeys`; `SecureAuthLevel` 加 `CredentialAuthenticated` |
| `easytier/src/proto/api_instance.proto` | 新增 `CredentialManageRpc` 服务及消息定义 |
| `easytier/src/peers/credential_manager.rs` | **新文件** — 凭据管理器（密钥对生成/撤销/列表） |
| `easytier/src/peers/mod.rs` | 导出 credential_manager |
| `easytier/src/peers/peer_ospf_route.rs` | `new_updated_self()` 填 trusted_pubkeys; 新增 `verify_credential_peers()`; 路由表过滤 |
| `easytier/src/peers/peer_conn.rs` | `do_noise_handshake_as_server()` 放宽 secret_proof 失败为非致命; 可选握手阶段快速拒绝 |
| `easytier/src/peers/peer_manager.rs` | 集成 CredentialManager; 不可信 peer 断连逻辑 |
| `easytier/src/common/global_ctx.rs` | 持有 CredentialManager; 新增 CredentialChanged 事件 |
| `easytier/src/common/config.rs` | 新增 `--credential` 参数处理 |
| `easytier/src/peers/rpc_service.rs` | 实现 CredentialManageRpc |
| `easytier/src/proto/common.rs` | SecureModeConfig 可选: credential 模式识别 |

## 复用现有机制

| 现有机制 | 路径 | 复用方式 |
|----------|------|----------|
| Noise XX 握手 | `peer_conn.rs:680,934` | 临时节点直接使用凭据密钥对走完整 Noise 流程 |
| `SecureModeConfig` | `proto/common.rs:367` | 临时节点的凭据私钥直接设为 local_private_key |
| `noise_static_pubkey` | `RoutePeerInfo` 字段 18 | 临时节点的凭据公钥已在 OSPF 中传播 |
| `verify_and_update_group_trusts()` | `peer_ospf_route.rs:743` | 凭据校验逻辑参考此模式 |
| `PeerMap::close_peer()` | `peer_map.rs:317` | 断开不可信 peer |
| OSPF 路由同步 | `SyncRouteInfoRequest` | 可信公钥列表随 RoutePeerInfo 自然传播 |
| `PeerManagerRpcService` | `rpc_service.rs:24` | RPC 服务实现模式 |
| `GlobalCtxEvent` | `global_ctx.rs:32` | 新增事件触发同步 |

## 验证方案

1. **单元测试**:
   - `credential_manager.rs`: 密钥对生成、撤销、列表
   - `peer_conn.rs`: 凭据节点 Noise 握手成功（无 network_secret）

2. **集成测试** (参考 `tests/three_node.rs`):
   - 3 节点: A + B (管理节点, network_secret) + C (临时节点, credential)
   - A 生成凭据（groups=["guest"]）→ C 使用凭据连接 → 验证 C 加入路由表、可达
   - 验证 C 的 ACL group 为 "guest"，配置 group ACL 规则后生效
   - A 撤销凭据 → 等待 OSPF 同步 (~1-3s) → 验证 C 被 A 和 B 断开
   - C 尝试重连 → 验证握手阶段被拒

3. **手动测试**:
   ```bash
   # A: 管理节点
   easytier-core -n test -s secret --secure-mode --listeners tcp://0.0.0.0:11010
   easytier-cli credential generate  # → credential_id + credential_secret

   # C: 临时节点
   easytier-core -n test --secure-mode --credential <私钥base64> --peers tcp://A:11010

   # 验证后撤销
   easytier-cli credential revoke <credential_id>
   # C 数秒内被踢出
   ```

### Step 9: 临时节点 OSPF 路由限制

**约束**: 临时节点传播的路由信息不可信，需严格限制。

#### 9a. 管理节点不主动发起到临时节点的 OSPF session

**核心原则**: OSPF `maintain_sessions()` 构建最小生成树时，只在管理节点之间选择 initiator，不将临时节点纳入 `dst_peer_id_to_initiate`。但管理节点**被动接受**临时节点发起的 session。

**文件: `easytier/src/peers/peer_ospf_route.rs`**

修改 `maintain_sessions()` (line 2485):
- 在构建 `dst_peer_id_to_initiate` 候选列表时，过滤掉临时节点
- 管理节点之间的 MST 不受影响

```rust
// 在 maintain_sessions() 中，构建 initiator 候选时过滤临时节点
let peers: Vec<PeerId> = peers.into_iter().filter(|peer_id| {
    // 只主动发起到管理节点的 session，不主动连临时节点
    !self.is_credential_peer(*peer_id)
}).collect();
```

- **临时节点自身**: 在 `maintain_sessions()` 中只将管理节点作为 initiator 候选，跳过其他临时节点

```rust
// 临时节点侧: 只主动连管理节点
if self.is_credential_node() {
    let peers: Vec<PeerId> = peers.into_iter().filter(|peer_id| {
        !self.is_credential_peer(*peer_id)  // 只连管理节点
    }).collect();
}
```

**session 建立方式**:
- **管理节点 → 管理节点**: 正常 MST initiator 选择（不变）
- **临时节点 → 管理节点**: 临时节点主动发起 session，管理节点被动接受
- **临时节点 → 临时节点**: 不建立（双方都过滤掉对方）
- **管理节点 → 临时节点**: 不主动发起（不在 initiator 候选中）

**路由信息传播**: 临时节点通过其主动发起的 session 调用 `sync_route_info` 推送自身 RoutePeerInfo。管理节点在正常 OSPF sync 中将其代理传播给其他管理节点。管理节点也通过该 session 向临时节点推送完整路由表。

#### 9b. 管理节点只选择性接收临时节点的路由信息

**文件: `easytier/src/peers/peer_ospf_route.rs`**

临时节点通过其主动发起的 session 调用 `sync_route_info`，管理节点在处理时需做过滤：

- 只接收该临时节点**自己的** `RoutePeerInfo`（`route_info.peer_id == dst_peer_id`），丢弃其声称的其他 peer 的路由信息
- 对临时节点自身的 RoutePeerInfo，过滤其 `proxy_cidrs`：只保留在 `TrustedCredentialPubkey.allowed_proxy_cidrs` 范围内的网段，移除超出范围的声明
- 临时节点的 `foreign_network_infos` 应忽略
- 临时节点的 `conn_info`（连接拓扑）**根据 `allow_relay` 标志决定**（见下方）

修改 `update_peer_infos()` (line 461):

```rust
fn update_peer_infos(
    &self, my_peer_id, my_peer_route_id, dst_peer_id,
    peer_infos, raw_peer_infos,
) -> Result<(), Error> {
    let dst_is_credential_peer = self.is_credential_peer(dst_peer_id);

    for (idx, route_info) in peer_infos.iter().enumerate() {
        // 临时节点只允许传播自己的路由信息
        if dst_is_credential_peer && route_info.peer_id != dst_peer_id {
            tracing::debug!(
                ?dst_peer_id, peer_id=?route_info.peer_id,
                "ignoring route info from credential peer for other peer"
            );
            continue;
        }

        // 过滤临时节点的 proxy_cidrs，只保留凭据允许的范围
        if dst_is_credential_peer {
            let allowed = self.get_credential_allowed_proxy_cidrs(dst_peer_id);
            if let Some(allowed_cidrs) = allowed {
                route_info.proxy_cidrs.retain(|cidr| {
                    allowed_cidrs.iter().any(|a| cidr_is_subset(cidr, a))
                });
            }
        }
        // ... existing logic ...
    }
}
```

修改 `do_sync_route_info()` (line 2614):

```rust
// 在 do_sync_route_info 中
let from_is_credential = self.is_credential_peer(from_peer_id);
let credential_allows_relay = from_is_credential
    && self.is_credential_relay_allowed(from_peer_id);

if let Some(peer_infos) = &peer_infos {
    // update_peer_infos 内部会过滤临时节点的非自身信息
    service_impl.synced_route_info.update_peer_infos(...);
}

// 临时节点的 conn_info: 仅当 allow_relay=true 时接收
if let Some(conn_info) = &conn_info {
    if !from_is_credential || credential_allows_relay {
        service_impl.synced_route_info.update_conn_info(conn_info);
    }
}

// 临时节点的 foreign_network_infos 始终不接收
if let Some(foreign_network) = &foreign_network {
    if !from_is_credential {
        service_impl.synced_route_info.update_foreign_network(foreign_network);
    }
}
```

**conn_info 处理**:
- 临时节点的 `conn_info`: 根据凭据的 `allow_relay` 标志决定是否接收
  - `allow_relay = true`: 管理节点接收并传播该临时节点的 conn_info，使其参与路由图，可作为 relay 转发数据
  - `allow_relay = false`（默认）: 忽略 conn_info，该临时节点不参与中继（仅作为叶子节点存在于路由图中）
- 临时节点的 `foreign_network_infos` 始终忽略

**`is_credential_relay_allowed()` 实现**:
```rust
fn is_credential_relay_allowed(&self, peer_id: PeerId) -> bool {
    // 从全网汇总的 trusted_credential_pubkeys 中查找该 peer 的凭据
    // 检查对应 TrustedCredentialPubkey.allow_relay 标志
    let peer_info = self.peer_infos.read();
    if let Some(info) = peer_info.get(&peer_id) {
        for tc in &self.all_trusted_credentials {
            if tc.pubkey == info.noise_static_pubkey {
                return tc.allow_relay;
            }
        }
    }
    false
}
```

**注意**: 即使 `allow_relay=true`，临时节点仍然不能转发握手包（Step 10b 限制不变），因此不会有新节点通过 relay 临时节点接入网络。relay 能力仅用于已建立连接的 peer 之间的数据转发。

#### 9c. 临时节点的 `RoutePeerInfo` 中的 `trusted_credential_pubkeys` 被忽略

已在 Step 5 中说明：只信任 `secret_digest` 匹配的管理节点发布的 trusted 列表。

#### 判断 peer 是否为临时节点的方法

在 `SyncedRouteInfo` / `PeerRouteServiceImpl` 中新增:
```rust
fn is_credential_peer(&self, peer_id: PeerId) -> bool {
    // 方法: 检查该 peer 的 RoutePeerInfo
    // 1. 如果 peer 的 noise_static_pubkey 在 trusted_credential_pubkeys 中 → 是临时节点
    // 2. 如果 peer 通过了 network_secret 确认 (secret_digest 匹配) → 是管理节点
    // 3. 在 peer_conn 握手后，可以记录 secure_auth_level 到连接信息中
    let peer_info = self.synced_route_info.peer_infos.read();
    if let Some(info) = peer_info.get(&peer_id) {
        if !info.noise_static_pubkey.is_empty()
            && self.trusted_credential_pubkeys.contains(&info.noise_static_pubkey) {
            return true;
        }
    }
    false
}
```

对于直连 peer，也可以在握手阶段直接记录 `secure_auth_level`，用于快速判断。

### Step 10: 禁止通过临时节点接入网络

**约束**: 不得有新节点（无论是否持有 network_secret）通过临时节点的 listener 接入网络。但允许通过管理节点中继后建立 P2P 连接。

#### 10a. 临时节点天然无法接受新节点接入（无需额外代码）

临时节点作为 listener 时，新节点的连接会**自然失败**，因为：
1. 临时节点没有 `network_secret`，无法验证对端的 `secret_proof` → 无法确认对端是管理节点
2. 临时节点不发布 `trusted_credential_pubkeys` → 对端公钥不在可信列表中
3. 对端也无法验证临时节点的 `secret_proof`（临时节点没有 network_secret）

因此 **不需要在 `add_tunnel_as_server()` 中添加显式拦截逻辑**。已有的 Noise 握手 + 凭据校验机制已足够阻止新节点通过临时节点接入。

**例外**: 已知的管理节点可以连接到临时节点（如 P2P hole punch 场景），因为管理节点的公钥已通过 OSPF 同步被临时节点知晓，握手可以成功。

#### 10b. 临时节点不转发来自未知 peer 的连接请求

**文件: `easytier/src/peers/peer_manager.rs`**

在 packet forwarding 路径 (line 718-766) 中:
- 临时节点不应转发 `HandShake` / `NoiseHandshakeMsg*` 类型的包
- 这防止新节点通过临时节点的中继接入网络

```rust
// 在 peer_recv 循环的 forward 分支中
if to_peer_id != my_peer_id {
    // 临时节点不转发握手包（阻止新节点通过临时节点接入）
    if is_credential_node && (
        hdr.packet_type == PacketType::HandShake as u8
        || hdr.packet_type == PacketType::NoiseHandshakeMsg1 as u8
        || hdr.packet_type == PacketType::NoiseHandshakeMsg2 as u8
        || hdr.packet_type == PacketType::NoiseHandshakeMsg3 as u8
    ) {
        tracing::debug!("credential node dropping forwarded handshake packet");
        continue;
    }
    // ... existing forward logic ...
}
```

#### 10c. P2P 连接通过管理节点中继仍然允许

P2P hole punch 的流程:
1. 两个节点通过管理节点交换打洞信息（RPC）
2. 建立直接 P2P tunnel
3. 在 P2P tunnel 上握手

这个流程不受影响，因为:
- 打洞信息交换通过管理节点中继（RPC），不经过临时节点
- P2P tunnel 建立后的握手是直连，不通过临时节点的 listener
- `is_directly_connected=false` 的连接（hole punch 结果）可以被临时节点接受

**设计思路**: 将凭据映射为 ACL Group，复用现有的 group-based ACL 规则系统。

现有 ACL 系统已支持基于 group 的规则匹配:
- `Rule.source_groups` / `Rule.destination_groups` (acl.proto:72-73)
- `PeerGroupInfo` 通过 HMAC proof 验证 peer 所属 group (peer_rpc.rs:8-38)
- `verify_and_update_group_trusts()` 在 OSPF 同步时更新 group trust map (peer_ospf_route.rs:743)
- `get_peer_groups()` 返回 peer 所属的 group 列表，用于 ACL 匹配 (peer_ospf_route.rs:2287)

**方案**: 生成凭据时，为每个凭据创建一个隐式 ACL Group。

1. **凭据生成时**: 管理节点为凭据创建一个关联的 group:
   - group_name = `"credential:<credential_id>"` 或用户自定义名称
   - group_secret = 由 credential_secret 派生的密钥
   - 可选：指定凭据所属的 group_name（批量管理，如 `"guest"`, `"contractor"`）

2. **临时节点加入时**: 临时节点使用凭据私钥连接。其 group 归属由管理节点在 `TrustedCredentialPubkey.groups` 中声明（无需临时节点自己提供 group proof）。验证节点在 `verify_credential_peers()` 中匹配公钥后，直接将声明的 groups 加入 `group_trust_map`。

3. **ACL 规则配置**: 管理员可配置基于 group 的 ACL 规则:
   ```toml
   # 示例配置: 限制 "guest" group 只能访问特定子网
   [[acl.acl_v1.chains]]
   name = "inbound"
   chain_type = "Inbound"
   default_action = "Allow"

   [[acl.acl_v1.chains.rules]]
   name = "restrict_guest"
   source_groups = ["guest"]
   destination_ips = ["10.0.0.0/24"]
   action = "Drop"
   ```

4. **管理节点发布 group 信息**:
   - 在 `RoutePeerInfo.trusted_credential_pubkeys` 中传播可信公钥时，同时包含关联的 group 信息
   - 扩展 proto:
   （使用 Step 1 中定义的 `TrustedCredentialPubkey`，group 归属由管理节点声明，无需 proof 验证）
   - 替换 `repeated bytes trusted_credential_pubkeys` 为 `repeated TrustedCredentialPubkey trusted_credential_pubkeys`

5. **校验节点处理**: 在 `verify_credential_peers()` 中:
   - 验证凭据公钥在可信列表中后
   - 直接将 `TrustedCredentialPubkey.groups` 中声明的 group 加入 `group_trust_map` / `group_trust_map_cache`（无需验证 group proof，因为管理节点的声明已是可信的）
   - ACL filter 在处理数据包时自动基于 group 匹配规则

**API 扩展**:

生成凭据时可指定 group:
```protobuf
message GenerateCredentialRequest {
  repeated string groups = 1;           // 可选: 为该凭据关联的 group 名称
  bool allow_relay = 2;                 // 可选: 是否允许 relay
  repeated string allowed_proxy_cidrs = 3; // 可选: 限制可声明的 proxy_cidrs
  int64 ttl_seconds = 4;               // 必选: 凭据有效期（秒）
}
```

CLI:
```bash
# 生成带 group 的凭据，有效期 24 小时
easytier-cli credential generate --groups guest,restricted --ttl 86400

# 生成允许 relay 的凭据，有效期 7 天
easytier-cli credential generate --groups relay-node --allow-relay --ttl 604800

# 最简用法（默认 group 名为 "credential"）
easytier-cli credential generate --ttl 3600
```

## 安全审查

### 已覆盖的安全性

- **端到端加密**: 数据包在源端加密、目的端解密，relay 节点（含 `allow_relay` 的临时节点）无法看到明文
- **临时节点自我授权防护**: 只信任 `secret_digest` 匹配的管理节点发布的 `trusted_credential_pubkeys`
- **临时节点路由篡改防护**: 只接收临时节点自身的 RoutePeerInfo，忽略其转发的其他路由
- **临时节点网络接入防护**: 临时节点天然无法接受新节点接入（无 network_secret、不发布 trusted 列表）

### 需要关注的安全问题

**1. Step 8 握手后快速拒绝应为必选（非可选）**

当前 Step 8 标记为"可选优化"，但实际上是**必须的安全措施**。如果不做快速拒绝：
- 任何随机节点（无 credential、无 network_secret）都能完成 Noise 握手（因为 Step 3 放宽了 secret_proof 失败）
- 在等待 OSPF 同步验证期间，该节点持有一个有效的加密连接，浪费资源
- **修改**: Step 8 改为必选。握手完成后立即检查：对端 secret_proof 失败 + 公钥不在本节点已知的 trusted 列表中 → 立即断开

**2. Group proof 验证机制需要明确**

当前方案：临时节点在 `RoutePeerInfo.groups` 中携带 `PeerGroupInfo`（HMAC proof），管理节点在 `TrustedCredentialPubkey` 中传播 `group_secret_hash`。

问题：HMAC 验证需要**原始 secret**，不是 hash。验证节点如何知道 credential 的 group secret？

**解决方案**: `TrustedCredentialPubkey.group_secret_hash` 改为 `group_secret_digest`，使用与现有 `NetworkIdentity.network_secret_digest` 相同的 digest 算法。验证时：
- 管理节点在 `TrustedCredentialPubkey` 中包含 `group_secret_digest`
- 临时节点发送的 `PeerGroupInfo` 中包含 `group_proof`（HMAC）
- 验证节点无法直接验证 HMAC（没有原始 secret），但可以信任管理节点的声明：如果管理节点在 `TrustedCredentialPubkey.groups` 中列出了某个 group，且临时节点的公钥匹配，就直接信任该 group 归属
- 即：**group 归属由管理节点在 `TrustedCredentialPubkey` 中声明，无需临时节点提供 proof**
- 这简化了实现，且安全性不降低（管理节点已是可信源）

**3. 凭据持久化**

`CredentialManager` 当前设计为内存存储。管理节点重启后所有凭据丢失，导致使用这些凭据的临时节点被踢出。

**解决方案**:
- 管理节点可配置凭据存储的 JSON 文件路径（如 `--credential-file /path/to/credentials.json`）
- `CredentialManager` 启动时从该文件加载已有凭据
- 生成/撤销凭据时自动写入该文件
- 未配置文件路径时，凭据仅存内存（重启丢失）

**4. 同一凭据多节点复用**

同一个 credential 私钥可以被多个节点同时使用。它们有不同的 `peer_id` 但相同的 `noise_static_pubkey`。这会导致：
- 路由表中多个 RoutePeerInfo 有相同的 `noise_static_pubkey`
- 撤销时所有使用该凭据的节点同时被踢出（符合预期）
- **这是预期行为**，但应在文档中说明

**5. 临时节点 proxy_cidrs 限制**

临时节点可能声明虚假的 `proxy_cidrs`（子网代理），导致流量黑洞。

**解决方案**（已纳入设计）:
- 生成凭据时通过 `allowed_proxy_cidrs` 字段限制该凭据可声明的网段范围
- 管理节点在 Step 9b 的 `update_peer_infos()` 中过滤：只保留临时节点声明的 proxy_cidrs 中属于 `allowed_proxy_cidrs` 子集的网段
- 未配置 `allowed_proxy_cidrs` 时（空列表），临时节点不允许声明任何 proxy_cidrs

**6. 凭据过期时间（TTL）**

凭据必须设置过期时间。过期后自动失效，等同于被撤销。
- 生成凭据时必须指定 `--ttl` 或 `--expiry`
- `verify_credential_peers()` 中检查 `expiry_unix`，过期的凭据从可信列表中移除
- 过期检查在每次路由同步时执行，无需额外定时器

## 优势

- **最小改动**: Noise 握手消息格式不变，完全复用现有流程
- **安全性**: X25519 密钥对提供强身份认证，不弱于 network_secret；端到端加密保护 relay 场景
- **自然传播**: 利用 OSPF 已有基础设施，无需新 RPC
- **去中心化撤销**: 任何管理节点都可撤销，全网通过路由同步感知
- **ACL 复用**: 凭据映射为 ACL Group，完全复用现有 group-based ACL 规则系统，无需新的 ACL 机制

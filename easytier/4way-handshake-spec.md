# 规范：EasyTier 四次握手认证实现

## 当前问题
当前的认证机制直接在 `HandshakeRequest` 消息中通过 `network_secret_digrest` 字段发送 PSK（预共享密钥）的哈希值。这存在以下安全隐患：
1. 哈希值可以被捕获并重放
2. 没有双向认证 - 只有单向验证
3. 没有新鲜性保证 - 无法防御重放攻击

## 解决方案：基于挑战-响应的四次握手

### 概述
实现一个安全的四次握手协议，使用随机数（nonce）的挑战-响应认证机制，在不暴露共享密钥的情况下证明拥有该密钥。

### 协议流程

**四次握手序列：**
1. **客户端 → 服务端**: 初始 `HandshakeRequest`（不含密钥摘要）
2. **服务端 → 客户端**: `HandshakeRequest` + `ChallengeRequest`（包含服务端随机数）
3. **客户端 → 服务端**: `ChallengeResponse`（服务端随机数的 HMAC）+ `ChallengeRequest`（包含客户端随机数）
4. **服务端 → 客户端**: `ChallengeResponse`（客户端随机数的 HMAC）

### 实现细节

#### 1. Protocol Buffer 更新 (`proto/peer_rpc.proto`)
```protobuf
// 添加新消息类型
message ChallengeRequest {
    bytes nonce = 1; // 32字节随机数
}

message ChallengeResponse {
    bytes response = 1; // HMAC-SHA256 结果
}

// 更新 HandshakeRequest - 移除 network_secret_digrest
message HandshakeRequest {
    uint32 magic = 1;
    uint32 my_peer_id = 2;
    uint32 version = 3;
    repeated string features = 4;
    string network_name = 5;
    // bytes network_secret_digrest = 6; // 完全移除，不需要兼容
    
    // 四次握手的新字段
    optional ChallengeRequest challenge_request = 7;
    optional ChallengeResponse challenge_response = 8;
}
```

#### 2. 核心认证逻辑 (`peers/peer_conn.rs`)

**新增方法：**
- `generate_challenge()` - 使用 `OsRng` 创建 32 字节随机数
- `compute_challenge_response(challenge: &[u8], network_secret: &str, my_peer_id: u32, remote_peer_id: u32, network_name: &str, is_client: bool) -> [u8; 32]`
  - 计算方式：`HMAC-SHA256(network_secret, challenge || my_peer_id || remote_peer_id || network_name || role || "EASYTIER_HANDSHAKE")`
  - `role` 为 "CLIENT" 或 "SERVER"，防止反射攻击
  - 包含固定字符串 "EASYTIER_HANDSHAKE" 作为域分隔，防止签名被用于其他目的
- `verify_challenge_response(challenge: &[u8], response: &[u8], expected_secret: &str, my_peer_id: u32, remote_peer_id: u32, network_name: &str, is_client: bool) -> bool`

**更新的握手方法：**
- `do_handshake_as_client()`:
  1. 发送初始 `HandshakeRequest`（包含 my_peer_id）
  2. 等待服务端的 `HandshakeRequest` 和 `ChallengeRequest`
  3. 使用服务端的 peer_id 计算响应（role="CLIENT"），生成自己的挑战，一起发送
  4. 等待并验证服务端的 `ChallengeResponse`（role="SERVER"）

- `do_handshake_as_server()`:
  1. 等待客户端的 `HandshakeRequest`（获取客户端的 peer_id）
  2. 生成挑战并与 `HandshakeRequest` 一起发送
  3. 等待客户端的响应和挑战
  4. 验证响应（role="CLIENT"），计算并发送自己的响应（role="SERVER"）

- `do_handshake_as_server_ext()`:
  - 保持现有的扩展接口，用于处理跨网络连接时的额外验证逻辑
  - 在基础握手完成后，允许通过回调函数进行自定义验证

#### 3. 安全验证 (`foreign_network_manager.rs`)
- 使用新的认证状态更新网络身份比较
- 无需更改实际的比较逻辑，只需确保握手成功完成

### 最小改动范围

1. **Protocol Buffer**: 在 `HandshakeRequest` 中添加 2 个新字段，新增 2 个消息类型
2. **peer_conn.rs**: 
   - 添加约 4 个用于挑战生成/验证的新方法
   - 修改现有握手方法以支持新流程
   - 添加握手进度的状态跟踪
3. **测试**: 更新现有测试以支持新协议

### 安全优势
- **不暴露 PSK**: 密钥永远不会在网络上传输
- **防重放**: 新鲜的随机数防止重放攻击
- **双向认证**: 双方都需证明拥有密钥
- **防反射攻击**: 客户端和服务端使用不同的角色标识
- **域分隔**: 包含固定字符串防止签名被用于其他目的
- **完整性保护**: HMAC包含所有关键信息（双方ID、网络名、角色）
- **前向兼容**: 可扩展以派生会话密钥

### 测试策略
1. 挑战/响应计算的单元测试
2. 完整握手流程的集成测试
3. 失败场景测试（错误密钥、重放尝试）

## 实现顺序
1. 更新 protocol buffer 定义
2. 实现核心加密函数（挑战生成、HMAC）
3. 更新握手逻辑
4. 更新并运行测试
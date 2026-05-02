# HTTP/TXT/SRV 连接器多节点支持

## 概述

HTTP、TXT DNS 和 SRV DNS 连接器现已支持：
1. **批量添加所有节点** - 从响应中添加所有有效 URL
2. **自动定期刷新** - 每 300 秒自动更新节点列表
3. **失败保护** - 如果获取失败则保留现有连接，不执行列表刷新

## 修改内容

### 1. 核心功能变更

**之前**: HTTP/TXT/SRV 响应中的多个 URL，只随机选择一个进行连接  
**现在**: HTTP/TXT/SRV 响应中的所有有效 URL 都会被添加到 ManualConnectorManager，实现多节点同时连接

### 2. 技术实现

#### 全局动态连接器管理器

采用**单例模式**的全局管理器，所有网络实例共享同一个后台刷新任务：

```rust
// easytier/src/connector/dynamic_connector_manager.rs
pub struct GlobalDynamicConnectorManager {
    /// 所有动态连接器配置
    connectors: DashMap<url::Url, DynamicConnectorMeta>,
    /// 缓存的节点列表
    cached_nodes: DashMap<url::Url, Vec<url::Url>>,
    /// 多个 ManualConnectorManager 实例（支持多网络实例）
    manual_managers: DashMap<String, Arc<ManualConnectorManager>>,
    /// 只有一个后台刷新任务
    refresh_task: Mutex<Option<JoinHandle<()>>>,
}

impl GlobalDynamicConnectorManager {
    // 单例访问
    pub fn get_instance() -> &'static Arc<Self> { ... }
    
    // 注册 ManualConnectorManager 实例
    pub fn register_manual_manager(&self, instance_id: String, manager: Arc<...>) { ... }
    
    // 添加动态连接器源
    pub async fn add_dynamic_connector(...) { ... }
    
    // 主刷新循环（每 300 秒执行一次）
    async fn refresh_loop(&self) {
        loop {
            sleep(300s).await;
            // 刷新所有注册的动态连接器
            for source_url in all_connectors {
                self.refresh_single_connector(&source_url).await?;
            }
        }
    }
}
```

#### 优势

✅ **无任务泄漏**: 只有一个后台任务，不会随连接器数量增加  
✅ **资源共享**: 多个网络实例共享同一个刷新任务  
✅ **统一管理**: 所有动态连接器的状态集中管理  
✅ **自动清理**: 当没有动态连接器时自动停止刷新任务  

#### HTTP/TXT/SRV 连接器注册

```rust
// HTTP 连接器
fn register_for_auto_refresh(&self) {
    let global_manager = GlobalDynamicConnectorManager::get_instance();
    tokio::spawn(async move {
        global_manager.add_dynamic_connector(
            source_url.clone(),
            DynamicConnectorType::Http,
            ip_version,
            300,  // 300 seconds
        ).await
    });
}

// TXT/SRV 连接器类似...
```

#### 新增 GlobalCtx 字段
```rust
// easytier/src/common/global_ctx.rs
pub struct GlobalCtx {
    // ... 其他字段 ...
    
    /// Weak reference to ManualConnectorManager for adding connectors dynamically
    manual_connector_manager: Mutex<Option<std::sync::Weak<ManualConnectorManager>>>,
}
```

#### 新增方法
```rust
impl GlobalCtx {
    /// 设置 ManualConnectorManager 的弱引用
    pub fn set_manual_connector_manager(
        &self,
        manager: std::sync::Weak<ManualConnectorManager>,
    );

    /// 获取 ManualConnectorManager（如果可用）
    pub fn get_manual_connector_manager(
        &self,
    ) -> Option<Arc<ManualConnectorManager>>;
}
```

#### HTTP 连接器逻辑更新
```rust
// easytier/src/connector/http_connector.rs
async fn handle_200_success(&mut self, body: &String) -> Result<...> {
    // 1. 解析所有有效的 URL
    let mut valid_urls = Vec::new();
    for line in lines {
        if let Ok(url) = url::Url::parse(line) {
            valid_urls.push(url);
        }
    }
    
    // 2. 将除第一个外的所有 URL 添加到连接器管理器
    if valid_urls.len() > 1 {
        if let Some(conn_manager) = self.global_ctx.get_manual_connector_manager() {
            for url in valid_urls.iter().skip(1) {
                conn_manager.add_connector_by_url(url.clone()).await?;
            }
        }
    }
    
    // 3. 返回第一个 URL 作为主连接器
    create_connector_by_url(valid_urls[0], ...).await
}
```

#### TXT DNS 连接器逻辑更新
```rust
// easytier/src/connector/dns_connector.rs
pub async fn handle_txt_record(&self, domain_name: &str) -> Result<...> {
    // 1. 解析 TXT 记录，空格分隔的 URL 列表
    let txt_data = resolve_txt_record(domain_name).await?;
    let mut candidate_urls = txt_data
        .split(" ")
        .filter_map(|s| url::Url::parse(s).ok())
        .collect::<Vec<_>>();
    
    // 2. 随机打乱顺序（负载均衡）
    candidate_urls.shuffle(&mut rand::thread_rng());
    
    // 3. 批量添加额外的连接器
    if candidate_urls.len() > 1 {
        if let Some(conn_manager) = self.global_ctx.get_manual_connector_manager() {
            for url in candidate_urls.iter().skip(1) {
                conn_manager.add_connector_by_url(url.clone()).await?;
            }
        }
    }
    
    // 4. 返回第一个 URL 作为主连接器
    create_connector_by_url(candidate_urls[0], ...).await
}
```

#### SRV DNS 连接器逻辑更新
```rust
// easytier/src/connector/dns_connector.rs
pub async fn handle_srv_record(&self, domain_name: &str) -> Result<...> {
    // 1. 并行查询所有协议的 SRV 记录
    // _easytier._tcp.example.com, _easytier._udp.example.com, etc.
    let srv_records = query_all_srv_records(domain_name).await?;
    
    // 2. 批量添加额外的连接器
    if srv_records.len() > 1 {
        if let Some(conn_manager) = self.global_ctx.get_manual_connector_manager() {
            for (url, _) in srv_records.iter().skip(1) {
                conn_manager.add_connector_by_url(url.clone()).await?;
            }
        }
    }
    
    // 3. 根据权重选择主连接器
    let (primary_url, _) = weighted_choice(srv_records.as_slice())?;
    create_connector_by_url(primary_url, ...).await
}
```

### 3. 使用示例

#### HTTP 服务器响应格式

```http
GET http://config-server.com/nodes HTTP/1.1
User-Agent: easytier/2.6.3
X-Network-Name: mynetwork

HTTP/1.1 200 OK
Content-Type: text/plain

tcp://node1.example.com:11010
udp://node2.example.com:11010
ws://node3.example.com:80
quic://node4.example.com:11012
```

#### HTTP 连接器 TTL 配置

HTTP 连接器支持通过 URL 查询参数指定刷新间隔（TTL）：

```bash
# 默认 TTL: 300 秒（5分钟）
easytier-core -i 10.144.144.1 \
  -p "http://config-server.com/nodes"

# 自定义 TTL: 120 秒（2分钟）
easytier-core -i 10.144.144.1 \
  -p "http://config-server.com/nodes?ttl=120"

# 自定义 TTL: 600 秒（10分钟）
easytier-core -i 10.144.144.1 \
  -p "http://config-server.com/nodes?ttl=600"
```

**TTL 参数说明**:
- **范围**: 60-6000 秒（1分钟 - 100分钟）
- **默认值**: 300 秒（5分钟）
- **超出范围**: 自动使用默认值 300 秒，并记录警告日志
- **无效值**: 非数字或空值会使用默认值 300 秒

**示例**:
```bash
# TTL 太小（< 60），使用默认值 300
easytier-core -p "http://config.com/nodes?ttl=30"
# [WARN] TTL 30 is less than minimum 60, using default 300

# TTL 太大（> 6000），使用默认值 300
easytier-core -p "http://config.com/nodes?ttl=10000"
# [WARN] TTL 10000 exceeds maximum 6000, using default 300

# TTL 有效，使用指定值
easytier-core -p "http://config.com/nodes?ttl=120"
# [INFO] Using custom TTL: 120 seconds
```

#### TXT DNS 记录配置

```dns
; DNS TXT 记录配置
; 域名: txt.easytier.cn
; 记录类型: TXT
; 记录值: 空格分隔的 URL 列表

txt.easytier.cn. IN TXT "tcp://10.1.1.1:11010 udp://10.1.1.2:11010 ws://10.1.1.3:80"
```

#### SRV DNS 记录配置

```dns
; DNS SRV 记录配置
; 为每种协议创建独立的 SRV 记录
; 格式: _easytier._<protocol>.<domain>

_easytier._tcp.example.com. IN SRV 10 60 11010 node1.example.com.
_easytier._tcp.example.com. IN SRV 10 40 11010 node2.example.com.
_easytier._udp.example.com. IN SRV 10 50 11010 node3.example.com.
_easytier._ws.example.com.  IN SRV 10 30 80    node4.example.com.

; 优先级（Priority）：数值越小优先级越高
; 权重（Weight）：相同优先级下的负载均衡比例
```

#### 客户端配置

```bash
# 方式1: 使用 HTTP 连接器
easytier-core -i 10.144.144.1 \
  -p "http://config-server.com/nodes"

# 方式2: 使用 TXT DNS 连接器
easytier-core -i 10.144.144.1 \
  -p "txt://txt.easytier.cn"

# 方式3: 使用 SRV DNS 连接器
easytier-core -i 10.144.144.1 \
  -p "srv://example.com"
```

#### 执行流程

**HTTP 连接器**:
1. **发起 HTTP 请求**到 `http://config-server.com/nodes`
2. **接收响应**，解析出 4 个节点 URL
3. **选择第一个 URL** (`tcp://node1.example.com:11010`) 作为主连接器并立即连接
4. **批量添加其他 URL** 到 ManualConnectorManager：
   - `udp://node2.example.com:11010`
   - `ws://node3.example.com:80`
   - `quic://node4.example.com:11012`
5. **ManualConnectorManager 自动重连机制**会尝试连接所有添加的节点
6. **最终结果**: 客户端同时连接到所有 4 个节点

**TXT DNS 连接器**:
1. **查询 TXT 记录** `txt.easytier.cn`
2. **解析响应**，得到空格分隔的 URL 列表：`"tcp://10.1.1.1:11010 udp://10.1.1.2:11010 ws://10.1.1.3:80"`
3. **随机打乱顺序**（负载均衡）
4. **选择第一个 URL** 作为主连接器并立即连接
5. **批量添加其他 URL** 到 ManualConnectorManager
6. **最终结果**: 客户端同时连接到所有节点

**SRV DNS 连接器**:
1. **并行查询 SRV 记录**：
   - `_easytier._tcp.example.com`
   - `_easytier._udp.example.com`
   - `_easytier._ws.example.com`
   - `_easytier._quic.example.com`
2. **收集所有有效记录**，包含优先级和权重信息
3. **批量添加除主节点外的所有 URL** 到 ManualConnectorManager
4. **根据权重选择主连接器**（weighted_choice 算法）
5. **最终结果**: 客户端同时连接到所有节点，主节点按权重选择

### 4. 优势

✅ **提高可用性**: 多节点冗余，单个节点故障不影响整体连接  
✅ **负载均衡**: 流量可以分散到多个节点  
✅ **动态扩展**: 服务端可随时增加节点，客户端自动感知  
✅ **智能路由**: PeerManager 会根据延迟和丢包率选择最优路径  
✅ **向后兼容**: 单节点响应仍然正常工作  
✅ **自动刷新**: 每 300 秒自动更新节点列表，保持最新状态  
✅ **失败保护**: 刷新失败时保留现有连接，不会因为临时网络问题断开  

### 5. 日志示例

**首次连接日志**:

**HTTP 连接器日志**:
```
[INFO] get 4 lines of connector urls
[INFO] Adding additional connector from HTTP response: udp://node2.example.com:11010
[INFO] Adding additional connector from HTTP response: ws://node3.example.com:80
[INFO] Adding additional connector from HTTP response: quic://node4.example.com:11012
[INFO] Added 3 additional connectors from HTTP response
[INFO] Using primary connector from HTTP response: tcp://node1.example.com:11010
[INFO] connect tcp start, bind addrs: []
[INFO] Connector added: udp://node2.example.com:11010
[INFO] Connector added: ws://node3.example.com:80
[INFO] Connector added: quic://node4.example.com:11012
```

**自动刷新日志（300秒后）**:

**HTTP 自动刷新**:
```
[DEBUG] Auto-refreshing HTTP connector: http://config-server.com/nodes
[INFO] Adding refreshed node from HTTP: tcp://node1.example.com:11010
[INFO] Adding refreshed node from HTTP: udp://node2.example.com:11010
[INFO] Adding refreshed node from HTTP: ws://node5.example.com:80
[INFO] Refreshed 3 nodes from HTTP
```

**TXT 自动刷新**:
```
[DEBUG] Auto-refreshing TXT connector: txt://txt.easytier.cn
[INFO] Adding refreshed node from TXT: tcp://10.1.1.1:11010
[INFO] Adding refreshed node from TXT: udp://10.1.1.4:11010
[INFO] Refreshed 2 nodes from TXT
```

**SRV 自动刷新**:
```
[DEBUG] Auto-refreshing SRV connector: srv://example.com
[INFO] Adding refreshed node from SRV: tcp://node1.example.com:11010
[INFO] Adding refreshed node from SRV: udp://node6.example.com:11010
[INFO] Refreshed 2 nodes from SRV
```

**刷新失败日志**:
```
[DEBUG] Auto-refreshing HTTP connector: http://config-server.com/nodes
[WARN] Failed to refresh HTTP connector http://config-server.com/nodes, keeping existing connections: InvalidUrl("HTTP request failed: ...")
```

**TXT DNS 连接器日志**:
```
[INFO] Found 3 valid URLs from TXT record
[INFO] Adding additional connector from TXT record: udp://10.1.1.2:11010
[INFO] Adding additional connector from TXT record: ws://10.1.1.3:80
[INFO] Added 2 additional connectors from TXT record
[INFO] Using primary connector from TXT record: tcp://10.1.1.1:11010
[INFO] connect tcp start, bind addrs: []
[INFO] Connector added: udp://10.1.1.2:11010
[INFO] Connector added: ws://10.1.1.3:80
```

**SRV DNS 连接器日志**:
```
[INFO] handle_srv_record: example.com
[INFO] build srv_domains: [(Tcp, "_easytier._tcp.example.com"), (Udp, "_easytier._udp.example.com"), ...]
[INFO] Found 4 valid SRV records
[INFO] Adding additional connector from SRV record: tcp://node2.example.com:11010
[INFO] Adding additional connector from SRV record: udp://node3.example.com:11010
[INFO] Adding additional connector from SRV record: ws://node4.example.com:80
[INFO] Added 3 additional connectors from SRV record
[INFO] Using primary connector from SRV record: tcp://node1.example.com:11010
[INFO] connect tcp start, bind addrs: []
[INFO] Connector added: tcp://node2.example.com:11010
[INFO] Connector added: udp://node3.example.com:11010
[INFO] Connector added: ws://node4.example.com:80
```

### 6. 注意事项

⚠️ **需要完整的 Instance 环境**: HTTP/TXT/SRV 连接器需要在 NetworkInstance 中运行才能访问 ManualConnectorManager  
⚠️ **节点数量限制**: 建议单次响应不超过 20 个节点，避免连接过多导致资源浪费  
⚠️ **URL 有效性**: 无效的 URL 会被跳过并记录警告日志  
⚠️ **随机顺序**: URL 列表会在处理前随机打乱，确保负载均衡（SRV 除外，它使用权重选择）  
⚠️ **DNS TTL**: TXT/SRV 记录受 DNS TTL 限制，更新可能需要等待缓存过期  
⚠️ **自动刷新间隔**: 
   - HTTP: 可通过 `?ttl=xxx` 参数自定义（60-6000秒），默认 300 秒
   - TXT/SRV: 固定为 300 秒
   - 首次刷新在连接后立即执行  
⚠️ **失败保护**: 如果刷新失败（网络错误、DNS 解析失败等），会保留现有连接，不会断开  
✅ **全局单例**: 所有动态源共享同一个后台刷新任务，无任务泄漏问题  
✅ **多实例支持**: 多个网络实例可以注册各自的 ManualConnectorManager  

### 7. 测试

新增了单元测试验证功能：
- `http_multi_node_test`: 验证 HTTP 多节点添加
- （可添加）`txt_multi_node_test`: 验证 TXT 多节点添加
- （可添加）`srv_multi_node_test`: 验证 SRV 多节点添加

运行测试：
```bash
cargo test --package easytier http_multi_node_test
```

### 8. 与其他发现机制对比

| 机制 | 多节点支持 | 负载均衡 | 动态更新 | 复杂度 |
|------|----------|---------|---------|--------|
| **HTTP (新)** | ✅ 全部添加 | ✅ 随机顺序 | ✅ 每次请求 | 中 |
| **TXT DNS (新)** | ✅ 全部添加 | ✅ 随机顺序 | ⚠️ 受 TTL 限制 | 低 |
| **SRV DNS (新)** | ✅ 全部添加 | ✅ 权重选择 | ⚠️ 受 TTL 限制 | 中 |
| 直接配置 | ❌ 需手动指定 | ❌ 无 | ❌ 需重启 | 低 |

### 9. 未来优化方向

🔮 **可能的改进**:
- 支持 TXT/SRV 自定义刷新间隔（当前仅 HTTP 支持）
- 支持优先级配置（某些节点优先连接）
- 支持区域感知（根据地理位置选择节点）
- 支持健康检查（自动剔除不可用节点）
- 支持增量更新（只添加新节点，不移除旧节点）
- 支持刷新失败重试机制（指数退避）

## 相关文件

- `easytier/src/connector/http_connector.rs` - HTTP 连接器实现（已修改）
- `easytier/src/connector/dns_connector.rs` - TXT/SRV DNS 连接器实现（已修改）
- `easytier/src/common/global_ctx.rs` - 全局上下文（新增字段和方法）
- `easytier/src/instance/instance.rs` - 实例初始化（设置引用）
- `easytier/src/connector/manual.rs` - 手动连接器管理器

## 兼容性

✅ **完全向后兼容**: 现有的单节点 HTTP/TXT/SRV 响应仍然正常工作  
✅ **不影响其他协议**: TCP/UDP/WS/WG 等直连方式不受影响  
✅ **可选功能**: 如果 ManualConnectorManager 不可用，只会记录警告，不会失败  
✅ **统一行为**: HTTP、TXT、SRV 三种发现机制现在具有一致的多节点支持  

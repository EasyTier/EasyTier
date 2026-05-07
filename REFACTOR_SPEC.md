# Connector 架构重构规范

## 1. 问题分析

### 1.1 现状

当前 `create_connector_by_url` 是一个**工厂函数**，返回 `Box<dyn TunnelConnector>`。不同的 URL scheme 走完全不同的路径，产生了三条不对称的代码路径：

```
用户 URL           →  create_connector_by_url()  → 返回的组件            → 生命周期管理
────────────────────────────────────────────────────────────────────────────────────
tcp://host:port     一次 DNS 解析，固化 resolved_addr    TcpTunnelConnector    无（仅依赖 ManualConnectorManager 重连）
http://host         每次 connect 时 HTTP 拉取           HttpTunnelConnector    GlobalDynamicConnectorManager 周期性刷新
txt://domain         每次 connect 时 TXT 解析           DnsTunnelConnector     GlobalDynamicConnectorManager 周期性刷新
srv://domain         每次 connect 时 SRV 解析           DnsTunnelConnector     GlobalDynamicConnectorManager 周期性刷新
```

### 1.2 关键问题

1. **tcp:// 不支持动态解析（DDNS）**：`TcpTunnelConnector` 的 `resolved_addr` 在创建时固化，DDNS 更新后不会重新解析。当前重连只是"碰巧"通过 `ManualConnectorManager.conn_reconnect` 重新调用了 `create_connector_by_url` 再次解析了 DNS。

2. **GlobalDynamicConnectorManager 是一个全局单例插件**：它被"附加"在 HttpTunnelConnector/DnsTunnelConnector 旁边，通过 `register_manual_manager` 跨实例操作所有 `ManualConnectorManager`，产生了不必要的全局耦合。

3. **多节点支持不对称**：HTTP/TXT/SRV 各自在 connect() 内部将"额外"节点注入到 `ManualConnectorManager`，这是一种副作用式设计——connect() 不应负责管理其他连接的声明周期。

4. **静态地址是动态地址的特例**：`tcp://1.2.3.4:11010` = 一个不会变化的"解析器"，应该与 `tcp://ddns.example.com:11010` 共用同一套机制。

## 2. 核心设计

### 2.1 核心理念

将 `create_connector_by_url` 从一个**工厂函数**转变为一个**生命周期组件**。引入统一的核心抽象：

```
ManagedConnector (implements TunnelConnector)
├── resolver: Box<dyn ConnectorResolver>   // 如何解析 source_url
├── candidates: Vec<url::Url>              // 当前解析出的候选列表
├── refresh_interval: Duration             // 刷新间隔
└── last_refresh: Instant                  // 上次刷新时间
```

所有 URL 类型都用 `ManagedConnector` 包装，区别仅在 Resolver 的实现上。

### 2.2 ConnectorResolver trait

```rust
/// 连接器解析器：将源 URL 解析为一个或多个具体的候选 URL
#[async_trait]
pub trait ConnectorResolver: Debug + Send + Sync {
    /// 执行一次解析，返回候选 URL 列表
    async fn resolve(&self) -> Result<Vec<ResolvedCandidate>, Error>;

    /// 返回推荐的刷新间隔（秒）
    fn refresh_interval_secs(&self) -> u64;

    /// 源 URL
    fn source_url(&self) -> &url::Url;
}

/// 解析候选
#[derive(Debug, Clone)]
pub struct ResolvedCandidate {
    /// 具体的连接 URL，如 tcp://1.2.3.4:11010
    pub url: url::Url,
}
```

### 2.3 Resolver 实现族

| URL Scheme | Resolver | 解析方式 | refresh_interval |
|---|---|---|---|
| `tcp://1.2.3.4:11010` | `StaticResolver` | 直接使用 URL，不做额外解析 | `u64::MAX`（永不刷新） |
| `tcp://hostname:port` | `DnsResolver` | DNS A/AAAA 查询 | TTL 或默认 300s |
| `udp://hostname:port` | `DnsResolver` | DNS A/AAAA 查询 | TTL 或默认 300s |
| `quic://hostname:port` | `DnsResolver` | DNS A/AAAA 查询 | TTL 或默认 300s |
| `http(s)://` | `HttpResolver` | HTTP GET，解析响应体 | 300s（可配置） |
| `txt://domain` | `TxtResolver` | DNS TXT 查询 | 300s（可配置） |
| `srv://domain` | `SrvResolver` | DNS SRV 查询 | 300s（可配置） |
| `ws(s)://` | `DnsResolver` | DNS A/AAAA | TTL 或默认 300s |
| `ring://` | `StaticResolver` | 直接使用 | 永不刷新 |

### 2.4 ManagedConnector

```rust
pub struct ManagedConnector {
    source_url: url::Url,
    resolver: Box<dyn ConnectorResolver>,
    candidates: Arc<RwLock<Vec<ResolvedCandidate>>>,
    ip_version: IpVersion,
    bind_addrs: Vec<SocketAddr>,
    global_ctx: ArcGlobalCtx,
}
```

#### connect() 行为

```
connect()
  ├→ maybe_refresh()          // 检查是否过期，过期则重新 resolve
  ├→ pick_candidate()         // 从候选列表中选一个（shuffle / 随机）
  ├→ create_direct_connector() // 为选中的 URL 创建一次性连接器（不再包装 ManagedConnector）
  └→ inner_connector.connect()
```

**关键**：`create_direct_connector` 是 `create_connector_by_url` 中 `IpScheme` 分支的内联版本——解析 DNS、创建具体 TunnelConnector、设置 resolved_addr、连接。不会递归创建 `ManagedConnector`。

#### maybe_refresh() 行为

```
maybe_refresh()
  ├→ 判断是否过期（last_refresh + refresh_interval）
  ├→ 过期 → resolver.resolve()
  │   ├→ 解析成功 → update candidates, report diff
  │   └→ 解析失败 → retain old candidates, log warning
  └→ 未过期 → skip
```

#### 多节点处理

对于返回多条候选 URL 的 Resolver（HttpResolver / TxtResolver / SrvResolver / DnsResolver）：

- `ManagedConnector` 内部持有所有候选
- `connect()` 每次随机选一个（负载均衡 / 故障转移）
- `ManualConnectorManager` 不再需要为每个动态源管理多个独立连接——`ManagedConnector` 自包含

## 3. 组件关系

### 3.1 重构后的组件图

```
                    ┌─────────────────────────────────────┐
                    │         ManualConnectorManager       │
                    │  ┌─────────────────────────────────┐ │
                    │  │ managers: Vec<ManagedConnector>  │ │
                    │  │ reconnect_loop:                  │ │
                    │  │   for each dead URL:             │ │
                    │  │     managed.connect()            │ │
                    │  └─────────────────────────────────┘ │
                    └─────────────────────────────────────┘
                                │ owns
                                ▼
                    ┌─────────────────────────────────────┐
                    │         ManagedConnector              │
                    │  ┌─────────────────────────────────┐ │
                    │  │ resolver: DnsResolver            │ │
                    │  │ candidates: [tcp://1.2.3.4,     │ │
                    │  │               tcp://5.6.7.8]    │ │
                    │  │ last_refresh: Instant            │ │
                    │  └─────────────────────────────────┘ │
                    └─────────────────────────────────────┘
                                │ uses (per connect attempt)
                                ▼
                    ┌─────────────────────────────────────┐
                    │    TcpTunnelConnector / UdpTunnel    │
                    │    (一次性，不持久化)                  │
                    └─────────────────────────────────────┘
```

### 3.2 GlobalDynamicConnectorManager → 删除

当前的 `GlobalDynamicConnectorManager` 的职责被 `ManagedConnector` 自身吸收：

| 职责 | 旧（GlobalDynamicConnectorManager） | 新（ManagedConnector） |
|---|---|---|
| 周期刷新 | 全局单例的 refresh_loop | 每个 ManagedConnector 在 connect() 前 maybe_refresh() |
| 节点 diff | 计算 to_add / to_remove | 内部更新 candidates，connect() 时从新列表中选择 |
| 注册 manual managers | register_manual_manager | 不再需要——ManagedConnector 自包含 |
| 注入新节点 | 通过 manual_managers 注入 | 不再需要——ManagedConnector 自己管理候选列表 |

### 3.3 HttpTunnelConnector / DnsTunnelConnector → 简化或删除

当前 HttpTunnelConnector 和 DnsTunnelConnector 的解析逻辑迁移到对应的 Resolver 中：

- `HttpTunnelConnector.Handle200Success` → `HttpResolver.resolve()`
- `DnsTunnelConnector.handle_txt_record` → `TxtResolver.resolve()`
- `DnsTunnelConnector.handle_srv_record` → `SrvResolver.resolve()`

这些连接器本身可以简化为 `ManagedConnector` + 对应 Resolver 的组合，或者完全删除。

## 4. 统一的生命周期

### 4.1 场景对比

```
场景：tcp://ddns.example.com:11010
─────────────────────────────────────
before:
  create_connector_by_url → TcpTunnelConnector { resolved_addr: 1.2.3.4 }
  DDNS 更新 → 1.2.3.4 -> 5.6.7.8
  TcpTunnelConnector 仍然连 1.2.3.4
  连接断开 → ManualConnectorManager 重连 → create_connector_by_url → 新的 DNS 解析 → 运气好连上了 5.6.7.8

after:
  create_connector_by_url → ManagedConnector { resolver: DnsResolver }
  connect() → maybe_refresh() → DnsResolver.resolve() → [tcp://5.6.7.8:11010]
  → TcpTunnelConnector connecting to 5.6.7.8
  DDNS 更新 → connect() → maybe_refresh() → 自动解析到新地址


场景：http://api.example.com/nodes
─────────────────────────────────────
before:
  create_connector_by_url → HttpTunnelConnector
  connect() → HTTP GET → [tcp://1.2.3.4, tcp://5.6.7.8, ...]
  → 返回第一个给 connect()，其余注入 ManualConnectorManager（副作用）
  → 注册 GlobalDynamicConnectorManager 周期性刷新

after:
  create_connector_by_url → ManagedConnector { resolver: HttpResolver }
  connect() → maybe_refresh() → HttpResolver.resolve() → [tcp://1.2.3.4, tcp://5.6.7.8, ...]
  → 从中随机选一个 → create_direct_connector → connect
  无副作用，无需外部管理器


场景：txt://txt.easytier.cn
─────────────────────────────────────
before:
  create_connector_by_url → DnsTunnelConnector
  connect() → TXT 查询 → [tcp://a, udp://b, ...]
  → 返回第一个，其余注入 ManualConnectorManager
  → 注册 GlobalDynamicConnectorManager

after:
  create_connector_by_url → ManagedConnector { resolver: TxtResolver }
  connect() → maybe_refresh() → TxtResolver.resolve() → [...]
  → 随机选一个 → connect
  无副作用
```

### 4.2 重连行为

`ManualConnectorManager` 的重连循环：

```rust
// 当前（简化）
for dead_url in dead_connectors {
    let connector = create_connector_by_url(&dead_url).await?;
    let (peer_id, conn_id) = pm.try_direct_connect(connector).await?;
}

// 重构后
for dead_managed in managed_connectors {
    // ManagedConnector.connect() 自动处理：
    // 1. maybe_refresh() - 重新解析获取最新候选列表
    // 2. pick_candidate() - 选择下一个可用的候选（不同节点）
    // 3. create_direct_connector() + connect()
    let (peer_id, conn_id) = pm.try_direct_connect(dead_managed).await?;
}
```

## 5. 代码结构

### 5.1 文件变更

```
当前结构                                  重构后结构
──────────────────────────────────────  ──────────────────────────────────────
connector/                               connector/
├── mod.rs                               ├── mod.rs
├── dynamic_connector_manager.rs   →    │   （删除）
├── http_connector.rs              →    │   （简化为 HttpResolver，或删除）
├── dns_connector.rs               →    │   （拆解为 TxtResolver + SrvResolver）
├── manual.rs                            ├── manual.rs          （适配 ManagedConnector）
├── direct.rs                            ├── direct.rs          （无需变更）
├── tcp_hole_punch.rs                    ├── tcp_hole_punch.rs
├── udp_hole_punch.rs                    ├── udp_hole_punch.rs
│                                 →    ├── managed.rs           （新增：ManagedConnector）
│                                 →    ├── resolver/            （新增）
│                                 →    │   ├── mod.rs           （ConnectorResolver trait）
│                                 →    │   ├── dns.rs           （DnsResolver）
│                                 →    │   ├── http.rs          （HttpResolver）
│                                 →    │   ├── txt.rs           （TxtResolver）
│                                 →    │   ├── srv.rs           （SrvResolver）
│                                 →    │   └── r#static.rs     （StaticResolver）
```

### 5.2 create_connector_by_url 新行为

```rust
pub async fn create_connector_by_url(
    url: &str,
    global_ctx: &ArcGlobalCtx,
    ip_version: IpVersion,
) -> Result<Box<dyn TunnelConnector + 'static>, Error>
{
    let url = parse_and_validate(url)?;
    let scheme: TunnelScheme = (&url).try_into()?;

    // 对于需要 DNS 解析的 IP 协议，创建 DnsResolver
    // 对于 http(s)://，创建 HttpResolver
    // 对于 txt://，创建 TxtResolver
    // 等等

    let resolver: Box<dyn ConnectorResolver> = match scheme {
        TunnelScheme::Ip(scheme) => {
            if url.host().map_or(false, |h| h.is_domain()) {
                Box::new(DnsResolver::new(url.clone(), scheme, ip_version))
            } else {
                Box::new(StaticResolver::new(url.clone()))
            }
        }
        TunnelScheme::Http | TunnelScheme::Https => {
            Box::new(HttpResolver::new(url.clone(), global_ctx.clone()))
        }
        TunnelScheme::Txt => {
            Box::new(TxtResolver::new(url.clone()))
        }
        TunnelScheme::Srv => {
            Box::new(SrvResolver::new(url.clone()))
        }
        TunnelScheme::Ring => {
            Box::new(StaticResolver::new(url.clone()))
        }
        #[cfg(unix)]
        TunnelScheme::Unix => {
            Box::new(StaticResolver::new(url.clone()))
        }
    };

    let connector = ManagedConnector::new(url, resolver, ip_version, global_ctx.clone());
    Ok(Box::new(connector))
}
```

## 6. 向后兼容

对 `instance.rs` 和 `direct.rs` 等调用方透明：
- `create_connector_by_url` 签名不变，仍然返回 `Box<dyn TunnelConnector>`
- `ManualConnectorManager` 对外接口不变（`add_connector_by_url`, `remove_connector`, `list_connectors`）
- `PeerManager.try_direct_connect` 签名不变，接受 `impl TunnelConnector`

唯一需要调整调用方的是：
- `instance.rs` 中删除 `GlobalDynamicConnectorManager` 的注册代码
- 测试代码中调整对 `HttpTunnelConnector` / `DnsTunnelConnector` 的直接构造

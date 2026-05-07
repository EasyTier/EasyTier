# Connector 架构重构 - 实现任务分解

## 阶段一：基础设施（T01-T04）

### T01 | 创建 resolver/mod.rs —— ConnectorResolver trait

- 定义 `ConnectorResolver` trait
- 定义 `ResolvedCandidate` 结构体
- 所有 Resolver 实现的公共基础

**文件**：`easytier/src/connector/resolver/mod.rs`

**依赖**：无

**验收条件**：
- [ ] trait 定义正确，所有方法签名完整
- [ ] `ResolvedCandidate` 字段满足需求

---

### T02 | 创建 resolver 实现族

**T02a | StaticResolver**

- 适用于 `tcp://ip:port`、`ring://`、`unix://` 等不需要解析的 URL
- `resolve()` 直接返回 `source_url`
- `refresh_interval_secs()` 返回 `u64::MAX`

**文件**：`easytier/src/connector/resolver/static.rs`

**依赖**：T01

**验收条件**：
- [ ] 对 `tcp://1.2.3.4:11010` 返回 `[tcp://1.2.3.4:11010]`
- [ ] 刷新间隔为 `u64::MAX`

---

**T02b | DnsResolver**

- 适用于 `tcp://hostname:port`、`udp://hostname:port`、`quic://hostname:port`、`ws(s)://hostname:port`
- `resolve()` 执行 DNS A/AAAA 查询，返回 `scheme://ip:port` 列表
- `refresh_interval_secs()` 从 DNS TTL 获取，兜底 300s

**文件**：`easytier/src/connector/resolver/dns.rs`

**依赖**：T01

**验收条件**：
- [ ] 对 `tcp://example.com:11010` 解析出 `[tcp://1.2.3.4:11010, tcp://5.6.7.8:11010]`
- [ ] 对 `tcp://1.2.3.4:11010` 解析出 `[tcp://1.2.3.4:11010]`（StaticResolver 场景，但 DnsResolver 也支持）
- [ ] 刷新间隔基于 DNS TTL
- [ ] 考虑 IPv4/IPv6 偏好

---

**T02c | HttpResolver**

- 适用于 `http(s)://host/path`
- `resolve()` 执行 HTTP GET，解析响应体
- 支持 302 重定向（RedirectToQuery / RedirectToUrl）
- 支持 200 响应体（BodyUrls：每行一个 URL）
- `refresh_interval_secs()` 返回 300s

**文件**：`easytier/src/connector/resolver/http.rs`

**依赖**：T01

**验收条件**：
- [ ] 将现有 `HttpTunnelConnector.get_redirected_connector()` 的解析逻辑完整迁移
- [ ] 支持 302 + Query、302 + URL 重写、200 body 三种模式
- [ ] 返回候选 URL 列表

---

**T02d | TxtResolver**

- 适用于 `txt://domain`
- `resolve()` 执行 DNS TXT 查询，解析空格分隔的 URL 列表
- `refresh_interval_secs()` 返回 300s

**文件**：`easytier/src/connector/resolver/txt.rs`

**依赖**：T01

**验收条件**：
- [ ] 将现有 `DnsTunnelConnector.handle_txt_record()` 的解析逻辑完整迁移
- [ ] 返回候选 URL 列表（shuffle 前）
- [ ] 刷新间隔 300s

---

**T02e | SrvResolver**

- 适用于 `srv://domain`
- `resolve()` 遍历 `IpScheme` 所有变体，查询 `_easytier._<scheme>.<domain>` SRV 记录
- `refresh_interval_secs()` 返回 300s

**文件**：`easytier/src/connector/resolver/srv.rs`

**依赖**：T01

**验收条件**：
- [ ] 将现有 `DnsTunnelConnector.handle_srv_record()` 的解析逻辑完整迁移
- [ ] 返回候选 (URL, weight) 列表
- [ ] 支持 weighted_choice

---

### T03 | 创建 managed.rs —— ManagedConnector

`ManagedConnector` 实现了 `TunnelConnector` trait，内部持有：
- `resolver: Box<dyn ConnectorResolver>`
- `candidates: Arc<RwLock<Vec<ResolvedCandidate>>>`
- `last_refresh: Instant`
- `ip_version`, `bind_addrs`, `global_ctx`

**核心方法**：
- `connect()` → maybe_refresh → pick_candidate → create_direct_connector → connect
- `maybe_refresh()` → 判断过期 → resolver.resolve() → update candidates
- `pick_candidate()` → 从 candidates 中选一个（随机）

**文件**：`easytier/src/connector/managed.rs`

**依赖**：T01, T02

**验收条件**：
- [ ] 实现 `TunnelConnector` trait（connect, remote_url, set_bind_addrs, set_ip_version）
- [ ] `connect()` 正确执行 maybe_refresh → pick → direct_connect 流程
- [ ] `remote_url()` 返回 `source_url`
- [ ] 刷新过期后自动重新 resolve
- [ ] 多候选时随机选择

---

### T04 | 抽取 create_direct_connector

将当前 `create_connector_by_url` 中 `TunnelScheme::Ip` 分支抽取为独立的 `create_direct_connector` 函数：

```rust
/// 为具体 IP URL 创建一次性连接器（不包装 ManagedConnector，不再解析 hostname）
pub(crate) async fn create_direct_connector(
    url: &url::Url,
    global_ctx: &ArcGlobalCtx,
    ip_version: IpVersion,
) -> Result<Box<dyn TunnelConnector + 'static>, Error>
```

- 不解析 DNS（调用方保证 url 的 host 已解析为 IP）
- 仍然使用 `resolve_connector_socket_addr` 处理 IP 解析（因为 IP 的 socket_addrs 是平凡操作）

**文件**：`easytier/src/connector/mod.rs`

**依赖**：T03

**验收条件**：
- [ ] 函数签名正确
- [ ] 对 `tcp://1.2.3.4:11010` 返回 `TcpTunnelConnector`，正确设置 `resolved_addr`、`bind_addrs`
- [ ] 支持所有 IpScheme 变体（tcp, udp, quic, ws, wss, faketcp, wg）

---

## 阶段二：重构 create_connector_by_url（T05）

### T05 | 重写 create_connector_by_url

修改 `create_connector_by_url`，使其返回 `ManagedConnector`：

```rust
pub async fn create_connector_by_url(
    url: &str,
    global_ctx: &ArcGlobalCtx,
    ip_version: IpVersion,
) -> Result<Box<dyn TunnelConnector + 'static>, Error>
```

新逻辑：
1. 解析 URL
2. 根据 scheme 创建对应的 Resolver
3. 用 Resolver 创建 `ManagedConnector`
4. 返回 `Box::new(managed_connector)`

**文件**：`easytier/src/connector/mod.rs`

**依赖**：T01-T04

**验收条件**：
- [ ] `tcp://ip:port` → ManagedConnector { resolver: StaticResolver }
- [ ] `tcp://hostname:port` → ManagedConnector { resolver: DnsResolver }
- [ ] `http(s)://...` → ManagedConnector { resolver: HttpResolver }
- [ ] `txt://...` → ManagedConnector { resolver: TxtResolver }
- [ ] `srv://...` → ManagedConnector { resolver: SrvResolver }
- [ ] `ring://...` → ManagedConnector { resolver: StaticResolver }
- [ ] 其他 scheme 保持兼容
- [ ] IPv6 过滤逻辑（easytier-managed IPv6）保留
- [ ] bind_device 逻辑保留

---

## 阶段三：清理旧代码（T06-T08）

### T06 | 删除 GlobalDynamicConnectorManager

删除以下文件和引用：
- `easytier/src/connector/dynamic_connector_manager.rs`
- `easytier/src/connector/dynamic_connector_tests.rs`
- 在 `instance.rs` 中删除注册代码
- 在 `mod.rs` 中删除 module 声明

**文件**：
- `easytier/src/connector/dynamic_connector_manager.rs`（删除）
- `easytier/src/connector/dynamic_connector_tests.rs`（删除）
- `easytier/src/connector/mod.rs`（删除 module 声明）
- `easytier/src/instance/instance.rs`（删除注册代码和 import）

**依赖**：T05

**验收条件**：
- [ ] `dynamic_connector_manager.rs` 被删除
- [ ] 没有任何代码引用 `GlobalDynamicConnectorManager`
- [ ] 编译通过

---

### T07 | 简化 HttpTunnelConnector

将 `HttpTunnelConnector` 简化为可直接删除的过渡态：
- 删除 `with_dynamic_manager` 构造和 `dynamic_manager` 字段
- 删除 `handle_200_success` 中的多节点注入侧效应（注入 ManualConnectorManager 的逻辑）
- connect() 改为使用 `create_connector_by_url`（通过 ManagedConnector）获得 sub-connector

实际上此阶段 HttpTunnelConnector 应已不再被 `create_connector_by_url` 使用——`create_connector_by_url` 直接返回 ManagedConnector。HttpTunnelConnector 仅保留用于**兼容已有测试**。

**文件**：`easytier/src/connector/http_connector.rs`

**依赖**：T05

**验收条件**：
- [ ] 删除 `dynamic_manager` 相关代码
- [ ] 删除 `handle_200_success` 中的 `conn_manager.add_connector_by_url` 副作用
- [ ] 测试通过

---

### T08 | 简化 DnsTunnelConnector

与 T07 同理，将 `DnsTunnelConnector` 简化为过渡态：
- 删除 `with_dynamic_manager` 构造和 `dynamic_manager` 字段
- 删除 `register_for_auto_refresh_txt` / `register_for_auto_refresh_srv`
- 删除多节点注入侧效应

**文件**：`easytier/src/connector/dns_connector.rs`

**依赖**：T05

**验收条件**：
- [ ] 删除 `dynamic_manager` 相关代码
- [ ] 删除 register/refresh 逻辑
- [ ] 删除多节点注入副作用
- [ ] 测试通过

---

## 阶段四：适配 ManualConnectorManager（T09）

### T09 | 适配 ManualConnectorManager 使用 ManagedConnector

`ManualConnectorManager` 当前存储 `DashSet<url::Url>`，重构后存储 `DashMap<url::Url, ManagedConnector>` 或等效结构。

关键变更：
- `add_connector_by_url(url)` → 调用 `create_connector_by_url` 创建 `ManagedConnector` 并存储
- `remove_connector(url)` → 移除对应的 `ManagedConnector`
- `conn_reconnect` → 直接调用 `managed_connector.connect()`（自动多候选 + 刷新）
- `list_connectors()` → 适配新结构

同时删除 `ManualConnectorManager` 中不再需要的 `dead_urls` 收集逻辑——`ManagedConnector.connect()` 自己处理刷新和候选选择。

**文件**：`easytier/src/connector/manual.rs`

**依赖**：T05

**验收条件**：
- [ ] 内部存储从 `DashSet<url::Url>` 改为 `DashMap<url::Url, ManagedConnector>`
- [ ] `add_connector_by_url` 调用 `create_connector_by_url` 创建 ManagedConnector
- [ ] `remove_connector` 正确移除
- [ ] `list_connectors` 正确列出
- [ ] `conn_reconnect` 直接调用 `managed_connector.connect()`
- [ ] 删除不再需要的 manual 管理器

---

## 阶段五：清理和测试（T10-T12）

### T10 | 清理 global_ctx

- 删除 `set_manual_connector_manager` / `get_manual_connector_manager`
- `HttpTunnelConnector` 和 `DnsTunnelConnector` 不再需要通过 `GlobalCtx` 获取 `ManualConnectorManager`

**文件**：`easytier/src/common/global_ctx.rs`

**依赖**：T06, T07, T08

**验收条件**：
- [ ] `manual_connector_manager` 字段从 GlobalCtx 中删除
- [ ] setter/getter 方法删除
- [ ] 编译通过

---

### T11 | 适配 instance.rs

- 删除 `GlobalDynamicConnectorManager` 注册代码
- 确认 `Instance` 创建流程正确

**文件**：`easytier/src/instance/instance.rs`

**依赖**：T06, T10

**验收条件**：
- [ ] 删除 `use crate::connector::dynamic_connector_manager::GlobalDynamicConnectorManager`
- [ ] 删除 `global_dynamic_manager.register_manual_manager(...)`
- [ ] `ManualConnectorManager` 创建正常
- [ ] 添加初始 peers 正常工作

---

### T12 | 适配 direct.rs

- `DirectConnectorManager` 使用 `create_connector_by_url` 获得 `ManagedConnector`
- 确认 P2P 直连逻辑不受影响

**文件**：无需变更（由 `create_connector_by_url` 签名兼容）

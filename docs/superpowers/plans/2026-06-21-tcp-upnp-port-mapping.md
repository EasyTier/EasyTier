# TCP UPnP 端口映射支持 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 TCP 打洞流程（Server 端）中添加 UPnP TCP 端口映射，让路由器放行入站 TCP 连接。

**Architecture:** 泛化现有 UPnP 内部函数支持 TCP/UDP 协议参数，新增 `resolve_tcp_public_addr` 入口函数，在 `TcpHolePunchServer` 的 `exchange_mapped_addr` 中创建 UPnP TCP 映射。

**Tech Stack:** Rust, igd crate (UPnP IGD), nat-pmp crate (NAT-PMP), tokio

## Global Constraints

- Rust Edition 2024, Rust 1.95
- 不修改任何现有函数签名
- UPnP TCP 映射必须保证内外端口一致（使用 `add_port` 而非 `add_any_port`）
- UPnP 失败不阻断打洞流程
- 复用现有 `disable_upnp` 配置标志

---

### Task 1: upnp.rs 内部函数泛化 — IGD 部分

**Files:**
- Modify: `easytier/src/common/upnp.rs:540-582` — `add_udp_mapping_port_igd` 函数
- Modify: `easytier/src/common/upnp.rs:737-753` — `renew_udp_mapping_igd` 函数
- Modify: `easytier/src/common/upnp.rs:755-764` — `remove_udp_mapping_igd` 函数

**Interfaces:**
- Produces: `add_mapping_port_igd(gateway, local_addr, local_listener, protocol) -> Result<u16>`
- Produces: `renew_mapping_igd(gateway, local_addr, external_port, local_listener, protocol) -> Result<()>`
- Produces: `remove_mapping_igd(gateway, external_port, local_listener, protocol) -> Result<()>`

- [ ] **Step 1: 新增泛化 `add_mapping_port_igd` 函数**

在 `upnp.rs` 中 `add_udp_mapping_port_igd` 函数之后添加：

```rust
async fn add_mapping_port_igd(
    gateway: &TokioGateway,
    local_addr: SocketAddr,
    local_listener: &url::Url,
    protocol: PortMappingProtocol,
) -> anyhow::Result<u16> {
    match protocol {
        PortMappingProtocol::UDP => {
            // UDP: 先尝试 any_port，失败回退 same-port
            match gateway
                .add_any_port(protocol, local_addr, UPNP_LEASE_DURATION_SECS, UPNP_DESCRIPTION)
                .await
            {
                Ok(external_port) => Ok(external_port),
                Err(AddAnyPortError::RequestError(err)) => {
                    tracing::debug!(
                        ?err,
                        %local_listener,
                        gateway = %gateway.addr,
                        %local_addr,
                        "igd any-port mapping failed, retry with same-port mapping"
                    );
                    gateway
                        .add_port(protocol, local_addr.port(), local_addr, UPNP_LEASE_DURATION_SECS, UPNP_DESCRIPTION)
                        .await
                        .map(|_| local_addr.port())
                        .map_err(|same_port_err| {
                            anyhow!(
                                "igd mapping failed for {local_listener}: any-port error: {err}; same-port error: {same_port_err}"
                            )
                        })
                }
                Err(err) => Err(err.into()),
            }
        }
        PortMappingProtocol::TCP => {
            // TCP: 必须保证内外端口一致，直接使用 add_port
            gateway
                .add_port(protocol, local_addr.port(), local_addr, UPNP_LEASE_DURATION_SECS, UPNP_DESCRIPTION)
                .await
                .map(|_| local_addr.port())
                .map_err(|err| {
                    anyhow!("igd tcp mapping failed for {local_listener}: {err}")
                })
        }
    }
}
```

- [ ] **Step 2: 将 `add_udp_mapping_port_igd` 改为调用泛化版本**

将原有函数体替换为：

```rust
async fn add_udp_mapping_port_igd(
    gateway: &TokioGateway,
    local_addr: SocketAddr,
    local_listener: &url::Url,
) -> anyhow::Result<u16> {
    add_mapping_port_igd(gateway, local_addr, local_listener, PortMappingProtocol::UDP).await
}
```

- [ ] **Step 3: 新增泛化 `renew_mapping_igd` 函数**

在 `renew_udp_mapping_igd` 之后添加：

```rust
async fn renew_mapping_igd(
    gateway: &TokioGateway,
    local_addr: SocketAddr,
    external_port: u16,
    local_listener: &url::Url,
    protocol: PortMappingProtocol,
) -> anyhow::Result<()> {
    gateway
        .add_port(protocol, external_port, local_addr, UPNP_LEASE_DURATION_SECS, UPNP_DESCRIPTION)
        .await
        .with_context(|| format!("renew {:?} port mapping {local_listener}", protocol))
}
```

- [ ] **Step 4: 将 `renew_udp_mapping_igd` 改为调用泛化版本**

```rust
async fn renew_udp_mapping_igd(
    gateway: &TokioGateway,
    local_addr: SocketAddr,
    external_port: u16,
    local_listener: &url::Url,
) -> anyhow::Result<()> {
    renew_mapping_igd(gateway, local_addr, external_port, local_listener, PortMappingProtocol::UDP).await
}
```

- [ ] **Step 5: 新增泛化 `remove_mapping_igd` 并改写 `remove_udp_mapping_igd`**

```rust
async fn remove_mapping_igd(
    gateway: &TokioGateway,
    external_port: u16,
    local_listener: &url::Url,
    protocol: PortMappingProtocol,
) -> anyhow::Result<()> {
    gateway
        .remove_port(protocol, external_port)
        .await
        .with_context(|| format!("remove {:?} port mapping {local_listener}", protocol))
}

async fn remove_udp_mapping_igd(
    gateway: &TokioGateway,
    external_port: u16,
    local_listener: &url::Url,
) -> anyhow::Result<()> {
    remove_mapping_igd(gateway, external_port, local_listener, PortMappingProtocol::UDP).await
}
```

- [ ] **Step 6: 运行 clippy 验证**

Run: `cargo clippy --package easytier -- -D warnings`
Expected: 无新增 warning

- [ ] **Step 7: Commit**

```bash
git add easytier/src/common/upnp.rs
git commit -m "refactor(upnp): generalize IGD mapping functions with protocol parameter"
```

---

### Task 2: upnp.rs 内部函数泛化 — NAT-PMP 部分

**Files:**
- Modify: `easytier/src/common/upnp.rs:584-614` — `add_udp_mapping_port_nat_pmp` 函数
- Modify: `easytier/src/common/upnp.rs:666-688` — `renew_udp_mapping_nat_pmp` / `remove_udp_mapping_nat_pmp` 函数

**Interfaces:**
- Produces: `add_mapping_port_nat_pmp(gateway, local_addr, local_listener, protocol) -> Result<u16>`
- Produces: `renew_mapping_nat_pmp(gateway, local_addr, external_port, local_listener, protocol) -> Result<()>`
- Produces: `remove_mapping_nat_pmp(gateway, local_addr, external_port, local_listener, protocol) -> Result<()>`

- [ ] **Step 1: 新增泛化 `add_mapping_port_nat_pmp` 函数**

在 `add_udp_mapping_port_nat_pmp` 之后添加：

```rust
async fn add_mapping_port_nat_pmp(
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
    local_listener: &url::Url,
    protocol: PortMappingProtocol,
) -> anyhow::Result<u16> {
    let nat_pmp_protocol = match protocol {
        PortMappingProtocol::UDP => NatPmpProtocol::UDP,
        PortMappingProtocol::TCP => NatPmpProtocol::TCP,
        _ => bail!("unsupported protocol for nat-pmp: {:?}", protocol),
    };

    match protocol {
        PortMappingProtocol::TCP => {
            // TCP: 必须保证内外端口一致
            request_nat_pmp_mapping(gateway, local_addr.port(), local_addr.port(), UPNP_LEASE_DURATION_SECS, nat_pmp_protocol)
                .await
                .map_err(|err| {
                    anyhow!("nat-pmp tcp mapping failed for {local_listener}: {err}")
                })
        }
        _ => {
            // UDP: 先尝试 any-port，失败回退 same-port
            match request_nat_pmp_mapping(gateway, local_addr.port(), 0, UPNP_LEASE_DURATION_SECS, nat_pmp_protocol).await {
                Ok(external_port) => Ok(external_port),
                Err(any_port_err) => {
                    tracing::debug!(
                        ?any_port_err,
                        %local_listener,
                        gateway = %gateway,
                        %local_addr,
                        "nat-pmp any-port mapping failed, retry with same-port mapping"
                    );
                    request_nat_pmp_mapping(gateway, local_addr.port(), local_addr.port(), UPNP_LEASE_DURATION_SECS, nat_pmp_protocol)
                        .await
                        .map_err(|same_port_err| {
                            anyhow!("nat-pmp mapping failed for {local_listener}: any-port error: {any_port_err}; same-port error: {same_port_err}")
                        })
                }
            }
        }
    }
}
```

- [ ] **Step 2: 将 `add_udp_mapping_port_nat_pmp` 改为调用泛化版本**

```rust
async fn add_udp_mapping_port_nat_pmp(
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
    local_listener: &url::Url,
) -> anyhow::Result<u16> {
    add_mapping_port_nat_pmp(gateway, local_addr, local_listener, PortMappingProtocol::UDP).await
}
```

- [ ] **Step 3: 新增泛化 `renew_mapping_nat_pmp` 和 `remove_mapping_nat_pmp`**

```rust
async fn renew_mapping_nat_pmp(
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
    external_port: u16,
    local_listener: &url::Url,
    protocol: PortMappingProtocol,
) -> anyhow::Result<()> {
    let nat_pmp_protocol = match protocol {
        PortMappingProtocol::UDP => NatPmpProtocol::UDP,
        PortMappingProtocol::TCP => NatPmpProtocol::TCP,
        _ => bail!("unsupported protocol for nat-pmp: {:?}", protocol),
    };
    request_nat_pmp_mapping(gateway, local_addr.port(), external_port, UPNP_LEASE_DURATION_SECS, nat_pmp_protocol)
        .await
        .map(|_| ())
        .with_context(|| format!("renew {:?} port mapping {local_listener}", protocol))
}

async fn remove_mapping_nat_pmp(
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
    external_port: u16,
    local_listener: &url::Url,
    protocol: PortMappingProtocol,
) -> anyhow::Result<()> {
    let nat_pmp_protocol = match protocol {
        PortMappingProtocol::UDP => NatPmpProtocol::UDP,
        PortMappingProtocol::TCP => NatPmpProtocol::TCP,
        _ => bail!("unsupported protocol for nat-pmp: {:?}", protocol),
    };
    request_nat_pmp_mapping(gateway, local_addr.port(), external_port, 0, nat_pmp_protocol)
        .await
        .map(|_| ())
        .with_context(|| format!("remove {:?} port mapping {local_listener}", protocol))
}
```

- [ ] **Step 4: 将现有 UDP NAT-PMP 函数改为调用泛化版本**

```rust
async fn renew_udp_mapping_nat_pmp(
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
    external_port: u16,
    local_listener: &url::Url,
) -> anyhow::Result<()> {
    renew_mapping_nat_pmp(gateway, local_addr, external_port, local_listener, PortMappingProtocol::UDP).await
}

async fn remove_udp_mapping_nat_pmp(
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
    external_port: u16,
    local_listener: &url::Url,
) -> anyhow::Result<()> {
    remove_mapping_nat_pmp(gateway, local_addr, external_port, local_listener, PortMappingProtocol::UDP).await
}
```

- [ ] **Step 5: 运行 clippy 验证**

Run: `cargo clippy --package easytier -- -D warnings`
Expected: 无新增 warning

- [ ] **Step 6: Commit**

```bash
git add easytier/src/common/upnp.rs
git commit -m "refactor(upnp): generalize NAT-PMP mapping functions with protocol parameter"
```

---

### Task 3: upnp.rs 流程函数泛化

**Files:**
- Modify: `easytier/src/common/upnp.rs:336-534` — `discover_udp_port_mapping` / `run_udp_port_mapping_task` / `try_start_udp_port_mapping` 函数
- Modify: `easytier/src/common/upnp.rs:616-665` — `request_nat_pmp_mapping` 函数（添加 protocol 参数）

**Interfaces:**
- Produces: `discover_port_mapping(ctx, listener, protocol) -> Result<ActiveUdpPortMapping>`
- Produces: `run_port_mapping_task(listener, mapping, stop_rx, protocol)`
- Produces: `try_start_port_mapping(ctx, listener, protocol) -> Result<Option<UdpPortMappingLease>>`

- [ ] **Step 1: 修改 `request_nat_pmp_mapping` 添加协议参数**

将现有函数签名从硬编码 `NatPmpProtocol::UDP` 改为参数化：

```rust
async fn request_nat_pmp_mapping(
    gateway: Ipv4Addr,
    private_port: u16,
    public_port: u16,
    lifetime_secs: u32,
    protocol: NatPmpProtocol,
) -> anyhow::Result<u16> {
    let client = new_tokio_natpmp_with(gateway)
        .await
        .with_context(|| format!("create nat-pmp client for gateway {gateway}"))?;
    client
        .send_port_mapping_request(protocol, private_port, public_port, lifetime_secs)
        .await
        .with_context(|| {
            format!(
                "send nat-pmp {:?} mapping request private_port={private_port} public_port={public_port} gateway={gateway}",
                protocol
            )
        })?;
    // ... 其余逻辑不变，只把日志中的 "udp" 改为 protocol ...
}
```

注意：此函数被 Task 2 的泛化 NAT-PMP 函数调用，需要同步更新调用点。

- [ ] **Step 2: 新增泛化 `discover_port_mapping` 函数**

在 `discover_udp_port_mapping` 之后添加。逻辑与原函数相同，只是将内部调用的 `add_udp_mapping_port_igd` / `add_udp_mapping_port_nat_pmp` 替换为泛化版本：

```rust
async fn discover_port_mapping(
    global_ctx: ArcGlobalCtx,
    local_listener: url::Url,
    protocol: PortMappingProtocol,
) -> anyhow::Result<ActiveUdpPortMapping> {
    let local_addr = resolve_internal_addr(gateway_addr, &local_listener).await?;
    // 尝试 IGD
    match add_mapping_port_igd(&igd_gw, local_addr, &local_listener, protocol).await {
        Ok(external_port) => {
            return Ok(ActiveUdpPortMapping {
                local_addr,
                gateway_external_port: external_port,
                local_listener,
                backend: PortMappingBackend::Igd { gateway: igd_gw },
                global_ctx,
            });
        }
        // ... IGD 失败时尝试 NAT-PMP ...
    }
}
```

- [ ] **Step 3: 新增泛化 `run_port_mapping_task` 函数**

```rust
async fn run_port_mapping_task(
    local_listener: url::Url,
    mapping: ActiveUdpPortMapping,
    stop_rx: tokio::sync::oneshot::Receiver<()>,
    protocol: PortMappingProtocol,
) {
    // 与 run_udp_port_mapping_task 相同，但续期/移除时使用泛化函数
    // renew_mapping_igd / renew_mapping_nat_pmp / remove_mapping_igd / remove_mapping_nat_pmp
}
```

- [ ] **Step 4: 新增泛化 `try_start_port_mapping` 函数**

```rust
async fn try_start_port_mapping(
    global_ctx: &ArcGlobalCtx,
    local_listener: &url::Url,
    protocol: PortMappingProtocol,
) -> anyhow::Result<Option<UdpPortMappingLease>> {
    if global_ctx.get_flags().disable_upnp || !should_map_listener(local_listener) {
        return Ok(None);
    }
    let mapping = discover_port_mapping(global_ctx.clone(), local_listener.clone(), protocol).await?;
    // ... 启动续期任务，使用 run_port_mapping_task(..., protocol) ...
    Ok(Some(UdpPortMappingLease { ... }))
}
```

- [ ] **Step 5: 将现有 UDP 流程函数改为调用泛化版本**

```rust
async fn discover_udp_port_mapping(...) -> anyhow::Result<ActiveUdpPortMapping> {
    discover_port_mapping(global_ctx, local_listener, PortMappingProtocol::UDP).await
}

async fn run_udp_port_mapping_task(...) {
    run_port_mapping_task(local_listener, mapping, stop_rx, PortMappingProtocol::UDP).await
}

async fn try_start_udp_port_mapping(...) -> anyhow::Result<Option<UdpPortMappingLease>> {
    try_start_port_mapping(global_ctx, local_listener, PortMappingProtocol::UDP).await
}
```

- [ ] **Step 6: 运行 clippy 验证**

Run: `cargo clippy --package easytier -- -D warnings`
Expected: 无新增 warning

- [ ] **Step 7: Commit**

```bash
git add easytier/src/common/upnp.rs
git commit -m "refactor(upnp): generalize flow functions with protocol parameter"
```

---

### Task 4: 新增 should_map_listener 和 resolve_tcp_public_addr

**Files:**
- Modify: `easytier/src/common/upnp.rs:690-704` — 添加新函数
- Modify: `easytier/src/common/upnp.rs:224-271` — 参考 `resolve_udp_public_addr` 实现

**Interfaces:**
- Produces: `should_map_listener(local_listener: &url::Url) -> bool`
- Produces: `resolve_tcp_public_addr(global_ctx, local_listener) -> Result<(SocketAddr, Option<UdpPortMappingLease>)>`

- [ ] **Step 1: 新增 `should_map_listener` 函数**

在 `should_map_udp_listener` 之后添加：

```rust
fn should_map_listener(local_listener: &url::Url) -> bool {
    let scheme = local_listener.scheme();
    if scheme != "udp" && scheme != "tcp" {
        return false;
    }

    let Some(host) = listener_ipv4_host(local_listener) else {
        return false;
    };

    if host.is_loopback() || host.is_broadcast() {
        return false;
    }

    host.is_unspecified() || host.is_private() || host.is_link_local()
}
```

- [ ] **Step 2: 新增 `resolve_tcp_public_addr` 函数**

在 `resolve_udp_public_addr` 之后添加：

```rust
pub async fn resolve_tcp_public_addr(
    global_ctx: ArcGlobalCtx,
    local_listener: &url::Url,
) -> anyhow::Result<(SocketAddr, Option<UdpPortMappingLease>)> {
    let port_mapping = match try_start_port_mapping(&global_ctx, local_listener, PortMappingProtocol::TCP).await {
        Ok(mapping) => mapping,
        Err(err) => {
            tracing::warn!(
                ?err,
                %local_listener,
                "failed to establish tcp port mapping, fallback to stun-only public addr resolution"
            );
            None
        }
    };

    let local_port = local_listener
        .port()
        .ok_or_else(|| anyhow!("tcp listener port is missing"))?;

    let mapped_addr = global_ctx
        .get_stun_info_collector()
        .get_tcp_port_mapping(local_port)
        .await
        .map_err(anyhow::Error::from)
        .with_context(|| format!("resolve tcp public addr for {local_listener}"))?;

    if let Some(port_mapping) = port_mapping.as_ref() {
        let mapped_listener = build_url_from_socket_addr(&mapped_addr.to_string(), "tcp");
        global_ctx.issue_event(GlobalCtxEvent::ListenerPortMappingEstablished {
            local_listener: local_listener.clone(),
            mapped_listener,
            backend: port_mapping.backend().to_string(),
        });
        tracing::info!(
            %local_listener,
            backend = port_mapping.backend(),
            gateway_external_port = port_mapping.gateway_external_port(),
            stun_mapped_addr = %mapped_addr,
            "tcp public addr resolved after port mapping"
        );
    } else {
        tracing::debug!(
            %local_listener,
            stun_mapped_addr = %mapped_addr,
            "tcp public addr resolved without port mapping"
        );
    }

    Ok((mapped_addr, port_mapping))
}
```

- [ ] **Step 3: 添加单元测试**

在 `upnp.rs` 的 `mod tests` 中添加：

```rust
#[test]
fn tcp_mapping_requires_private_or_unspecified_ipv4_listener() {
    assert!(super::should_map_listener(&"tcp://0.0.0.0:11010".parse().unwrap()));
    assert!(super::should_map_listener(&"tcp://192.168.1.10:11010".parse().unwrap()));
    assert!(!super::should_map_listener(&"tcp://127.0.0.1:11010".parse().unwrap()));
    assert!(!super::should_map_listener(&"tcp://8.8.8.8:11010".parse().unwrap()));
    assert!(super::should_map_listener(&"udp://0.0.0.0:11010".parse().unwrap()));
    assert!(!super::should_map_listener(&"wg://0.0.0.0:11010".parse().unwrap()));
}
```

- [ ] **Step 4: 运行测试**

Run: `cargo test --package easytier --lib common::upnp::tests`
Expected: 所有测试通过

- [ ] **Step 5: 运行 clippy 验证**

Run: `cargo clippy --package easytier -- -D warnings`
Expected: 无新增 warning

- [ ] **Step 6: Commit**

```bash
git add easytier/src/common/upnp.rs
git commit -m "feat(upnp): add TCP UPnP support with resolve_tcp_public_addr"
```

---

### Task 5: TCP 打洞集成 — Server 端添加 UPnP

**Files:**
- Modify: `easytier/src/connector/tcp_hole_punch.rs:153-164` — `TcpHolePunchServer` struct
- Modify: `easytier/src/connector/tcp_hole_punch.rs:171-225` — `exchange_mapped_addr` 方法

**Interfaces:**
- Consumes: `upnp::resolve_tcp_public_addr(global_ctx, local_listener) -> Result<(SocketAddr, Option<UdpPortMappingLease>)>`
- Modifies: `TcpHolePunchServer` 添加 `leases: Arc<Mutex<HashMap<u16, UdpPortMappingLease>>>` 字段

- [ ] **Step 1: 修改 `TcpHolePunchServer` 结构体**

```rust
struct TcpHolePunchServer {
    peer_mgr: Arc<PeerManager>,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    leases: Arc<std::sync::Mutex<std::collections::HashMap<u16, upnp::UdpPortMappingLease>>>,
}
```

- [ ] **Step 2: 修改 `TcpHolePunchServer::new`**

```rust
fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
    let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
    join_joinset_background(tasks.clone(), "tcp hole punch server".to_string());
    Arc::New(Self {
        peer_mgr,
        tasks,
        leases: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    })
}
```

- [ ] **Step 3: 修改 `exchange_mapped_addr` 方法**

在 `select_local_port` 之后、`get_tcp_port_mapping` 之前插入 UPnP 逻辑：

```rust
async fn exchange_mapped_addr(
    &self,
    _ctrl: Self::Controller,
    input: TcpHolePunchRequest,
) -> rpc_types::error::Result<TcpHolePunchResponse> {
    // ... 现有的 nat type 检查和 addr 校验 ...

    let is_v6 = a_mapped_addr.is_ipv6();
    let local_port = select_local_port(&self.peer_mgr, is_v6).await?;

    // 新增：清除旧端口的 UPnP 映射
    self.leases.lock().unwrap().remove(&local_port);

    // 新增：创建 UPnP TCP 端口映射
    let local_listener_url: url::Url = format!("tcp://0.0.0.0:{}", local_port).parse().unwrap();
    match upnp::resolve_tcp_public_addr(
        self.peer_mgr.get_global_ctx(),
        &local_listener_url,
    )
    .await
    {
        Ok((_mapped_addr, Some(lease))) => {
            tracing::info!(
                local_port,
                "tcp hole punch server upnp tcp port mapping established"
            );
            self.leases.lock().unwrap().insert(local_port, lease);
        }
        Ok((_mapped_addr, None)) => {
            tracing::debug!(
                local_port,
                "tcp hole punch server no upnp mapping created"
            );
        }
        Err(err) => {
            tracing::warn!(
                ?err,
                local_port,
                "tcp hole punch server failed to create upnp tcp mapping, continuing without"
            );
        }
    }

    // 现有：STUN 获取映射地址
    let mapped_addr = self
        .peer_mgr
        .get_global_ctx()
        .get_stun_info_collector()
        .get_tcp_port_mapping(local_port)
        .await
        .with_context(|| "failed to get tcp port mapping")?;

    // ... 现有的 spawn 连接任务和返回逻辑 ...
}
```

- [ ] **Step 4: 添加 upnp 模块引用**

在 `tcp_hole_punch.rs` 的 `use` 语句中确认已引入 `use crate::common::upnp;`。如果没有，添加：

```rust
use crate::common::upnp;
```

- [ ] **Step 5: 运行 clippy 验证**

Run: `cargo clippy --package easytier -- -D warnings`
Expected: 无新增 warning

- [ ] **Step 6: 运行编译验证**

Run: `cargo build --package easytier`
Expected: 编译成功

- [ ] **Step 7: Commit**

```bash
git add easytier/src/connector/tcp_hole_punch.rs
git commit -m "feat(tcp-hole-punch): add UPnP TCP port mapping on server side"
```

---

### Task 6: 最终验证

**Files:**
- Test: 整体编译和 clippy 检查

- [ ] **Step 1: 运行完整 clippy 检查**

Run: `cargo clippy --package easytier --features full -- -D warnings`
Expected: 无 warning

- [ ] **Step 2: 运行现有 UPnP 单元测试**

Run: `cargo test --package easytier --lib common::upnp::tests`
Expected: 所有测试通过（包括新增的 `tcp_mapping_requires_private_or_unspecified_ipv4_listener`）

- [ ] **Step 3: 运行格式检查**

Run: `cargo fmt --all -- --check`
Expected: 格式正确

- [ ] **Step 4: 最终 Commit（如有格式修正）**

```bash
git add -A
git commit -m "style: apply cargo fmt"
```

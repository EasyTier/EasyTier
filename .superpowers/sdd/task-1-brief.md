# Task 1: upnp.rs 内部函数泛化 — IGD 部分

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

# Task 2: upnp.rs 内部函数泛化 — NAT-PMP 部分

**Files:**
- Modify: `easytier/src/common/upnp.rs` — `add_udp_mapping_port_nat_pmp` 函数
- Modify: `easytier/src/common/upnp.rs` — `renew_udp_mapping_nat_pmp` / `remove_udp_mapping_nat_pmp` 函数
- Modify: `easytier/src/common/upnp.rs` — `request_nat_pmp_mapping` 函数

**Interfaces:**
- Produces: `add_mapping_port_nat_pmp(gateway, local_addr, local_listener, protocol) -> Result<u16>`
- Produces: `renew_mapping_nat_pmp(gateway, local_addr, external_port, local_listener, protocol) -> Result<()>`
- Produces: `remove_mapping_nat_pmp(gateway, local_addr, external_port, local_listener, protocol) -> Result<()>`

- [ ] **Step 1: 修改 `request_nat_pmp_mapping` 添加协议参数**

将现有函数签名从硬编码 `NatPmpProtocol::UDP` 改为参数化。当前函数在约第 616 行，签名是：
```rust
async fn request_nat_pmp_mapping(
    gateway: Ipv4Addr,
    private_port: u16,
    public_port: u16,
    lifetime_secs: u32,
) -> anyhow::Result<u16>
```

改为：
```rust
async fn request_nat_pmp_mapping(
    gateway: Ipv4Addr,
    private_port: u16,
    public_port: u16,
    lifetime_secs: u32,
    protocol: NatPmpProtocol,
) -> anyhow::Result<u16>
```

函数体中将 `NatPmpProtocol::UDP` 替换为 `protocol` 参数，日志中的 "udp" 改为 `{:?}` 格式化 protocol。

注意：此函数被 `add_udp_mapping_port_nat_pmp` 调用，需要同步更新调用点传入 `NatPmpProtocol::UDP`。

- [ ] **Step 2: 新增泛化 `add_mapping_port_nat_pmp` 函数**

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

- [ ] **Step 3: 将 `add_udp_mapping_port_nat_pmp` 改为调用泛化版本**

```rust
async fn add_udp_mapping_port_nat_pmp(
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
    local_listener: &url::Url,
) -> anyhow::Result<u16> {
    add_mapping_port_nat_pmp(gateway, local_addr, local_listener, PortMappingProtocol::UDP).await
}
```

- [ ] **Step 4: 新增泛化 `renew_mapping_nat_pmp` 和 `remove_mapping_nat_pmp`**

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

- [ ] **Step 5: 将现有 UDP NAT-PMP 函数改为调用泛化版本**

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

- [ ] **Step 6: 运行 clippy 验证**

Run: `cargo clippy --package easytier -- -D warnings`
Expected: 无新增 warning

- [ ] **Step 7: Commit**

```bash
git add easytier/src/common/upnp.rs
git commit -m "refactor(upnp): generalize NAT-PMP mapping functions with protocol parameter"
```

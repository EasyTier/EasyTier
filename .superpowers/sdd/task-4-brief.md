# Task 4: 新增 should_map_listener 和 resolve_tcp_public_addr

**Files:**
- Modify: `easytier/src/common/upnp.rs` — 添加新函数

**Interfaces:**
- Produces: `should_map_listener(local_listener: &url::Url) -> bool`
- Produces: `resolve_tcp_public_addr(global_ctx, local_listener) -> Result<(SocketAddr, Option<UdpPortMappingLease>)>`

## Context

Tasks 1-3 generalized the internal UPnP functions. Now we need to add:
1. A `should_map_listener` function that accepts both `tcp://` and `udp://` URLs
2. A `resolve_tcp_public_addr` entry point for TCP hole punch
3. Update `try_start_port_mapping` to use `should_map_listener` instead of `should_map_udp_listener`

The existing `should_map_udp_listener` only accepts `udp://` URLs. The new `should_map_listener` extends this to also accept `tcp://`.

- [ ] **Step 1: 新增 `should_map_listener` 函数**

In `upnp.rs`, after `should_map_udp_listener`, add:

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

In `upnp.rs`, after `resolve_udp_public_addr`, add:

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

Note: `build_url_from_socket_addr` is a helper function already in the file. `get_tcp_port_mapping` is a method on the STUN info collector. Check the current file for exact function names and imports.

- [ ] **Step 3: 更新 `try_start_port_mapping` 使用 `should_map_listener`**

Find the `try_start_port_mapping` function (added in Task 3). It currently has a TODO comment:
```rust
// TODO: Replace with should_map_listener in Task 4
if global_ctx.get_flags().disable_upnp || !should_map_udp_listener(local_listener) {
```

Replace with:
```rust
if global_ctx.get_flags().disable_upnp || !should_map_listener(local_listener) {
```

Remove the TODO comment.

- [ ] **Step 4: 添加单元测试**

In `upnp.rs`'s `mod tests` section, add:

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

- [ ] **Step 5: 运行测试**

Run: `cargo test --package easytier --lib common::upnp::tests`
Expected: 所有测试通过

- [ ] **Step 6: 运行 clippy 验证**

Run: `cargo clippy --package easytier -- -D warnings`
Expected: 无新增 warning

- [ ] **Step 7: Commit**

```bash
git add easytier/src/common/upnp.rs
git commit -m "feat(upnp): add TCP UPnP support with resolve_tcp_public_addr"
```

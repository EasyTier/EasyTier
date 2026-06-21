# Task 3: upnp.rs 流程函数泛化

**Files:**
- Modify: `easytier/src/common/upnp.rs` — `discover_udp_port_mapping` / `run_udp_port_mapping_task` / `try_start_udp_port_mapping` 函数

**Interfaces:**
- Produces: `discover_port_mapping(ctx, listener, protocol) -> Result<ActiveUdpPortMapping>`
- Produces: `run_port_mapping_task(listener, mapping, stop_rx, protocol)`
- Produces: `try_start_port_mapping(ctx, listener, protocol) -> Result<Option<UdpPortMappingLease>>`

## Context

Tasks 1 and 2 already generalized the low-level IGD and NAT-PMP functions. Now we need to generalize the flow functions that orchestrate the port mapping process.

The `request_nat_pmp_mapping` function was already updated in Task 2 to accept a `protocol: NatPmpProtocol` parameter.

The current flow functions (`discover_udp_port_mapping`, `run_udp_port_mapping_task`, `try_start_udp_port_mapping`) call the now-generalized internal functions. We need to:
1. Create generic versions that accept a `protocol: PortMappingProtocol` parameter
2. Convert existing UDP functions to wrappers

- [ ] **Step 1: 新增泛化 `discover_port_mapping` 函数**

Read the current `discover_udp_port_mapping` function to understand its structure. It discovers UPnP IGD and NAT-PMP gateways, tries IGD first, falls back to NAT-PMP.

Create `discover_port_mapping` in the same file, after `discover_udp_port_mapping`. The logic is identical, but:
- Internal calls use the generalized functions (`add_mapping_port_igd`, `add_mapping_port_nat_pmp`)
- Pass `protocol` parameter through

```rust
async fn discover_port_mapping(
    global_ctx: ArcGlobalCtx,
    local_listener: url::Url,
    protocol: PortMappingProtocol,
) -> anyhow::Result<ActiveUdpPortMapping> {
    // Same logic as discover_udp_port_mapping, but calling:
    // - add_mapping_port_igd(..., protocol) instead of add_udp_mapping_port_igd
    // - add_mapping_port_nat_pmp(..., protocol) instead of add_udp_mapping_port_nat_pmp
}
```

- [ ] **Step 2: 将 `discover_udp_port_mapping` 改为调用泛化版本**

```rust
async fn discover_udp_port_mapping(
    global_ctx: ArcGlobalCtx,
    local_listener: url::Url,
) -> anyhow::Result<ActiveUdpPortMapping> {
    discover_port_mapping(global_ctx, local_listener, PortMappingProtocol::UDP).await
}
```

- [ ] **Step 3: 新增泛化 `run_port_mapping_task` 函数**

Read the current `run_udp_port_mapping_task` function. It runs a renewal loop that periodically calls renew functions and removes the mapping on stop.

Create `run_port_mapping_task` after it. The logic is identical, but:
- Renewal calls use generalized functions (`renew_mapping_igd`, `renew_mapping_nat_pmp`)
- Removal calls use generalized functions (`remove_mapping_igd`, `remove_mapping_nat_pmp`)
- Pass `protocol` parameter through

```rust
async fn run_port_mapping_task(
    local_listener: url::Url,
    mapping: ActiveUdpPortMapping,
    stop_rx: tokio::sync::oneshot::Receiver<()>,
    protocol: PortMappingProtocol,
) {
    // Same logic as run_udp_port_mapping_task, but calling:
    // - renew_mapping_igd(..., protocol) / renew_mapping_nat_pmp(..., protocol)
    // - remove_mapping_igd(..., protocol) / remove_mapping_nat_pmp(..., protocol)
}
```

- [ ] **Step 4: 将 `run_udp_port_mapping_task` 改为调用泛化版本**

```rust
async fn run_udp_port_mapping_task(
    local_listener: url::Url,
    mapping: ActiveUdpPortMapping,
    stop_rx: tokio::sync::oneshot::Receiver<()>,
) {
    run_port_mapping_task(local_listener, mapping, stop_rx, PortMappingProtocol::UDP).await
}
```

- [ ] **Step 5: 新增泛化 `try_start_port_mapping` 函数**

Read the current `try_start_udp_port_mapping` function. It checks `disable_upnp` and `should_map_udp_listener`, discovers mapping, starts renewal task, returns lease.

Create `try_start_port_mapping` after it. The logic is identical, but:
- Use `should_map_listener` instead of `should_map_udp_listener` (note: `should_map_listener` will be added in Task 4, for now use `should_map_udp_listener` and we'll update in Task 4)
- Call `discover_port_mapping(..., protocol)` instead of `discover_udp_port_mapping`
- Call `run_port_mapping_task(..., protocol)` instead of `run_udp_port_mapping_task`

Actually, since `should_map_listener` doesn't exist yet (Task 4), use `should_map_udp_listener` for now and add a TODO comment. Task 4 will update this.

```rust
async fn try_start_port_mapping(
    global_ctx: &ArcGlobalCtx,
    local_listener: &url::Url,
    protocol: PortMappingProtocol,
) -> anyhow::Result<Option<UdpPortMappingLease>> {
    // TODO: Replace with should_map_listener in Task 4
    if global_ctx.get_flags().disable_upnp || !should_map_udp_listener(local_listener) {
        return Ok(None);
    }
    let mapping = discover_port_mapping(global_ctx.clone(), local_listener.clone(), protocol).await?;
    // ... start renewal task using run_port_mapping_task(..., protocol) ...
    Ok(Some(UdpPortMappingLease { ... }))
}
```

- [ ] **Step 6: 将 `try_start_udp_port_mapping` 改为调用泛化版本**

```rust
async fn try_start_udp_port_mapping(
    global_ctx: &ArcGlobalCtx,
    local_listener: &url::Url,
) -> anyhow::Result<Option<UdpPortMappingLease>> {
    try_start_port_mapping(global_ctx, local_listener, PortMappingProtocol::UDP).await
}
```

- [ ] **Step 7: 运行 clippy 验证**

Run: `cargo clippy --package easytier -- -D warnings`
Expected: 无新增 warning

- [ ] **Step 8: Commit**

```bash
git add easytier/src/common/upnp.rs
git commit -m "refactor(upnp): generalize flow functions with protocol parameter"
```

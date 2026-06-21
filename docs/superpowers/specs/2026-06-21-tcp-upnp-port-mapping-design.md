# TCP UPnP 端口映射支持

## 背景

在国内大部分网络环境中，网络拓扑为 NAT44（设备 → 路由器 → CGNAT → 互联网）：
- **CGNAT（运营商 NAT）**：对 TCP 是 NAT1（full cone），不改变源端口
- **路由器（家庭路由器）**：有过滤规则，导致整体 NAT 行为变为 NAT3（port restricted cone）

UPnP 的作用是在路由器上放行端口，让路由器不再过滤该端口的入站连接，使整体 NAT 行为从 NAT3 变回 NAT1。

当前 EasyTier 的 UDP 打洞已支持 UPnP，但 TCP 打洞仅依赖 STUN TCP port mapping，没有 UPnP 支持。

## 目标

在 TCP 打洞流程（Server 端）中添加 UPnP TCP 端口映射，让路由器放行入站 TCP 连接。

**范围**：仅 TCP 打洞的 Server 端（被动监听方）。Initiator 端不需要 UPnP。

## 设计方案

### 1. upnp.rs 内部泛化

**原则**：不改现有函数签名，内部实现泛化支持 TCP/UDP。

#### 1.1 内部函数添加 protocol 参数

将以下内部函数添加 `protocol: PortMappingProtocol` 参数：

| 现有内部函数 | 泛化后 |
|---|---|
| `add_mapping_port_igd(gateway, local_addr, local_listener)` | `add_mapping_port_igd(gateway, local_addr, local_listener, protocol)` |
| `add_mapping_port_nat_pmp(gateway, local_addr, local_listener)` | `add_mapping_port_nat_pmp(gateway, local_addr, local_listener, protocol)` |
| `renew_mapping_igd(gateway, local_addr, external_port, local_listener)` | `renew_mapping_igd(gateway, local_addr, external_port, local_listener, protocol)` |
| `renew_mapping_nat_pmp(gateway, local_addr, external_port, local_listener)` | `renew_mapping_nat_pmp(gateway, local_addr, external_port, local_listener, protocol)` |
| `remove_mapping_igd(gateway, external_port, local_listener)` | `remove_mapping_igd(gateway, external_port, local_listener, protocol)` |
| `remove_mapping_nat_pmp(gateway, local_addr, external_port, local_listener)` | `remove_mapping_nat_pmp(gateway, local_addr, external_port, local_listener, protocol)` |

注意：`request_nat_pmp_mapping` 已有 `NatPmpProtocol` 参数，只需在调用点传入正确协议。

#### 1.2 现有 UDP 函数改为包装调用

现有的 UDP 特定函数（`add_udp_mapping_port_igd` 等）改为调用泛化版本并传入 `PortMappingProtocol::UDP`。签名不变，调用点零改动。

#### 1.3 流程函数泛化

| 现有函数 | 泛化后 |
|---|---|
| `discover_udp_port_mapping(ctx, listener)` | `discover_port_mapping(ctx, listener, protocol)` |
| `run_udp_port_mapping_task(listener, mapping, stop_rx)` | `run_port_mapping_task(listener, mapping, stop_rx, protocol)` |
| `try_start_udp_port_mapping(ctx, listener)` | `try_start_port_mapping(ctx, listener, protocol)` |

现有 UDP 版本改为调用泛化版本传入 `PortMappingProtocol::UDP`。

#### 1.4 TCP 端口映射使用 add_port（非 add_any_port）

**关键**：TCP 打洞时必须保证 UPnP 的外部端口等于本地端口。因此 TCP 映射使用 `add_port(protocol, local_port, local_addr)` 而非 `add_any_port`。

在 `add_mapping_port_igd` 和 `add_mapping_port_nat_pmp` 中：
- 当 `protocol == UDP` 时：先尝试 `add_any_port`，失败回退 `add_port`（现有行为）
- 当 `protocol == TCP` 时：直接使用 `add_port(protocol, local_port, local_addr)`，确保内外端口一致

#### 1.5 新增过滤函数

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

#### 1.6 新增 TCP 入口函数

```rust
pub async fn resolve_tcp_public_addr(
    global_ctx: ArcGlobalCtx,
    local_listener: &url::Url,
) -> anyhow::Result<(SocketAddr, Option<UdpPortMappingLease>)>
```

与 `resolve_udp_public_addr` 类似，但：
- 不需要 `socket` 参数（TCP 不需要绑定 socket 做 STUN）
- 使用 `get_tcp_port_mapping(local_port)` 获取 STUN 映射
- 使用 `PortMappingProtocol::TCP` 创建 UPnP 映射
- UPnP 映射使用 `add_port`（内外端口一致）

#### 1.7 不改动的内容

- `resolve_udp_public_addr` — 签名和行为不变
- `UdpPortMappingLease` — 名字保留（虽然名字含 Udp，但实际上已支持 TCP/UDP 两种协议，为避免改动现有代码不重命名）
- `should_map_udp_listener` — 名字保留
- 所有 UDP 调用点 — 零改动

### 2. TCP 打洞流程集成

**仅改动 Server 端**（`TcpHolePunchServer`）。Initiator 端不改动。

#### 2.1 TcpHolePunchServer 添加字段

```rust
struct TcpHolePunchServer {
    peer_mgr: Arc<PeerManager>,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    leases: Arc<Mutex<HashMap<u16, UdpPortMappingLease>>>,  // 新增：port → lease
}
```

#### 2.2 exchange_mapped_addr 流程改动

当前流程：
1. `select_local_port()` → 端口 X
2. STUN `get_tcp_port_mapping(X)` → 映射地址
3. spawn 连接任务
4. 返回映射地址

改动后：
1. `select_local_port()` → 端口 X
2. **清除 self.leases 中旧的映射**（如果有，drop lease 触发清除）
3. **`upnp::resolve_tcp_public_addr()` 创建 UPnP TCP 映射**
   - 使用 `add_port(TCP, X, X)` 确保内外端口一致
   - **失败不阻断流程**（warn 日志，继续）
4. **将 lease 存入 self.leases**（key = 端口 X）
5. STUN `get_tcp_port_mapping(X)` → 映射地址（仍然用 STUN 结果）
6. spawn 连接任务
7. 返回映射地址

#### 2.3 Lease 生命周期

- lease 存储在 `TcpHolePunchServer.leases` Map 中
- 当 `TcpHolePunchServer` drop 时（实例关闭），所有 lease 自动清理
- UPnP 映射有 300 秒固定租约，即使异常情况也能自然过期
- 重试时先清除旧端口的 lease，再为新端口创建新 lease

### 3. 关键设计决策

| 决策 | 说明 |
|---|---|
| UPnP 失败不阻断 | 路由器可能不支持 UPnP 或用户禁用了 UPnP，此时仅靠 STUN |
| STUN 仍用于地址发现 | UPnP 只负责路由器放行，STUN 负责探测外部地址（CGNAT 可能改变端口）|
| 复用 disable_upnp 标志 | 不新增配置项 |
| 仅 Server 端 | NAT4 场景下 initiator 是主动连接方，不需要路由器放行 |
| 内外端口一致 | TCP 映射使用 add_port 确保外部端口 = 本地端口 |
| 重试清理 | 重试换端口时先清除旧映射，避免端口泄漏 |

### 4. 文件改动清单

| 文件 | 改动 |
|---|---|
| `easytier/src/common/upnp.rs` | 内部函数泛化 + 新增 `should_map_listener` + 新增 `resolve_tcp_public_addr` |
| `easytier/src/connector/tcp_hole_punch.rs` | `TcpHolePunchServer` 添加 `leases` 字段 + `exchange_mapped_addr` 中创建 UPnP 映射 |

### 5. 不改动的文件

- `easytier/src/connector/udp_hole_punch/` — UDP 打洞零改动
- `easytier/src/instance/listeners.rs` — Listener 管理器零改动
- `easytier/src/instance/instance.rs` — 实例组装零改动
- `easytier/src/common/global_ctx.rs` — 事件系统零改动

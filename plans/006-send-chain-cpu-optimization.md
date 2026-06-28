# 计划 006：send_msg_internal 发包链路 CPU 优化

> **执行者说明**：按步骤执行本计划。每一步都必须运行验证命令，并确认结果符合预期后再继续。完成后更新 `plans/README.md` 中本计划的状态行。

## 状态

- **优先级**: P1
- **工作量**: M
- **风险**: LOW
- **依赖**: hotpath profiling infra (main branch commit `be2034dd`)
- **类别**: performance
- **数据来源**: hotpath-cpu samply 423,583,601 samples，4 threads，234K pps，pkt_size=1400

## 为什么重要

`send_msg_internal` 是数据面包转发的核心路径，每包耗时 3.26µs（wall time）。在 234K pps 下占 wall time 的 ~70%。samply inclusive CPU 分解显示有多处可通过减少冗余操作来省 µs 级开销。每包省 1µs 即可将吞吐提升 ~30%。

## 数据基线

### timing（wall time，含 await）

| Function | Calls | Avg/包 | 级差 |
|---|---|---|---|
| `send_msg_internal` | 6.9M | 3.26µs | — |
| └─ `send_msg_directly` | 6.9M | 2.83µs | 0.43µs（路由决策） |
| └─ `Peer::send_msg` | 6.9M | 2.69µs | 0.14µs（conn 选择） |
| └─ `PeerConn::send_msg` | 6.9M | 2.58µs | 0.11µs（session 选择） |

### samply inclusive CPU（send_msg_internal 子树，11.5M samples）

| % | Function | 含义 |
|---|---|---|
| 12.0% | `PeerMap::send_msg_directly` | 发包核心 |
| 7.5% | `tokio::mpsc::Sender::send` | mpsc 通道 |
| **7.1%** | **`TrafficMetricRecorder::record_tx`** | 每包流量统计 |
| **6.1%+4.8%+4.0%** | **`dashmap::get` ×3** | 冗余 dashmap 查询 |
| 5.6% | `batch_semaphore::Acquire::poll` | mpsc permit |
| **3.9%** | **`quanta::get_now`** | 时间戳获取 |
| 3.9% | `malloc` | 内存分配 |
| **1.2%** | **`TrafficCounters closure`** | 流量计数器 |
| 1.0% | `MpscTunnelSender::send` | tunnel 发送 |

## 当前代码

```rust
// easytier/src/peers/peer_manager.rs:1533-1588
async fn send_msg_internal(
    peers: &Arc<PeerMap>,
    foreign_network_client: &Arc<ForeignNetworkClient>,
    relay_peer_map: &Arc<RelayPeerMap>,
    direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
    msg: ZCPacket,
    dst_peer_id: PeerId,
) -> Result<(), Error> {
    // ...
    let send_result = if ... {
        // relay path
    } else if peers.has_peer(dst_peer_id) {           // dashmap get #1 (contains_key)
        peers.send_msg_directly(msg, dst_peer_id).await  // 内部 get_peer_by_id = dashmap get #2
    } else if foreign_network_client.has_next_hop(dst_peer_id) {
        // foreign network path
    } else if let Some(gateway) = peers.get_gateway_peer_id(dst_peer_id, policy.clone()).await {
        if peers.has_peer(gateway) || ... {              // dashmap get #3
            relay_peer_map.send_msg(msg, dst_peer_id, policy).await
        }
    }

    if send_result.is_ok() && let Some(metrics) = direct_tx_metrics {
        metrics.record_tx(dst_peer_id, packet_type, msg_len).await;  // 每包记录
    }
    send_result
}
```

```rust
// easytier/src/peers/peer_map.rs:136-164
pub async fn send_msg_directly(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
    if dst_peer_id == self.my_peer_id {
        // self-send path (tokio::spawn)
        return Ok(());
    }
    match self.get_peer_by_id(dst_peer_id) {  // dashmap get (重复)
        Some(peer) => peer.send_msg(msg).await?,
        None => return Err(Error::RouteError(...)),
    }
    Ok(())
}
```

## 优化项

### 步骤 1：合并 dashmap 冗余查询（P0，预期省 ~0.1-0.2µs/包）

**问题**：happy path 上 `has_peer(dst_peer_id)` + `send_msg_directly → get_peer_by_id(dst_peer_id)` 对同一个 key 做了 2 次 dashmap 查询。每次 ~100ns（hash + shard read lock）。

**方案**：在 `send_msg_internal` 中直接调 `get_peer_by_id`，根据 `Option<Arc<Peer>>` 分支，跳过 `has_peer` 检查。

```rust
// 改前
} else if peers.has_peer(dst_peer_id) {
    peers.send_msg_directly(msg, dst_peer_id).await
}

// 改后
} else if let Some(peer) = peers.get_peer_by_id(dst_peer_id) {
    peer.send_msg(msg).await
}
```

注意：`send_msg_directly` 中的 self-send 分支（`dst_peer_id == my_peer_id`）需要在上层处理或保留。当前 bench 场景 `dst_peer_id != my_peer_id`，不触发 self-send。

**涉及文件**：`easytier/src/peers/peer_manager.rs:1558-1559`
**冲突检查**：advisor/001-002 改过此文件（队列背压 + metrics 连带），需 rebase 后确认行号。
**验证**：`cargo test -p easytier -- send_msg_internal`

### 步骤 2：TrafficMetricRecorder 降频记录（P1，预期省 ~0.25µs/包）

**问题**：`record_tx` 每包都调用，占 inclusive CPU 的 7.1% + TrafficCounters 1.2% = 8.3%。内部做 histogram 记录（`hdrhistogram::record_n_inner`）和时间戳获取（`quanta::get_now`）。

**方案**：在 `TrafficMetricRecorder` 中引入 per-thread atomic 计数器，每 N 包（如 64）或每 T ms 刷入 histogram。

```rust
// 改前
metrics.record_tx(dst_peer_id, packet_type, msg_len).await;

// 改后
metrics.record_tx_fast(dst_peer_id, packet_type, msg_len);  // sync, atomic counter
// 内部: counter.fetch_add(msg_len); if counter % 64 == 0 { flush_to_histogram() }
```

**涉及文件**：`easytier/src/peers/traffic_metrics.rs`、`easytier/src/peers/peer_manager.rs:1584`
**冲突检查**：traffic_metrics.rs 零冲突。peer_manager.rs 同步骤 1。
**验证**：`cargo test -p easytier -- traffic_metrics`

### 步骤 3：缓存时间戳（P2，预期省 ~0.13µs/包）

**问题**：`quanta::get_now` 占 inclusive CPU 的 3.9%。send_msg_internal 路径上多处获取当前时间（record_tx 内部、traffic counters 等）。

**方案**：在 `send_msg_internal` 入口取一次时间戳，传入子函数。

```rust
let now = quanta::Instant::now();
// ...
metrics.record_tx_with_time(dst_peer_id, packet_type, msg_len, now);
```

**涉及文件**：`easytier/src/peers/peer_manager.rs`、`easytier/src/peers/traffic_metrics.rs`
**冲突检查**：同步骤 2。
**验证**：bench pps 对比。

### 步骤 4：mpsc batch send（P3，预期省 ~0.46µs/包）

**问题**：`PeerConn::send_msg` 每包做 1 次 `MpscTunnelSender::send`，触发 mpsc `Sender::send` (7.5%) + `batch_semaphore::Acquire::poll` (5.6%) + `add_permits_locked` (3.82%) = 16.9%。

**方案**：在 `PeerConn` 或 `Peer` 层引入 batch buffer，攒满 N 个包后一次 `send`（使用 `try_send` 或 unbounded channel）。

**涉及文件**：`easytier/src/peers/peer_conn.rs`、`easytier/src/tunnel/mpsc.rs`
**冲突检查**：peer_conn.rs 被 advisor/001-002 改过。mpsc.rs 被 perf/001 改过。需要协调合并顺序。
**验证**：bench pps 对比 + `cargo test -p easytier -- peer_conn`

### 步骤 5：ZCPacket 池化（P4，预期省 ~0.21µs/包）

**问题**：每包 malloc 3.9% + free 1.2% + morecore 1.2% = 6.3%。全局 munmap 4.73% 也部分来自此。

**方案**：对 ZCPacket 引入池化（`crossbeam-queue::ArrayQueue` 或 `tokio::sync::Pool`）。

**涉及文件**：`easytier/src/tunnel/packet_def.rs`
**冲突检查**：packet_def.rs 被 perf/001-003 改过。需要在 perf PR 合并后实施。
**验证**：bench pps + `cargo test -p easytier -- packet`

## 预期总收益

| 步骤 | 每包省 | 累计 |
|---|---|---|
| 步骤 1（dashmap 合并） | ~0.15µs | 3.26→3.11µs |
| 步骤 2（metrics 降频） | ~0.25µs | 3.11→2.86µs |
| 步骤 3（缓存时间戳） | ~0.13µs | 2.86→2.73µs |
| 步骤 4（batch send） | ~0.46µs | 2.73→2.27µs |
| 步骤 5（packet 池化） | ~0.21µs | 2.27→2.06µs |
| **合计** | **~1.2µs** | **3.26→2.06µs（-37%）** |

在 4 threads 配置下，预期 pps 从 234K 提升到 ~320K-370K（+37%-58%）。

## 验证方法

```bash
# baseline（当前 main + measure_all）
export PATH=$HOME/.cargo/bin:$PATH
cargo run --profile hotpath --features hotpath,hotpath-cpu --example cpu_hotspot_ring
# 记录 pps 和 timing avg

# 每个步骤实施后重跑，对比 pps 和 send_msg_internal avg
```

## 风险

- **步骤 1**：改变路由决策逻辑的边界条件（self-send、foreign network）。需确保不破坏 `send_msg_internal_*` 测试。
- **步骤 2**：metrics 精度降低（从每包精确变为每 64 包近似）。需确认 stats 查询端能接受。
- **步骤 4**：batch send 引入延迟（攒批期间包等待）。需设置 flush timeout。
- **步骤 5**：ZCPacket 池化改变生命周期模型，可能引入 use-after-free。需充分测试。

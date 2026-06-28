# hotpath CPU 热点分析与发包链路优化

## 概述

本文档记录了使用 hotpath + samply 对 easytier-core 发包链路进行 CPU 热点分析的全过程，包括工具链搭建、热点定位、优化实施、踩坑记录和最终 benchmark 结果。

## 最终 benchmark 数据

### 真实性能对比（不带 hotpath，3 runs average）

origin/main baseline 使用 `git worktree` 从 origin/main 构建，仅添加 bench example +
loopback bind fix（TCP/UDP convergence 需要）。无任何优化代码。

| Tunnel | origin/main baseline | 优化后 | **提升** | 带宽（优化后） |
|--------|---------------------|--------|---------|--------------|
| **Ring** | 293K pps / 3.3 Gbps | **1,124K pps** | **+284%** | 12.6 Gbps |
| **TCP**  | 298K pps / 3.3 Gbps | **975K pps**   | **+227%** | 10.9 Gbps |
| **UDP**  | 630K pps / 7.1 Gbps | **1,066K pps** | **+69%**  | 11.9 Gbps |

UDP baseline 本身较高（630K vs 293K/298K），因为 UDP tunnel 的 forward_from_ring_to_udp
独立 task 提供了天然的 pipeline overlap，部分隐藏了 channel 开销。

### 带 hotpath profiling（timing 可见，但有 observer effect）

| Tunnel | 原始 pps | 优化后 pps | 提升 | MpscTunnelSender::send |
|--------|---------|-----------|------|----------------------|
| Ring   | 234K    | 478K      | +104%| 138ns (原 2.23µs)    |
| UDP    | N/A     | 440K      | —    | 294ns               |
| TCP    | N/A     | 453K      | —    | 378ns               |

### hotpath observer effect

**hotpath 测量基础设施引入了 ~54-57% 的性能开销：**

| Tunnel | 不带 hotpath | 带 hotpath | hotpath 开销 |
|--------|-------------|-----------|-------------|
| Ring   | 1,124K pps  | 478K pps  | **-57%**    |
| TCP    | 975K pps    | 453K pps  | **-54%**    |

**含义：**
- timing 数据里的 `send_msg_by_ip: 2.15µs` 是膨胀值，真实成本 ~0.9µs
- 所有 timing 数据需要按 ~2.3x 校准才能反映真实开销
- hotpath 适用于相对比较（优化前 vs 后），不适用于绝对性能评估
- 生产环境部署不应用 hotpath feature 编译

测试条件：4 threads, 1400B packets, 10s, 宿主机直跑。

---

## 工具链搭建

### hotpath + samply 安装

```bash
# hotpath TUI (console)
cargo install hotpath --version 0.18.0 --bin hotpath --features tui

# hotpath-samply (samply wrapper，autospawn 依赖)
cargo install hotpath --version 0.18.0 --bin hotpath-samply

# samply 本体（hotpath-samply 内部 spawn samply record）
cargo install samply
```

### 内核参数

samply 需要 perf_event 开销，需要调整内核参数：

```bash
echo '1' | sudo tee /proc/sys/kernel/perf_event_paranoid
echo '65536' | sudo tee /proc/sys/kernel/perf_event_mlock_kb
```

- `perf_event_paranoid` 默认 2（不允许非 root 采样），需降到 1。
- `perf_event_mlock_kb` 默认 516 KB，32 核机器上 samply 的 mmap buffer 总量超限，需增大到 65536。

### hotpath profile 编译

```toml
# Cargo.toml
[profile.hotpath]
inherits = "release"
strip = false
debug = "line-tables-only"
```

samply 需要 debug symbols 且不能 strip。release profile 默认 `strip = true`，必须用单独的 profile。

### Docker 隔离环境（可选，TCP/UDP bench）

修复 loopback bind 地址后（见坑 11），TCP/UDP bench 可以直接在宿主机上跑，不需要 Docker：

```bash
# Ring（进程内，无需隔离）
HOTPATH_TUNNEL=ring ./target/hotpath/examples/cpu_hotspot_ring

# TCP/UDP（修复后也支持宿主机直跑）
HOTPATH_TUNNEL=tcp ./target/hotpath/examples/cpu_hotspot_ring
```

如果仍有 convergence 问题（多网卡环境），用 Docker 提供独立 netns：

```bash
docker run --rm \
  -v "$(pwd)/target/hotpath/examples/cpu_hotspot_ring:/bench:ro" \
  -e HOTPATH_TUNNEL=tcp \
  -e HOTPATH_BENCH_SECS=10 \
  fedora:latest \
  /bench
```

Docker 镜像需要匹配宿主机的 glibc 版本。Fedora 宿主用 `fedora:latest`。

---

## 踩坑记录

### 坑 1：samply 报 "failed to spawn samply: No such file or directory"

**现象**：hotpath CPU report 显示 `failed to spawn samply: No such file or directory (os error 2)`

**原因**：hotpath-samply 只是 wrapper，它内部 spawn `samply record --pid <pid>` 来采集 CPU 样本。samply 本体没装。

**解决**：
```bash
cargo install samply
```

如果 autospawn 找不到 hotpath-samply 本身，用环境变量指定完整路径：
```bash
export HOTPATH_SAMPLY_WRAPPER_BIN=~/.cargo/bin/hotpath-samply
```

### 坑 2：samply 报 "Failed to start profiling: mmap failed"

**现象**：samply 启动后立即报 mmap 失败。

**原因**：`perf_event_mlock_kb` 默认只有 516 KB。32 核机器上 samply 为每个 CPU core 创建 mmap buffer，总 mmap 量超过限制。

**解决**：
```bash
echo '65536' | sudo tee /proc/sys/kernel/perf_event_mlock_kb
```

### 坑 3：samply 报 "samply exited with status exit status: 1"

**现象**：samply 被 spawn 了但 exit 1。

**原因**：同坑 2——`perf_event_paranoid = 2` 时非 root 用户无法使用 perf_event_open。

**解决**：
```bash
echo '1' | sudo tee /proc/sys/kernel/perf_event_paranoid
```

### 坑 4：火焰图全是地址，看不到符号

**现象**：samply profile 打开后火焰图全是 `0x31dd24` 之类的地址。

**原因**：samply profile 里存储的是地址（不内联符号化）。符号化在查看时通过 symbol server 动态完成。如果直接下载 raw JSON 上传到 profiler.firefox.com，符号 server 无法访问本地二进制文件。

**解决**：必须用 `samply load` 本地打开（它启动 symbol server 自动做符号化）：
```bash
samply load /tmp/hotpath/<session>/hp.json.gz
```

不要下载 JSON 再上传到 profiler.firefox.com。

### 坑 5：samply 符号化后 `_dl_mcount_wrapper` 占 18.1%

**现象**：send_msg_internal inclusive 分析显示 `_dl_mcount_wrapper` 占 18.1% CPU。

**原因**：nm 的动态符号表里 `_dl_mcount_wrapper`（0x1498d0）到下一个符号（0x1b3e9e）之间有 **425 KB gap**。nm 的 bisect 查找把 gap 内所有地址错误归因到 `_dl_mcount_wrapper`。gap 里实际是 AVX2 优化的 memmove/memcmp/memset 等函数。

**解决**：用 addr2line 精确解析（而非 nm bisect）。实际开销是 memmove 1.67% + memcmp 0.20% + memset 0.19% = 2.1%，不是 18%。**没有 profiling 钩子**。

### 坑 6：parking_lot::MutexGuard 不是 Send

**现象**：使用 `parking_lot::Mutex` 替代 `tokio::sync::Mutex` 后，编译报 31 个 "future cannot be sent between threads safely"。

**原因**：`parking_lot::MutexGuard` 刻意不实现 `Send`——锁必须在获取它的同一个线程上释放。在 async fn 里 guard 跨 await 点会导致 Future 不是 Send，tokio multi_thread runtime 拒绝 spawn。

**解决**：自定义 `SpinSink`（AtomicBool spinlock），`SpinGuard` 只持有 `&SpinSink` 引用（SpinSink: Sync via unsafe impl），是 Send。

### 坑 7：std::sync::MutexGuard 也不是 Send（在某些配置下）

**现象**：`std::sync::Mutex` 同样报 "future cannot be sent between threads safely"。

**原因**：Rust 标准库的 `MutexGuard` 的 Send 实现依赖于内部类型。`Pin<Box<dyn ZCPacketSink>>` 包含 trait object，某些配置下 guard 不是 Send。

**解决**：用自定义 SpinSink 绕过所有标准 Mutex 实现。

### 坑 8：direct sink path 没有性能提升

**现象**：去掉 channel 中转（MpscTunnelSender 直接持有 sink），从 3 个 await 点（lock + feed + flush）改为 try_lock + poll_fn 合并。MpscTunnelSender::send 仍然 ~2µs。

**原因**：瓶颈不在 lock 或 channel，而在 **async fn Future 状态机的固有开销**。每次 `.await` 创建一个 Future struct、poll 它、drop 它。即使 poll 立即返回 Ready，整个 async machinery 开销 ~2µs。RingSink 实际操作只有 ~40ns（2%）。

**解决**：用 `noop_waker()` 在 async fn 内部同步调用 Sink trait 方法（poll_ready + start_send + poll_flush）。async fn 在第一次 poll 就同步完成返回——绕过所有 async 调度开销。开销从 2µs 降到 ~140ns。

### 坑 9：sync send 破坏了 TCP/UDP tunnel

**现象**：把 `send` 从 `async fn` 改为 sync `fn` 后，所有 TCP/UDP 相关测试失败（452 个失败）。

**原因**：TCP/UDP tunnel 用 channel mode（`MpscTunnel::new`）。sync `send` 的 channel path 只做 `try_send`，channel 满时返回 `BufferFull`（丢包），而不是 `send().await`（等待背压）。丢包导致 TCP/UDP 连接握手失败。

**解决**：保持 `send` 为 async fn。direct path（ring/UDP/TCP）内部用 noop_waker 同步完成（不 yield）。channel path 仍然走 async `send_async().await`。async fn wrapper 对 direct path 只有 ~100ns 开销（Future struct 创建 + 单次 poll），因为不 yield。

### 坑 10：poll_flush Pending 返回 Shutdown 导致连接断开

**现象**：noop_waker 模式下，TCP tunnel 的 `poll_flush` 可能返回 Pending（TCP 写缓冲区满）。返回 `Err(Shutdown)` 导致 PeerConn 认为连接断开。

**原因**：TCP 的 `FramedWriter::poll_flush` 做实际 socket write（系统调用）。socket 缓冲区满时返回 Pending。数据已经在 BufList 里，不需要 panic。

**解决**：poll_flush Pending 时返回 `Ok(())`。数据已在 buffer（ring buffer 或 BufList），后续操作会消费它。Pending 只意味着 "还没 flush 到网络"，不是 "错误"。

### 坑 11：TCP/UDP bench convergence 失败

**现象**：TCP/UDP tunnel 的 bench 中，两个实例无法建立连接（routes did not converge within 15s）。

**原因**：`set_bind_addr_for_peer_connector`（connector/mod.rs:70-77）收集所有本机 IP 作为 TCP bind 地址，但不包含 `127.0.0.1`。connector 绑定到 `172.17.0.2`（Docker eth0）后连接 `127.0.0.1` 路由不通 → 2 秒超时。

**解决**：在 bind 地址列表头部加入 `127.0.0.1:0`。connector 遍历所有 bind 地址，loopback 先被尝试，localhost 连接成功。

### 坑 12：ShardedCounter (#2385) 在高频路径引入回退

**现象**：cherry-pick PR #2385（ShardedCounter 替代 UnsafeCell）后，pps 下降 17%（246K → 203K）。

**原因**：ShardedCounter 的 TLS 分片设计优化多线程 contention，但每包调用 16 次 `ShardedCounter::add`（TLS load + store），单次 ~14ns，总 224ns/包。比原来的 `UnsafeCell`（~2ns/次）高 6 倍。每包 16 次的调用频率让 TLS 开销累积。

**教训**：TLS 分片策略适合 **低频高并发** 场景，不适合 **高频单线程** 的发包热路径。

### 坑 13：ZCPacket pool 不如 glibc tcache

**现象**：用 `crossbeam_queue::ArrayQueue` 做 BytesMut 对象池，每包从池取/归还。性能没有提升（甚至 -15%）。

**原因**：glibc malloc 对 ~1500 bytes 小块分配有 thread-local cache（tcache），单次 alloc ~10-15ns。ArrayQueue 的 pop/push 是 CAS 操作（~20-40ns），比 tcache 更慢。pool 还多了 capacity 检查和 clear 操作。

**教训**：手动对象池在现代 glibc tcache 面前没有优势。真正需要 pool 的场景是避免 munmap（大块 >128KB 分配），不是小块。

### 坑 14：Pipeline (FuturesUnordered) 效果微小

**现象**：用 FuturesUnordered 让多个 send_msg_by_ip 并发（pipeline_depth=4），pps 只提升 1.6%。

**原因**：try_send fast path 让 MpscTunnelSender::send 立即返回（不 await）。多个 send_msg_by_ip 之间没有自然的时间重叠——它们在 CPU 上是串行的。pipeline 需要利用 await 等待时间，但 fast path 消除了 await。

### 坑 15：hotpath 测量引入 54% observer effect

**现象**：同一 binary 带 hotpath feature 和不带 hotpath feature 跑 bench，pps 差距巨大。

**数据**：

| Tunnel | 不带 hotpath | 带 hotpath | hotpath 开销 |
|--------|-------------|-----------|-------------|
| Ring   | 1,124K pps  | 478K pps  | **-57%**    |
| TCP    | 975K pps    | 453K pps  | **-54%**    |

**原因**：hotpath `#[measure]` / `#[measure_all]` 在每个标注的 async fn 上包装 Future struct，每次 poll 记录开始/结束时间（quanta::Instant ~5ns × 2）、更新统计（atomic 操作）。measure_all 覆盖的 impl 块内所有方法都被插桩。当有 ~30 个 measure 点在发包热路径上时，累计开销超过 50%。

**教训**：
- hotpath timing 数据**适用于相对比较**（优化前 vs 后），**不适用于绝对性能评估**
- 生产环境**不应**用 hotpath feature 编译
- 要获取真实 pps，编译不带 `--features hotpath` 的版本
- timing 数据按 ~2.3x 校准可近似真实开销

---

## 优化实施记录

### 真实提升（不带 hotpath，origin/main baseline 对比）

baseline 构建：`git worktree` 从 origin/main，仅添加 bench example + loopback bind fix。

| Tunnel | baseline | 优化后 | 提升 |
|--------|---------|--------|------|
| Ring   | 293K pps | **1,124K pps** | **+284%** |
| TCP    | 298K pps | **975K pps** | **+227%** |
| UDP    | 630K pps | **1,066K pps** | **+69%** |

### 有效优化（按贡献排序）

| 优化 | 带 hotpath pps 变化 | 真实提升来源 | 机制 |
|------|--------------------|----|------|
| **noop_waker sync send** | **+90%** | **核心突破** | RingSink/FramedWriter 直接 sync poll，绕过 async machinery |
| try_send fast path | +7% | 次要 | 跳过 tokio mpsc semaphore |
| #2385 ZCPacket safe init | +5% (TCP) | TCP 专属 | copy_nonoverlapping 无 aliasing 检查 |
| metrics batch + sync | +1.6% | 小幅 | batch CounterHandle + sync fast path |
| #2381 advance (零拷贝) | ~0% | 代码质量 | Buf::advance 消除 split_off Arc churn |
| channel 32→1024 | ~0% | 减少 fallback | 更大 buffer |
| 接收侧 try_recv | ~0% (单向) | 双向有价值 | 消除 recv().await async overhead |
| loopback bind fix | — | TCP/UDP convergence 必需 | 127.0.0.1 加入 bind 地址列表 |

### 验证无效并回退

| 尝试 | 结果 | 原因 |
|------|------|------|
| ShardedCounter (#2385) | -17% pps | TLS 分片高频开销 > UnsafeCell |
| ZCPacket pool | -15% pps | glibc tcache 比 ArrayQueue CAS 更快 |
| Allocator 切换 (jemalloc/mimalloc) | ~0% | 小块分配 tcache 都已足够 |
| Pipeline (FuturesUnordered) | +1.6% | try_send 消除了 await 空隙 |
| dashmap 合并 | ~0% | contains_key 本身 ~50ns |

### noop_waker 技术详解

核心原理：async fn `send()` 内部用 `noop_waker()` 构造 dummy Context，直接调 Sink trait 的 `poll_ready` + `start_send` + `poll_flush`。RingSink 在 ring buffer 不满时所有操作立即返回 Ready——noop_waker 永远不会被触发。

```rust
pub async fn send(&self, item: ZCPacket) -> Result<(), TunnelError> {
    if let Some(sink) = &self.direct_sink {
        if let Some(mut guard) = sink.try_lock() {
            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            match guard.as_mut().poll_ready(&mut cx) {
                Poll::Ready(Ok(())) => {
                    guard.as_mut().start_send(item)?;
                    match guard.as_mut().poll_flush(&mut cx) {
                        Poll::Ready(Err(e)) => return Err(e),
                        _ => return Ok(()),  // Ready(Ok) 或 Pending 都返回 Ok
                    }
                }
                // ...
            }
        }
        return Err(TunnelError::BufferFull);
    }
    // Channel mode: async with backpressure
    self.send_async(item).await
}
```

**为什么 Pending 返回 Ok**：poll_flush Pending 意味着数据已在 buffer（ring buffer 或 BufList）但还没 flush 到网络。forward task 或下一次 send 会消费它。这是安全的——数据不丢、不乱序。

**适用范围**：所有 Sink 的 `start_send` 是同步内存操作的 tunnel：
- Ring tunnel: RingSink → ring buffer（内存）
- UDP tunnel: RingSink → ring buffer → forward_from_ring_to_udp task → socket
- TCP tunnel: FramedWriter → BufList（内存）→ poll_flush 时 write socket

---

## hotpath measure 布点

### 当前覆盖

```
send_msg_by_ip                    ✅ measure
 ├─ try_compress_and_encrypt      ✅ measure
 ├─ get_msg_dst_peer_ipv4         ✅ measure
 ├─ run_nic_packet_process_pipeline ✅ measure
 ├─ send_msg_internal             ✅ measure
 │   ├─ PeerMap::send_msg_directly  ✅ measure_all
 │   ├─ PeerMap::get_peer_by_id     ✅ measure_all
 │   ├─ PeerMap::get_gateway_peer_id ✅ measure_all
 │   ├─ PeerMap::has_peer           ✅ measure_all
 │   ├─ record_tx_fast             ❌ (sync fn, 无 measure)
 │   └─ Peer::send_msg             ✅ measure
 │       └─ PeerConn::send_msg     ✅ measure
 │           └─ MpscTunnelSender::send ✅ measure
 ├─ MpscTunnel::forward_one_round ✅ measure
 │   ├─ RingSink::poll_ready       ✅ measure_all
 │   ├─ RingSink::start_send       ✅ measure_all
 │   └─ RingSink::poll_flush       ✅ measure_all
 └─ CidrSet::*                    ✅ measure_all
```

### 布点排除项（避免与已有 PR 冲突）

| 文件 | 排除原因 |
|------|---------|
| stats_manager.rs | PR #2385 重写中 |
| traffic_metrics.rs | 依赖 stats_manager |
| peer_manager.rs (部分) | advisor/001-002 改动 |
| peer_conn.rs (部分) | advisor/001-002 改动 |
| tunnel/mpsc.rs (部分) | perf/001 改动 |
| packet_def.rs | perf/001-003 改动 |
| peer_ospf_route.rs | advisor/003-004 改动 |

---

## 运行方式

### Ring tunnel bench

```bash
cargo build --profile hotpath --features hotpath --example cpu_hotspot_ring
HOTPATH_BENCH_SECS=15 ./target/hotpath/examples/cpu_hotspot_ring
```

### TCP/UDP bench（需要 Docker 隔离）

```bash
docker run --rm \
  -v "$(pwd)/target/hotpath/examples/cpu_hotspot_ring:/bench:ro" \
  -e HOTPATH_TUNNEL=tcp \
  -e HOTPATH_BENCH_SECS=10 \
  fedora:latest \
  /bench
```

### 带 samply CPU profiling

```bash
export PATH=$HOME/.cargo/bin:$PATH
cargo run --profile hotpath --features hotpath,hotpath-cpu --example cpu_hotspot_ring

# 另一终端查看 CPU top
hotpath console
```

### 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `HOTPATH_BENCH_SECS` | 30 | 打流持续秒数 |
| `HOTPATH_PKT_SIZE` | 1400 | 包大小 |
| `HOTPATH_TUNNEL` | ring | ring / udp / tcp |
| `HOTPATH_PIPELINE` | 1 | pipeline 深度 |
| `HOTPATH_SAMPLY_WRAPPER_BIN` | — | hotpath-samply 完整路径 |
| `HOTPATH_SAMPLY_BIN` | — | samply 本体完整路径 |

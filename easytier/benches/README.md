# Benchmarks

Criterion benchmarks for EasyTier hot paths.

| Bench                       | What it measures                                                                 |
| --------------------------- | -------------------------------------------------------------------------------- |
| `tx_throughput`             | End-to-end TX injection path through `peer_manager::send_msg_by_ip`              |
| `packet_bytes_extraction`   | `ZCPacket::payload_bytes` / `tunnel_payload_bytes` extraction (advance hot path)  |

## Packet Bytes Extraction

Criterion benchmark for `ZCPacket` bytes extraction — the methods touched by the
`advance`-based slicing refactor. Measures `payload_bytes` and
`tunnel_payload_bytes` at two payload sizes (1280, 4096). Setup
(`ZCPacket::new_with_payload`) runs in the benchmark harness's preparation
phase and is excluded from the timed region, so the numbers reflect only the
extraction call.

### Quick start

```bash
cargo bench --bench packet_bytes_extraction
```

Smoke run:

```bash
PACKET_BYTES_MEASUREMENT_SECS=2 \
PACKET_BYTES_WARMUP_SECS=1 \
PACKET_BYTES_SAMPLE_SIZE=10 \
cargo bench --bench packet_bytes_extraction -- --quiet
```

### Environment variables

| Variable                        | Default | Notes                        |
| ------------------------------- | ------- | ---------------------------- |
| `PACKET_BYTES_MEASUREMENT_SECS` | `10`    | Criterion `measurement_time` |
| `PACKET_BYTES_WARMUP_SECS`      | `3`     | Criterion `warm_up_time`     |
| `PACKET_BYTES_SAMPLE_SIZE`      | `10`    | Criterion `sample_size` (min 10) |

---

## TX Throughput Benchmark

Criterion benchmark for EasyTier's TX injection path (`peer_manager::send_msg_by_ip`).

## What it measures

The benchmark sets up two EasyTier instances (`hot-a` / `hot-b`) and drives
packets from `hot-a` to `hot-b` via `peer_manager.send_msg_by_ip`. This is the
same entry point `easytier-core` uses for daily forwarded traffic, so the
numbers reflect the real TX hot path: NIC pipeline → route lookup →
compress/encrypt → peer connection → tunnel send.

Two variants are reported per tunnel kind:

| Bench                             | What it measures                                                                                                                                                                            |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tx_throughput/<tunnel>`          | Serial baseline. One send in flight at a time. Reports per-packet CPU cost (TX injection latency).                                                                                          |
| `tx_throughput/<tunnel>-saturate` | Spawns `TX_THROUGHPUT_INFLIGHT` tokio tasks that independently pump `send_msg_by_ip`. Reports the aggregate throughput ceiling the peer manager + tunnel can sustain across worker threads. |

> **Out of scope (by design):** TUN read/write (`no_tun = true`), compression
> (default `None`), reverse/RX-side measurement, multi-peer fanout. Add
> separate benchmarks if you need those.

## Quick start

### ring tunnel (no root, fastest)

```bash
cargo bench --bench tx_throughput
```

Smoke run (faster iteration):

```bash
TX_THROUGHPUT_MEASUREMENT_SECS=2 \
TX_THROUGHPUT_WARMUP_SECS=1 \
TX_THROUGHPUT_SAMPLE_SIZE=10 \
cargo bench --bench tx_throughput -- --quiet
```

### tcp / udp tunnels (requires Docker + root)

The benchmark creates a Docker network and registers each container's netns
under `/var/run/netns`, which requires root. Run the whole command under
`sudo`:

```bash
sudo TX_THROUGHPUT_TUNNEL=tcp \
     TX_THROUGHPUT_MEASUREMENT_SECS=5 \
     TX_THROUGHPUT_WARMUP_SECS=2 \
     TX_THROUGHPUT_INFLIGHT=64 \
     cargo bench --bench tx_throughput -- --quiet

sudo TX_THROUGHPUT_TUNNEL=udp cargo bench --bench tx_throughput -- --quiet
```

> If `sudo` cannot find `cargo`, use `sudo -E` or the absolute path
> (`$(which cargo)`).

## Environment variables

| Variable                         | Default               | Notes                                  |
| -------------------------------- | --------------------- | -------------------------------------- |
| `TX_THROUGHPUT_TUNNEL`           | `ring`                | `ring` / `tcp` / `udp`                 |
| `TX_THROUGHPUT_PKT_SIZE`         | `1400`                | IP total length in bytes               |
| `TX_THROUGHPUT_WORKER_THREADS`   | `4`                   | tokio worker threads                   |
| `TX_THROUGHPUT_INFLIGHT`         | `64`                  | saturate-mode concurrency (task count) |
| `TX_THROUGHPUT_TUNNEL_PORT`      | `35521`               | tcp/udp listen port                    |
| `TX_THROUGHPUT_MEASUREMENT_SECS` | `10`                  | Criterion `measurement_time`           |
| `TX_THROUGHPUT_WARMUP_SECS`      | `3`                   | Criterion `warm_up_time`               |
| `TX_THROUGHPUT_SAMPLE_SIZE`      | `10`                  | Criterion `sample_size` (min 10)       |
| `TX_THROUGHPUT_DOCKER_IMAGE`     | `busybox:latest`      | tcp/udp only                           |
| `TX_THROUGHPUT_DOCKER_NET`       | `easytier-bench-<id>` | auto-generated unique name             |
| `TX_THROUGHPUT_DOCKER_SUBNET`    | `172.31.250.0/24`     |                                        |
| `TX_THROUGHPUT_DOCKER_IP_A`      | `172.31.250.2`        |                                        |
| `TX_THROUGHPUT_DOCKER_IP_B`      | `172.31.250.3`        |                                        |

## Parameter sweeps

```bash
# Packet size
for sz in 64 256 1400 9000; do
  TX_THROUGHPUT_PKT_SIZE=$sz cargo bench --bench tx_throughput -- --quick
done

# Inflight depth (self-check: depth=1 should match serial baseline)
for d in 1 4 16 64 256; do
  TX_THROUGHPUT_INFLIGHT=$d cargo bench --bench tx_throughput -- --quick
done

# Worker threads
for w in 1 2 4 8; do
  TX_THROUGHPUT_WORKER_THREADS=$w cargo bench --bench tx_throughput -- --quick
done
```

## Interpreting results

- **`<tunnel>`** reports per-packet latency. Lower is better. Throughput
  column here is "what one in-flight sender sustains".
- **`<tunnel>-saturate`** reports aggregate throughput across
  `TX_THROUGHPUT_INFLIGHT` concurrent senders. If this matches the serial
  baseline, the TX path is bottlenecked on an internal serialization point
  (lock, single-threaded queue, etc.) rather than CPU or link bandwidth.

### Known finding (ring, single peer)

On the ring tunnel with a single destination peer, saturate does **not** beat
serial (observed ~277 MiB/s saturate vs ~288 MiB/s serial on a 4-worker
runtime). This points to a serialization point inside the peer-connection TX
path. Tunnels with real I/O await points (tcp/udp via Docker) are expected to
show a saturate > serial gap; verify with the sudo commands above.

## Output artifacts

Criterion writes HTML reports + SVG plots under
`easytier/target/criterion/`. Open `tx_throughput/<tunnel>/report/index.html`
or `.../<tunnel>-saturate/report/index.html` in a browser to inspect
distributions and regressions across runs.

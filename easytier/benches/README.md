# Benchmarks

Criterion benchmarks for EasyTier hot paths.

| Bench                     | What it measures                                                                |
| ------------------------- | ------------------------------------------------------------------------------- |
| `packet_bytes_extraction` | `ZCPacket::payload_bytes` / `tunnel_payload_bytes` extraction (advance hot path) |

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

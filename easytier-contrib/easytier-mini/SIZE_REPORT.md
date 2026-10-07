# Nano Size And Runtime Report

## Current Nano Build

The final artifact is named `easytier-nano`. It retains static IPv4/IPv6,
OS TUN, encrypted TCP/UDP, mesh routing, relay, STUN and automatic UDP hole
punching. DHCP, logs/startup notices, management services and observability
statistics are absent from the default build.

| Uncompressed static x86-64 musl build | Bytes |
| --- | ---: |
| Official mini baseline | 4,544,608 |
| Earlier static-IP mini | 2,702,128 |
| Current nano | 2,626,960 |

Nano is 42.20% smaller than the official mini baseline. Both Linux build
helpers check the produced ELF for an interpreter and `NEEDED` entries
and reject dynamically linked output. No executable compression was used.

The comparable static-address test scenarios contain seven node samples;
the DHCP scenario is excluded from both columns:

| Scenario | Official mini RSS, KiB | Nano RSS, KiB |
| --- | --- | --- |
| Two-node TCP | 5,084 / 5,172 | 3,028 / 3,036 |
| Two-node UDP | 5,180 / 5,332 | 3,100 / 3,160 |
| Relay: center / A / C | 5,136 / 5,200 / 5,176 | 3,064 / 3,064 / 3,044 |
| Mean across seven samples | 5,182.86 | 3,070.86 |

The sample mean is 40.75% lower, approximately 3.00 MiB. This is not a
peak-memory measurement or hard limit. Difficult NATs, more peers and
larger traffic loads still need more memory.

Additional memory changes:

- Unix owned UDP receive buffers are allocated only after read readiness,
  not while an idle socket waits. A `WouldBlock` retry releases its buffer.
- Small UDP packets up to 2 KiB are copied into smaller backing storage
  when the original capacity is at least four times their length. This
  trades a copy for less retained queue memory.
- The 8 KiB UDP session limit, truncation detection and source/destination
  metadata are unchanged. Maximum-sized packets remain intact.
- Without `statistics`, counters and traffic recorders are zero-sized;
  there is no metric registry, cleanup task or retained resolver closure.
  RPC metric labels are constructed only when a metrics provider exists.
- Rate limiting, throughput/latency calculations, adaptive pings, routing,
  direct connectivity, STUN and UDP punching are retained.
- Debug formatting is omitted only by the size helper's target build.
  Fatal CLI/config errors use explicit `Display` output and remain readable.

Final unit checks passed with statistics enabled and disabled, including
STUN, punching, pinger, routing/relay policy and RPC. The nano/default and
original-capability frontend graphs passed 49 test executions, including
the real UDP buffer tests in both memory modes.

Real namespace checks passed for nano-to-nano IPv4 and nano-to-full-node
IPv4/IPv6 TCP/UDP plus forced relay. The full peer was the existing normal
core artifact reporting `2.7.0-custom-ebb6a6d1`, not another mini node.
The scripted test uses `-c`, which both core and nano accept.

The compiled nano reports `easytier-nano 2.7.0`. Invalid arguments and
missing configuration files still produce errors; successful startup is
silent. Real WAN/NAT traversal and stress are not measured by the isolated
namespace scenarios; the STUN/punch algorithms are covered by focused tests.

## Previous Mini Pass

The following measurements describe the earlier commit `7a8a0ab`, before
the nano default and additional memory changes. They are historical, not
the current default configuration.

Measured on 2026-10-07, against upstream commit `728ba94`.
The checkout was fast-forwarded by 13 upstream commits before optimization.

## Binary Size

All measurements are uncompressed x86-64 Linux musl static PIE binaries.
Rust 1.95.0, the workspace `mini` profile, LTO, one codegen unit, stripped
symbols and LLVM LLD were used. No UPX or other executable packer was used.

| Build | Bytes | Reduction vs upstream |
| --- | ---: | ---: |
| Official upstream mini | 4,544,608 | - |
| Small default: TUN + DHCP + low-memory | 2,710,928 | 40.35% |
| Small static-address VPN: TUN + low-memory | 2,702,128 | 40.54% |

The default saves 1,833,680 bytes. Removing DHCP saves another 8,800 bytes;
the default is usually the more useful choice.

This is a capability-reduced build, not an equal-feature comparison.
The default removes Web management, local RPC, the console event logger,
smoltcp and proxy CIDR monitoring. These remain optional Cargo features.
It retains AES-GCM, TCP/UDP mesh, relay, native TUN, static IPv4/IPv6,
DHCP IPv4, STUN and UDP hole punching.

Upstream baseline, using an unmodified source archive:

```sh
cargo rustc --locked --profile mini --target x86_64-unknown-linux-musl \
    -p easytier-mini -- -C link-arg=-fuse-ld=lld
```

Small default:

```sh
./easytier-contrib/easytier-mini/build-small.sh
```

Small static-address-only:

```sh
./easytier-contrib/easytier-mini/build-small.sh \
    x86_64-unknown-linux-musl --no-default-features --features tun,low-memory
```

The baseline uses the prebuilt Rust standard library. The small helper
rebuilds it with size optimization and immediate abort, strips panic
locations and disables release logging. Both retain static PIE and packed
relative relocations. `file`/`readelf` confirm the small binary is stripped
and has no dynamic-library `NEEDED` entries.

## RSS Samples

Host: WSL Ubuntu-Build, x86-64, 4 logical CPUs, approximately 8 GiB RAM.
The same isolated IPv4 namespace configurations and packet exchanges were
used for upstream and the small default. Samples come from `/proc/PID/status`
after a defined two-second quiet interval following the traffic checks.

| Scenario | Upstream RSS, KiB | Small default RSS, KiB |
| --- | --- | --- |
| Two-node TCP | 5,084 / 5,172 | 3,156 / 3,188 |
| Two-node UDP | 5,180 / 5,332 | 3,244 / 3,312 |
| DHCP: seed / node / node | 5,068 / 5,288 / 5,164 | 3,144 / 3,228 / 3,192 |
| Forced relay: center / A / C | 5,136 / 5,200 / 5,176 | 3,200 / 3,188 / 3,168 |
| Mean across 10 node samples | 5,180 | 3,202 |

The sample mean is 38.19% lower. RSS ranges are 4.95-5.21 MiB upstream
and 3.07-3.23 MiB for the small default. Threads were generally two,
with one three-thread sample in each run. The runtime remains Tokio
current-thread plus any OS/DNS blocking threads.

These are workload samples, not a fixed RAM limit, peak-memory guarantee,
throughput benchmark or CPU benchmark. Larger networks, traffic bursts
and difficult NATs can use more resources.

## Runtime Changes

- Peer ingress, host egress and UDP queues: 128 to 32 under `low-memory`.
- STUN response broadcast: 1,024 to 32 under `low-memory`.
- UDP's reserved control slots, backpressure and packet sizes are unchanged.
- STUN lagged receivers skip overwritten responses without extending their
  original deadline; a closed response stream still fails.
- The hard-symmetric NAT port shuffle is allocated on first use, avoiding
  131,070 payload bytes per instance beforehand. The complete permutation
  and ongoing request indices remain unchanged.
- Native Noise includes only the protocol's 25519/ChaChaPoly/SHA256
  algorithms; full/default full-node and `official` restore the complete
  resolver algorithm set. AES-GCM data encryption remains enabled.
- CLI/completion, localization and service-manager dependencies are only
  enabled for the full management build.

Shorter UDP queues absorb smaller bursts and may drop incoming packets
sooner under congestion. This is an explicit memory/performance tradeoff.
The size helper sacrifices panic diagnostics and uses toolchain-specific
unstable flags. The normal stable Cargo build remains available.

## Verification Scope

The real Linux namespace tests cover encrypted TCP and UDP connections,
bidirectional IPv4 TUN ping, exact 64 KiB TCP and 1,200-byte UDP payload
round trips, two distinct DHCP leases through a seed, and forced three-node
relay. The small default passes these tests with itself and with upstream.
Optional IPv6 tests also pass against upstream: bidirectional TUN ping
and exact TCP/UDP payloads over both tunnel transports.

The static-address-only binary is tested with DHCP explicitly skipped.
Missing DHCP and interface features produce actionable configuration errors.

Focused Rust tests cover both 32-entry and original queue profiles, UDP
control reservation/backpressure, packet delivery, lazy NAT permutation,
STUN overflow/closure/deadline handling, Noise handshakes, secure relay and
Web security. Mini argument/configuration tests exercise default, no-default,
RPC-only, Web-only, original-capability and logging-enabled variants.

Real WAN NAT traversal and high-load NAT/throughput stress were not measured.
MIPS scripts are updated but MIPS, ARM and Windows binaries were not built
or benchmarked in this run. Those targets must be validated independently.

# ADR-0002: Go Host Provides Sockets to a Tokio-Driven WASI Core

- Status: Accepted for Phase 0 validation
- Date: 2026-07-10

## Context

The target integration loads EasyTier into a Go process without cgo. Mihomo
must control DNS and the creation of every real socket so that it can enforce
routing, loop prevention, platform policy, and security. That requirement does
not imply that Go must own EasyTier's socket I/O scheduling or protocol state.

Core already models this ownership split: a Host Adapter creates a socket, and
the resulting core Socket Interface supports asynchronous I/O below portable
tunnel framing. The desired wasm model preserves the same Interface and keeps
read/write scheduling, backpressure, framing, and protocol decisions in core.

Tokio 1.52 supports `rt`, `time`, `sync`, `macros`, and `io-util` on WASM without
unstable configuration. It also has unstable `tokio::net` support on
`wasm32-wasi`; because WASIp1 cannot create sockets, those sockets must be
provided through `FromRawFd`.

Local verification ran the existing wasm test artifacts with Go and wazero
v1.12.0:

- 220 default/no-default tests passed;
- 239 all-feature tests passed;
- timer tests exercised WASI `clock_time_get` and `poll_oneoff`.

This proves finite execution of the stable Tokio subset. It does not prove
long-lived socket I/O. wazero v1.12.0 exposes experimental pre-opened TCP
listeners, but its public socket configuration does not dynamically register an
arbitrary Go `net.Conn` or `net.PacketConn`, and its current WASIp1 polling does
not provide complete socket readiness. A virtual-fd handoff therefore requires
validation and may require a wazero extension.

wazero guest calls are synchronous on the calling Go goroutine. Calls into one
module instance must not overlap or re-enter it. An individual blocking socket
import would pause the only current-thread guest executor.

## Decision

1. Retain Tokio as core's internal executor and I/O scheduler.
2. Keep wasm execution current-thread; do not require multi-thread Tokio.
3. Give the Go Host Adapter authority over DNS and every real socket creation,
   including dial, listen, bind, and accepted platform resources.
4. Keep read/write scheduling, backpressure, portable framing, and protocol
   state in core. Host-backed I/O is not host-scheduled I/O.
5. Require every actual socket OS operation to cross WASI or a Host Adapter;
   core never accesses a host OS resource directly.
6. Prefer a host-created virtual-fd socket that core can drive through Tokio if
   Phase 0 proves dynamic resource registration and readiness are viable.
7. Treat an opaque-handle Socket Adapter and a host-owned operation/completion
   queue as fallback Implementations to compare, not predetermined ownership.
8. Forbid an individual DNS or socket import from blocking the guest executor.
9. Do not expose Tokio runtime handles, tasks, futures, or wakers across the
   Go/wasm seam, and forbid host-to-guest re-entry from an import.
10. Use cooperative stop. Closing the wasm Module is a hard watchdog, not the
    ordinary shutdown path.
11. Select the socket handoff, readiness, and executor-drive Implementation only
    after the Phase 0 measurements.

## Consequences

- The native and Go hosts share the same deep Socket Interface: the host creates
  platform resources, while core receives asynchronous sockets.
- Go does not have to own EasyTier's socket read/write state, protocol
  lifecycle, or one worker queue per operation.
- A virtual-fd Implementation may use unstable `tokio::net` support and may need
  a maintained wazero extension. Neither dependency is accepted for production
  until the PoC measures it.
- A logical Go `net.Conn` or `net.PacketConn` cannot always be reduced to an OS
  descriptor. A viable Interface must preserve wrapper behaviour when the Host
  Adapter supplies a logical connection.
- If opaque handles are used, borrowed wasm-memory views cannot outlive a host
  call. Data ownership and readiness notification must be explicit.
- A fixed periodic drive is not accepted without idle-CPU and latency evidence.

## Implementation update (2026-07-12)

The unmodified wazero 1.12.0 virtual-fd path failed its first Tokio I/O-driver
poll with WASIp1 `ENOTSUP`, so the current functional implementation uses
opaque host handles and bounded cooperative drives. This is the selected
reference implementation while the quantitative Phase 0 gates remain open.

The reusable root [`easytier-go-host`](../../easytier-go-host/README.md) package
reflects the ownership boundary in this decision:

- `SocketFactory` controls only TCP connect, UDP bind, and TCP listen creation;
- returned `net.Conn`, `net.PacketConn`, and `net.Listener` resources enter one
  host handle table;
- core/Tokio initiates every read, write, receive, send, and accept operation;
- `DNSResolver` and `ConnectorEnvironment` preserve host policy without adding
  blocking guest imports;
- `CoreModule` serializes all handles in one wazero module;
- `Bridge.Close` stops new host work, releases resources, and waits for workers.

Complete core instances use the exported exact timer deadline plus coalesced
host completions, not a periodic drive tick. Functional socket, DNS,
environment, packet, lifecycle, two-peer route, and packet-exchange gates pass;
performance, repeated-failure, and hard-isolation gates are still outstanding.

The host-driven create schema is version 13 as of 2026-07-15. Peer configuration
is submitted as one normalized runtime snapshot instead of separate runtime and
legacy-flag objects. The connectivity snapshot also carries normalized UDP,
TCP, and IPv6 UDP STUN server lists. Socket creation, DNS, and connector route
probes carry the complete core `SocketContext`, while the Go host exposes no
STUN/NAT-state or STUN port-mapping API. `CoreInstance` constructs its STUN
collector from those lists and the same host-created TCP/UDP sockets used by
native core. The opaque completion model and Tokio ownership are unchanged.
Version 13 accepts normalized listener URLs, IPv6 policy, and `SocketContext`.
Core derives the implicit Ring listener and internal TCP/UDP transport requests;
Go no longer serializes `TransportListenerConfig`. Host-submitted running
listener state remains absent, so Go cannot create a second truth source.
It names the long endpoint-discovery budget `endpoint_discovery_timeout`.
WS/WSS, QUIC and WireGuard remain native-only protocol engines and are not
advertised by the Go/WASI core artifact.

## Phase 0 unresolved decisions

Phase 0 must resolve four independent choices:

1. socket reference: injected WASI virtual fd, opaque host handle, or
   operation/completion fallback;
2. readiness: WASI `poll_oneoff`, a host readiness Interface, or completion
   delivery;
3. executor progress: a long-lived serialized guest call or bounded cooperative
   drives;
4. data transfer: direct WASI buffers or copied host-seam buffers.

The accepted combination must preserve Tokio timer and socket progress, avoid
head-of-line blocking and busy polling, support clean cancellation, preserve
logical Go connection behaviour, and meet measured idle-CPU and latency gates.

## Rejected alternatives

### Remove Tokio before validating the socket seam

Rejected because the supported Tokio subset already runs under wazero, and the
host-created socket model may allow Tokio to retain I/O scheduling.

### Require Go workers for all socket I/O

Rejected as an architectural requirement. It is a valid fallback
Implementation, but Mihomo needs creation and DNS authority rather than
EasyTier protocol ownership.

### Block in each socket or DNS import

Rejected because one pending read, write, accept, or resolution would freeze
all peer, timer, reconnect, and shutdown tasks in that wasm instance.

### Concurrent or re-entrant calls into one wasm instance

Rejected because wazero function calls are not safe to overlap and core state
has one serialized owner.

## References

- <https://docs.rs/tokio/1.52.1/src/tokio/lib.rs.html#424-455>
- <https://tokio.rs/tokio/topics/bridging>
- <https://pkg.go.dev/github.com/tetratelabs/wazero/experimental/sock>
- <https://github.com/tetratelabs/wazero/blob/v1.12.0/imports/wasi_snapshot_preview1/poll.go>
- <https://wazero.io/languages/>
- <https://pkg.go.dev/github.com/tetratelabs/wazero/api#Function>
- <https://doc.rust-lang.org/nightly/rustc/platform-support/wasm32-wasip1.html>

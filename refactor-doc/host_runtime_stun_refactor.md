# Process Host Runtime and Core STUN Refactor

> Status: complete. Updated 2026-07-14.

## Outcome

The native and Go hosts now implement the same ownership boundary:

- native uses one process-level runtime for real TCP, UDP, listener, DNS, Unix,
  FakeTCP, route-probe, and connector interface-discovery resources, while Go
  supplies the equivalent injected capability implementations;
- every instance difference needed by an OS operation is carried in the request,
  principally through `SocketContext`;
- connector and listener policy, STUN protocol/state, retries, NAT inference,
  port mapping, and lifecycle remain in `easytier-core`;
- `CoreInstance` constructs the sole production STUN collector from normalized
  server configuration plus socket and DNS Host Adapters;
- native `GlobalCtx` retains only an initially empty, stable STUN projection
  slot for pre-Core consumers and test replacement; it is not a socket, DNS,
  collector, or STUN algorithm owner;
- the Go host no longer implements a parallel STUN surface.

This closes the process-vs-instance capability debt without making instance
state process-global and without changing connectivity or wire semantics.

## Final ownership

### `easytier-core`

Core owns:

- STUN codec, change requests, UDP/TCP clients, server response handling, retry
  and probing rules;
- UDP and TCP NAT inference, public endpoint and port-range state, redetection,
  and per-instance task lifecycle;
- production construction of `StunInfoCollector` from `StunServerConfig`, the
  Host socket runtime, separate UDP/TCP `SocketContext` values, and combined
  address/record DNS capabilities;
- `StunInfoProvider`, `StunSocketMapper`, and installation into the stable
  per-instance `StunProviderSlot` used by peer state, direct connectivity, TCP
  hole punching, UDP hole punching, IP collection, and native UPnP composition;
- the normalized socket request model, including IP family, `Option<u32>` socket
  mark semantics (where `Some(0)` is distinct from `None`), and an opaque netns
  token;
- connector policy deciding when route and preferred-source facts are needed.

Core does not interpret a netns token, set a socket mark, enumerate a host
interface, or create a real socket.

### Process-level native host runtime

`easytier/src/host_runtime.rs` owns the single
`OnceLock<Arc<NativeHostRuntime>>`. It contains no `GlobalCtx`, instance netns,
socket mark, or mutable per-instance state. It implements:

- TCP connect and listen;
- UDP bind and hole-punch control sends;
- DNS address, TXT, and SRV resolution;
- Unix byte-stream creation;
- FakeTCP platform resource creation;
- route-source probes and preferred-IPv6 interface discovery.

Call sites may clone the shared `Arc`; they do not construct new factories.
`RuntimeDnsResolver` and `RuntimeUdpSocketFactory` production construction is
localized to this composition root.

Thread-scoped Linux netns guards cover synchronous OS resource creation only.
They never cross an `await`. A created socket retains its namespace while Tokio
continues connect/read/write scheduling. FakeTCP's pnet fallback keys shared raw
workers by current netns inode plus interface name; if the inode cannot be read,
worker sharing is disabled.

### Instance projection

Core's `ConnectorHostAdapter` composes `NativeHostRuntime` with
`NativeInstanceEnvironment`. The environment retains `GlobalCtx` only for facts
that are legitimately instance-specific:

- collected interface/public-address observations;
- mapped listeners;
- local, protected-port, and EasyTier-managed-address checks.

It does not implement socket factories. All real connector socket operations
are supplied separately by `NativeHostRuntime`. Route
probes and preferred-source discovery receive the active request's
`SocketContext`; they do not recover netns or mark from the retained
`GlobalCtx`.

### Native-only capabilities

UPnP and NAT-PMP remain host capabilities because they integrate with native
gateway discovery and platform resources. They may consume the core
`StunSocketMapper`; this does not make native code the STUN state owner.

`easytier/src/common/stun.rs` now contains native default-list selection, test
fixtures, and the standalone CLI diagnostic collector. It does not construct a
collector for a complete EasyTier instance and contains no production STUN
codec, probing state machine, retry policy, or NAT inference implementation.

## Go/WASM contract

Host instance create schema version 11 submits one normalized peer snapshot,
normalized STUN server configuration, and core-owned gateway runtime
configuration, and uses:

- Go-owned `SocketFactory`, `DNSResolver`, `ConnectorEnvironment`, and packet
  sink implementations;
- a core-created STUN collector rather than a host-created Module;
- core/Tokio-owned read, write, accept, readiness, cancellation, framing, and
  protocol scheduling over opaque host handles;
- a route-probe environment request carrying the complete `SocketContext`;
- no host-provided STUN state, NAT type, public endpoint, or UDP/TCP STUN mapping
  operation.
- no host-provided running-listener state; core owns one listener registry.
- URL-level listener input replaces serialized internal transport plans; core
  owns scheme classification and listener lifecycle.

The Go host therefore supplies platform capabilities without reconstructing
STUN or connectivity policy.

## Deletion and source checks

The boundary is closed when all of these remain true:

- `NativeInstanceEnvironment` has no socket factory or socket I/O implementation;
- production `RuntimeDnsResolver::new` and `RuntimeUdpSocketFactory::new` calls
  exist only in `NativeHostRuntime`;
- `GlobalCtx` contains no running-listener registry;
- Go `ConnectorEnvironment` exposes only host facts such as
  `LocalAddrForRemote`, not STUN state or port mapping;
- STUN production algorithms and mutable state live under
  `easytier-core/src/stun`;
- `easytier-core` continues to compile for `wasm32-wasip1` without real OS
  networking or DNS calls.

## Validation snapshot

The 2026-07-14 closure run passes:

- 482 `easytier-core` all-feature tests;
- native `easytier --all-features` compilation with the repository's required
  `tokio_unstable` cfg;
- `easytier-core` compilation for `wasm32-wasip1`;
- all 31 `easytier-go-host` tests, including guest rebuild, lifecycle, DNS,
  socket, environment, two-instance route, and packet exchange paths;
- focused native process-runtime, stable STUN-provider identity, and UDP/TCP
  STUN/connectivity checks run during the migration.

Known pre-existing integration-test limitations were not repaired in this
ownership refactor: legacy Ring test helpers without `TunnelInfo` block several
native hole-punch tests before the changed path, and a root-required bind test
receives `EPERM` outside the privileged Docker environment.

The earlier full Go `-race` run produced no race-detector report. Eight tests
exceeded their fixed deadline while initializing an instrumented WASM module or
probe; normal Go tests pass. This is recorded as a race-instrumented performance
limit, not evidence of a data race or a core ownership failure.

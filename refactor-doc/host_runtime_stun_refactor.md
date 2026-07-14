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
- native `GlobalCtx` projects product and instance facts but is not a socket,
  DNS, or STUN algorithm owner;
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
- `StunInfoProvider`, `StunSocketMapper`, and the stable per-instance
  `StunProviderSlot` used by peer state, direct connectivity, TCP hole punching,
  UDP hole punching, IP collection, and native UPnP composition;
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

`RuntimeConnectorHost` is an instance facts projection, not an OS runtime. Its
constructor is private and all native composition uses
`runtime_connector_host(global_ctx)`. It retains `GlobalCtx` only for facts that
are legitimately instance-specific:

- collected interface/public-address observations;
- mapped and currently running listeners;
- local, protected-port, and EasyTier-managed-address checks.

All real connector socket operations delegate to `NativeHostRuntime`. Route
probes and preferred-source discovery receive the active request's
`SocketContext`; they do not recover netns or mark from the retained
`GlobalCtx`.

### Native-only capabilities

UPnP and NAT-PMP remain host capabilities because they integrate with native
gateway discovery and platform resources. They may consume the core
`StunSocketMapper`; this does not make native code the STUN state owner.

`easytier/src/common/stun.rs` is now native composition, server-default
selection, and test fixtures around `easytier_core::stun::StunInfoCollector`.
It contains no production STUN codec, probing state machine, retry policy, or
NAT inference implementation.

## Go/WASM contract

Host instance create schema version 5 submits one normalized peer snapshot and
uses:

- Go-owned `SocketFactory`, `DNSResolver`, `ConnectorEnvironment`, and packet
  sink implementations;
- core/Tokio-owned read, write, accept, readiness, cancellation, framing, and
  protocol scheduling over opaque host handles;
- a route-probe environment request carrying the complete `SocketContext`;
- no host-provided STUN state, NAT type, public endpoint, or UDP/TCP STUN mapping
  operation.

The Go host therefore supplies platform capabilities without reconstructing
STUN or connectivity policy.

## Deletion and source checks

The boundary is closed when all of these remain true:

- production `RuntimeConnectorHost::new` calls exist only inside the centralized
  helper;
- production `RuntimeDnsResolver::new` and `RuntimeUdpSocketFactory::new` calls
  exist only in `NativeHostRuntime`;
- `RuntimeConnectorHost` contains no direct netns read, Unix connect, or raw
  interface enumeration;
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
